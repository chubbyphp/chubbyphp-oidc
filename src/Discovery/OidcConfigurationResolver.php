<?php

declare(strict_types=1);

namespace Chubbyphp\Oidc\Discovery;

use Chubbyphp\Oidc\Clock\SystemClock;
use Chubbyphp\Oidc\Exception\OidcConfigurationException;
use Psr\Clock\ClockInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

/**
 * @phpstan-import-type OidcConfiguration from OidcConfigurationResolverInterface
 */
final class OidcConfigurationResolver implements OidcConfigurationResolverInterface
{
    private readonly string $url;

    /**
     * @var null|array{configuration: OidcConfiguration, validUntil: int}
     */
    private ?array $cache = null;

    /**
     * @var null|array{error: \Throwable, retryAfter: int}
     */
    private ?array $failure = null;

    public function __construct(
        private readonly string $issuer,
        private readonly ClientInterface $client,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly int $maxAge = 3600,
        private readonly int $cooldown = 30,
        bool $allowInsecureIssuer = false,
        private readonly ClockInterface $clock = new SystemClock(),
    ) {
        if (!self::isHttpUrl($issuer)) {
            throw new \InvalidArgumentException(
                \sprintf('Invalid issuer "%s": must be an absolute http(s) url', $issuer)
            );
        }

        // whoever can tamper with an unprotected discovery / jwks fetch can forge accepted tokens: a plain http
        // issuer (local development) has to be a deliberate decision, not a copied example or a missing "s"
        if (!$allowInsecureIssuer && !self::isHttpsUrl($issuer)) {
            throw new \InvalidArgumentException(\sprintf(
                'Insecure issuer "%s": use https or explicitly opt in with allowInsecureIssuer (local development only)',
                $issuer
            ));
        }

        self::assertNonNegative('maxAge', $maxAge);
        self::assertNonNegative('cooldown', $cooldown);

        $this->url = rtrim($issuer, '/').'/.well-known/openid-configuration';
    }

    public function resolve(): array
    {
        $now = $this->clock->now()->getTimestamp();

        if (null !== $this->cache && $this->cache['validUntil'] > $now) {
            return $this->cache['configuration'];
        }

        if (null !== $this->failure && $this->failure['retryAfter'] > $now) {
            return $this->resolveStaleConfiguration($this->failure['error']);
        }

        return $this->resolveConfiguration($now);
    }

    /**
     * @return OidcConfiguration
     */
    private function resolveConfiguration(int $now): array
    {
        try {
            $configuration = $this->fetchConfiguration();

            $this->cache = ['configuration' => $configuration, 'validUntil' => $now + $this->maxAge];
            $this->failure = null;

            return $configuration;
        } catch (\Throwable $error) {
            // fail fast during an outage instead of hitting the issuer with every request
            $this->failure = ['error' => $error, 'retryAfter' => $now + $this->cooldown];

            return $this->resolveStaleConfiguration($error);
        }
    }

    /**
     * An issuer outage should not take the resource server down: keep serving the last known configuration (the
     * jwks itself is fetched and cached separately) and only fail if there never was one.
     *
     * @return OidcConfiguration
     */
    private function resolveStaleConfiguration(\Throwable $error): array
    {
        if (null !== $this->cache) {
            return $this->cache['configuration'];
        }

        throw $error;
    }

    /**
     * @return OidcConfiguration
     */
    private function fetchConfiguration(): array
    {
        $response = $this->client->sendRequest($this->requestFactory->createRequest('GET', $this->url));

        $statusCode = $response->getStatusCode();

        if ($statusCode < 200 || $statusCode >= 300) {
            throw new OidcConfigurationException(
                \sprintf('Cannot fetch oidc configuration from "%s": status %d', $this->url, $statusCode)
            );
        }

        try {
            $configuration = json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new OidcConfigurationException(
                \sprintf('Cannot fetch oidc configuration from "%s": invalid json', $this->url),
                previous: $exception
            );
        }

        if (!\is_array($configuration)) {
            throw new OidcConfigurationException(
                \sprintf('Cannot fetch oidc configuration from "%s": invalid json', $this->url)
            );
        }

        $givenIssuer = $configuration['issuer'] ?? null;

        if ($givenIssuer !== $this->issuer) {
            throw new OidcConfigurationException(\sprintf(
                'Issuer mismatch: expected "%s", given "%s"',
                $this->issuer,
                \is_string($givenIssuer) ? $givenIssuer : get_debug_type($givenIssuer)
            ));
        }

        $jwksUri = $configuration['jwks_uri'] ?? null;

        // fail here with a clear message instead of an obscure error on the first token verification
        if (!\is_string($jwksUri) || !self::isHttpUrl($jwksUri)) {
            throw new OidcConfigurationException(\sprintf(
                'Missing or invalid jwks_uri "%s" for issuer "%s"',
                \is_string($jwksUri) ? $jwksUri : get_debug_type($jwksUri),
                $this->issuer
            ));
        }

        // a https issuer must not downgrade its keys to plain http (mitm on the jwks fetch means forged tokens)
        if (self::isHttpsUrl($this->issuer) && !self::isHttpsUrl($jwksUri)) {
            throw new OidcConfigurationException(
                \sprintf('Insecure jwks_uri "%s" for https issuer "%s"', $jwksUri, $this->issuer)
            );
        }

        /** @var OidcConfiguration $configuration */
        return $configuration;
    }

    private static function assertNonNegative(string $name, int $value): void
    {
        if ($value < 0) {
            throw new \InvalidArgumentException(
                \sprintf('Invalid %s %d: must be a non-negative number of seconds', $name, $value)
            );
        }
    }

    /**
     * An absolute url with a http or https scheme (an issuer or a jwks uri with any other scheme makes no sense
     * for a discovery / jwks fetch).
     */
    private static function isHttpUrl(string $value): bool
    {
        return false !== filter_var($value, FILTER_VALIDATE_URL)
            && \in_array(strtolower((string) parse_url($value, PHP_URL_SCHEME)), ['http', 'https'], true);
    }

    private static function isHttpsUrl(string $value): bool
    {
        return str_starts_with(strtolower($value), 'https://');
    }
}
