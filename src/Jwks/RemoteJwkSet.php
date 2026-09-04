<?php

declare(strict_types=1);

namespace Chubbyphp\Oidc\Jwks;

use Chubbyphp\Oidc\Exception\InvalidTokenException;
use Chubbyphp\Oidc\Exception\JwksException;
use Jose\Component\Core\JWK;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

/**
 * Fetches and caches the JSON Web Key Set of a jwks uri and selects the (single) key a token can be verified with:
 * the jwks gets refetched after maxAge, on an unknown key id (key rotation) at most once per cooldown, and during
 * an outage the last known keys are served (stale) instead of failing, but for at most maxStale after the cache
 * expired.
 */
final class RemoteJwkSet
{
    /**
     * All asymmetric signature algorithms supported by web-token/jwt-library and the key type ("kty") each of them
     * needs. Symmetric algorithms (HS*) are not supported at all: a public (jwks) key must never be usable as a
     * hmac secret (algorithm confusion).
     */
    public const SUPPORTED_ALGORITHMS = [
        'EdDSA' => 'OKP',
        'ES256' => 'EC',
        'ES384' => 'EC',
        'ES512' => 'EC',
        'PS256' => 'RSA',
        'PS384' => 'RSA',
        'PS512' => 'RSA',
        'RS256' => 'RSA',
        'RS384' => 'RSA',
        'RS512' => 'RSA',
    ];

    /**
     * The jwks uri the cached jwks and the failure belong to.
     */
    private ?string $jwksUri = null;

    /**
     * @var null|array{keys: list<array<string, mixed>>, fetchedAt: int}
     */
    private ?array $jwks = null;

    /**
     * @var null|array{error: \Throwable, retryAfter: int}
     */
    private ?array $failure = null;

    /**
     * @param null|int $maxStale seconds an expired jwks keeps being used while its refetch fails (0: never, null: for
     *                           as long as the outage lasts). Bounded by default: a key the issuer removed (e.g. a
     *                           compromised one) must not stay valid for as long as a jwks outage lasts, null trades
     *                           this for availability.
     */
    public function __construct(
        private readonly ClientInterface $client,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly int $maxAge = 600,
        private readonly int $cooldown = 30,
        private readonly ?int $maxStale = 3600,
    ) {
        self::assertNonNegative('maxAge', $maxAge);
        self::assertNonNegative('cooldown', $cooldown);

        if (null !== $maxStale) {
            self::assertNonNegative('maxStale', $maxStale);
        }
    }

    /**
     * @param string $alg the "alg" (Algorithm) header parameter of the token
     * @param mixed  $kid the "kid" (Key ID) header parameter of the token, if any
     * @param int    $now the current unix timestamp
     *
     * @throws InvalidTokenException if there is no (or no unambiguous) applicable key for the token
     * @throws JwksException         if the jwks cannot be fetched or is malformed (and there are no stale keys, or
     *                               they are stale for longer than maxStale)
     * @throws \Throwable            any error of the http client (and there are no stale keys, or they are stale
     *                               for longer than maxStale)
     */
    public function resolveKey(string $jwksUri, string $alg, mixed $kid, int $now): JWK
    {
        // a changed jwks uri (new configuration) starts over
        if ($this->jwksUri !== $jwksUri) {
            $this->jwksUri = $jwksUri;
            $this->jwks = null;
            $this->failure = null;
        }

        // fail fast (or serve stale) during an outage instead of hitting the jwks uri with every request
        if (null !== $this->failure && $this->failure['retryAfter'] > $now) {
            return $this->resolveStaleKey($alg, $kid, $now, $this->failure['error']);
        }

        try {
            return $this->resolveRemoteKey($jwksUri, $alg, $kid, $now);
        } catch (InvalidTokenException $exception) {
            // a token error (unknown key id, ...) is not an outage
            throw $exception;
        } catch (\Throwable $error) {
            $this->failure = ['error' => $error, 'retryAfter' => $now + $this->cooldown];

            return $this->resolveStaleKey($alg, $kid, $now, $error);
        }
    }

    /**
     * A jwks outage should not take the resource server down: verify against the last known keys (if there ever
     * were any) instead of failing, but only for maxStale after the cache expired: a key the issuer removed since
     * (e.g. a compromised one) must not stay valid for as long as the outage lasts.
     */
    private function resolveStaleKey(string $alg, mixed $kid, int $now, \Throwable $error): JWK
    {
        if (null === $this->jwks) {
            throw $error;
        }

        if (null !== $this->maxStale && $this->jwks['fetchedAt'] + $this->maxAge + $this->maxStale <= $now) {
            throw $error;
        }

        return $this->findKey($this->jwks['keys'], $alg, $kid)
            ?? throw new InvalidTokenException('no applicable key found in the JSON Web Key Set');
    }

    private function resolveRemoteKey(string $jwksUri, string $alg, mixed $kid, int $now): JWK
    {
        $jwks = null === $this->jwks || $this->jwks['fetchedAt'] + $this->maxAge <= $now
            ? $this->fetchJwks($jwksUri, $now)
            : $this->jwks;

        $jwk = $this->findKey($jwks['keys'], $alg, $kid);

        // an unknown key id (key rotation) triggers a refetch, but at most once per cooldown
        if (null === $jwk && $jwks['fetchedAt'] + $this->cooldown <= $now) {
            $jwks = $this->fetchJwks($jwksUri, $now);

            $jwk = $this->findKey($jwks['keys'], $alg, $kid);
        }

        return $jwk ?? throw new InvalidTokenException('no applicable key found in the JSON Web Key Set');
    }

    /**
     * @return array{keys: list<array<string, mixed>>, fetchedAt: int}
     */
    private function fetchJwks(string $jwksUri, int $now): array
    {
        $response = $this->client->sendRequest($this->requestFactory->createRequest('GET', $jwksUri));

        if (200 !== $response->getStatusCode()) {
            throw new JwksException('Expected 200 OK from the JSON Web Key Set HTTP response');
        }

        try {
            $jwks = json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException $exception) {
            throw new JwksException(
                'Failed to parse the JSON Web Key Set HTTP response as JSON',
                previous: $exception
            );
        }

        if (!\is_array($jwks) || !self::isJwkList($jwks['keys'] ?? null)) {
            throw new JwksException('JSON Web Key Set malformed');
        }

        return $this->jwks = ['keys' => $jwks['keys'], 'fetchedAt' => $now];
    }

    /**
     * @param list<array<string, mixed>> $keys
     */
    private function findKey(array $keys, string $alg, mixed $kid): ?JWK
    {
        $kty = self::SUPPORTED_ALGORITHMS[$alg]
            ?? throw new InvalidTokenException('Unsupported "alg" value for a JSON Web Key Set');

        $candidate = null;

        foreach ($keys as $jwk) {
            if (!self::isCandidate($jwk, $kty, $alg, $kid)) {
                continue;
            }

            // ambiguous key selection (e.g. token without "kid" against a jwks with multiple keys of the same alg):
            // the token cannot be verified, treat it like a token without a matching key instead of an internal error
            if (null !== $candidate) {
                throw new InvalidTokenException('multiple matching keys found in the JSON Web Key Set');
            }

            $candidate = $jwk;
        }

        return null !== $candidate ? new JWK($candidate) : null;
    }

    /**
     * @param array<string, mixed> $jwk
     */
    private static function isCandidate(array $jwk, string $kty, string $alg, mixed $kid): bool
    {
        // "alg", "use" and "key_ops" are optional, but when present they must be well-formed (rfc 7517) and match:
        // a malformed one (e.g. "key_ops": "sign") must not be treated as unrestricted
        return $kty === ($jwk['kty'] ?? null)
            && (!\is_string($kid) || $kid === ($jwk['kid'] ?? null))
            && (!\array_key_exists('alg', $jwk) || $alg === $jwk['alg'])
            && (!\array_key_exists('use', $jwk) || 'sig' === $jwk['use'])
            && (!\array_key_exists('key_ops', $jwk) || self::hasKeyOperation($jwk['key_ops'], 'verify'))
            && self::matchesCurve($jwk['crv'] ?? null, $alg);
    }

    private static function hasKeyOperation(mixed $keyOps, string $keyOp): bool
    {
        return \is_array($keyOps) && \in_array($keyOp, $keyOps, true);
    }

    private static function matchesCurve(mixed $crv, string $alg): bool
    {
        return match ($alg) {
            'ES256' => 'P-256' === $crv,
            'ES384' => 'P-384' === $crv,
            'ES512' => 'P-521' === $crv,
            'EdDSA' => 'Ed25519' === $crv,
            default => true,
        };
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
     * @phpstan-assert-if-true list<array<string, mixed>> $value
     */
    private static function isJwkList(mixed $value): bool
    {
        if (!\is_array($value) || !array_is_list($value)) {
            return false;
        }

        foreach ($value as $jwk) {
            if (!\is_array($jwk)) {
                return false;
            }
        }

        return true;
    }
}
