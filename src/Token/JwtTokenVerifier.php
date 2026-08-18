<?php

declare(strict_types=1);

namespace Chubbyphp\Oidc\Token;

use Chubbyphp\Oidc\Clock\SystemClock;
use Chubbyphp\Oidc\Discovery\OidcConfigurationResolverInterface;
use Chubbyphp\Oidc\Exception\InvalidTokenException;
use Chubbyphp\Oidc\Jwks\RemoteJwkSet;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\CallableChecker;
use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\ClaimCheckerManager;
use Jose\Component\Checker\ClaimExceptionInterface;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\InvalidHeaderException;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\MissingMandatoryHeaderParameterException;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Checker\UnencodedPayloadChecker;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSTokenSupport;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Psr\Clock\ClockInterface;

final class JwtTokenVerifier implements TokenVerifierInterface
{
    private readonly CompactSerializer $compactSerializer;

    private readonly JWSVerifier $jwsVerifier;

    private readonly HeaderCheckerManager $headerCheckerManager;

    /**
     * @var array<string>
     */
    private readonly array $mandatoryHeaderParameters;

    /**
     * The claim checkers which do not depend on the resolved configuration.
     *
     * @var array<ClaimChecker>
     */
    private readonly array $claimCheckers;

    /**
     * @var array<string>
     */
    private readonly array $mandatoryClaims;

    /**
     * @param array<string>|string $audience
     * @param null|array<string>   $algorithms
     * @param array<string>        $requiredClaims
     */
    public function __construct(
        private readonly OidcConfigurationResolverInterface $oidcConfigurationResolver,
        private readonly RemoteJwkSet $remoteJwkSet,
        array|string $audience,
        ?array $algorithms = null,
        int $clockTolerance = 0,
        ?string $typ = null,
        array $requiredClaims = [],
        private readonly ClockInterface $clock = new SystemClock(),
    ) {
        // a runtime check protects consumers from silently skipping the audience check and accepting any token
        // of the issuer
        if (!self::isNonEmptyAudience($audience)) {
            throw new \InvalidArgumentException(
                'Invalid audience: must be a non-empty string or a non-empty array of non-empty strings'
            );
        }

        if ($clockTolerance < 0) {
            throw new \InvalidArgumentException(
                \sprintf('Invalid clockTolerance %d: must be a non-negative number of seconds', $clockTolerance)
            );
        }

        if (null !== $algorithms) {
            $unsupportedAlgorithms = array_diff($algorithms, array_keys(RemoteJwkSet::SUPPORTED_ALGORITHMS));

            if ([] !== $unsupportedAlgorithms) {
                throw new \InvalidArgumentException(\sprintf(
                    'Unsupported algorithms "%s", supported (asymmetric) algorithms are "%s"',
                    implode('", "', $unsupportedAlgorithms),
                    implode('", "', array_keys(RemoteJwkSet::SUPPORTED_ALGORITHMS))
                ));
            }
        }

        $this->compactSerializer = new CompactSerializer();

        $this->jwsVerifier = new JWSVerifier(new AlgorithmManager([
            new EdDSA(),
            new ES256(),
            new ES384(),
            new ES512(),
            new PS256(),
            new PS384(),
            new PS512(),
            new RS256(),
            new RS384(),
            new RS512(),
        ]));

        $headerCheckers = [
            new AlgorithmChecker($algorithms ?? array_keys(RemoteJwkSet::SUPPORTED_ALGORITHMS)),
            new UnencodedPayloadChecker(),
        ];

        $mandatoryHeaderParameters = ['alg'];

        if (null !== $typ) {
            $headerCheckers[] = new CallableChecker(
                'typ',
                static fn (mixed $value): bool => \is_string($value)
                    && self::normalizeTyp($value) === self::normalizeTyp($typ)
            );

            $mandatoryHeaderParameters[] = 'typ';
        }

        $this->headerCheckerManager = new HeaderCheckerManager($headerCheckers, [new JWSTokenSupport()]);

        $this->mandatoryHeaderParameters = $mandatoryHeaderParameters;

        $audiences = \is_array($audience) ? $audience : [$audience];

        // "iat" is checked for its type only (via a callable): the IssuedAtChecker would also reject tokens issued
        // in the future, which neither rfc 7519 nor jose (the reference implementation) do
        $this->claimCheckers = [
            new CallableChecker('aud', static fn (mixed $value): bool => self::hasAudience($value, $audiences)),
            new CallableChecker('iat', static fn (mixed $value): bool => \is_int($value) || \is_float($value)),
            new NotBeforeChecker($clock, $clockTolerance),
            // the ExpirationTimeChecker rejects a token once now > exp + drift, while rfc 7519 (and jose) reject
            // it at now >= exp + tolerance: drift - 1 restores the exact (fail closed) boundary
            new ExpirationTimeChecker($clock, $clockTolerance - 1),
        ];

        // "iss", "aud" and "exp" are always required, "exp" needs to be required explicitly, otherwise a token
        // without expiration would be valid forever
        $this->mandatoryClaims = ['iss', 'aud', 'exp', ...$requiredClaims];
    }

    public function verify(string $token): array
    {
        $configuration = $this->oidcConfigurationResolver->resolve();

        $jws = $this->unserialize($token);

        $protectedHeader = $this->validateHeader($jws);

        /** @var string $alg guaranteed to be a non-empty string by the header checker manager */
        $alg = $protectedHeader['alg'];

        $jwk = $this->remoteJwkSet->resolveKey(
            $configuration['jwks_uri'],
            $alg,
            $protectedHeader['kid'] ?? null,
            $this->clock->now()->getTimestamp()
        );

        if (!$this->jwsVerifier->verifyWithKey($jws, $jwk, 0)) {
            throw new InvalidTokenException('signature verification failed');
        }

        $claims = $this->resolveClaims($jws);

        $this->validateClaims($claims, $configuration['issuer']);

        return $claims;
    }

    private function unserialize(string $token): JWS
    {
        try {
            $jws = $this->compactSerializer->unserialize($token);
        } catch (\Throwable $exception) {
            throw new InvalidTokenException('Invalid Compact JWS', previous: $exception);
        }

        // an empty payload is a detached one for the serializer, but a jwt always carries its claims
        if ($jws->isPayloadDetached()) {
            throw new InvalidTokenException('Invalid Compact JWS');
        }

        return $jws;
    }

    /**
     * @return array<string, mixed> the protected header
     */
    private function validateHeader(JWS $jws): array
    {
        try {
            $this->headerCheckerManager->check($jws, 0, $this->mandatoryHeaderParameters);
        } catch (InvalidHeaderException|MissingMandatoryHeaderParameterException $exception) {
            throw new InvalidTokenException($exception->getMessage(), previous: $exception);
        }

        $protectedHeader = $jws->getSignature(0)->getProtectedHeader();

        // the only recognized critical extension is "b64" (rfc 7797), and even that one must not be used to disable
        // the payload encoding of a jwt
        /** @var null|array<string> $crit guaranteed to be an array by the header checker manager */
        $crit = $protectedHeader['crit'] ?? null;

        if (null === $crit) {
            // rfc 7797: "b64" must be listed in "crit" whenever it is present, without it the payload encoding is
            // ambiguous
            if (\array_key_exists('b64', $protectedHeader)) {
                throw new InvalidTokenException('"b64" must be listed in "crit" (rfc 7797)');
            }

            return $protectedHeader;
        }

        if ([] === $crit) {
            throw new InvalidTokenException(
                '"crit" (Critical) Header Parameter MUST be a non-empty array of strings when present'
            );
        }

        foreach ($crit as $parameter) {
            if ('b64' !== $parameter) {
                throw new InvalidTokenException(
                    \sprintf('Extension Header Parameter "%s" is not recognized', $parameter)
                );
            }
        }

        // the header checker manager made sure "b64" is present (it is part of "crit") and a boolean
        if (false === ($protectedHeader['b64'] ?? null)) {
            throw new InvalidTokenException('JWTs MUST NOT use unencoded payload');
        }

        return $protectedHeader;
    }

    /**
     * @return array<string, mixed>
     */
    private function resolveClaims(JWS $jws): array
    {
        // invalid json decodes to null, which is not an object either
        $claims = json_decode((string) $jws->getPayload(), true);

        if (!\is_array($claims)) {
            throw new InvalidTokenException('JWT Claims Set must be a top-level JSON object');
        }

        /** @var array<string, mixed> $claims */
        return $claims;
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function validateClaims(array $claims, string $issuer): void
    {
        // only the issuer is known at verification time (from the resolved configuration), the other checkers are
        // shared between verifications
        $claimCheckerManager = new ClaimCheckerManager([new IssuerChecker([$issuer]), ...$this->claimCheckers]);

        try {
            $claimCheckerManager->check($claims, $this->mandatoryClaims);
        } catch (ClaimExceptionInterface $exception) {
            throw new InvalidTokenException($exception->getMessage(), previous: $exception);
        }
    }

    /**
     * @param array<string> $audiences
     */
    private static function hasAudience(mixed $tokenAudience, array $audiences): bool
    {
        if (\is_string($tokenAudience)) {
            return \in_array($tokenAudience, $audiences, true);
        }

        if (\is_array($tokenAudience)) {
            foreach ($tokenAudience as $value) {
                if (\in_array($value, $audiences, true)) {
                    return true;
                }
            }
        }

        return false;
    }

    private static function normalizeTyp(string $typ): string
    {
        $typ = strtolower($typ);

        return str_starts_with($typ, 'application/') ? substr($typ, 12) : $typ;
    }

    /**
     * @phpstan-assert-if-true non-empty-string $value
     */
    private static function isNonEmptyString(mixed $value): bool
    {
        return \is_string($value) && '' !== $value;
    }

    /**
     * @phpstan-assert-if-true non-empty-array<non-empty-string> $value
     */
    private static function isNonEmptyStringArray(mixed $value): bool
    {
        if (!\is_array($value) || [] === $value) {
            return false;
        }

        foreach ($value as $item) {
            if (!self::isNonEmptyString($item)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param array<mixed>|string $audience
     */
    private static function isNonEmptyAudience(array|string $audience): bool
    {
        return self::isNonEmptyString($audience) || self::isNonEmptyStringArray($audience);
    }
}
