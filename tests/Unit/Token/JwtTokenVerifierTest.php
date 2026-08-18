<?php

declare(strict_types=1);

namespace Chubbyphp\Tests\Oidc\Unit\Token;

use Chubbyphp\Mock\MockMethod\WithException;
use Chubbyphp\Mock\MockMethod\WithReturn;
use Chubbyphp\Mock\MockObjectBuilder;
use Chubbyphp\Oidc\Discovery\OidcConfigurationResolverInterface;
use Chubbyphp\Oidc\Exception\InvalidTokenException;
use Chubbyphp\Oidc\Exception\JwksException;
use Chubbyphp\Oidc\Jwks\RemoteJwkSet;
use Chubbyphp\Oidc\Token\JwtTokenVerifier;
use Chubbyphp\Tests\Oidc\FrozenClock;
use Chubbyphp\Tests\Oidc\JwsHelper;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

/**
 * @covers \Chubbyphp\Oidc\Token\JwtTokenVerifier
 *
 * @internal
 */
final class JwtTokenVerifierTest extends TestCase
{
    private const ISSUER = 'https://issuer.example.com';
    private const JWKS_URI = 'https://issuer.example.com/jwks';
    private const CONFIGURATION = ['issuer' => self::ISSUER, 'jwks_uri' => self::JWKS_URI];
    private const NOW = 1750000000;

    /**
     * @param array<mixed>|string $audience
     */
    #[DataProvider('provideCreateVerifierWithInvalidAudienceCases')]
    public function testCreateVerifierWithInvalidAudience(array|string $audience): void
    {
        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, []);

        [$client, $requestFactory] = self::createFetchMocks($builder, []);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Invalid audience: must be a non-empty string or a non-empty array of non-empty strings'
        );

        /** @var array<string>|string $audience */
        new JwtTokenVerifier($oidcConfigurationResolver, new RemoteJwkSet($client, $requestFactory), $audience);
    }

    /**
     * @return iterable<string, array{array<mixed>|string}>
     */
    public static function provideCreateVerifierWithInvalidAudienceCases(): iterable
    {
        yield 'empty string' => [''];

        yield 'empty array' => [[]];

        yield 'array with empty string' => [['audience-1', '']];

        yield 'array with non string' => [['audience-1', 123]];
    }

    public function testCreateVerifierWithUnsupportedAlgorithms(): void
    {
        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, []);

        [$client, $requestFactory] = self::createFetchMocks($builder, []);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Unsupported algorithms "HS256", "none", supported (asymmetric) algorithms are "EdDSA", "ES256", "ES384",'
                .' "ES512", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512"'
        );

        new JwtTokenVerifier($oidcConfigurationResolver, new RemoteJwkSet($client, $requestFactory), 'audience-1', ['RS256', 'HS256', 'none']);
    }

    public function testCreateVerifierWithNegativeClockTolerance(): void
    {
        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, []);

        [$client, $requestFactory] = self::createFetchMocks($builder, []);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid clockTolerance -1: must be a non-negative number of seconds');

        new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clockTolerance: -1
        );
    }

    public function testVerifyToken(): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $claims = self::createClaims();

        $token = self::createToken($privateJwk, $claims);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertSame($claims, $tokenVerifier->verify($token));
    }

    public function testVerifyTokenWithAudienceArray(): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $claims = self::createClaims();

        $token = self::createToken($privateJwk, $claims);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            ['audience-2', 'audience-1'],
            clock: new FrozenClock(self::NOW)
        );

        self::assertSame($claims, $tokenVerifier->verify($token));
    }

    public function testVerifyTokenWithCachedJwkSet(): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $claims = self::createClaims();

        $token = self::createToken($privateJwk, $claims);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver(
            $builder,
            [self::CONFIGURATION, self::CONFIGURATION]
        );

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertSame($claims, $tokenVerifier->verify($token));
        self::assertSame($claims, $tokenVerifier->verify($token));
    }

    public function testVerifyTokenWithChangedJwksUri(): void
    {
        $otherJwksUri = 'https://issuer.example.com/other-jwks';

        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $claims = self::createClaims();

        $token = self::createToken($privateJwk, $claims);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [
            self::CONFIGURATION,
            ['jwks_uri' => $otherJwksUri] + self::CONFIGURATION,
        ]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['jwks' => $jwks],
            ['url' => $otherJwksUri, 'jwks' => $jwks],
        ]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertSame($claims, $tokenVerifier->verify($token));
        self::assertSame($claims, $tokenVerifier->verify($token));
    }

    public function testVerifyTokenWithInvalidIssuer(): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $token = self::createToken($privateJwk, self::createClaims(['iss' => 'https://other-issuer.example.com']));

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertInvalidToken($tokenVerifier, $token, 'Unknown issuer.');
    }

    #[DataProvider('provideVerifyTokenWithInvalidAudienceCases')]
    public function testVerifyTokenWithInvalidAudience(mixed $aud): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $token = self::createToken($privateJwk, self::createClaims(['aud' => $aud]));

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertInvalidToken($tokenVerifier, $token, 'The "aud" claim is invalid.');
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function provideVerifyTokenWithInvalidAudienceCases(): iterable
    {
        yield 'string' => ['audience-2'];

        yield 'array' => [['audience-2', 'audience-3']];

        yield 'non string' => [123];
    }

    public function testVerifyExpiredToken(): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $token = self::createToken(
            $privateJwk,
            self::createClaims(['iat' => self::NOW - 3600, 'exp' => self::NOW - 3600 + 300])
        );

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertInvalidToken($tokenVerifier, $token, 'The token expired.');
    }

    public function testVerifyExpiredTokenWithinClockTolerance(): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $claims = self::createClaims(['iat' => self::NOW - 3600, 'exp' => self::NOW - 3600 + 300]);

        $token = self::createToken($privateJwk, $claims);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clockTolerance: 7200,
            clock: new FrozenClock(self::NOW)
        );

        self::assertSame($claims, $tokenVerifier->verify($token));
    }

    public function testVerifyTokenWithoutExpiration(): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $token = self::createToken($privateJwk, self::createClaims(without: ['exp']));

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertInvalidToken($tokenVerifier, $token, 'The following claims are mandatory: exp.');
    }

    public function testVerifyTokenWithMissingRequiredClaim(): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $token = self::createToken($privateJwk, self::createClaims());

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            requiredClaims: ['sub', 'jti'],
            clock: new FrozenClock(self::NOW)
        );

        self::assertInvalidToken($tokenVerifier, $token, 'The following claims are mandatory: jti.');
    }

    public function testVerifyTokenWithMatchingTyp(): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $claims = self::createClaims();

        $token = self::createToken($privateJwk, $claims, ['alg' => 'RS256', 'kid' => 'key-1', 'typ' => 'at+jwt']);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            typ: 'at+jwt',
            clock: new FrozenClock(self::NOW)
        );

        self::assertSame($claims, $tokenVerifier->verify($token));
    }

    #[DataProvider('provideVerifyTokenWithNotMatchingTypAndExpectedTypCases')]
    public function testVerifyTokenWithNotMatchingTypAndExpectedTyp(?string $typ, string $message): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $token = self::createToken(
            $privateJwk,
            self::createClaims(),
            ['alg' => 'RS256', 'kid' => 'key-1'] + (null !== $typ ? ['typ' => $typ] : [])
        );

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        // the "typ" header gets checked before the jwks gets fetched
        [$client, $requestFactory] = self::createFetchMocks($builder, []);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            typ: 'at+jwt',
            clock: new FrozenClock(self::NOW)
        );

        self::assertInvalidToken($tokenVerifier, $token, $message);
    }

    /**
     * @return iterable<string, array{null|string, string}>
     */
    public static function provideVerifyTokenWithNotMatchingTypAndExpectedTypCases(): iterable
    {
        yield 'without typ' => [null, 'The following header parameters are mandatory: typ.'];

        yield 'with other typ' => ['JWT', 'The "typ" header is invalid.'];
    }

    public function testVerifyTokenWithNotAllowedAlgorithm(): void
    {
        [$privateJwk] = self::createKeyAndJwks();

        $token = self::createToken($privateJwk, self::createClaims());

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, []);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            algorithms: ['ES256'],
            clock: new FrozenClock(self::NOW)
        );

        self::assertInvalidToken($tokenVerifier, $token, 'Unsupported algorithm.');
    }

    public function testVerifyInvalidTokenWithDefaultOptions(): void
    {
        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, []);

        $tokenVerifier = new JwtTokenVerifier($oidcConfigurationResolver, new RemoteJwkSet($client, $requestFactory), 'audience-1');

        self::assertInvalidToken($tokenVerifier, 'invalid', 'Invalid Compact JWS');
    }

    public function testVerifyTokenWithNonJsonPayload(): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $token = JwsHelper::sign('not json', $privateJwk, ['alg' => 'RS256', 'kid' => 'key-1']);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertInvalidToken($tokenVerifier, $token, 'JWT Claims Set must be a top-level JSON object');
    }

    public function testVerifyTokenWithUnsupportedAlgorithm(): void
    {
        $secret = new JWK(['kty' => 'oct', 'k' => Base64UrlSafe::encodeUnpadded('some-secret-which-is-at-least-32-bytes-long')]);

        $token = self::createToken($secret, self::createClaims(), ['alg' => 'HS256', 'kid' => 'key-1']);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        // the symmetric (hs) algorithm gets rejected before the jwks gets fetched (algorithm confusion)
        [$client, $requestFactory] = self::createFetchMocks($builder, []);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertInvalidToken($tokenVerifier, $token, 'Unsupported algorithm.');
    }

    public function testVerifyTokenWithUnknownKeyId(): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $token = self::createToken($privateJwk, self::createClaims(), ['alg' => 'RS256', 'kid' => 'key-2']);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertInvalidToken($tokenVerifier, $token, 'no applicable key found in the JSON Web Key Set');
    }

    public function testVerifyTokenWithoutKeyIdAgainstJwksWithMultipleMatchingKeys(): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();
        [, $otherJwks] = self::createKeyAndJwks('key-2');

        $token = self::createToken($privateJwk, self::createClaims(), ['alg' => 'RS256']);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['jwks' => ['keys' => [...$jwks['keys'], ...$otherJwks['keys']]]],
        ]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertInvalidToken($tokenVerifier, $token, 'multiple matching keys found in the JSON Web Key Set');
    }

    public function testVerifyTokenWithInvalidSignature(): void
    {
        [, $jwks] = self::createKeyAndJwks();
        [$otherPrivateJwk] = self::createKeyAndJwks('key-2');

        $token = self::createToken($otherPrivateJwk, self::createClaims());

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertInvalidToken($tokenVerifier, $token, 'signature verification failed');
    }

    public function testVerifyTokenWithFailingOidcConfigurationResolver(): void
    {
        [$privateJwk] = self::createKeyAndJwks();

        $token = self::createToken($privateJwk, self::createClaims());

        $error = new \RuntimeException(
            'Cannot fetch oidc configuration from "https://issuer.example.com": status 500'
        );

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [$error]);

        [$client, $requestFactory] = self::createFetchMocks($builder, []);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertThrows($tokenVerifier, $token, $error);
    }

    public function testVerifyTokenWithUnreachableJwksUri(): void
    {
        [$privateJwk] = self::createKeyAndJwks();

        $token = self::createToken($privateJwk, self::createClaims());

        $error = new \RuntimeException('fetch failed');

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['exception' => $error]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertThrows($tokenVerifier, $token, $error);
    }

    public function testVerifyTokenWithFailingJwksUri(): void
    {
        [$privateJwk] = self::createKeyAndJwks();

        $token = self::createToken($privateJwk, self::createClaims());

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['status' => 500]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        try {
            $tokenVerifier->verify($token);

            self::fail('Expected exception not thrown');
        } catch (JwksException $error) {
            self::assertSame('Expected 200 OK from the JSON Web Key Set HTTP response', $error->getMessage());
        }
    }

    public function testVerifyTokenWithUnreachableJwksUriWithinCooldown(): void
    {
        $clock = new FrozenClock(self::NOW);

        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $claims = self::createClaims();

        $token = self::createToken($privateJwk, $claims);

        $error = new \RuntimeException('fetch failed');

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver(
            $builder,
            [self::CONFIGURATION, self::CONFIGURATION, self::CONFIGURATION]
        );

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['exception' => $error],
            ['jwks' => $jwks],
        ]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory, cooldown: 10),
            'audience-1',
            clock: $clock
        );

        self::assertThrows($tokenVerifier, $token, $error);

        $clock->setTimestamp(self::NOW + 9);

        // within cooldown, no jwks known: fail fast with the same error, no fetch
        self::assertThrows($tokenVerifier, $token, $error);

        $clock->setTimestamp(self::NOW + 10);

        // after cooldown: fetch again
        self::assertSame($claims, $tokenVerifier->verify($token));
    }

    public function testVerifyTokenWithExpiredJwksCacheAndFailedRefresh(): void
    {
        $clock = new FrozenClock(self::NOW);

        [$privateJwk, $jwks] = self::createKeyAndJwks();
        [$otherPrivateJwk, $otherJwks] = self::createKeyAndJwks('key-2');

        $claims = self::createClaims();

        $token = self::createToken($privateJwk, $claims);
        $otherToken = self::createToken($otherPrivateJwk, $claims, ['alg' => 'RS256', 'kid' => 'key-2']);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver(
            $builder,
            array_fill(0, 5, self::CONFIGURATION)
        );

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['jwks' => $jwks],
            ['status' => 500],
            ['jwks' => $otherJwks],
        ]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory, 10, 10),
            'audience-1',
            clock: $clock
        );

        self::assertSame($claims, $tokenVerifier->verify($token));

        $clock->setTimestamp(self::NOW + 9);

        // fresh cache: no fetch
        self::assertSame($claims, $tokenVerifier->verify($token));

        $clock->setTimestamp(self::NOW + 10);

        // expired cache, failed refresh: verify against the stale jwks instead of failing
        self::assertSame($claims, $tokenVerifier->verify($token));

        $clock->setTimestamp(self::NOW + 19);

        // within cooldown: still stale, no fetch
        self::assertSame($claims, $tokenVerifier->verify($token));

        $clock->setTimestamp(self::NOW + 20);

        // after cooldown: fetch again, success replaces the stale jwks
        self::assertSame($claims, $tokenVerifier->verify($otherToken));
    }

    public function testVerifyTokenWithRotatedKey(): void
    {
        $clock = new FrozenClock(self::NOW);

        [$privateJwk, $jwks] = self::createKeyAndJwks();
        [$otherPrivateJwk, $otherJwks] = self::createKeyAndJwks('key-2');

        $claims = self::createClaims();

        $token = self::createToken($privateJwk, $claims);
        $otherToken = self::createToken($otherPrivateJwk, $claims, ['alg' => 'RS256', 'kid' => 'key-2']);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver(
            $builder,
            array_fill(0, 3, self::CONFIGURATION)
        );

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['jwks' => $jwks],
            ['jwks' => $otherJwks],
        ]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory, cooldown: 10),
            'audience-1',
            clock: $clock
        );

        self::assertSame($claims, $tokenVerifier->verify($token));

        $clock->setTimestamp(self::NOW + 9);

        // unknown key id within cooldown: no refetch (rate limit)
        self::assertInvalidToken($tokenVerifier, $otherToken, 'no applicable key found in the JSON Web Key Set');

        $clock->setTimestamp(self::NOW + 10);

        // unknown key id after cooldown: refetch
        self::assertSame($claims, $tokenVerifier->verify($otherToken));
    }

    public function testVerifyTokenWithUnknownKeyIdAndFailedJwksRefresh(): void
    {
        $clock = new FrozenClock(self::NOW);

        [$privateJwk, $jwks] = self::createKeyAndJwks();
        [$otherPrivateJwk] = self::createKeyAndJwks('key-2');

        $claims = self::createClaims();

        $token = self::createToken($privateJwk, $claims);
        $otherToken = self::createToken($otherPrivateJwk, $claims, ['alg' => 'RS256', 'kid' => 'key-2']);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver(
            $builder,
            array_fill(0, 3, self::CONFIGURATION)
        );

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['jwks' => $jwks],
            ['exception' => new \RuntimeException('fetch failed')],
        ]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory, cooldown: 10),
            'audience-1',
            clock: $clock
        );

        self::assertSame($claims, $tokenVerifier->verify($token));

        $clock->setTimestamp(self::NOW + 10);

        // unknown key id, failed refetch: the token cannot be verified against the stale jwks
        self::assertInvalidToken($tokenVerifier, $otherToken, 'no applicable key found in the JSON Web Key Set');

        // within cooldown: known keys keep working, no fetch
        self::assertSame($claims, $tokenVerifier->verify($token));
    }

    public function testVerifyTokenWithUnknownKeyIdDoesNotTriggerTheFailureCooldown(): void
    {
        $clock = new FrozenClock(self::NOW);

        [$privateJwk, $jwks] = self::createKeyAndJwks();
        [$otherPrivateJwk] = self::createKeyAndJwks('key-2');

        $claims = self::createClaims();

        $token = self::createToken($privateJwk, $claims);
        $otherToken = self::createToken($otherPrivateJwk, $claims, ['alg' => 'RS256', 'kid' => 'key-2']);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver(
            $builder,
            array_fill(0, 3, self::CONFIGURATION)
        );

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['jwks' => $jwks],
            ['jwks' => $jwks],
            ['jwks' => $jwks],
        ]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory, 5, 10),
            'audience-1',
            clock: $clock
        );

        self::assertSame($claims, $tokenVerifier->verify($token));

        $clock->setTimestamp(self::NOW + 5);

        // expired cache, successful refetch, but still no matching key: a token error, not an outage
        self::assertInvalidToken($tokenVerifier, $otherToken, 'no applicable key found in the JSON Web Key Set');

        $clock->setTimestamp(self::NOW + 10);

        // expired cache: refetch (no failure cooldown got triggered by the token error)
        self::assertSame($claims, $tokenVerifier->verify($token));
    }

    public function testVerifyTokenWithExpiredJwksCacheAndDefaultJwksMaxAge(): void
    {
        $clock = new FrozenClock(self::NOW);

        [$privateJwk, $jwks] = self::createKeyAndJwks();
        [, $otherJwks] = self::createKeyAndJwks('key-2');

        $claims = self::createClaims(['exp' => self::NOW + 3600]);

        $token = self::createToken($privateJwk, $claims);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver(
            $builder,
            array_fill(0, 3, self::CONFIGURATION)
        );

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['jwks' => $jwks],
            ['jwks' => $otherJwks],
        ]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: $clock
        );

        self::assertSame($claims, $tokenVerifier->verify($token));

        $clock->setTimestamp(self::NOW + 599);

        // fresh cache: no fetch
        self::assertSame($claims, $tokenVerifier->verify($token));

        $clock->setTimestamp(self::NOW + 600);

        // expired cache: refetch, the key got rotated away
        self::assertInvalidToken($tokenVerifier, $token, 'no applicable key found in the JSON Web Key Set');
    }

    public function testVerifyTokenWithRotatedKeyAndDefaultJwksCooldown(): void
    {
        $clock = new FrozenClock(self::NOW);

        [$privateJwk, $jwks] = self::createKeyAndJwks();
        [$otherPrivateJwk, $otherJwks] = self::createKeyAndJwks('key-2');

        $claims = self::createClaims();

        $token = self::createToken($privateJwk, $claims);
        $otherToken = self::createToken($otherPrivateJwk, $claims, ['alg' => 'RS256', 'kid' => 'key-2']);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver(
            $builder,
            array_fill(0, 3, self::CONFIGURATION)
        );

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['jwks' => $jwks],
            ['jwks' => $otherJwks],
        ]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: $clock
        );

        self::assertSame($claims, $tokenVerifier->verify($token));

        $clock->setTimestamp(self::NOW + 29);

        // unknown key id within cooldown: no refetch (rate limit)
        self::assertInvalidToken($tokenVerifier, $otherToken, 'no applicable key found in the JSON Web Key Set');

        $clock->setTimestamp(self::NOW + 30);

        // unknown key id after cooldown: refetch
        self::assertSame($claims, $tokenVerifier->verify($otherToken));
    }

    public function testVerifyTokenWithChangedJwksUriAfterFailure(): void
    {
        $otherJwksUri = 'https://issuer.example.com/other-jwks';

        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $claims = self::createClaims();

        $token = self::createToken($privateJwk, $claims);

        $error = new \RuntimeException('fetch failed');

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [
            self::CONFIGURATION,
            ['jwks_uri' => $otherJwksUri] + self::CONFIGURATION,
        ]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['exception' => $error],
            ['url' => $otherJwksUri, 'jwks' => $jwks],
        ]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertThrows($tokenVerifier, $token, $error);

        // a changed jwks uri (new configuration) starts over, the failure cooldown of the old one does not apply
        self::assertSame($claims, $tokenVerifier->verify($token));
    }

    #[DataProvider('provideVerifyTokenWithAlgorithmCases')]
    public function testVerifyTokenWithAlgorithm(string $alg): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks(alg: $alg);

        $claims = self::createClaims();

        $token = self::createToken($privateJwk, $claims, ['alg' => $alg, 'kid' => 'key-1']);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertSame($claims, $tokenVerifier->verify($token));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideVerifyTokenWithAlgorithmCases(): iterable
    {
        foreach (['EdDSA', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'RS256', 'RS384', 'RS512'] as $alg) {
            yield $alg => [$alg];
        }
    }

    /**
     * @param array<string, mixed> $notMatchingJwk
     */
    #[DataProvider('provideVerifyTokenWithoutKeyIdAgainstJwksWithNotMatchingKeyCases')]
    public function testVerifyTokenWithoutKeyIdAgainstJwksWithNotMatchingKey(string $alg, array $notMatchingJwk): void
    {
        [$privateJwk, $publicJwk] = JwsHelper::keyPair($alg);

        $claims = self::createClaims();

        $token = self::createToken($privateJwk, $claims, ['alg' => $alg]);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        // neither key has a "kid" nor an "alg": only the not matching one gets excluded, the other one is unambiguous
        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['jwks' => ['keys' => [$notMatchingJwk, $publicJwk]]],
        ]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertSame($claims, $tokenVerifier->verify($token));
    }

    /**
     * @return iterable<string, array{string, array<string, mixed>}>
     */
    public static function provideVerifyTokenWithoutKeyIdAgainstJwksWithNotMatchingKeyCases(): iterable
    {
        [, $rsaJwk] = JwsHelper::keyPair('RS256');
        [, $ecJwk] = JwsHelper::keyPair('ES256');

        yield 'other key type' => ['RS256', $ecJwk];

        yield 'other algorithm' => ['RS256', ['alg' => 'RS384'] + $rsaJwk];

        yield 'other use' => ['RS256', ['use' => 'enc'] + $rsaJwk];

        yield 'other key operations' => ['RS256', ['key_ops' => ['encrypt']] + $rsaJwk];

        yield 'malformed key operations' => ['RS256', ['key_ops' => 'verify'] + $rsaJwk];

        yield 'other curve for ES256' => ['ES256', ['crv' => 'P-384'] + $ecJwk];

        yield 'other curve for ES384' => ['ES384', $ecJwk];

        yield 'other curve for ES512' => ['ES512', $ecJwk];

        yield 'other curve for EdDSA' => ['EdDSA', ['kty' => 'OKP', 'crv' => 'Ed448', 'x' => 'x']];
    }

    public function testVerifyTokenWithKeyIdAgainstJwksWithMultipleKeys(): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();
        [, $otherJwks] = self::createKeyAndJwks('key-2');

        $claims = self::createClaims();

        $token = self::createToken($privateJwk, $claims);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['jwks' => ['keys' => [...$otherJwks['keys'], ...$jwks['keys']]]],
        ]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertSame($claims, $tokenVerifier->verify($token));
    }

    public function testVerifyTokenWithNonStringKeyId(): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $claims = self::createClaims();

        // a non string "kid" is ignored, like a missing one
        $token = self::createToken($privateJwk, $claims, ['alg' => 'RS256', 'kid' => 42]);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertSame($claims, $tokenVerifier->verify($token));
    }

    public function testVerifyTokenWithEmptyPayload(): void
    {
        [$privateJwk] = self::createKeyAndJwks();

        $token = JwsHelper::sign('', $privateJwk, ['alg' => 'RS256', 'kid' => 'key-1']);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, []);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertInvalidToken($tokenVerifier, $token, 'Invalid Compact JWS');
    }

    /**
     * @param array<string, mixed> $protectedHeader
     */
    #[DataProvider('provideVerifyTokenWithInvalidAlgorithmCases')]
    public function testVerifyTokenWithInvalidAlgorithm(array $protectedHeader, string $message): void
    {
        $token = JwsHelper::encodeUnsigned($protectedHeader, self::createClaims());

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, []);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertInvalidToken($tokenVerifier, $token, $message);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideVerifyTokenWithInvalidAlgorithmCases(): iterable
    {
        yield 'without alg' => [['kid' => 'key-1'], 'The following header parameters are mandatory: alg.'];

        yield 'with empty alg' => [['alg' => '', 'kid' => 'key-1'], 'Unsupported algorithm.'];

        yield 'with non string alg' => [['alg' => 42, 'kid' => 'key-1'], '"alg" must be a string.'];
    }

    public function testVerifyTokenWithCriticalHeader(): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();
        [, $otherJwks] = self::createKeyAndJwks('key-2');

        $claims = self::createClaims();

        $token = self::createToken(
            $privateJwk,
            $claims,
            ['alg' => 'RS256', 'kid' => 'key-1', 'crit' => ['b64'], 'b64' => true]
        );

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        // a jwks with multiple keys of the same algorithm: the "kid" is needed to select the key
        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['jwks' => ['keys' => [...$otherJwks['keys'], ...$jwks['keys']]]],
        ]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertSame($claims, $tokenVerifier->verify($token));
    }

    /**
     * @param array<string, mixed> $protectedHeader
     */
    #[DataProvider('provideVerifyTokenWithInvalidCriticalHeaderCases')]
    public function testVerifyTokenWithInvalidCriticalHeader(array $protectedHeader, string $message): void
    {
        [$privateJwk] = self::createKeyAndJwks();

        $token = self::createToken(
            $privateJwk,
            self::createClaims(),
            ['alg' => 'RS256', 'kid' => 'key-1'] + $protectedHeader
        );

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, []);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertInvalidToken($tokenVerifier, $token, $message);
    }

    /**
     * @return iterable<string, array{array<string, mixed>, string}>
     */
    public static function provideVerifyTokenWithInvalidCriticalHeaderCases(): iterable
    {
        $notChecked = 'One or more header parameters are marked as critical,'
            .' but they are missing or have not been checked: %s.';

        yield 'b64 without crit' => [['b64' => false], '"b64" must be listed in "crit" (rfc 7797)'];

        yield 'encoded b64 without crit' => [['b64' => true], '"b64" must be listed in "crit" (rfc 7797)'];

        yield 'non array crit' => [
            ['crit' => 'b64', 'b64' => true],
            'The header "crit" must be a list of header parameters.',
        ];

        yield 'empty crit' => [
            ['crit' => [], 'b64' => true],
            '"crit" (Critical) Header Parameter MUST be a non-empty array of strings when present',
        ];

        yield 'crit with empty string' => [['crit' => [''], 'b64' => true], \sprintf($notChecked, '')];

        yield 'crit with non string' => [['crit' => [42], 'b64' => true], \sprintf($notChecked, '42')];

        yield 'crit with not recognized parameter' => [
            ['crit' => ['b64', 'exp'], 'b64' => true, 'exp' => self::NOW + 300],
            \sprintf($notChecked, 'exp'),
        ];

        yield 'crit with checked but not recognized parameter' => [
            ['crit' => ['alg']],
            'Extension Header Parameter "alg" is not recognized',
        ];

        yield 'crit with missing parameter' => [
            ['crit' => ['b64']],
            \sprintf($notChecked, 'b64'),
        ];

        yield 'crit with non boolean b64' => [
            ['crit' => ['b64'], 'b64' => 'true'],
            '"b64" must be a boolean.',
        ];

        yield 'crit with unencoded payload' => [
            ['crit' => ['b64'], 'b64' => false],
            'JWTs MUST NOT use unencoded payload',
        ];
    }

    #[DataProvider('provideVerifyTokenWithEquivalentTypCases')]
    public function testVerifyTokenWithEquivalentTyp(string $typ, string $expectedTyp): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $claims = self::createClaims();

        $token = self::createToken($privateJwk, $claims, ['alg' => 'RS256', 'kid' => 'key-1', 'typ' => $typ]);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            typ: $expectedTyp,
            clock: new FrozenClock(self::NOW)
        );

        self::assertSame($claims, $tokenVerifier->verify($token));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideVerifyTokenWithEquivalentTypCases(): iterable
    {
        yield 'other case' => ['AT+JWT', 'at+jwt'];

        yield 'with media type prefix' => ['application/at+jwt', 'at+jwt'];

        yield 'expected with media type prefix' => ['at+jwt', 'application/AT+JWT'];
    }

    public function testVerifyTokenWithoutClaims(): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $token = self::createToken($privateJwk, []);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            requiredClaims: ['sub', 'jti'],
            clock: new FrozenClock(self::NOW)
        );

        // the same order as with jose: issuer, audience, expiration, additionally required claims
        self::assertInvalidToken($tokenVerifier, $token, 'The following claims are mandatory: iss, aud, exp, sub, jti.');
    }

    public function testVerifyTokenWithoutAudience(): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $token = self::createToken($privateJwk, self::createClaims(without: ['aud']));

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertInvalidToken($tokenVerifier, $token, 'The following claims are mandatory: aud.');
    }

    public function testVerifyTokenWithAudienceArrayClaim(): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $claims = self::createClaims(['aud' => ['audience-2', 'audience-1']]);

        $token = self::createToken($privateJwk, $claims);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertSame($claims, $tokenVerifier->verify($token));
    }

    #[DataProvider('provideVerifyTokenWithNonNumericTimestampClaimCases')]
    public function testVerifyTokenWithNonNumericTimestampClaim(string $claim, string $message): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $token = self::createToken($privateJwk, self::createClaims([$claim => (string) self::NOW]));

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertInvalidToken($tokenVerifier, $token, $message);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideVerifyTokenWithNonNumericTimestampClaimCases(): iterable
    {
        yield 'iat' => ['iat', 'The "iat" claim is invalid.'];

        yield 'nbf' => ['nbf', '"nbf" must be an integer.'];

        yield 'exp' => ['exp', '"exp" must be an integer.'];
    }

    public function testVerifyTokenExpiringNow(): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $token = self::createToken($privateJwk, self::createClaims(['exp' => self::NOW]));

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertInvalidToken($tokenVerifier, $token, 'The token expired.');
    }

    public function testVerifyTokenExpiringNextSecond(): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $claims = self::createClaims(['exp' => self::NOW + 1]);

        $token = self::createToken($privateJwk, $claims);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertSame($claims, $tokenVerifier->verify($token));
    }

    public function testVerifyTokenValidFromNow(): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $claims = self::createClaims(['nbf' => self::NOW]);

        $token = self::createToken($privateJwk, $claims);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertSame($claims, $tokenVerifier->verify($token));
    }

    public function testVerifyTokenValidFromNextSecond(): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $token = self::createToken($privateJwk, self::createClaims(['nbf' => self::NOW + 1]));

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        self::assertInvalidToken($tokenVerifier, $token, 'The JWT can not be used yet.');
    }

    public function testVerifyTokenValidFromNextSecondWithinClockTolerance(): void
    {
        [$privateJwk, $jwks] = self::createKeyAndJwks();

        $claims = self::createClaims(['nbf' => self::NOW + 1]);

        $token = self::createToken($privateJwk, $claims);

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['jwks' => $jwks]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clockTolerance: 1,
            clock: new FrozenClock(self::NOW)
        );

        self::assertSame($claims, $tokenVerifier->verify($token));
    }

    public function testVerifyTokenWithInvalidJwksJson(): void
    {
        [$privateJwk] = self::createKeyAndJwks();

        $token = self::createToken($privateJwk, self::createClaims());

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['body' => '{']]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        $this->expectException(JwksException::class);
        $this->expectExceptionMessage('Failed to parse the JSON Web Key Set HTTP response as JSON');

        $tokenVerifier->verify($token);
    }

    #[DataProvider('provideVerifyTokenWithMalformedJwksCases')]
    public function testVerifyTokenWithMalformedJwks(string $body): void
    {
        [$privateJwk] = self::createKeyAndJwks();

        $token = self::createToken($privateJwk, self::createClaims());

        $builder = new MockObjectBuilder();

        $oidcConfigurationResolver = self::createOidcConfigurationResolver($builder, [self::CONFIGURATION]);

        [$client, $requestFactory] = self::createFetchMocks($builder, [['body' => $body]]);

        $tokenVerifier = new JwtTokenVerifier(
            $oidcConfigurationResolver,
            new RemoteJwkSet($client, $requestFactory),
            'audience-1',
            clock: new FrozenClock(self::NOW)
        );

        $this->expectException(JwksException::class);
        $this->expectExceptionMessage('JSON Web Key Set malformed');

        $tokenVerifier->verify($token);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideVerifyTokenWithMalformedJwksCases(): iterable
    {
        yield 'non object' => ['"keys"'];

        yield 'without keys' => ['{}'];

        yield 'with non array keys' => ['{"keys":"key-1"}'];

        yield 'with non list keys' => ['{"keys":{"key-1":{}}}'];

        yield 'with non object key' => ['{"keys":["key-1"]}'];
    }

    /**
     * @return array{JWK, array{keys: list<array<string, mixed>>}}
     */
    private static function createKeyAndJwks(string $kid = 'key-1', string $alg = 'RS256'): array
    {
        [$privateJwk, $publicJwk] = JwsHelper::keyPair($alg, $kid);

        return [$privateJwk, ['keys' => [$publicJwk + ['kid' => $kid, 'alg' => $alg, 'use' => 'sig']]]];
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string>        $without
     *
     * @return array<string, mixed>
     */
    private static function createClaims(array $claims = [], array $without = []): array
    {
        return array_diff_key(
            array_replace([
                'scope' => 'openid',
                'sub' => 'subject-1',
                'iss' => self::ISSUER,
                'aud' => 'audience-1',
                'iat' => self::NOW,
                'exp' => self::NOW + 300,
            ], $claims),
            array_flip($without)
        );
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $protectedHeader
     */
    private static function createToken(
        JWK $privateJwk,
        array $claims,
        array $protectedHeader = ['alg' => 'RS256', 'kid' => 'key-1'],
    ): string {
        return JwsHelper::sign($claims, $privateJwk, $protectedHeader);
    }

    /**
     * @param list<array<string, mixed>|\Throwable> $configurations
     */
    private static function createOidcConfigurationResolver(
        MockObjectBuilder $builder,
        array $configurations,
    ): OidcConfigurationResolverInterface {
        /** @var OidcConfigurationResolverInterface $oidcConfigurationResolver */
        $oidcConfigurationResolver = $builder->create(OidcConfigurationResolverInterface::class, array_map(
            static fn (array|\Throwable $configuration) => $configuration instanceof \Throwable
                ? new WithException('resolve', [], $configuration)
                : new WithReturn('resolve', [], $configuration),
            $configurations
        ));

        return $oidcConfigurationResolver;
    }

    /**
     * @param list<array{url?: string, jwks?: array<string, mixed>, status?: int, body?: string, exception?: \Throwable}> $fetches
     *
     * @return array{ClientInterface, RequestFactoryInterface}
     */
    private static function createFetchMocks(MockObjectBuilder $builder, array $fetches): array
    {
        $clientMethods = [];
        $requestFactoryMethods = [];

        foreach ($fetches as $fetch) {
            /** @var RequestInterface $request */
            $request = $builder->create(RequestInterface::class, []);

            $requestFactoryMethods[] = new WithReturn(
                'createRequest',
                ['GET', $fetch['url'] ?? self::JWKS_URI],
                $request
            );

            if (isset($fetch['exception'])) {
                $clientMethods[] = new WithException('sendRequest', [$request], $fetch['exception']);

                continue;
            }

            $status = $fetch['status'] ?? 200;

            $responseMethods = [new WithReturn('getStatusCode', [], $status)];

            // the body is only read for a 200 response
            if (200 === $status) {
                /** @var StreamInterface $body */
                $body = $builder->create(StreamInterface::class, [
                    new WithReturn('__toString', [], $fetch['body'] ?? (string) json_encode($fetch['jwks'] ?? [])),
                ]);

                $responseMethods[] = new WithReturn('getBody', [], $body);
            }

            /** @var ResponseInterface $response */
            $response = $builder->create(ResponseInterface::class, $responseMethods);

            $clientMethods[] = new WithReturn('sendRequest', [$request], $response);
        }

        /** @var ClientInterface $client */
        $client = $builder->create(ClientInterface::class, $clientMethods);

        /** @var RequestFactoryInterface $requestFactory */
        $requestFactory = $builder->create(RequestFactoryInterface::class, $requestFactoryMethods);

        return [$client, $requestFactory];
    }

    private static function assertInvalidToken(JwtTokenVerifier $tokenVerifier, string $token, string $message): void
    {
        try {
            $tokenVerifier->verify($token);
        } catch (InvalidTokenException $exception) {
            self::assertSame($message, $exception->getMessage());

            return;
        }

        self::fail('Expected InvalidTokenException not thrown');
    }

    private static function assertThrows(JwtTokenVerifier $tokenVerifier, string $token, \Throwable $error): void
    {
        try {
            $tokenVerifier->verify($token);
        } catch (\Throwable $throwable) {
            self::assertSame($error, $throwable);

            return;
        }

        self::fail('Expected exception not thrown');
    }
}
