<?php

declare(strict_types=1);

namespace Chubbyphp\Tests\Oidc\Unit\Jwks;

use Chubbyphp\Mock\MockMethod\WithException;
use Chubbyphp\Mock\MockMethod\WithReturn;
use Chubbyphp\Mock\MockObjectBuilder;
use Chubbyphp\Oidc\Exception\InvalidTokenException;
use Chubbyphp\Oidc\Exception\JwksException;
use Chubbyphp\Oidc\Jwks\RemoteJwkSet;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

/**
 * @covers \Chubbyphp\Oidc\Jwks\RemoteJwkSet
 *
 * @internal
 */
final class RemoteJwkSetTest extends TestCase
{
    private const JWKS_URI = 'https://issuer.example.com/jwks';
    private const OTHER_JWKS_URI = 'https://other-issuer.example.com/jwks';
    private const NOW = 1750000000;

    private const RSA_JWK = ['kty' => 'RSA', 'kid' => 'key-1', 'alg' => 'RS256', 'use' => 'sig', 'n' => 'n', 'e' => 'AQAB'];
    private const OTHER_RSA_JWK = ['kty' => 'RSA', 'kid' => 'key-2', 'alg' => 'RS256', 'use' => 'sig', 'n' => 'n', 'e' => 'AQAB'];
    private const EC_JWK = ['kty' => 'EC', 'crv' => 'P-256', 'x' => 'x', 'y' => 'y'];

    #[DataProvider('provideCreateRemoteJwkSetWithNegativeOptionCases')]
    public function testCreateRemoteJwkSetWithNegativeOption(
        string $name,
        int $maxAge,
        int $cooldown,
        int $maxStale,
    ): void {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, []);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(\sprintf('Invalid %s -1: must be a non-negative number of seconds', $name));

        new RemoteJwkSet($client, $requestFactory, $maxAge, $cooldown, $maxStale);
    }

    /**
     * @return iterable<string, array{string, int, int, int}>
     */
    public static function provideCreateRemoteJwkSetWithNegativeOptionCases(): iterable
    {
        yield 'negative maxAge' => ['maxAge', -1, 30, 3600];

        yield 'negative cooldown' => ['cooldown', 600, -1, 3600];

        yield 'negative maxStale' => ['maxStale', 600, 30, -1];
    }

    public function testCreateRemoteJwkSetWithUnboundedMaxStale(): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, []);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory, maxStale: null);

        $maxStaleReflectionProperty = new \ReflectionProperty($remoteJwkSet, 'maxStale');

        self::assertNull($maxStaleReflectionProperty->getValue($remoteJwkSet));
    }

    public function testResolveKey(): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [['keys' => [self::RSA_JWK]]]);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory);

        self::assertSame(self::RSA_JWK, $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW)->all());
    }

    public function testResolveKeyWithoutCaching(): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['keys' => [self::RSA_JWK]],
            ['keys' => [self::OTHER_RSA_JWK]],
        ]);

        // zero is the (valid) lower bound: no caching, no cooldown, every call fetches
        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory, maxAge: 0, cooldown: 0);

        self::assertSame(self::RSA_JWK, $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW)->all());

        self::assertSame(
            self::OTHER_RSA_JWK,
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-2', self::NOW)->all()
        );
    }

    public function testResolveKeyWithCachedJwks(): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['keys' => [self::RSA_JWK]],
            ['keys' => [self::OTHER_RSA_JWK]],
        ]);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory, maxAge: 10);

        self::assertSame(self::RSA_JWK, $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW)->all());

        // fresh cache: no fetch
        self::assertSame(
            self::RSA_JWK,
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW + 9)->all()
        );

        // expired cache: fetch again
        self::assertSame(
            self::OTHER_RSA_JWK,
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-2', self::NOW + 10)->all()
        );
    }

    public function testResolveKeyWithDefaultMaxAge(): void
    {
        $renewedRsaJwk = ['n' => 'renewed-n'] + self::RSA_JWK;

        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['keys' => [self::RSA_JWK]],
            ['keys' => [$renewedRsaJwk]],
        ]);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory);

        self::assertSame(self::RSA_JWK, $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW)->all());

        // fresh cache: no fetch
        self::assertSame(
            self::RSA_JWK,
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW + 599)->all()
        );

        // expired cache: fetch again (the key id is known, so the refetch is not triggered by an unknown key id)
        self::assertSame(
            $renewedRsaJwk,
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW + 600)->all()
        );
    }

    public function testResolveKeyWithChangedJwksUri(): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['keys' => [self::RSA_JWK]],
            ['url' => self::OTHER_JWKS_URI, 'keys' => [self::OTHER_RSA_JWK]],
        ]);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory);

        self::assertSame(self::RSA_JWK, $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW)->all());

        // a changed jwks uri starts over, the cached jwks does not apply
        self::assertSame(
            self::OTHER_RSA_JWK,
            $remoteJwkSet->resolveKey(self::OTHER_JWKS_URI, 'RS256', 'key-2', self::NOW)->all()
        );
    }

    public function testResolveKeyWithUnknownKeyId(): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [['keys' => [self::RSA_JWK]]]);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('no applicable key found in the JSON Web Key Set');

        $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-2', self::NOW);
    }

    public function testResolveKeyWithRotatedKey(): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['keys' => [self::RSA_JWK]],
            ['keys' => [self::OTHER_RSA_JWK]],
        ]);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory, cooldown: 10);

        self::assertSame(self::RSA_JWK, $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW)->all());

        // unknown key id within cooldown: no refetch
        try {
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-2', self::NOW + 9);

            self::fail('Expected InvalidTokenException not thrown');
        } catch (InvalidTokenException $exception) {
            self::assertSame('no applicable key found in the JSON Web Key Set', $exception->getMessage());
        }

        // unknown key id after cooldown: refetch
        self::assertSame(
            self::OTHER_RSA_JWK,
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-2', self::NOW + 10)->all()
        );
    }

    public function testResolveKeyWithRotatedKeyAndDefaultCooldown(): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['keys' => [self::RSA_JWK]],
            ['keys' => [self::OTHER_RSA_JWK]],
        ]);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory);

        self::assertSame(self::RSA_JWK, $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW)->all());

        try {
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-2', self::NOW + 29);

            self::fail('Expected InvalidTokenException not thrown');
        } catch (InvalidTokenException $exception) {
            self::assertSame('no applicable key found in the JSON Web Key Set', $exception->getMessage());
        }

        self::assertSame(
            self::OTHER_RSA_JWK,
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-2', self::NOW + 30)->all()
        );
    }

    public function testResolveKeyWithUnknownKeyIdAndFailedRefetch(): void
    {
        $error = new \RuntimeException('fetch failed');

        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['keys' => [self::RSA_JWK]],
            ['exception' => $error],
            ['keys' => [self::RSA_JWK]],
        ]);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory, maxAge: 5, cooldown: 10);

        self::assertSame(self::RSA_JWK, $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW)->all());

        // expired cache, failed refetch: the stale jwks does not know the key either
        try {
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-2', self::NOW + 5);

            self::fail('Expected InvalidTokenException not thrown');
        } catch (InvalidTokenException $exception) {
            self::assertSame('no applicable key found in the JSON Web Key Set', $exception->getMessage());
        }

        // within cooldown: the stale jwks is served, no fetch
        self::assertSame(
            self::RSA_JWK,
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW + 14)->all()
        );

        // after cooldown: fetch again
        self::assertSame(
            self::RSA_JWK,
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW + 15)->all()
        );
    }

    public function testResolveKeyWithUnknownKeyIdDoesNotTriggerTheFailureCooldown(): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['keys' => [self::RSA_JWK]],
            ['keys' => [self::RSA_JWK]],
            ['keys' => [self::OTHER_RSA_JWK]],
        ]);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory, maxAge: 5, cooldown: 10);

        self::assertSame(self::RSA_JWK, $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW)->all());

        // expired cache, successful refetch, but still no matching key: a token error, not an outage
        try {
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-2', self::NOW + 5);

            self::fail('Expected InvalidTokenException not thrown');
        } catch (InvalidTokenException $exception) {
            self::assertSame('no applicable key found in the JSON Web Key Set', $exception->getMessage());
        }

        // expired cache: refetch (no failure cooldown got triggered by the token error)
        self::assertSame(
            self::OTHER_RSA_JWK,
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-2', self::NOW + 10)->all()
        );
    }

    public function testResolveKeyWithUnreachableJwksUri(): void
    {
        $error = new \RuntimeException('fetch failed');

        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['exception' => $error],
            ['keys' => [self::RSA_JWK]],
        ]);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory, cooldown: 10);

        self::assertThrows($remoteJwkSet, self::NOW, $error);

        // within cooldown, no jwks known: fail fast with the same error, no fetch
        self::assertThrows($remoteJwkSet, self::NOW + 9, $error);

        // after cooldown: fetch again
        self::assertSame(
            self::RSA_JWK,
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW + 10)->all()
        );
    }

    public function testResolveKeyWithExpiredJwksCacheAndFailedRefresh(): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['keys' => [self::RSA_JWK]],
            ['status' => 500],
            ['keys' => [self::OTHER_RSA_JWK]],
        ]);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory, maxAge: 10, cooldown: 10);

        self::assertSame(self::RSA_JWK, $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW)->all());

        // expired cache, failed refresh: serve the stale jwks instead of failing
        self::assertSame(
            self::RSA_JWK,
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW + 10)->all()
        );

        // within cooldown: still stale, no fetch
        self::assertSame(
            self::RSA_JWK,
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW + 19)->all()
        );

        // after cooldown: fetch again, success replaces the stale jwks
        self::assertSame(
            self::OTHER_RSA_JWK,
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-2', self::NOW + 20)->all()
        );
    }

    public function testResolveKeyWithExpiredJwksCacheAndFailedRefreshBeyondMaxStale(): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['keys' => [self::RSA_JWK]],
            ['status' => 500],
            ['status' => 500],
            ['keys' => [self::OTHER_RSA_JWK]],
        ]);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory, maxAge: 10, cooldown: 10, maxStale: 20);

        self::assertSame(self::RSA_JWK, $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW)->all());

        // expired cache, failed refresh: serve the stale jwks instead of failing
        self::assertSame(
            self::RSA_JWK,
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW + 10)->all()
        );

        // after cooldown, failed refresh again, still within max stale: still stale
        self::assertSame(
            self::RSA_JWK,
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW + 21)->all()
        );

        // within cooldown, one second before max stale (maxAge + maxStale since the last successful fetch): still
        // stale, no fetch
        self::assertSame(
            self::RSA_JWK,
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW + 29)->all()
        );

        // max stale reached (within cooldown): the stale jwks is not used anymore, fail with the last jwks error
        try {
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW + 30);

            self::fail('Expected JwksException not thrown');
        } catch (JwksException $exception) {
            self::assertSame('Expected 200 OK from the JSON Web Key Set HTTP response', $exception->getMessage());
        }

        // after cooldown: fetch again, success revives the key resolution
        self::assertSame(
            self::OTHER_RSA_JWK,
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-2', self::NOW + 31)->all()
        );
    }

    public function testResolveKeyWithExpiredJwksCacheAndFailedRefreshBeyondDefaultMaxStale(): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['keys' => [self::RSA_JWK]],
            ['status' => 500],
            ['status' => 500],
            ['keys' => [self::OTHER_RSA_JWK]],
        ]);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory, maxAge: 10, cooldown: 10);

        self::assertSame(self::RSA_JWK, $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW)->all());

        // expired cache, failed refresh: serve the stale jwks instead of failing
        self::assertSame(
            self::RSA_JWK,
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW + 10)->all()
        );

        // after cooldown, failed refresh again, one second before the default max stale of one hour: still stale
        self::assertSame(
            self::RSA_JWK,
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW + 3609)->all()
        );

        // max stale reached (within cooldown): the stale jwks is not used anymore, fail with the last jwks error
        try {
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW + 3610);

            self::fail('Expected JwksException not thrown');
        } catch (JwksException $exception) {
            self::assertSame('Expected 200 OK from the JSON Web Key Set HTTP response', $exception->getMessage());
        }

        // after cooldown: fetch again, success revives the key resolution
        self::assertSame(
            self::OTHER_RSA_JWK,
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-2', self::NOW + 3619)->all()
        );
    }

    public function testResolveKeyWithExpiredJwksCacheAndFailedRefreshWithoutMaxStale(): void
    {
        $error = new \RuntimeException('fetch failed');

        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['keys' => [self::RSA_JWK]],
            ['exception' => $error],
            ['keys' => [self::OTHER_RSA_JWK]],
        ]);

        // zero never serves a stale jwks
        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory, maxAge: 10, cooldown: 10, maxStale: 0);

        self::assertSame(self::RSA_JWK, $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW)->all());

        // expired cache, failed refresh: fail instead of serving the stale jwks
        self::assertThrows($remoteJwkSet, self::NOW + 10, $error);

        // within cooldown: fail fast with the same error, no fetch
        self::assertThrows($remoteJwkSet, self::NOW + 19, $error);

        // after cooldown: fetch again
        self::assertSame(
            self::OTHER_RSA_JWK,
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-2', self::NOW + 20)->all()
        );
    }

    public function testResolveKeyWithExpiredJwksCacheAndFailedRefreshWithUnboundedMaxStale(): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['keys' => [self::RSA_JWK]],
            ['status' => 500],
            ['status' => 500],
        ]);

        // null serves the stale jwks for as long as the outage lasts
        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory, maxAge: 10, cooldown: 10, maxStale: null);

        self::assertSame(self::RSA_JWK, $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW)->all());

        // expired cache, failed refresh: serve the stale jwks instead of failing
        self::assertSame(
            self::RSA_JWK,
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW + 10)->all()
        );

        // a year later, failed refresh again: still stale
        self::assertSame(
            self::RSA_JWK,
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW + 31536000)->all()
        );
    }

    public function testResolveKeyWithChangedJwksUriAfterFailure(): void
    {
        $error = new \RuntimeException('fetch failed');

        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['exception' => $error],
            ['url' => self::OTHER_JWKS_URI, 'keys' => [self::RSA_JWK]],
        ]);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory);

        self::assertThrows($remoteJwkSet, self::NOW, $error);

        // a changed jwks uri starts over, the failure cooldown does not apply
        self::assertSame(
            self::RSA_JWK,
            $remoteJwkSet->resolveKey(self::OTHER_JWKS_URI, 'RS256', 'key-1', self::NOW)->all()
        );
    }

    public function testResolveKeyWithFailingJwksUri(): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [['status' => 500]]);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory);

        $this->expectException(JwksException::class);
        $this->expectExceptionMessage('Expected 200 OK from the JSON Web Key Set HTTP response');

        $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW);
    }

    public function testResolveKeyWithInvalidJwksJson(): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [['body' => '{']]);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory);

        $this->expectException(JwksException::class);
        $this->expectExceptionMessage('Failed to parse the JSON Web Key Set HTTP response as JSON');

        $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW);
    }

    #[DataProvider('provideResolveKeyWithMalformedJwksCases')]
    public function testResolveKeyWithMalformedJwks(string $body): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [['body' => $body]]);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory);

        $this->expectException(JwksException::class);
        $this->expectExceptionMessage('JSON Web Key Set malformed');

        $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideResolveKeyWithMalformedJwksCases(): iterable
    {
        yield 'non object' => ['"keys"'];

        yield 'without keys' => ['{}'];

        yield 'with non array keys' => ['{"keys":"key-1"}'];

        yield 'with non list keys' => ['{"keys":{"key-1":{}}}'];

        yield 'with non object key' => ['{"keys":["key-1"]}'];
    }

    public function testResolveKeyWithUnsupportedAlgorithm(): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['keys' => [['kty' => 'oct', 'kid' => 'key-1', 'k' => 'k']]],
        ]);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('Unsupported "alg" value for a JSON Web Key Set');

        $remoteJwkSet->resolveKey(self::JWKS_URI, 'HS256', 'key-1', self::NOW);
    }

    public function testResolveKeyWithoutKeyIdAgainstJwksWithMultipleMatchingKeys(): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['keys' => [self::RSA_JWK, self::OTHER_RSA_JWK]],
        ]);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('multiple matching keys found in the JSON Web Key Set');

        $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', null, self::NOW);
    }

    public function testResolveKeyWithKeyIdAgainstJwksWithMultipleKeys(): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['keys' => [self::OTHER_RSA_JWK, self::RSA_JWK]],
        ]);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory);

        self::assertSame(self::RSA_JWK, $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', self::NOW)->all());
    }

    public function testResolveKeyWithNonStringKeyId(): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [['keys' => [self::RSA_JWK]]]);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory);

        // a non string "kid" is ignored, like a missing one
        self::assertSame(self::RSA_JWK, $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 42, self::NOW)->all());
    }

    /**
     * @param array<string, mixed> $matchingJwk
     * @param array<string, mixed> $notMatchingJwk
     */
    #[DataProvider('provideResolveKeyWithoutKeyIdAgainstJwksWithNotMatchingKeyCases')]
    public function testResolveKeyWithoutKeyIdAgainstJwksWithNotMatchingKey(
        string $alg,
        array $matchingJwk,
        array $notMatchingJwk,
    ): void {
        $builder = new MockObjectBuilder();

        // neither key has a "kid": only the not matching one gets excluded, the other one is unambiguous
        [$client, $requestFactory] = self::createFetchMocks($builder, [['keys' => [$notMatchingJwk, $matchingJwk]]]);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory);

        self::assertSame($matchingJwk, $remoteJwkSet->resolveKey(self::JWKS_URI, $alg, null, self::NOW)->all());
    }

    /**
     * @return iterable<string, array{string, array<string, mixed>, array<string, mixed>}>
     */
    public static function provideResolveKeyWithoutKeyIdAgainstJwksWithNotMatchingKeyCases(): iterable
    {
        $rsaJwk = ['kty' => 'RSA', 'n' => 'n', 'e' => 'AQAB'];
        $okpJwk = ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => 'x'];

        yield 'other key type' => ['RS256', $rsaJwk, self::EC_JWK];

        yield 'other algorithm' => ['RS256', $rsaJwk, ['alg' => 'RS384'] + $rsaJwk];

        yield 'other use' => ['RS256', $rsaJwk, ['use' => 'enc'] + $rsaJwk];

        yield 'other key operations' => ['RS256', $rsaJwk, ['key_ops' => ['encrypt']] + $rsaJwk];

        // malformed (rfc 7517) parameters do not make a key unrestricted
        yield 'malformed algorithm' => ['RS256', $rsaJwk, ['alg' => 42] + $rsaJwk];

        yield 'malformed use' => ['RS256', $rsaJwk, ['use' => ['sig']] + $rsaJwk];

        yield 'malformed key operations' => ['RS256', $rsaJwk, ['key_ops' => 'verify'] + $rsaJwk];

        yield 'matching algorithm, use and key operations' => [
            'RS256',
            ['alg' => 'RS256', 'use' => 'sig', 'key_ops' => ['verify']] + $rsaJwk,
            ['alg' => 'RS384'] + $rsaJwk,
        ];

        yield 'other curve for ES256' => ['ES256', self::EC_JWK, ['crv' => 'P-384'] + self::EC_JWK];

        yield 'other curve for ES384' => ['ES384', ['crv' => 'P-384'] + self::EC_JWK, self::EC_JWK];

        yield 'other curve for ES512' => ['ES512', ['crv' => 'P-521'] + self::EC_JWK, self::EC_JWK];

        yield 'other curve for EdDSA' => ['EdDSA', $okpJwk, ['crv' => 'Ed448'] + $okpJwk];
    }

    /**
     * @param list<array{url?: string, keys?: list<array<string, mixed>>, status?: int, body?: string, exception?: \Throwable}> $fetches
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
                    new WithReturn(
                        '__toString',
                        [],
                        $fetch['body'] ?? (string) json_encode(['keys' => $fetch['keys'] ?? []])
                    ),
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

    private static function assertThrows(RemoteJwkSet $remoteJwkSet, int $now, \Throwable $error): void
    {
        try {
            $remoteJwkSet->resolveKey(self::JWKS_URI, 'RS256', 'key-1', $now);
        } catch (\Throwable $throwable) {
            self::assertSame($error, $throwable);

            return;
        }

        self::fail('Expected exception not thrown');
    }
}
