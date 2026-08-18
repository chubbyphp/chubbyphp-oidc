<?php

declare(strict_types=1);

namespace Chubbyphp\Tests\Oidc\Unit\Discovery;

use Chubbyphp\Mock\MockMethod\WithException;
use Chubbyphp\Mock\MockMethod\WithReturn;
use Chubbyphp\Mock\MockObjectBuilder;
use Chubbyphp\Oidc\Discovery\OidcConfigurationResolver;
use Chubbyphp\Oidc\Exception\OidcConfigurationException;
use Chubbyphp\Tests\Oidc\FrozenClock;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;

/**
 * @covers \Chubbyphp\Oidc\Discovery\OidcConfigurationResolver
 *
 * @internal
 */
final class OidcConfigurationResolverTest extends TestCase
{
    private const ISSUER = 'https://issuer.example.com';
    private const URL = 'https://issuer.example.com/.well-known/openid-configuration';
    private const NOW = 1750000000;

    private const CONFIGURATION = [
        'issuer' => self::ISSUER,
        'jwks_uri' => 'https://issuer.example.com/jwks',
        'authorization_endpoint' => 'https://issuer.example.com/authorize',
        'token_endpoint' => 'https://issuer.example.com/token',
    ];

    #[DataProvider('provideCreateResolverWithInvalidIssuerCases')]
    public function testCreateResolverWithInvalidIssuer(string $issuer): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, []);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(\sprintf('Invalid issuer "%s": must be an absolute http(s) url', $issuer));

        new OidcConfigurationResolver($issuer, $client, $requestFactory);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCreateResolverWithInvalidIssuerCases(): iterable
    {
        yield 'relative' => ['issuer.example.com'];

        yield 'not a url' => ['not a url'];

        yield 'non http scheme' => ['ftp://issuer.example.com'];
    }

    #[DataProvider('provideCreateResolverWithInsecureIssuerCases')]
    public function testCreateResolverWithInsecureIssuer(string $issuer): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, []);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(\sprintf(
            'Insecure issuer "%s": use https or explicitly opt in with allowInsecureIssuer (local development only)',
            $issuer
        ));

        new OidcConfigurationResolver($issuer, $client, $requestFactory);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideCreateResolverWithInsecureIssuerCases(): iterable
    {
        yield 'lowercase scheme' => ['http://issuer.example.com'];

        yield 'uppercase scheme' => ['HTTP://issuer.example.com'];
    }

    #[DataProvider('provideCreateResolverWithNegativeOptionCases')]
    public function testCreateResolverWithNegativeOption(string $name, int $maxAge, int $cooldown): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, []);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(\sprintf('Invalid %s -1: must be a non-negative number of seconds', $name));

        new OidcConfigurationResolver(self::ISSUER, $client, $requestFactory, $maxAge, $cooldown);
    }

    /**
     * @return iterable<string, array{string, int, int}>
     */
    public static function provideCreateResolverWithNegativeOptionCases(): iterable
    {
        yield 'negative maxAge' => ['maxAge', -1, 30];

        yield 'negative cooldown' => ['cooldown', 3600, -1];
    }

    public function testResolveConfiguration(): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [['configuration' => self::CONFIGURATION]]);

        $oidcConfigurationResolver = new OidcConfigurationResolver(self::ISSUER, $client, $requestFactory);

        self::assertSame(self::CONFIGURATION, $oidcConfigurationResolver->resolve());
    }

    public function testResolveConfigurationWithTrailingSlashIssuer(): void
    {
        $issuerWithTrailingSlash = 'https://issuer.example.com/';

        $configurationWithTrailingSlashIssuer = ['issuer' => $issuerWithTrailingSlash] + self::CONFIGURATION;

        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['configuration' => $configurationWithTrailingSlashIssuer],
        ]);

        $oidcConfigurationResolver = new OidcConfigurationResolver($issuerWithTrailingSlash, $client, $requestFactory);

        self::assertSame($configurationWithTrailingSlashIssuer, $oidcConfigurationResolver->resolve());
    }

    public function testResolveConfigurationWithMultipleTrailingSlashesIssuer(): void
    {
        $issuerWithTrailingSlashes = 'https://issuer.example.com//';

        $configurationWithTrailingSlashesIssuer = ['issuer' => $issuerWithTrailingSlashes] + self::CONFIGURATION;

        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['configuration' => $configurationWithTrailingSlashesIssuer],
        ]);

        $oidcConfigurationResolver = new OidcConfigurationResolver(
            $issuerWithTrailingSlashes,
            $client,
            $requestFactory
        );

        self::assertSame($configurationWithTrailingSlashesIssuer, $oidcConfigurationResolver->resolve());
    }

    public function testResolveConfigurationWithExpiringCache(): void
    {
        $clock = new FrozenClock(self::NOW);

        $refreshedConfiguration = ['jwks_uri' => 'https://issuer.example.com/jwks2'] + self::CONFIGURATION;

        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['configuration' => self::CONFIGURATION],
            ['configuration' => $refreshedConfiguration],
        ]);

        $oidcConfigurationResolver = new OidcConfigurationResolver(
            self::ISSUER,
            $client,
            $requestFactory,
            maxAge: 10,
            clock: $clock
        );

        self::assertSame(self::CONFIGURATION, $oidcConfigurationResolver->resolve());

        $clock->setTimestamp(self::NOW + 9);

        // fresh cache: no fetch
        self::assertSame(self::CONFIGURATION, $oidcConfigurationResolver->resolve());

        $clock->setTimestamp(self::NOW + 10);

        // expired cache: fetch again
        self::assertSame($refreshedConfiguration, $oidcConfigurationResolver->resolve());
    }

    public function testResolveConfigurationWithExpiringCacheAndDefaultMaxAge(): void
    {
        $clock = new FrozenClock(self::NOW);

        $refreshedConfiguration = ['jwks_uri' => 'https://issuer.example.com/jwks2'] + self::CONFIGURATION;

        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['configuration' => self::CONFIGURATION],
            ['configuration' => $refreshedConfiguration],
        ]);

        $oidcConfigurationResolver = new OidcConfigurationResolver(
            self::ISSUER,
            $client,
            $requestFactory,
            clock: $clock
        );

        self::assertSame(self::CONFIGURATION, $oidcConfigurationResolver->resolve());

        $clock->setTimestamp(self::NOW + 3599);

        // fresh cache: no fetch
        self::assertSame(self::CONFIGURATION, $oidcConfigurationResolver->resolve());

        $clock->setTimestamp(self::NOW + 3600);

        // expired cache: fetch again
        self::assertSame($refreshedConfiguration, $oidcConfigurationResolver->resolve());
    }

    public function testResolveConfigurationWithCache(): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [['configuration' => self::CONFIGURATION]]);

        $oidcConfigurationResolver = new OidcConfigurationResolver(self::ISSUER, $client, $requestFactory);

        $resolvedConfiguration = $oidcConfigurationResolver->resolve();

        self::assertSame(self::CONFIGURATION, $resolvedConfiguration);
        self::assertSame($resolvedConfiguration, $oidcConfigurationResolver->resolve());
    }

    public function testResolveConfigurationWithoutCache(): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['configuration' => self::CONFIGURATION],
            ['configuration' => self::CONFIGURATION],
        ]);

        $oidcConfigurationResolver = new OidcConfigurationResolver(self::ISSUER, $client, $requestFactory, maxAge: 0);

        self::assertSame(self::CONFIGURATION, $oidcConfigurationResolver->resolve());
        self::assertSame(self::CONFIGURATION, $oidcConfigurationResolver->resolve());
    }

    #[DataProvider('provideResolveConfigurationWithFailedResponseCases')]
    public function testResolveConfigurationWithFailedResponse(int $status): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [['status' => $status]]);

        $oidcConfigurationResolver = new OidcConfigurationResolver(self::ISSUER, $client, $requestFactory);

        $this->expectException(OidcConfigurationException::class);
        $this->expectExceptionMessage(\sprintf('Cannot fetch oidc configuration from "%s": status %d', self::URL, $status));

        $oidcConfigurationResolver->resolve();
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideResolveConfigurationWithFailedResponseCases(): iterable
    {
        yield 'informational' => [199];

        yield 'redirect' => [300];

        yield 'client error' => [404];

        yield 'server error' => [500];
    }

    public function testResolveConfigurationWithLastSuccessfulResponseStatus(): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['status' => 299, 'configuration' => self::CONFIGURATION],
        ]);

        $oidcConfigurationResolver = new OidcConfigurationResolver(self::ISSUER, $client, $requestFactory);

        self::assertSame(self::CONFIGURATION, $oidcConfigurationResolver->resolve());
    }

    #[DataProvider('provideResolveConfigurationWithInvalidJsonCases')]
    public function testResolveConfigurationWithInvalidJson(string $body): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [['body' => $body]]);

        $oidcConfigurationResolver = new OidcConfigurationResolver(self::ISSUER, $client, $requestFactory);

        $this->expectException(OidcConfigurationException::class);
        $this->expectExceptionMessage(\sprintf('Cannot fetch oidc configuration from "%s": invalid json', self::URL));

        $oidcConfigurationResolver->resolve();
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideResolveConfigurationWithInvalidJsonCases(): iterable
    {
        yield 'malformed' => ['{'];

        yield 'non object' => ['"issuer"'];
    }

    public function testResolveConfigurationWithIssuerMismatch(): void
    {
        $configurationWithOtherIssuer = ['issuer' => 'https://other-issuer.example.com'] + self::CONFIGURATION;

        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['configuration' => $configurationWithOtherIssuer],
        ]);

        $oidcConfigurationResolver = new OidcConfigurationResolver(self::ISSUER, $client, $requestFactory);

        $this->expectException(OidcConfigurationException::class);
        $this->expectExceptionMessage(
            'Issuer mismatch: expected "https://issuer.example.com", given "https://other-issuer.example.com"'
        );

        $oidcConfigurationResolver->resolve();
    }

    public function testResolveConfigurationWithMissingIssuer(): void
    {
        $configurationWithoutIssuer = array_diff_key(self::CONFIGURATION, ['issuer' => true]);

        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['configuration' => $configurationWithoutIssuer],
        ]);

        $oidcConfigurationResolver = new OidcConfigurationResolver(self::ISSUER, $client, $requestFactory);

        $this->expectException(OidcConfigurationException::class);
        $this->expectExceptionMessage('Issuer mismatch: expected "https://issuer.example.com", given "null"');

        $oidcConfigurationResolver->resolve();
    }

    public function testResolveConfigurationWithUnreachableIssuer(): void
    {
        $fetchError = new \RuntimeException('fetch failed');

        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [['exception' => $fetchError]]);

        $oidcConfigurationResolver = new OidcConfigurationResolver(self::ISSUER, $client, $requestFactory);

        self::assertThrows($oidcConfigurationResolver, $fetchError);
    }

    public function testResolveConfigurationWithFailureCooldown(): void
    {
        $clock = new FrozenClock(self::NOW);

        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['status' => 500],
            ['configuration' => self::CONFIGURATION],
        ]);

        $oidcConfigurationResolver = new OidcConfigurationResolver(
            self::ISSUER,
            $client,
            $requestFactory,
            cooldown: 10,
            clock: $clock
        );

        $firstError = self::catchThrowable($oidcConfigurationResolver);

        self::assertInstanceOf(OidcConfigurationException::class, $firstError);
        self::assertSame(
            'Cannot fetch oidc configuration from "https://issuer.example.com/.well-known/openid-configuration": status 500',
            $firstError->getMessage()
        );

        $clock->setTimestamp(self::NOW + 9);

        // within cooldown: same error, no fetch
        self::assertThrows($oidcConfigurationResolver, $firstError);

        $clock->setTimestamp(self::NOW + 10);

        // after cooldown: fetch again, success clears the failure
        self::assertSame(self::CONFIGURATION, $oidcConfigurationResolver->resolve());
        self::assertSame(self::CONFIGURATION, $oidcConfigurationResolver->resolve());
    }

    public function testResolveConfigurationWithFailureCooldownAndDefaultCooldown(): void
    {
        $clock = new FrozenClock(self::NOW);

        $fetchError = new \RuntimeException('fetch failed');

        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['exception' => $fetchError],
            ['configuration' => self::CONFIGURATION],
        ]);

        $oidcConfigurationResolver = new OidcConfigurationResolver(
            self::ISSUER,
            $client,
            $requestFactory,
            clock: $clock
        );

        self::assertThrows($oidcConfigurationResolver, $fetchError);

        $clock->setTimestamp(self::NOW + 29);

        // within cooldown: same error, no fetch
        self::assertThrows($oidcConfigurationResolver, $fetchError);

        $clock->setTimestamp(self::NOW + 30);

        // after cooldown: fetch again, success clears the failure
        self::assertSame(self::CONFIGURATION, $oidcConfigurationResolver->resolve());
    }

    public function testResolveConfigurationWithExpiredCacheAndFailedRefresh(): void
    {
        $clock = new FrozenClock(self::NOW);

        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['configuration' => self::CONFIGURATION],
            ['status' => 500],
            ['configuration' => ['jwks_uri' => 'https://issuer.example.com/jwks2'] + self::CONFIGURATION],
        ]);

        $oidcConfigurationResolver = new OidcConfigurationResolver(
            self::ISSUER,
            $client,
            $requestFactory,
            maxAge: 10,
            cooldown: 10,
            clock: $clock
        );

        self::assertSame(self::CONFIGURATION, $oidcConfigurationResolver->resolve());

        $clock->setTimestamp(self::NOW + 10);

        // expired cache, failed refresh: serve the stale configuration instead of failing
        self::assertSame(self::CONFIGURATION, $oidcConfigurationResolver->resolve());

        $clock->setTimestamp(self::NOW + 19);

        // within cooldown: still stale, no fetch
        self::assertSame(self::CONFIGURATION, $oidcConfigurationResolver->resolve());

        $clock->setTimestamp(self::NOW + 20);

        // after cooldown: fetch again, success replaces the stale configuration
        self::assertSame(
            ['jwks_uri' => 'https://issuer.example.com/jwks2'] + self::CONFIGURATION,
            $oidcConfigurationResolver->resolve()
        );
    }

    public function testResolveConfigurationWithoutFailureCooldown(): void
    {
        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['status' => 500],
            ['configuration' => self::CONFIGURATION],
        ]);

        $oidcConfigurationResolver = new OidcConfigurationResolver(
            self::ISSUER,
            $client,
            $requestFactory,
            cooldown: 0
        );

        $error = self::catchThrowable($oidcConfigurationResolver);

        self::assertInstanceOf(OidcConfigurationException::class, $error);
        self::assertStringEndsWith('status 500', $error->getMessage());

        self::assertSame(self::CONFIGURATION, $oidcConfigurationResolver->resolve());
    }

    #[DataProvider('provideResolveConfigurationWithInvalidJwksUriCases')]
    public function testResolveConfigurationWithInvalidJwksUri(string $givenIssuer, mixed $jwksUri): void
    {
        $invalidConfiguration = ['issuer' => $givenIssuer] + self::CONFIGURATION;

        if (null === $jwksUri) {
            unset($invalidConfiguration['jwks_uri']);
        } else {
            $invalidConfiguration['jwks_uri'] = $jwksUri;
        }

        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['url' => $givenIssuer.'/.well-known/openid-configuration', 'configuration' => $invalidConfiguration],
        ]);

        $oidcConfigurationResolver = new OidcConfigurationResolver(
            $givenIssuer,
            $client,
            $requestFactory,
            allowInsecureIssuer: !str_starts_with($givenIssuer, 'https://')
        );

        $this->expectException(OidcConfigurationException::class);
        $this->expectExceptionMessage(\sprintf(
            'Missing or invalid jwks_uri "%s" for issuer "%s"',
            \is_string($jwksUri) ? $jwksUri : get_debug_type($jwksUri),
            $givenIssuer
        ));

        $oidcConfigurationResolver->resolve();
    }

    /**
     * @return iterable<string, array{string, mixed}>
     */
    public static function provideResolveConfigurationWithInvalidJwksUriCases(): iterable
    {
        yield 'https issuer and invalid jwks_uri' => ['https://issuer.example.com', 'not-a-url'];

        yield 'https issuer and missing jwks_uri' => ['https://issuer.example.com', null];

        yield 'https issuer and non string jwks_uri' => ['https://issuer.example.com', 42];

        yield 'https issuer and non http jwks_uri' => ['https://issuer.example.com', 'ftp://issuer.example.com/jwks'];

        yield 'http issuer and invalid jwks_uri' => ['http://issuer.example.com', 'not-a-url'];

        yield 'http issuer and missing jwks_uri' => ['http://issuer.example.com', null];
    }

    #[DataProvider('provideResolveConfigurationWithHttpsIssuerAndHttpJwksUriCases')]
    public function testResolveConfigurationWithHttpsIssuerAndHttpJwksUri(string $httpsIssuer): void
    {
        $insecureConfiguration = [
            'issuer' => $httpsIssuer,
            'jwks_uri' => 'http://issuer.example.com/jwks',
        ] + self::CONFIGURATION;

        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['url' => $httpsIssuer.'/.well-known/openid-configuration', 'configuration' => $insecureConfiguration],
        ]);

        $oidcConfigurationResolver = new OidcConfigurationResolver($httpsIssuer, $client, $requestFactory);

        $this->expectException(OidcConfigurationException::class);
        $this->expectExceptionMessage(
            \sprintf('Insecure jwks_uri "http://issuer.example.com/jwks" for https issuer "%s"', $httpsIssuer)
        );

        $oidcConfigurationResolver->resolve();
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideResolveConfigurationWithHttpsIssuerAndHttpJwksUriCases(): iterable
    {
        yield 'lowercase scheme' => ['https://issuer.example.com'];

        yield 'uppercase scheme' => ['HTTPS://issuer.example.com'];
    }

    public function testResolveConfigurationWithHttpIssuerAndHttpJwksUri(): void
    {
        $httpIssuer = 'http://issuer.example.com';
        $httpUrl = 'http://issuer.example.com/.well-known/openid-configuration';

        $httpConfiguration = [
            'issuer' => $httpIssuer,
            'jwks_uri' => 'http://issuer.example.com/jwks',
        ] + self::CONFIGURATION;

        $builder = new MockObjectBuilder();

        [$client, $requestFactory] = self::createFetchMocks($builder, [
            ['url' => $httpUrl, 'configuration' => $httpConfiguration],
        ]);

        $oidcConfigurationResolver = new OidcConfigurationResolver(
            $httpIssuer,
            $client,
            $requestFactory,
            allowInsecureIssuer: true
        );

        self::assertSame($httpConfiguration, $oidcConfigurationResolver->resolve());
    }

    /**
     * @param list<array{url?: string, configuration?: array<string, mixed>, status?: int, body?: string, exception?: \Throwable}> $fetches
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

            $requestFactoryMethods[] = new WithReturn('createRequest', ['GET', $fetch['url'] ?? self::URL], $request);

            if (isset($fetch['exception'])) {
                $clientMethods[] = new WithException('sendRequest', [$request], $fetch['exception']);

                continue;
            }

            $status = $fetch['status'] ?? 200;

            $responseMethods = [new WithReturn('getStatusCode', [], $status)];

            // the body is only read for a successful response
            if ($status >= 200 && $status < 300) {
                /** @var StreamInterface $body */
                $body = $builder->create(StreamInterface::class, [
                    new WithReturn(
                        '__toString',
                        [],
                        $fetch['body'] ?? (string) json_encode($fetch['configuration'] ?? [])
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

    private static function catchThrowable(OidcConfigurationResolver $oidcConfigurationResolver): \Throwable
    {
        try {
            $oidcConfigurationResolver->resolve();
        } catch (\Throwable $throwable) {
            return $throwable;
        }

        self::fail('Expected exception not thrown');
    }

    private static function assertThrows(OidcConfigurationResolver $oidcConfigurationResolver, \Throwable $error): void
    {
        self::assertSame($error, self::catchThrowable($oidcConfigurationResolver));
    }
}
