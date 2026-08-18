<?php

declare(strict_types=1);

namespace Chubbyphp\Tests\Oidc\Unit\ServiceFactory;

use Chubbyphp\Mock\MockMethod\WithReturn;
use Chubbyphp\Mock\MockObjectBuilder;
use Chubbyphp\Oidc\Discovery\OidcConfigurationResolverInterface;
use Chubbyphp\Oidc\Jwks\RemoteJwkSet;
use Chubbyphp\Oidc\ServiceFactory\JwtTokenVerifierFactory;
use Chubbyphp\Oidc\Token\JwtTokenVerifier;
use Jose\Component\Checker\ClaimChecker;
use Jose\Component\Checker\HeaderCheckerManager;
use Jose\Component\Checker\InvalidClaimException;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

/**
 * @covers \Chubbyphp\Oidc\ServiceFactory\JwtTokenVerifierFactory
 *
 * @internal
 */
final class JwtTokenVerifierFactoryTest extends TestCase
{
    public function testInvokeWithDefaults(): void
    {
        $builder = new MockObjectBuilder();

        /** @var OidcConfigurationResolverInterface $oidcConfigurationResolver */
        $oidcConfigurationResolver = $builder->create(OidcConfigurationResolverInterface::class, []);

        /** @var ClientInterface $client */
        $client = $builder->create(ClientInterface::class, []);

        /** @var RequestFactoryInterface $requestFactory */
        $requestFactory = $builder->create(RequestFactoryInterface::class, []);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory);

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, [
            new WithReturn('get', ['config'], [
                'chubbyphp' => [
                    'oidc' => [
                        'audience' => 'https://api.example.com',
                    ],
                ],
            ]),
            new WithReturn('has', [OidcConfigurationResolverInterface::class], true),
            new WithReturn('get', [OidcConfigurationResolverInterface::class], $oidcConfigurationResolver),
            new WithReturn('has', [RemoteJwkSet::class], true),
            new WithReturn('get', [RemoteJwkSet::class], $remoteJwkSet),
        ]);

        $factory = new JwtTokenVerifierFactory();

        $service = $factory($container);

        self::assertInstanceOf(JwtTokenVerifier::class, $service);

        $headerCheckerManagerReflectionProperty = new \ReflectionProperty($service, 'headerCheckerManager');

        $headerCheckerManager = $headerCheckerManagerReflectionProperty->getValue($service);

        self::assertInstanceOf(HeaderCheckerManager::class, $headerCheckerManager);

        $headerCheckers = $headerCheckerManager->getCheckers();

        self::assertSame(['alg', 'b64'], array_keys($headerCheckers));

        $supportedAlgorithmsReflectionProperty = new \ReflectionProperty($headerCheckers['alg'], 'supportedAlgorithms');

        self::assertSame(
            array_keys(RemoteJwkSet::SUPPORTED_ALGORITHMS),
            $supportedAlgorithmsReflectionProperty->getValue($headerCheckers['alg'])
        );

        $mandatoryHeaderParametersReflectionProperty = new \ReflectionProperty($service, 'mandatoryHeaderParameters');

        self::assertSame(['alg'], $mandatoryHeaderParametersReflectionProperty->getValue($service));

        self::assertClaimChecks($service, ['https://api.example.com'], 0, []);

        $remoteJwkSetReflectionProperty = new \ReflectionProperty($service, 'remoteJwkSet');

        self::assertSame($remoteJwkSet, $remoteJwkSetReflectionProperty->getValue($service));
    }

    public function testInvoke(): void
    {
        $builder = new MockObjectBuilder();

        /** @var OidcConfigurationResolverInterface $oidcConfigurationResolver */
        $oidcConfigurationResolver = $builder->create(OidcConfigurationResolverInterface::class, []);

        /** @var ClientInterface $client */
        $client = $builder->create(ClientInterface::class, []);

        /** @var RequestFactoryInterface $requestFactory */
        $requestFactory = $builder->create(RequestFactoryInterface::class, []);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory);

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, [
            new WithReturn('get', ['config'], [
                'chubbyphp' => [
                    'oidc' => [
                        'audience' => ['https://api.example.com', 'https://other-api.example.com'],
                        'algorithms' => ['RS256'],
                        'clockTolerance' => 5,
                        'typ' => 'at+jwt',
                        'requiredClaims' => ['sub', 'jti'],
                    ],
                ],
            ]),
            new WithReturn('has', [OidcConfigurationResolverInterface::class], true),
            new WithReturn('get', [OidcConfigurationResolverInterface::class], $oidcConfigurationResolver),
            new WithReturn('has', [RemoteJwkSet::class], true),
            new WithReturn('get', [RemoteJwkSet::class], $remoteJwkSet),
        ]);

        $factory = new JwtTokenVerifierFactory();

        $service = $factory($container);

        self::assertInstanceOf(JwtTokenVerifier::class, $service);

        $headerCheckerManagerReflectionProperty = new \ReflectionProperty($service, 'headerCheckerManager');

        $headerCheckerManager = $headerCheckerManagerReflectionProperty->getValue($service);

        self::assertInstanceOf(HeaderCheckerManager::class, $headerCheckerManager);

        $headerCheckers = $headerCheckerManager->getCheckers();

        self::assertSame(['alg', 'b64', 'typ'], array_keys($headerCheckers));

        $supportedAlgorithmsReflectionProperty = new \ReflectionProperty($headerCheckers['alg'], 'supportedAlgorithms');

        self::assertSame(['RS256'], $supportedAlgorithmsReflectionProperty->getValue($headerCheckers['alg']));

        $mandatoryHeaderParametersReflectionProperty = new \ReflectionProperty($service, 'mandatoryHeaderParameters');

        self::assertSame(['alg', 'typ'], $mandatoryHeaderParametersReflectionProperty->getValue($service));

        self::assertClaimChecks(
            $service,
            ['https://api.example.com', 'https://other-api.example.com'],
            5,
            ['sub', 'jti']
        );

        $remoteJwkSetReflectionProperty = new \ReflectionProperty($service, 'remoteJwkSet');

        self::assertSame($remoteJwkSet, $remoteJwkSetReflectionProperty->getValue($service));
    }

    public function testInvokeWithoutAudience(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, [
            new WithReturn('get', ['config'], [
                'chubbyphp' => [
                    'oidc' => [],
                ],
            ]),
        ]);

        $factory = new JwtTokenVerifierFactory();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Missing config "chubbyphp.oidc.audience"');

        $factory($container);
    }

    public function testCallStatic(): void
    {
        $builder = new MockObjectBuilder();

        /** @var OidcConfigurationResolverInterface $oidcConfigurationResolver */
        $oidcConfigurationResolver = $builder->create(OidcConfigurationResolverInterface::class, []);

        /** @var ClientInterface $client */
        $client = $builder->create(ClientInterface::class, []);

        /** @var RequestFactoryInterface $requestFactory */
        $requestFactory = $builder->create(RequestFactoryInterface::class, []);

        $remoteJwkSet = new RemoteJwkSet($client, $requestFactory);

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, [
            new WithReturn('get', ['config'], [
                'chubbyphp' => [
                    'oidc' => [
                        'default' => [
                            'audience' => 'https://api.example.com',
                            'clockTolerance' => 5,
                        ],
                    ],
                ],
            ]),
            new WithReturn('has', [OidcConfigurationResolverInterface::class.'default'], true),
            new WithReturn('get', [OidcConfigurationResolverInterface::class.'default'], $oidcConfigurationResolver),
            new WithReturn('has', [RemoteJwkSet::class.'default'], true),
            new WithReturn('get', [RemoteJwkSet::class.'default'], $remoteJwkSet),
        ]);

        $factory = [JwtTokenVerifierFactory::class, 'default'];

        $service = $factory($container);

        self::assertInstanceOf(JwtTokenVerifier::class, $service);

        self::assertClaimChecks($service, ['https://api.example.com'], 5, []);
    }

    /**
     * @param array<string> $audiences
     * @param array<string> $requiredClaims
     */
    private static function assertClaimChecks(
        JwtTokenVerifier $service,
        array $audiences,
        int $clockTolerance,
        array $requiredClaims,
    ): void {
        $claimCheckersReflectionProperty = new \ReflectionProperty($service, 'claimCheckers');

        /** @var array<ClaimChecker> $claimCheckers */
        $claimCheckers = $claimCheckersReflectionProperty->getValue($service);

        self::assertSame(
            ['aud', 'iat', 'nbf', 'exp'],
            array_map(static fn (ClaimChecker $claimChecker): string => $claimChecker->supportedClaim(), $claimCheckers)
        );

        self::assertAudienceChecker($claimCheckers[0], $audiences);

        $notBeforeAllowedTimeDriftReflectionProperty = new \ReflectionProperty($claimCheckers[2], 'allowedTimeDrift');

        self::assertSame($clockTolerance, $notBeforeAllowedTimeDriftReflectionProperty->getValue($claimCheckers[2]));

        $expirationTimeAllowedTimeDriftReflectionProperty = new \ReflectionProperty($claimCheckers[3], 'allowedTimeDrift');

        self::assertSame(
            $clockTolerance - 1,
            $expirationTimeAllowedTimeDriftReflectionProperty->getValue($claimCheckers[3])
        );

        $mandatoryClaimsReflectionProperty = new \ReflectionProperty($service, 'mandatoryClaims');

        self::assertSame(
            ['iss', 'aud', 'exp', ...$requiredClaims],
            $mandatoryClaimsReflectionProperty->getValue($service)
        );
    }

    /**
     * The audience checker accepts each configured audience and nothing else.
     *
     * @param array<string> $audiences
     */
    private static function assertAudienceChecker(ClaimChecker $claimChecker, array $audiences): void
    {
        foreach ($audiences as $audience) {
            $claimChecker->checkClaim($audience);
        }

        try {
            $claimChecker->checkClaim('https://unknown.example.com');
        } catch (InvalidClaimException) {
            return;
        }

        self::fail('Expected InvalidClaimException not thrown');
    }
}
