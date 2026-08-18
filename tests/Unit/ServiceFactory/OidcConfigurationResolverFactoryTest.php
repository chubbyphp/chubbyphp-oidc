<?php

declare(strict_types=1);

namespace Chubbyphp\Tests\Oidc\Unit\ServiceFactory;

use Chubbyphp\Mock\MockMethod\WithReturn;
use Chubbyphp\Mock\MockObjectBuilder;
use Chubbyphp\Oidc\Discovery\OidcConfigurationResolver;
use Chubbyphp\Oidc\ServiceFactory\OidcConfigurationResolverFactory;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

/**
 * @covers \Chubbyphp\Oidc\ServiceFactory\OidcConfigurationResolverFactory
 *
 * @internal
 */
final class OidcConfigurationResolverFactoryTest extends TestCase
{
    public function testInvokeWithDefaults(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ClientInterface $client */
        $client = $builder->create(ClientInterface::class, []);

        /** @var RequestFactoryInterface $requestFactory */
        $requestFactory = $builder->create(RequestFactoryInterface::class, []);

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, [
            new WithReturn('get', ['config'], [
                'chubbyphp' => [
                    'oidc' => [
                        'issuer' => 'https://issuer.example.com',
                    ],
                ],
            ]),
            new WithReturn('get', [ClientInterface::class], $client),
            new WithReturn('get', [RequestFactoryInterface::class], $requestFactory),
        ]);

        $factory = new OidcConfigurationResolverFactory();

        $service = $factory($container);

        self::assertInstanceOf(OidcConfigurationResolver::class, $service);

        $issuerReflectionProperty = new \ReflectionProperty($service, 'issuer');

        self::assertSame('https://issuer.example.com', $issuerReflectionProperty->getValue($service));

        $maxAgeReflectionProperty = new \ReflectionProperty($service, 'maxAge');

        self::assertSame(3600, $maxAgeReflectionProperty->getValue($service));

        $cooldownReflectionProperty = new \ReflectionProperty($service, 'cooldown');

        self::assertSame(30, $cooldownReflectionProperty->getValue($service));
    }

    public function testInvokeWithDefaultsRejectsInsecureIssuer(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ClientInterface $client */
        $client = $builder->create(ClientInterface::class, []);

        /** @var RequestFactoryInterface $requestFactory */
        $requestFactory = $builder->create(RequestFactoryInterface::class, []);

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, [
            new WithReturn('get', ['config'], [
                'chubbyphp' => [
                    'oidc' => [
                        'issuer' => 'http://issuer.example.com',
                    ],
                ],
            ]),
            new WithReturn('get', [ClientInterface::class], $client),
            new WithReturn('get', [RequestFactoryInterface::class], $requestFactory),
        ]);

        $factory = new OidcConfigurationResolverFactory();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(
            'Insecure issuer "http://issuer.example.com": use https or explicitly opt in with allowInsecureIssuer'
        );

        $factory($container);
    }

    public function testInvoke(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ClientInterface $client */
        $client = $builder->create(ClientInterface::class, []);

        /** @var RequestFactoryInterface $requestFactory */
        $requestFactory = $builder->create(RequestFactoryInterface::class, []);

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, [
            new WithReturn('get', ['config'], [
                'chubbyphp' => [
                    'oidc' => [
                        'issuer' => 'http://issuer.example.com',
                        'maxAge' => 300,
                        'cooldown' => 10,
                        'allowInsecureIssuer' => true,
                    ],
                ],
            ]),
            new WithReturn('get', [ClientInterface::class], $client),
            new WithReturn('get', [RequestFactoryInterface::class], $requestFactory),
        ]);

        $factory = new OidcConfigurationResolverFactory();

        $service = $factory($container);

        self::assertInstanceOf(OidcConfigurationResolver::class, $service);

        $maxAgeReflectionProperty = new \ReflectionProperty($service, 'maxAge');

        self::assertSame(300, $maxAgeReflectionProperty->getValue($service));

        $cooldownReflectionProperty = new \ReflectionProperty($service, 'cooldown');

        self::assertSame(10, $cooldownReflectionProperty->getValue($service));
    }

    public function testInvokeWithoutIssuer(): void
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

        $factory = new OidcConfigurationResolverFactory();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Missing config "chubbyphp.oidc.issuer"');

        $factory($container);
    }

    public function testCallStatic(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ClientInterface $client */
        $client = $builder->create(ClientInterface::class, []);

        /** @var RequestFactoryInterface $requestFactory */
        $requestFactory = $builder->create(RequestFactoryInterface::class, []);

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, [
            new WithReturn('get', ['config'], [
                'chubbyphp' => [
                    'oidc' => [
                        'default' => [
                            'issuer' => 'https://issuer.example.com',
                            'maxAge' => 300,
                        ],
                    ],
                ],
            ]),
            new WithReturn('get', [ClientInterface::class], $client),
            new WithReturn('get', [RequestFactoryInterface::class], $requestFactory),
        ]);

        $factory = [OidcConfigurationResolverFactory::class, 'default'];

        $service = $factory($container);

        self::assertInstanceOf(OidcConfigurationResolver::class, $service);

        $maxAgeReflectionProperty = new \ReflectionProperty($service, 'maxAge');

        self::assertSame(300, $maxAgeReflectionProperty->getValue($service));
    }
}
