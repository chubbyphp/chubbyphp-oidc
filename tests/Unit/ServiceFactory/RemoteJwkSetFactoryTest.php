<?php

declare(strict_types=1);

namespace Chubbyphp\Tests\Oidc\Unit\ServiceFactory;

use Chubbyphp\Mock\MockMethod\WithReturn;
use Chubbyphp\Mock\MockObjectBuilder;
use Chubbyphp\Oidc\Jwks\RemoteJwkSet;
use Chubbyphp\Oidc\ServiceFactory\RemoteJwkSetFactory;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

/**
 * @covers \Chubbyphp\Oidc\ServiceFactory\RemoteJwkSetFactory
 *
 * @internal
 */
final class RemoteJwkSetFactoryTest extends TestCase
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
                    'oidc' => [],
                ],
            ]),
            new WithReturn('get', [ClientInterface::class], $client),
            new WithReturn('get', [RequestFactoryInterface::class], $requestFactory),
        ]);

        $factory = new RemoteJwkSetFactory();

        $service = $factory($container);

        self::assertInstanceOf(RemoteJwkSet::class, $service);

        $clientReflectionProperty = new \ReflectionProperty($service, 'client');

        self::assertSame($client, $clientReflectionProperty->getValue($service));

        $requestFactoryReflectionProperty = new \ReflectionProperty($service, 'requestFactory');

        self::assertSame($requestFactory, $requestFactoryReflectionProperty->getValue($service));

        $maxAgeReflectionProperty = new \ReflectionProperty($service, 'maxAge');

        self::assertSame(600, $maxAgeReflectionProperty->getValue($service));

        $cooldownReflectionProperty = new \ReflectionProperty($service, 'cooldown');

        self::assertSame(30, $cooldownReflectionProperty->getValue($service));

        $maxStaleReflectionProperty = new \ReflectionProperty($service, 'maxStale');

        self::assertSame(3600, $maxStaleReflectionProperty->getValue($service));
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
                        'jwksMaxAge' => 300,
                        'jwksCooldown' => 10,
                        'jwksMaxStale' => 60,
                    ],
                ],
            ]),
            new WithReturn('get', [ClientInterface::class], $client),
            new WithReturn('get', [RequestFactoryInterface::class], $requestFactory),
        ]);

        $factory = new RemoteJwkSetFactory();

        $service = $factory($container);

        self::assertInstanceOf(RemoteJwkSet::class, $service);

        $maxAgeReflectionProperty = new \ReflectionProperty($service, 'maxAge');

        self::assertSame(300, $maxAgeReflectionProperty->getValue($service));

        $cooldownReflectionProperty = new \ReflectionProperty($service, 'cooldown');

        self::assertSame(10, $cooldownReflectionProperty->getValue($service));

        $maxStaleReflectionProperty = new \ReflectionProperty($service, 'maxStale');

        self::assertSame(60, $maxStaleReflectionProperty->getValue($service));
    }

    public function testInvokeWithUnboundedMaxStale(): void
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
                        // null (unbounded) is a valid value, not a missing one
                        'jwksMaxStale' => null,
                    ],
                ],
            ]),
            new WithReturn('get', [ClientInterface::class], $client),
            new WithReturn('get', [RequestFactoryInterface::class], $requestFactory),
        ]);

        $factory = new RemoteJwkSetFactory();

        $service = $factory($container);

        self::assertInstanceOf(RemoteJwkSet::class, $service);

        $maxStaleReflectionProperty = new \ReflectionProperty($service, 'maxStale');

        self::assertNull($maxStaleReflectionProperty->getValue($service));
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
                            'jwksMaxAge' => 300,
                            'jwksCooldown' => 10,
                            'jwksMaxStale' => 60,
                        ],
                    ],
                ],
            ]),
            new WithReturn('get', [ClientInterface::class], $client),
            new WithReturn('get', [RequestFactoryInterface::class], $requestFactory),
        ]);

        $factory = [RemoteJwkSetFactory::class, 'default'];

        $service = $factory($container);

        self::assertInstanceOf(RemoteJwkSet::class, $service);

        $maxAgeReflectionProperty = new \ReflectionProperty($service, 'maxAge');

        self::assertSame(300, $maxAgeReflectionProperty->getValue($service));

        $cooldownReflectionProperty = new \ReflectionProperty($service, 'cooldown');

        self::assertSame(10, $cooldownReflectionProperty->getValue($service));

        $maxStaleReflectionProperty = new \ReflectionProperty($service, 'maxStale');

        self::assertSame(60, $maxStaleReflectionProperty->getValue($service));
    }
}
