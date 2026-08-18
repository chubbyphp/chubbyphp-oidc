<?php

declare(strict_types=1);

namespace Chubbyphp\Tests\Oidc\Unit\ServiceFactory;

use Chubbyphp\Mock\MockMethod\WithReturn;
use Chubbyphp\Mock\MockObjectBuilder;
use Chubbyphp\Oidc\Middleware\OidcAuthenticationMiddleware;
use Chubbyphp\Oidc\ServiceFactory\OidcAuthenticationMiddlewareFactory;
use Chubbyphp\Oidc\Token\TokenExtractorInterface;
use Chubbyphp\Oidc\Token\TokenVerifierInterface;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * @covers \Chubbyphp\Oidc\ServiceFactory\OidcAuthenticationMiddlewareFactory
 *
 * @internal
 */
final class OidcAuthenticationMiddlewareFactoryTest extends TestCase
{
    public function testInvokeWithDefaults(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ResponseFactoryInterface $responseFactory */
        $responseFactory = $builder->create(ResponseFactoryInterface::class, []);

        /** @var TokenExtractorInterface $tokenExtractor */
        $tokenExtractor = $builder->create(TokenExtractorInterface::class, []);

        /** @var TokenVerifierInterface $tokenVerifier */
        $tokenVerifier = $builder->create(TokenVerifierInterface::class, []);

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, [
            new WithReturn('get', ['config'], [
                'chubbyphp' => [
                    'oidc' => [],
                ],
            ]),
            new WithReturn('get', [ResponseFactoryInterface::class], $responseFactory),
            new WithReturn('has', [TokenExtractorInterface::class], true),
            new WithReturn('get', [TokenExtractorInterface::class], $tokenExtractor),
            new WithReturn('has', [TokenVerifierInterface::class], true),
            new WithReturn('get', [TokenVerifierInterface::class], $tokenVerifier),
            new WithReturn('has', [LoggerInterface::class], false),
        ]);

        $factory = new OidcAuthenticationMiddlewareFactory();

        $service = $factory($container);

        self::assertInstanceOf(OidcAuthenticationMiddleware::class, $service);

        $realmReflectionProperty = new \ReflectionProperty($service, 'realm');

        self::assertNull($realmReflectionProperty->getValue($service));

        $loggerReflectionProperty = new \ReflectionProperty($service, 'logger');

        self::assertInstanceOf(NullLogger::class, $loggerReflectionProperty->getValue($service));
    }

    public function testInvoke(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ResponseFactoryInterface $responseFactory */
        $responseFactory = $builder->create(ResponseFactoryInterface::class, []);

        /** @var TokenExtractorInterface $tokenExtractor */
        $tokenExtractor = $builder->create(TokenExtractorInterface::class, []);

        /** @var TokenVerifierInterface $tokenVerifier */
        $tokenVerifier = $builder->create(TokenVerifierInterface::class, []);

        /** @var LoggerInterface $logger */
        $logger = $builder->create(LoggerInterface::class, []);

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, [
            new WithReturn('get', ['config'], [
                'chubbyphp' => [
                    'oidc' => [
                        'realm' => 'api',
                    ],
                ],
            ]),
            new WithReturn('get', [ResponseFactoryInterface::class], $responseFactory),
            new WithReturn('has', [TokenExtractorInterface::class], true),
            new WithReturn('get', [TokenExtractorInterface::class], $tokenExtractor),
            new WithReturn('has', [TokenVerifierInterface::class], true),
            new WithReturn('get', [TokenVerifierInterface::class], $tokenVerifier),
            new WithReturn('has', [LoggerInterface::class], true),
            new WithReturn('get', [LoggerInterface::class], $logger),
        ]);

        $factory = new OidcAuthenticationMiddlewareFactory();

        $service = $factory($container);

        self::assertInstanceOf(OidcAuthenticationMiddleware::class, $service);

        $realmReflectionProperty = new \ReflectionProperty($service, 'realm');

        self::assertSame('api', $realmReflectionProperty->getValue($service));

        $loggerReflectionProperty = new \ReflectionProperty($service, 'logger');

        self::assertSame($logger, $loggerReflectionProperty->getValue($service));
    }

    public function testCallStatic(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ResponseFactoryInterface $responseFactory */
        $responseFactory = $builder->create(ResponseFactoryInterface::class, []);

        /** @var TokenExtractorInterface $tokenExtractor */
        $tokenExtractor = $builder->create(TokenExtractorInterface::class, []);

        /** @var TokenVerifierInterface $tokenVerifier */
        $tokenVerifier = $builder->create(TokenVerifierInterface::class, []);

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, [
            new WithReturn('get', ['config'], [
                'chubbyphp' => [
                    'oidc' => [
                        'default' => [
                            'realm' => 'api',
                        ],
                    ],
                ],
            ]),
            new WithReturn('get', [ResponseFactoryInterface::class], $responseFactory),
            new WithReturn('has', [TokenExtractorInterface::class.'default'], true),
            new WithReturn('get', [TokenExtractorInterface::class.'default'], $tokenExtractor),
            new WithReturn('has', [TokenVerifierInterface::class.'default'], true),
            new WithReturn('get', [TokenVerifierInterface::class.'default'], $tokenVerifier),
            new WithReturn('has', [LoggerInterface::class], false),
        ]);

        $factory = [OidcAuthenticationMiddlewareFactory::class, 'default'];

        $service = $factory($container);

        self::assertInstanceOf(OidcAuthenticationMiddleware::class, $service);

        $realmReflectionProperty = new \ReflectionProperty($service, 'realm');

        self::assertSame('api', $realmReflectionProperty->getValue($service));
    }
}
