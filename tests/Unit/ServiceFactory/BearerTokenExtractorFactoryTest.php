<?php

declare(strict_types=1);

namespace Chubbyphp\Tests\Oidc\Unit\ServiceFactory;

use Chubbyphp\Mock\MockObjectBuilder;
use Chubbyphp\Oidc\ServiceFactory\BearerTokenExtractorFactory;
use Chubbyphp\Oidc\Token\BearerTokenExtractor;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

/**
 * @covers \Chubbyphp\Oidc\ServiceFactory\BearerTokenExtractorFactory
 *
 * @internal
 */
final class BearerTokenExtractorFactoryTest extends TestCase
{
    public function testInvoke(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, []);

        $factory = new BearerTokenExtractorFactory();

        self::assertInstanceOf(BearerTokenExtractor::class, $factory($container));
    }

    public function testCallStatic(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ContainerInterface $container */
        $container = $builder->create(ContainerInterface::class, []);

        $factory = [BearerTokenExtractorFactory::class, 'default'];

        self::assertInstanceOf(BearerTokenExtractor::class, $factory($container));
    }
}
