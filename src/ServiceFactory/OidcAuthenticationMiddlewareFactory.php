<?php

declare(strict_types=1);

namespace Chubbyphp\Oidc\ServiceFactory;

use Chubbyphp\Laminas\Config\Factory\AbstractFactory;
use Chubbyphp\Oidc\Middleware\OidcAuthenticationMiddleware;
use Chubbyphp\Oidc\Token\TokenExtractorInterface;
use Chubbyphp\Oidc\Token\TokenVerifierInterface;
use Psr\Container\ContainerInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final class OidcAuthenticationMiddlewareFactory extends AbstractFactory
{
    public function __invoke(ContainerInterface $container): OidcAuthenticationMiddleware
    {
        /** @var array{chubbyphp?: array{oidc?: array<string, mixed>}} $config */
        $config = $container->get('config');

        /** @var array{realm?: string} $oidcConfig */
        $oidcConfig = $this->resolveConfig($config['chubbyphp']['oidc'] ?? []);

        $realm = $oidcConfig['realm'] ?? null;

        /** @var ResponseFactoryInterface $responseFactory */
        $responseFactory = $container->get(ResponseFactoryInterface::class);

        /** @var TokenExtractorInterface $tokenExtractor */
        $tokenExtractor = $this->resolveDependency(
            $container,
            TokenExtractorInterface::class,
            BearerTokenExtractorFactory::class
        );

        /** @var TokenVerifierInterface $tokenVerifier */
        $tokenVerifier = $this->resolveDependency(
            $container,
            TokenVerifierInterface::class,
            JwtTokenVerifierFactory::class
        );

        /** @var LoggerInterface $logger */
        $logger = $container->has(LoggerInterface::class) ? $container->get(LoggerInterface::class) : new NullLogger();

        return new OidcAuthenticationMiddleware(
            $responseFactory,
            $tokenExtractor,
            $tokenVerifier,
            $realm,
            $logger
        );
    }
}
