<?php

declare(strict_types=1);

namespace Chubbyphp\Oidc\ServiceFactory;

use Chubbyphp\Laminas\Config\Factory\AbstractFactory;
use Chubbyphp\Oidc\Discovery\OidcConfigurationResolverInterface;
use Chubbyphp\Oidc\Jwks\RemoteJwkSet;
use Chubbyphp\Oidc\Token\JwtTokenVerifier;
use Psr\Container\ContainerInterface;

final class JwtTokenVerifierFactory extends AbstractFactory
{
    public function __invoke(ContainerInterface $container): JwtTokenVerifier
    {
        /** @var array{chubbyphp?: array{oidc?: array<string, mixed>}} $config */
        $config = $container->get('config');

        /**
         * @var array{
         *     audience?: array<string>|string,
         *     algorithms?: array<string>,
         *     clockTolerance?: int,
         *     typ?: string,
         *     requiredClaims?: array<string>
         * } $oidcConfig
         */
        $oidcConfig = $this->resolveConfig($config['chubbyphp']['oidc'] ?? []);

        /** @var array<string>|string $audience */
        $audience = $oidcConfig['audience'] ?? throw new \LogicException('Missing config "chubbyphp.oidc.audience"');

        $algorithms = $oidcConfig['algorithms'] ?? null;
        $clockTolerance = $oidcConfig['clockTolerance'] ?? 0;
        $typ = $oidcConfig['typ'] ?? null;
        $requiredClaims = $oidcConfig['requiredClaims'] ?? [];

        /** @var OidcConfigurationResolverInterface $oidcConfigurationResolver */
        $oidcConfigurationResolver = $this->resolveDependency(
            $container,
            OidcConfigurationResolverInterface::class,
            OidcConfigurationResolverFactory::class
        );

        /** @var RemoteJwkSet $remoteJwkSet */
        $remoteJwkSet = $this->resolveDependency($container, RemoteJwkSet::class, RemoteJwkSetFactory::class);

        return new JwtTokenVerifier(
            $oidcConfigurationResolver,
            $remoteJwkSet,
            $audience,
            $algorithms,
            $clockTolerance,
            $typ,
            $requiredClaims
        );
    }
}
