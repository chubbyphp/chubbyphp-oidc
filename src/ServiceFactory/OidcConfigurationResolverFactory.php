<?php

declare(strict_types=1);

namespace Chubbyphp\Oidc\ServiceFactory;

use Chubbyphp\Laminas\Config\Factory\AbstractFactory;
use Chubbyphp\Oidc\Discovery\OidcConfigurationResolver;
use Psr\Container\ContainerInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

final class OidcConfigurationResolverFactory extends AbstractFactory
{
    public function __invoke(ContainerInterface $container): OidcConfigurationResolver
    {
        /** @var array{chubbyphp?: array{oidc?: array<string, mixed>}} $config */
        $config = $container->get('config');

        /** @var array{issuer?: string, maxAge?: int, cooldown?: int, allowInsecureIssuer?: bool} $oidcConfig */
        $oidcConfig = $this->resolveConfig($config['chubbyphp']['oidc'] ?? []);

        /** @var string $issuer */
        $issuer = $oidcConfig['issuer'] ?? throw new \LogicException('Missing config "chubbyphp.oidc.issuer"');

        $maxAge = $oidcConfig['maxAge'] ?? 3600;
        $cooldown = $oidcConfig['cooldown'] ?? 30;
        $allowInsecureIssuer = $oidcConfig['allowInsecureIssuer'] ?? false;

        /** @var ClientInterface $client */
        $client = $container->get(ClientInterface::class);

        /** @var RequestFactoryInterface $requestFactory */
        $requestFactory = $container->get(RequestFactoryInterface::class);

        return new OidcConfigurationResolver($issuer, $client, $requestFactory, $maxAge, $cooldown, $allowInsecureIssuer);
    }
}
