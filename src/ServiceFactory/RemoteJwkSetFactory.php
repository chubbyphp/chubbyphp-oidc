<?php

declare(strict_types=1);

namespace Chubbyphp\Oidc\ServiceFactory;

use Chubbyphp\Laminas\Config\Factory\AbstractFactory;
use Chubbyphp\Oidc\Jwks\RemoteJwkSet;
use Psr\Container\ContainerInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;

final class RemoteJwkSetFactory extends AbstractFactory
{
    public function __invoke(ContainerInterface $container): RemoteJwkSet
    {
        /** @var array{chubbyphp?: array{oidc?: array<string, mixed>}} $config */
        $config = $container->get('config');

        /** @var array{jwksMaxAge?: int, jwksCooldown?: int} $oidcConfig */
        $oidcConfig = $this->resolveConfig($config['chubbyphp']['oidc'] ?? []);

        $jwksMaxAge = $oidcConfig['jwksMaxAge'] ?? 600;
        $jwksCooldown = $oidcConfig['jwksCooldown'] ?? 30;

        /** @var ClientInterface $client */
        $client = $container->get(ClientInterface::class);

        /** @var RequestFactoryInterface $requestFactory */
        $requestFactory = $container->get(RequestFactoryInterface::class);

        return new RemoteJwkSet($client, $requestFactory, $jwksMaxAge, $jwksCooldown);
    }
}
