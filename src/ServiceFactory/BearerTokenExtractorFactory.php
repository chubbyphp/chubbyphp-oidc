<?php

declare(strict_types=1);

namespace Chubbyphp\Oidc\ServiceFactory;

use Chubbyphp\Laminas\Config\Factory\AbstractFactory;
use Chubbyphp\Oidc\Token\BearerTokenExtractor;
use Psr\Container\ContainerInterface;

final class BearerTokenExtractorFactory extends AbstractFactory
{
    public function __invoke(ContainerInterface $container): BearerTokenExtractor
    {
        return new BearerTokenExtractor();
    }
}
