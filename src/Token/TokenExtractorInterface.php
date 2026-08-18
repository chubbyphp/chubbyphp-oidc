<?php

declare(strict_types=1);

namespace Chubbyphp\Oidc\Token;

use Psr\Http\Message\ServerRequestInterface;

interface TokenExtractorInterface
{
    public function extract(ServerRequestInterface $request): ?string;
}
