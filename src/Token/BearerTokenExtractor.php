<?php

declare(strict_types=1);

namespace Chubbyphp\Oidc\Token;

use Psr\Http\Message\ServerRequestInterface;

final class BearerTokenExtractor implements TokenExtractorInterface
{
    public function extract(ServerRequestInterface $request): ?string
    {
        if (1 !== preg_match('/^Bearer +(\S+)$/i', $request->getHeaderLine('authorization'), $matches)) {
            return null;
        }

        return $matches[1];
    }
}
