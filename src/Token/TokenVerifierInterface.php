<?php

declare(strict_types=1);

namespace Chubbyphp\Oidc\Token;

use Chubbyphp\Oidc\Exception\InvalidTokenException;

interface TokenVerifierInterface
{
    /**
     * @return array<string, mixed> the verified claims
     *
     * @throws InvalidTokenException if the token itself is invalid (malformed, wrong signature, expired, wrong
     *                               issuer / audience, ...). Any other throwable is treated as an internal
     *                               failure (unreachable discovery / jwks endpoint, ...)
     */
    public function verify(string $token): array;
}
