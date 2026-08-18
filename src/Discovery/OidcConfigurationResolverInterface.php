<?php

declare(strict_types=1);

namespace Chubbyphp\Oidc\Discovery;

/**
 * @phpstan-type OidcConfiguration array{
 *     issuer: string,
 *     jwks_uri: string,
 *     authorization_endpoint?: string,
 *     token_endpoint?: string,
 *     userinfo_endpoint?: string,
 *     end_session_endpoint?: string,
 *     ...<string, mixed>
 * }
 */
interface OidcConfigurationResolverInterface
{
    /**
     * @return OidcConfiguration
     */
    public function resolve(): array;
}
