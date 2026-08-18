<?php

declare(strict_types=1);

namespace Chubbyphp\Oidc\Exception;

/**
 * Thrown by the oidc configuration resolver if the openid configuration cannot be fetched from the issuer or is
 * invalid (issuer mismatch, missing / insecure jwks_uri, ...). Treated as an internal failure by the middleware.
 */
final class OidcConfigurationException extends \RuntimeException {}
