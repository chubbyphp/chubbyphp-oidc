<?php

declare(strict_types=1);

namespace Chubbyphp\Oidc\Exception;

/**
 * Thrown by the jwt token verifier if the JSON Web Key Set cannot be fetched from the jwks_uri or is malformed.
 * Treated as an internal failure by the middleware.
 */
final class JwksException extends \RuntimeException {}
