<?php

declare(strict_types=1);

namespace Chubbyphp\Oidc\Exception;

/**
 * Thrown by a token verifier if the given token itself is invalid (malformed, wrong signature, expired, wrong
 * issuer / audience, ...). Any other error thrown by a token verifier is treated as an internal failure
 * (unreachable discovery / jwks endpoint, ...) and gets rethrown by the middleware.
 */
final class InvalidTokenException extends \RuntimeException {}
