<?php

declare(strict_types=1);

namespace Chubbyphp\Oidc\Middleware;

use Chubbyphp\Oidc\Exception\InvalidTokenException;
use Chubbyphp\Oidc\Token\TokenExtractorInterface;
use Chubbyphp\Oidc\Token\TokenVerifierInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

final class OidcAuthenticationMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly ResponseFactoryInterface $responseFactory,
        private readonly TokenExtractorInterface $tokenExtractor,
        private readonly TokenVerifierInterface $tokenVerifier,
        private readonly ?string $realm = null,
        private readonly LoggerInterface $logger = new NullLogger(),
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $token = $this->tokenExtractor->extract($request);

        if (null === $token) {
            return $this->createUnauthorizedResponse($this->createChallenge([]));
        }

        // only the verification is guarded: an InvalidTokenException thrown by the handler (or a middleware behind
        // it) is not this middleware's business and gets rethrown like any other handler error
        try {
            $claims = $this->tokenVerifier->verify($token);
        } catch (InvalidTokenException $exception) {
            $this->logger->info('Invalid token', [
                'method' => $request->getMethod(),
                'pathnameSearch' => self::resolvePathnameSearch($request->getUri()),
                'error' => ['name' => $exception::class, 'message' => $exception->getMessage()],
            ]);

            // do not reflect the verification error to the client: it may leak internal details (issuer, jwks
            // uri, ...)
            return $this->createUnauthorizedResponse($this->createChallenge([
                'error' => 'invalid_token',
                'error_description' => 'The access token is invalid or expired',
            ]));
        }

        return $handler->handle($request->withAttribute('oidc', ['token' => $token, 'claims' => $claims]));
    }

    /**
     * @param array<string, string> $parameters
     */
    private function createChallenge(array $parameters): string
    {
        if (null !== $this->realm) {
            $parameters = ['realm' => $this->realm] + $parameters;
        }

        $formattedParameters = [];

        foreach ($parameters as $key => $value) {
            $formattedParameters[] = \sprintf(' %s="%s"', $key, self::sanitizeChallengeValue($value));
        }

        return 'Bearer'.implode(',', $formattedParameters);
    }

    /**
     * Quoted-string (rfc 7230): a backslash escapes the next char and control chars are not allowed at all (crlf
     * could even enable a response splitting attack), so drop them and downgrade double quotes to single quotes.
     */
    private static function sanitizeChallengeValue(string $value): string
    {
        /** @var string $value */
        $value = preg_replace('/[\\\\\x00-\x1f\x7f]/', '', $value) ?? '';

        return str_replace('"', "'", $value);
    }

    private function createUnauthorizedResponse(string $challenge): ResponseInterface
    {
        return $this->responseFactory
            ->createResponse(401, 'Unauthorized')
            ->withHeader('WWW-Authenticate', $challenge)
        ;
    }

    private static function resolvePathnameSearch(UriInterface $uri): string
    {
        $pathnameSearch = $uri->getPath();

        if ('' !== $query = $uri->getQuery()) {
            $pathnameSearch .= '?'.$query;
        }

        return $pathnameSearch;
    }
}
