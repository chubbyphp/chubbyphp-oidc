<?php

declare(strict_types=1);

namespace Chubbyphp\Tests\Oidc\Unit\Middleware;

use Chubbyphp\Mock\MockMethod\WithException;
use Chubbyphp\Mock\MockMethod\WithoutReturn;
use Chubbyphp\Mock\MockMethod\WithReturn;
use Chubbyphp\Mock\MockMethod\WithReturnSelf;
use Chubbyphp\Mock\MockObjectBuilder;
use Chubbyphp\Oidc\Exception\InvalidTokenException;
use Chubbyphp\Oidc\Middleware\OidcAuthenticationMiddleware;
use Chubbyphp\Oidc\Token\TokenExtractorInterface;
use Chubbyphp\Oidc\Token\TokenVerifierInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

/**
 * @covers \Chubbyphp\Oidc\Middleware\OidcAuthenticationMiddleware
 *
 * @internal
 */
final class OidcAuthenticationMiddlewareTest extends TestCase
{
    public function testWithoutTokenWithoutRealm(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ServerRequestInterface $serverRequest */
        $serverRequest = $builder->create(ServerRequestInterface::class, []);

        /** @var ResponseInterface $response */
        $response = $builder->create(ResponseInterface::class, [
            new WithReturnSelf('withHeader', ['WWW-Authenticate', 'Bearer']),
        ]);

        /** @var ResponseFactoryInterface $responseFactory */
        $responseFactory = $builder->create(ResponseFactoryInterface::class, [
            new WithReturn('createResponse', [401, 'Unauthorized'], $response),
        ]);

        /** @var TokenExtractorInterface $tokenExtractor */
        $tokenExtractor = $builder->create(TokenExtractorInterface::class, [
            new WithReturn('extract', [$serverRequest], null),
        ]);

        /** @var TokenVerifierInterface $tokenVerifier */
        $tokenVerifier = $builder->create(TokenVerifierInterface::class, []);

        /** @var RequestHandlerInterface $handler */
        $handler = $builder->create(RequestHandlerInterface::class, []);

        $middleware = new OidcAuthenticationMiddleware($responseFactory, $tokenExtractor, $tokenVerifier);

        self::assertSame($response, $middleware->process($serverRequest, $handler));
    }

    public function testWithoutTokenWithRealm(): void
    {
        $builder = new MockObjectBuilder();

        /** @var ServerRequestInterface $serverRequest */
        $serverRequest = $builder->create(ServerRequestInterface::class, []);

        /** @var ResponseInterface $response */
        $response = $builder->create(ResponseInterface::class, [
            new WithReturnSelf('withHeader', ['WWW-Authenticate', 'Bearer realm="api"']),
        ]);

        /** @var ResponseFactoryInterface $responseFactory */
        $responseFactory = $builder->create(ResponseFactoryInterface::class, [
            new WithReturn('createResponse', [401, 'Unauthorized'], $response),
        ]);

        /** @var TokenExtractorInterface $tokenExtractor */
        $tokenExtractor = $builder->create(TokenExtractorInterface::class, [
            new WithReturn('extract', [$serverRequest], null),
        ]);

        /** @var TokenVerifierInterface $tokenVerifier */
        $tokenVerifier = $builder->create(TokenVerifierInterface::class, []);

        /** @var RequestHandlerInterface $handler */
        $handler = $builder->create(RequestHandlerInterface::class, []);

        $middleware = new OidcAuthenticationMiddleware($responseFactory, $tokenExtractor, $tokenVerifier, 'api');

        self::assertSame($response, $middleware->process($serverRequest, $handler));
    }

    #[DataProvider('provideWithoutTokenWithRealmContainingSpecialCharactersCases')]
    public function testWithoutTokenWithRealmContainingSpecialCharacters(string $realm, string $expectedChallenge): void
    {
        $builder = new MockObjectBuilder();

        /** @var ServerRequestInterface $serverRequest */
        $serverRequest = $builder->create(ServerRequestInterface::class, []);

        /** @var ResponseInterface $response */
        $response = $builder->create(ResponseInterface::class, [
            new WithReturnSelf('withHeader', ['WWW-Authenticate', $expectedChallenge]),
        ]);

        /** @var ResponseFactoryInterface $responseFactory */
        $responseFactory = $builder->create(ResponseFactoryInterface::class, [
            new WithReturn('createResponse', [401, 'Unauthorized'], $response),
        ]);

        /** @var TokenExtractorInterface $tokenExtractor */
        $tokenExtractor = $builder->create(TokenExtractorInterface::class, [
            new WithReturn('extract', [$serverRequest], null),
        ]);

        /** @var TokenVerifierInterface $tokenVerifier */
        $tokenVerifier = $builder->create(TokenVerifierInterface::class, []);

        /** @var RequestHandlerInterface $handler */
        $handler = $builder->create(RequestHandlerInterface::class, []);

        $middleware = new OidcAuthenticationMiddleware($responseFactory, $tokenExtractor, $tokenVerifier, $realm);

        self::assertSame($response, $middleware->process($serverRequest, $handler));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideWithoutTokenWithRealmContainingSpecialCharactersCases(): iterable
    {
        yield 'double quotes' => ['my "api"', 'Bearer realm="my \'api\'"'];

        yield 'backslashes' => ['my\api\\', 'Bearer realm="myapi"'];

        yield 'control characters' => ["my\r\napi\u{0000}\u{007f}", 'Bearer realm="myapi"'];
    }

    public function testWithInvalidToken(): void
    {
        $builder = new MockObjectBuilder();

        /** @var UriInterface $uri */
        $uri = $builder->create(UriInterface::class, [
            new WithReturn('getPath', [], '/resource'),
            new WithReturn('getQuery', [], 'key=value'),
        ]);

        /** @var ServerRequestInterface $serverRequest */
        $serverRequest = $builder->create(ServerRequestInterface::class, [
            new WithReturn('getMethod', [], 'GET'),
            new WithReturn('getUri', [], $uri),
        ]);

        /** @var ResponseInterface $response */
        $response = $builder->create(ResponseInterface::class, [
            new WithReturnSelf('withHeader', [
                'WWW-Authenticate',
                'Bearer realm="api", error="invalid_token", error_description="The access token is invalid or expired"',
            ]),
        ]);

        /** @var ResponseFactoryInterface $responseFactory */
        $responseFactory = $builder->create(ResponseFactoryInterface::class, [
            new WithReturn('createResponse', [401, 'Unauthorized'], $response),
        ]);

        /** @var TokenExtractorInterface $tokenExtractor */
        $tokenExtractor = $builder->create(TokenExtractorInterface::class, [
            new WithReturn('extract', [$serverRequest], 'token-1'),
        ]);

        /** @var TokenVerifierInterface $tokenVerifier */
        $tokenVerifier = $builder->create(TokenVerifierInterface::class, [
            new WithException('verify', ['token-1'], new InvalidTokenException('"exp" claim timestamp check failed')),
        ]);

        /** @var RequestHandlerInterface $handler */
        $handler = $builder->create(RequestHandlerInterface::class, []);

        /** @var LoggerInterface $logger */
        $logger = $builder->create(LoggerInterface::class, [
            new WithoutReturn('info', [
                'Invalid token',
                [
                    'method' => 'GET',
                    'pathnameSearch' => '/resource?key=value',
                    'error' => [
                        'name' => InvalidTokenException::class,
                        'message' => '"exp" claim timestamp check failed',
                    ],
                ],
            ]),
        ]);

        $middleware = new OidcAuthenticationMiddleware(
            $responseFactory,
            $tokenExtractor,
            $tokenVerifier,
            'api',
            $logger
        );

        self::assertSame($response, $middleware->process($serverRequest, $handler));
    }

    public function testWithInvalidTokenWithoutRealmAndDefaultLogger(): void
    {
        $builder = new MockObjectBuilder();

        /** @var UriInterface $uri */
        $uri = $builder->create(UriInterface::class, [
            new WithReturn('getPath', [], '/resource'),
            new WithReturn('getQuery', [], ''),
        ]);

        /** @var ServerRequestInterface $serverRequest */
        $serverRequest = $builder->create(ServerRequestInterface::class, [
            new WithReturn('getMethod', [], 'GET'),
            new WithReturn('getUri', [], $uri),
        ]);

        /** @var ResponseInterface $response */
        $response = $builder->create(ResponseInterface::class, [
            new WithReturnSelf('withHeader', [
                'WWW-Authenticate',
                'Bearer error="invalid_token", error_description="The access token is invalid or expired"',
            ]),
        ]);

        /** @var ResponseFactoryInterface $responseFactory */
        $responseFactory = $builder->create(ResponseFactoryInterface::class, [
            new WithReturn('createResponse', [401, 'Unauthorized'], $response),
        ]);

        /** @var TokenExtractorInterface $tokenExtractor */
        $tokenExtractor = $builder->create(TokenExtractorInterface::class, [
            new WithReturn('extract', [$serverRequest], 'token-1'),
        ]);

        /** @var TokenVerifierInterface $tokenVerifier */
        $tokenVerifier = $builder->create(TokenVerifierInterface::class, [
            new WithException('verify', ['token-1'], new InvalidTokenException('Invalid Compact JWS')),
        ]);

        /** @var RequestHandlerInterface $handler */
        $handler = $builder->create(RequestHandlerInterface::class, []);

        $middleware = new OidcAuthenticationMiddleware($responseFactory, $tokenExtractor, $tokenVerifier);

        self::assertSame($response, $middleware->process($serverRequest, $handler));
    }

    public function testWithFailingTokenVerifier(): void
    {
        $builder = new MockObjectBuilder();

        $error = new \RuntimeException(
            'Cannot fetch oidc configuration from "https://issuer.example.com": status 500'
        );

        /** @var ServerRequestInterface $serverRequest */
        $serverRequest = $builder->create(ServerRequestInterface::class, []);

        /** @var ResponseFactoryInterface $responseFactory */
        $responseFactory = $builder->create(ResponseFactoryInterface::class, []);

        /** @var TokenExtractorInterface $tokenExtractor */
        $tokenExtractor = $builder->create(TokenExtractorInterface::class, [
            new WithReturn('extract', [$serverRequest], 'token-1'),
        ]);

        /** @var TokenVerifierInterface $tokenVerifier */
        $tokenVerifier = $builder->create(TokenVerifierInterface::class, [
            new WithException('verify', ['token-1'], $error),
        ]);

        /** @var RequestHandlerInterface $handler */
        $handler = $builder->create(RequestHandlerInterface::class, []);

        /** @var LoggerInterface $logger */
        $logger = $builder->create(LoggerInterface::class, []);

        $middleware = new OidcAuthenticationMiddleware(
            $responseFactory,
            $tokenExtractor,
            $tokenVerifier,
            'api',
            $logger
        );

        try {
            $middleware->process($serverRequest, $handler);

            self::fail('Expected exception not thrown');
        } catch (\RuntimeException $caught) {
            self::assertSame($error, $caught);
        }
    }

    public function testWithValidToken(): void
    {
        $builder = new MockObjectBuilder();

        $claims = ['iss' => 'https://issuer.example.com', 'sub' => 'subject-1'];

        /** @var ServerRequestInterface $handledServerRequest */
        $handledServerRequest = $builder->create(ServerRequestInterface::class, []);

        /** @var ServerRequestInterface $serverRequest */
        $serverRequest = $builder->create(ServerRequestInterface::class, [
            new WithReturn('withAttribute', ['oidc', ['token' => 'token-1', 'claims' => $claims]], $handledServerRequest),
        ]);

        /** @var ResponseInterface $handlerResponse */
        $handlerResponse = $builder->create(ResponseInterface::class, []);

        /** @var ResponseFactoryInterface $responseFactory */
        $responseFactory = $builder->create(ResponseFactoryInterface::class, []);

        /** @var TokenExtractorInterface $tokenExtractor */
        $tokenExtractor = $builder->create(TokenExtractorInterface::class, [
            new WithReturn('extract', [$serverRequest], 'token-1'),
        ]);

        /** @var TokenVerifierInterface $tokenVerifier */
        $tokenVerifier = $builder->create(TokenVerifierInterface::class, [
            new WithReturn('verify', ['token-1'], $claims),
        ]);

        /** @var RequestHandlerInterface $handler */
        $handler = $builder->create(RequestHandlerInterface::class, [
            new WithReturn('handle', [$handledServerRequest], $handlerResponse),
        ]);

        $middleware = new OidcAuthenticationMiddleware($responseFactory, $tokenExtractor, $tokenVerifier);

        self::assertSame($handlerResponse, $middleware->process($serverRequest, $handler));
    }

    public function testWithValidTokenAndHandlerThrowingInvalidTokenException(): void
    {
        $builder = new MockObjectBuilder();

        $claims = ['iss' => 'https://issuer.example.com', 'sub' => 'subject-1'];

        // an InvalidTokenException thrown behind the middleware is not a verification failure and must not become
        // a 401
        $error = new InvalidTokenException('thrown by the handler');

        /** @var ServerRequestInterface $handledServerRequest */
        $handledServerRequest = $builder->create(ServerRequestInterface::class, []);

        /** @var ServerRequestInterface $serverRequest */
        $serverRequest = $builder->create(ServerRequestInterface::class, [
            new WithReturn('withAttribute', ['oidc', ['token' => 'token-1', 'claims' => $claims]], $handledServerRequest),
        ]);

        /** @var ResponseFactoryInterface $responseFactory */
        $responseFactory = $builder->create(ResponseFactoryInterface::class, []);

        /** @var TokenExtractorInterface $tokenExtractor */
        $tokenExtractor = $builder->create(TokenExtractorInterface::class, [
            new WithReturn('extract', [$serverRequest], 'token-1'),
        ]);

        /** @var TokenVerifierInterface $tokenVerifier */
        $tokenVerifier = $builder->create(TokenVerifierInterface::class, [
            new WithReturn('verify', ['token-1'], $claims),
        ]);

        /** @var RequestHandlerInterface $handler */
        $handler = $builder->create(RequestHandlerInterface::class, [
            new WithException('handle', [$handledServerRequest], $error),
        ]);

        /** @var LoggerInterface $logger */
        $logger = $builder->create(LoggerInterface::class, []);

        $middleware = new OidcAuthenticationMiddleware(
            $responseFactory,
            $tokenExtractor,
            $tokenVerifier,
            'api',
            $logger
        );

        try {
            $middleware->process($serverRequest, $handler);

            self::fail('Expected exception not thrown');
        } catch (InvalidTokenException $caught) {
            self::assertSame($error, $caught);
        }
    }
}
