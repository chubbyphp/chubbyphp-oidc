<?php

declare(strict_types=1);

namespace Chubbyphp\Tests\Oidc\Integration;

use Chubbyphp\Oidc\Discovery\OidcConfigurationResolver;
use Chubbyphp\Oidc\Jwks\RemoteJwkSet;
use Chubbyphp\Oidc\Middleware\OidcAuthenticationMiddleware;
use Chubbyphp\Oidc\Token\BearerTokenExtractor;
use Chubbyphp\Oidc\Token\JwtTokenVerifier;
use Chubbyphp\Tests\Oidc\MockOAuth2ServerExtension;
use GuzzleHttp\Client as HttpClient;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Factory\RequestFactory;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\ServerRequestFactory;
use Slim\Psr7\Response;

/**
 * @coversNothing
 *
 * @internal
 */
final class OidcAuthenticationMiddlewareTest extends TestCase
{
    private static string $issuer;

    public static function setUpBeforeClass(): void
    {
        // resolved by the MockOAuth2ServerExtension registered within phpunit.integration.xml
        $serverUrl = getenv(MockOAuth2ServerExtension::ENV_MOCK_OAUTH2_SERVER_URL);

        if (false === $serverUrl || '' === $serverUrl) {
            self::markTestSkipped(
                'A docker compatible daemon is required for the integration tests'
                .' (or set MOCK_OAUTH2_SERVER_URL to a running mock-oauth2-server)'
            );
        }

        self::$issuer = $serverUrl.'/default';
    }

    public function testWithoutToken(): void
    {
        $request = (new ServerRequestFactory())->createServerRequest('GET', 'https://api.example.com/resource');

        $response = $this->createMiddleware(['audience' => 'https://api.example.com'])
            ->process($request, $this->createHandler())
        ;

        self::assertSame(401, $response->getStatusCode());
        self::assertSame('Bearer realm="api"', $response->getHeaderLine('WWW-Authenticate'));
    }

    public function testWithInvalidToken(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://api.example.com/resource')
            ->withHeader('authorization', 'Bearer invalid-token')
        ;

        $response = $this->createMiddleware(['audience' => 'https://api.example.com'])
            ->process($request, $this->createHandler())
        ;

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(
            'Bearer realm="api", error="invalid_token",'
                .' error_description="The access token is invalid or expired"',
            $response->getHeaderLine('WWW-Authenticate')
        );
    }

    public function testWithValidToken(): void
    {
        $client = $this->createClient();
        $issuer = $this->getIssuer();

        $accessToken = $this->fetchAccessToken($client, $issuer);

        /** @var array<string>|string $aud */
        $aud = self::decodeTokenPart($accessToken, 1)['aud'] ?? '';

        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://api.example.com/resource')
            ->withHeader('authorization', 'Bearer '.$accessToken)
        ;

        $response = $this->createMiddleware(['audience' => $aud])
            ->process($request, $this->createHandler())
        ;

        self::assertSame(200, $response->getStatusCode());

        /** @var array{token: string, claims: array<string, mixed>} $oidc */
        $oidc = json_decode((string) $response->getBody(), true);

        self::assertSame($accessToken, $oidc['token']);
        self::assertSame($issuer, $oidc['claims']['iss']);
        self::assertSame('api', $oidc['claims']['sub']);
    }

    public function testWithValidTokenAndMatchingTyp(): void
    {
        $client = $this->createClient();
        $issuer = $this->getIssuer();

        $accessToken = $this->fetchAccessToken($client, $issuer);

        /** @var string $typ */
        $typ = self::decodeTokenPart($accessToken, 0)['typ'] ?? '';

        /** @var array<string>|string $aud */
        $aud = self::decodeTokenPart($accessToken, 1)['aud'] ?? '';

        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://api.example.com/resource')
            ->withHeader('authorization', 'Bearer '.$accessToken)
        ;

        $response = $this->createMiddleware(['audience' => $aud, 'typ' => $typ])
            ->process($request, $this->createHandler())
        ;

        self::assertSame(200, $response->getStatusCode());
    }

    public function testWithValidTokenAndWrongTyp(): void
    {
        $client = $this->createClient();
        $issuer = $this->getIssuer();

        $accessToken = $this->fetchAccessToken($client, $issuer);

        /** @var array<string>|string $aud */
        $aud = self::decodeTokenPart($accessToken, 1)['aud'] ?? '';

        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://api.example.com/resource')
            ->withHeader('authorization', 'Bearer '.$accessToken)
        ;

        $response = $this->createMiddleware(['audience' => $aud, 'typ' => 'other+jwt'])
            ->process($request, $this->createHandler())
        ;

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(
            'Bearer realm="api", error="invalid_token",'
                .' error_description="The access token is invalid or expired"',
            $response->getHeaderLine('WWW-Authenticate')
        );
    }

    public function testWithValidTokenAndWrongAudience(): void
    {
        $client = $this->createClient();
        $issuer = $this->getIssuer();

        $accessToken = $this->fetchAccessToken($client, $issuer);

        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://api.example.com/resource')
            ->withHeader('authorization', 'Bearer '.$accessToken)
        ;

        $response = $this->createMiddleware(['audience' => 'https://other-api.example.com'])
            ->process($request, $this->createHandler())
        ;

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(
            'Bearer realm="api", error="invalid_token",'
                .' error_description="The access token is invalid or expired"',
            $response->getHeaderLine('WWW-Authenticate')
        );
    }

    /**
     * @param array{audience: array<string>|string, typ?: string} $options
     */
    private function createMiddleware(array $options): OidcAuthenticationMiddleware
    {
        $client = $this->createClient();
        $requestFactory = new RequestFactory();

        return new OidcAuthenticationMiddleware(
            new ResponseFactory(),
            new BearerTokenExtractor(),
            new JwtTokenVerifier(
                // mock-oauth2-server is plain http
                new OidcConfigurationResolver($this->getIssuer(), $client, $requestFactory, allowInsecureIssuer: true),
                new RemoteJwkSet($client, $requestFactory),
                $options['audience'],
                typ: $options['typ'] ?? null
            ),
            'api'
        );
    }

    private function createHandler(): RequestHandlerInterface
    {
        return new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $response = new Response();
                $response->getBody()->write((string) json_encode($request->getAttribute('oidc')));

                return $response->withHeader('content-type', 'application/json');
            }
        };
    }

    private function getIssuer(): string
    {
        return self::$issuer;
    }

    private function createClient(): HttpClient
    {
        return new HttpClient(['timeout' => 5, 'connect_timeout' => 2, 'allow_redirects' => false]);
    }

    private function fetchAccessToken(HttpClient $client, string $issuer): string
    {
        $response = $client->post($issuer.'/token', [
            'form_params' => [
                'grant_type' => 'client_credentials',
                'client_id' => 'api',
                'client_secret' => 'api-secret',
            ],
        ]);

        self::assertSame(200, $response->getStatusCode());

        /** @var array{access_token: string} $data */
        $data = json_decode((string) $response->getBody(), true);

        return $data['access_token'];
    }

    /**
     * @return array<string, mixed>
     */
    private static function decodeTokenPart(string $token, int $index): array
    {
        $parts = explode('.', $token);

        /** @var null|array<string, mixed> $part */
        $part = json_decode((string) base64_decode(strtr($parts[$index], '-_', '+/'), true), true);

        return $part ?? [];
    }
}
