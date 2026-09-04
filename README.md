# chubbyphp-oidc

[![CI](https://github.com/chubbyphp/chubbyphp-oidc/actions/workflows/ci.yml/badge.svg)](https://github.com/chubbyphp/chubbyphp-oidc/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/chubbyphp/chubbyphp-oidc/badge.svg?branch=master)](https://coveralls.io/github/chubbyphp/chubbyphp-oidc?branch=master)
[![Mutation testing badge](https://img.shields.io/endpoint?style=flat&url=https%3A%2F%2Fbadge-api.stryker-mutator.io%2Fgithub.com%2Fchubbyphp%2Fchubbyphp-oidc%2Fmaster)](https://dashboard.stryker-mutator.io/reports/github.com/chubbyphp/chubbyphp-oidc/master)
[![Latest Stable Version](https://poser.pugx.org/chubbyphp/chubbyphp-oidc/v)](https://packagist.org/packages/chubbyphp/chubbyphp-oidc)
[![Total Downloads](https://poser.pugx.org/chubbyphp/chubbyphp-oidc/downloads)](https://packagist.org/packages/chubbyphp/chubbyphp-oidc)
[![Monthly Downloads](https://poser.pugx.org/chubbyphp/chubbyphp-oidc/d/monthly)](https://packagist.org/packages/chubbyphp/chubbyphp-oidc)

[![bugs](https://sonarcloud.io/api/project_badges/measure?project=chubbyphp_chubbyphp-oidc&metric=bugs)](https://sonarcloud.io/dashboard?id=chubbyphp_chubbyphp-oidc)
[![code_smells](https://sonarcloud.io/api/project_badges/measure?project=chubbyphp_chubbyphp-oidc&metric=code_smells)](https://sonarcloud.io/dashboard?id=chubbyphp_chubbyphp-oidc)
[![coverage](https://sonarcloud.io/api/project_badges/measure?project=chubbyphp_chubbyphp-oidc&metric=coverage)](https://sonarcloud.io/dashboard?id=chubbyphp_chubbyphp-oidc)
[![duplicated_lines_density](https://sonarcloud.io/api/project_badges/measure?project=chubbyphp_chubbyphp-oidc&metric=duplicated_lines_density)](https://sonarcloud.io/dashboard?id=chubbyphp_chubbyphp-oidc)
[![ncloc](https://sonarcloud.io/api/project_badges/measure?project=chubbyphp_chubbyphp-oidc&metric=ncloc)](https://sonarcloud.io/dashboard?id=chubbyphp_chubbyphp-oidc)
[![sqale_rating](https://sonarcloud.io/api/project_badges/measure?project=chubbyphp_chubbyphp-oidc&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=chubbyphp_chubbyphp-oidc)
[![alert_status](https://sonarcloud.io/api/project_badges/measure?project=chubbyphp_chubbyphp-oidc&metric=alert_status)](https://sonarcloud.io/dashboard?id=chubbyphp_chubbyphp-oidc)
[![reliability_rating](https://sonarcloud.io/api/project_badges/measure?project=chubbyphp_chubbyphp-oidc&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=chubbyphp_chubbyphp-oidc)
[![security_rating](https://sonarcloud.io/api/project_badges/measure?project=chubbyphp_chubbyphp-oidc&metric=security_rating)](https://sonarcloud.io/dashboard?id=chubbyphp_chubbyphp-oidc)
[![sqale_index](https://sonarcloud.io/api/project_badges/measure?project=chubbyphp_chubbyphp-oidc&metric=sqale_index)](https://sonarcloud.io/dashboard?id=chubbyphp_chubbyphp-oidc)
[![vulnerabilities](https://sonarcloud.io/api/project_badges/measure?project=chubbyphp_chubbyphp-oidc&metric=vulnerabilities)](https://sonarcloud.io/dashboard?id=chubbyphp_chubbyphp-oidc)


## Description

A minimal OIDC (OpenID Connect) resource server middleware for [PSR 15][5]: resolves the issuer's
[openid configuration](https://openid.net/specs/openid-connect-discovery-1_0.html), verifies JWT bearer tokens
against its [JWKS](https://www.rfc-editor.org/rfc/rfc7517) and passes the verified claims to the handler via
request attributes.

## Requirements

 * php: ^8.3
 * [psr/clock][2]: ^1.0
 * [psr/http-client][3]: ^1.0.3
 * [psr/http-factory][4]: ^1.1
 * [psr/http-message][5]: ^1.1|^2.0
 * [psr/http-server-middleware][6]: ^1.0.2
 * [psr/log][7]: ^3.0.2
 * [web-token/jwt-library][8]: ^4.2.2

## Installation

Through [Composer](http://getcomposer.org) as [chubbyphp/chubbyphp-oidc][1].

```sh
composer require chubbyphp/chubbyphp-oidc "^1.1"
```

## Usage

```php
<?php

use Chubbyphp\Oidc\Discovery\OidcConfigurationResolver;
use Chubbyphp\Oidc\Jwks\RemoteJwkSet;
use Chubbyphp\Oidc\Middleware\OidcAuthenticationMiddleware;
use Chubbyphp\Oidc\Token\BearerTokenExtractor;
use Chubbyphp\Oidc\Token\JwtTokenVerifier;
use GuzzleHttp\Client as HttpClient;
use Slim\Psr7\Factory\RequestFactory;
use Slim\Psr7\Factory\ResponseFactory;
use Slim\Psr7\Factory\ServerRequestFactory;

$client = new HttpClient(['timeout' => 5, 'allow_redirects' => false]); // any PSR-18 client
$requestFactory = new RequestFactory(); // any PSR-17 request factory
$responseFactory = new ResponseFactory(); // any PSR-17 response factory

$oidcAuthenticationMiddleware = new OidcAuthenticationMiddleware(
    $responseFactory,
    new BearerTokenExtractor(),
    new JwtTokenVerifier(
        new OidcConfigurationResolver('https://issuer.example.com', $client, $requestFactory),
        new RemoteJwkSet($client, $requestFactory),
        'https://api.example.com'
    ),
    'api'
);

// add the middleware to the routes you want to protect

$request = (new ServerRequestFactory())->createServerRequest('GET', 'https://api.example.com/pets');

$response = $oidcAuthenticationMiddleware->process($request, $handler);
```

Within the handler:

```php
<?php

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class Handler implements RequestHandlerInterface
{
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        // the middleware guarantees the "oidc" attribute for every handler behind it
        /** @var array{token: string, claims: array<string, mixed>} $oidc */
        $oidc = $request->getAttribute('oidc');

        $sub = $oidc['claims']['sub'] ?? null;

        ...
    }
}
```

 * **Audience:** `audience` is required and must match the `aud` claim your authorization server puts into access
   tokens for your API, otherwise any token of the issuer (even for other APIs, or ID tokens) would be accepted.
   If your server issues [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) access tokens (`typ: at+jwt` header),
   pass `typ: 'at+jwt'` too.
 * **Rejected requests:** Without a valid token the handler is not called and a `401` with a
   [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) challenge is returned:
   `WWW-Authenticate: Bearer realm="api"` (missing token) or
   `Bearer realm="api", error="invalid_token", error_description="The access token is invalid or expired"`
   (invalid token). The actual reason (expired, wrong signature, ...) is only logged (level `info`) via the
   optional logger, never sent to the client. Errors not related to the token (unreachable issuer, ...) are
   rethrown, so your error handling responds with a `5xx`.
 * **Browser clients:** Allow the `Authorization` request header and expose the `WWW-Authenticate` response header
   within your cors configuration (see [chubbyphp/chubbyphp-cors](https://packagist.org/packages/chubbyphp/chubbyphp-cors)).
 * **Token in the request attribute:** The `oidc` attribute carries the raw bearer token (`token`) next to the
   verified `claims`, so that handlers can forward it to downstream apis. Treat the attribute as sensitive: do
   not dump the request attributes into logs, error reports or responses.

### Options

```php
<?php

use Chubbyphp\Oidc\Clock\SystemClock;
use Chubbyphp\Oidc\Discovery\OidcConfigurationResolver;
use Chubbyphp\Oidc\Jwks\RemoteJwkSet;
use Chubbyphp\Oidc\Middleware\OidcAuthenticationMiddleware;
use Chubbyphp\Oidc\Token\BearerTokenExtractor;
use Chubbyphp\Oidc\Token\JwtTokenVerifier;

// resolves and caches {issuer}/.well-known/openid-configuration, lazily on first token verification
$oidcConfigurationResolver = new OidcConfigurationResolver(
    'https://issuer.example.com',
    $client, // any PSR-18 client, required
    $requestFactory, // any PSR-17 request factory, required
    maxAge: 3600, // seconds a resolved configuration is cached (non-negative), default: 3600
    cooldown: 30, // seconds until a failed (re)fetch is retried (non-negative), default: 30
    allowInsecureIssuer: false, // accept a plain http issuer (local development only), default: false
    clock: new SystemClock(), // any PSR-20 clock, default: SystemClock
);

// fetches and caches the jwks of the resolved jwks_uri, lazily on first token verification
$remoteJwkSet = new RemoteJwkSet(
    $client, // any PSR-18 client, required
    $requestFactory, // any PSR-17 request factory, required
    maxAge: 600, // seconds a fetched jwks is cached (non-negative), default: 600
    cooldown: 30, // seconds until a failed jwks (re)fetch is retried, and between refetches for unknown key ids
    // (non-negative), default: 30
    maxStale: 86400, // seconds an expired jwks keeps being used while its refetch fails (non-negative, 0: never,
    // null: for as long as the outage lasts), default: 3600
);

// verifies signature (via the issuer's JWKS), "iss", "aud", "exp", "nbf" and returns the claims
$tokenVerifier = new JwtTokenVerifier(
    $oidcConfigurationResolver,
    $remoteJwkSet,
    audience: 'https://api.example.com', // string | array<string>, required (non-empty, enforced at runtime)
    algorithms: ['RS256'], // non-empty subset of RemoteJwkSet::SUPPORTED_ALGORITHMS (keys), default: all of them
    clockTolerance: 5, // seconds (non-negative), default: 0
    typ: 'at+jwt', // expected "typ" header, default: not checked
    requiredClaims: ['sub', 'iat', 'jti'], // additionally required claims, "iss", "aud" and "exp" always are
    clock: new SystemClock(), // any PSR-20 clock, default: SystemClock
);

$oidcAuthenticationMiddleware = new OidcAuthenticationMiddleware(
    $responseFactory, // any PSR-17 response factory, required
    new BearerTokenExtractor(), // reads the "Authorization: Bearer <token>" header
    $tokenVerifier,
    'api', // realm within the challenge, optional
    $logger, // PSR-3 compatible logger, optional, default: no-op (NullLogger)
);
```

 * **Issuer:** Must be exactly the `issuer` from the openid configuration (`iss` claim),
   `https://issuer.example.com` and `https://issuer.example.com/` are not the same. Only absolute `https` urls
   are accepted by default: whoever can tamper with an unprotected discovery or jwks response can forge tokens
   your api accepts. A plain `http` issuer is only meant for local development and has to be opted in explicitly
   with `allowInsecureIssuer: true`, so an insecure deployment is a deliberate decision and not a copied
   example. A `https` issuer advertising a plain `http` `jwks_uri` is rejected in any case.
 * **HTTP client:** PSR-18 has no per-request timeout concept, configure connect/request timeouts on your HTTP
   client (e.g. `new GuzzleHttp\Client(['timeout' => 5, 'connect_timeout' => 2])`). The `https` checks above
   apply to the configured issuer and the advertised `jwks_uri` only: a client following redirects on its own
   would silently follow a `https` → `http` redirect of the discovery or jwks fetch. Neither endpoint should
   redirect, so disable redirects (Guzzle: `'allow_redirects' => false`) or restrict them to `https` (Guzzle:
   `'allow_redirects' => ['protocols' => ['https']]`).
 * **Algorithms:** Only asymmetric signature algorithms are supported
   (`EdDSA`, `ES256`, `ES384`, `ES512`, `PS256`, `PS384`, `PS512`, `RS256`, `RS384`, `RS512`): a public (jwks)
   key must never be usable as a hmac secret (algorithm confusion). Anything else, including `HS*`, is rejected
   at construction time.
 * **JWKS:** Fetched (by the `RemoteJwkSet`) from the `jwks_uri` of the openid configuration and cached in memory
   for its `maxAge`, an unknown key id (key rotation) triggers a refetch, but at most once per its `cooldown`.
 * **Outages:** If the issuer is unreachable while the cached configuration or jwks is expired, the last known one
   keeps being used (a refetch is retried after the respective `cooldown`), so a temporary issuer outage does
   not take your api down. Only if there never was a successful fetch the error is thrown (`5xx`), within the
   cooldown immediately without hitting the issuer again. Be aware that a stale jwks still contains keys the
   issuer removed in the meantime (e.g. a compromised one), so tokens signed with them stay valid while the stale
   jwks is used: the `maxStale` of the `RemoteJwkSet` bounds this window (default: one hour, after
   `maxAge + maxStale` since the last successful fetch, verification fails with the last jwks error until a
   refetch succeeds), `0` disables serving a stale jwks altogether, `null` keeps using it for as long as the
   outage lasts. An invalid discovery / jwks response is reported as
   `Chubbyphp\Oidc\Exception\OidcConfigurationException` / `Chubbyphp\Oidc\Exception\JwksException`. In a
   classic php-fpm setup the in-memory cache lives per request; use a long-running runtime (roadrunner, swoole,
   workerman, frankenphp) to benefit from it.
 * **Clock:** Every time based check (`exp`, `nbf`, configuration and jwks cache expiry) uses the injected PSR-20
   clock, which defaults to `Chubbyphp\Oidc\Clock\SystemClock`.
 * **Custom verifier:** A `TokenVerifierInterface` is just `verify(string $token): array`. Throw an
   `InvalidTokenException` (`Chubbyphp\Oidc\Exception\InvalidTokenException`) to get the `401` response, any
   other error is rethrown.

### Service factories (laminas-config)

The package ships [chubbyphp-laminas-config](https://packagist.org/packages/chubbyphp/chubbyphp-laminas-config)
factories within `Chubbyphp\Oidc\ServiceFactory`:

```php
<?php

use Chubbyphp\Oidc\Middleware\OidcAuthenticationMiddleware;
use Chubbyphp\Oidc\ServiceFactory\OidcAuthenticationMiddlewareFactory;

return [
    'chubbyphp' => [
        'oidc' => [
            'issuer' => 'https://issuer.example.com', // required
            'audience' => 'https://api.example.com', // required
            'realm' => 'api',
            // 'maxAge' => 3600,
            // 'cooldown' => 30,
            // 'allowInsecureIssuer' => false,
            // 'algorithms' => ['RS256'],
            // 'clockTolerance' => 5,
            // 'typ' => 'at+jwt',
            // 'requiredClaims' => ['sub', 'iat', 'jti'],
            // 'jwksMaxAge' => 600,
            // 'jwksCooldown' => 30,
            // 'jwksMaxStale' => 86400,
        ],
    ],
    'dependencies' => [
        'factories' => [
            OidcAuthenticationMiddleware::class => OidcAuthenticationMiddlewareFactory::class,
        ],
    ],
];
```

The container has to provide `Psr\Http\Client\ClientInterface`, `Psr\Http\Message\RequestFactoryInterface` and
`Psr\Http\Message\ResponseFactoryInterface` (`Psr\Log\LoggerInterface` is optional).

## Testing against a local OIDC provider

[Keycloak](https://www.keycloak.org) as a docker container is the easiest way to test manually:

```sh
docker run --rm -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.7 start-dev
```

Within the admin console at [http://localhost:8080](http://localhost:8080) (admin/admin) create a realm `test`
and a client `api` with *Client authentication* and *Service accounts roles* enabled, then:

```sh
curl -X POST http://localhost:8080/realms/test/protocol/openid-connect/token \
  -d grant_type=client_credentials -d client_id=api -d client_secret=<client-secret>
```

```php
// plain http is only accepted with the explicit opt-in, never do this in production
$oidcConfigurationResolver = new OidcConfigurationResolver(
    'http://localhost:8080/realms/test',
    $client,
    $requestFactory,
    allowInsecureIssuer: true
);
```

Keycloak specifics: access tokens contain `aud: "account"` until you add an *audience mapper*, have the header
`typ: "JWT"` (not `at+jwt`) and the `iss` claim matches the URL the token was requested through, so use the same
host for the resolver and the token request (or pin it, e.g. `KC_HOSTNAME=http://keycloak:8080` in docker
compose).

For automated tests [mock-oauth2-server](https://github.com/navikt/mock-oauth2-server) is a lightweight
alternative which issues tokens without any setup. This repository's integration tests start it via
[testcontainers](https://packagist.org/packages/testcontainers/testcontainers) (docker compatible daemon
required, set `MOCK_OAUTH2_SERVER_URL` to reuse a running one):

```sh
composer test:integration
```

This works on a machine with php and docker as well as within a container which has the docker socket mounted
(the ci runs `composer test` within a docker image): if the tests themselves run within a container, the
mock-oauth2-server joins the docker network of that container and is used through its container ip instead of a
port published on the docker host.

## Copyright

2026 Dominik Zogg

[1]: https://packagist.org/packages/chubbyphp/chubbyphp-oidc

[2]: https://packagist.org/packages/psr/clock
[3]: https://packagist.org/packages/psr/http-client
[4]: https://packagist.org/packages/psr/http-factory
[5]: https://packagist.org/packages/psr/http-message
[6]: https://packagist.org/packages/psr/http-server-middleware
[7]: https://packagist.org/packages/psr/log
[8]: https://packagist.org/packages/web-token/jwt-library
