<?php

declare(strict_types=1);

// the api call as seen by this library, shared by all flows: the client sends the access token as bearer token, the
// backend verifies it against the auth provider and either calls the handler or rejects the request

namespace Chubbyphp\Oidc\Resources\Flow;

require_once __DIR__.'/diagram.php';

const OIDC_CORE = 'https://openid.net/specs/openid-connect-core-1_0.html';

const SPEC = [
    'OpenID Connect Core 1.0' => OIDC_CORE,
    'OIDC Core 1.0 §3.1' => OIDC_CORE.'#CodeFlowAuth',
    'OIDC Core 1.0 §3.1.3.7' => OIDC_CORE.'#IDTokenValidation',
    'OpenID Connect Discovery 1.0' => 'https://openid.net/specs/openid-connect-discovery-1_0.html',
    'OpenID Connect RP-Initiated Logout 1.0' => 'https://openid.net/specs/openid-connect-rpinitiated-1_0.html',
    'RFC 6749' => 'https://www.rfc-editor.org/rfc/rfc6749',
    'RFC 6749 §4.4' => 'https://www.rfc-editor.org/rfc/rfc6749#section-4.4',
    'RFC 6750' => 'https://www.rfc-editor.org/rfc/rfc6750',
    'RFC 7517' => 'https://www.rfc-editor.org/rfc/rfc7517',
    'RFC 7519' => 'https://www.rfc-editor.org/rfc/rfc7519',
    'RFC 7523' => 'https://www.rfc-editor.org/rfc/rfc7523',
    'RFC 7636' => 'https://www.rfc-editor.org/rfc/rfc7636',
    'RFC 8705' => 'https://www.rfc-editor.org/rfc/rfc8705',
    'RFC 9068' => 'https://www.rfc-editor.org/rfc/rfc9068',
    'RFC 9700' => 'https://www.rfc-editor.org/rfc/rfc9700',
    'OAuth 2.0 for Browser-Based Apps' => 'https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/',
];

/**
 * @param key-of<SPEC>                                    $name
 * @param array{mono?: bool, bold?: bool, color?: string} $style
 *
 * @return FlowSegment
 */
function spec(string $name, array $style = []): array
{
    return link($name, SPEC[$name], $style);
}

const SOURCE = 'https://github.com/chubbyphp/chubbyphp-oidc/tree/master/src';

/**
 * a namespace of this library, linked to its source.
 *
 * @param 'Discovery'|'Jwks'|'Middleware'|'ServiceFactory'|'Token' $name
 *
 * @return FlowSegment
 */
function src(string $name, string $prefix = ''): array
{
    return link($prefix.'src/'.$name, SOURCE.'/'.$name, ['color' => muted('')['color']]);
}

/**
 * @return FlowSegment
 */
function jwtLibrary(): array
{
    return link('jwt-library', 'https://github.com/web-token/jwt-library');
}

/**
 * @return FlowSegment
 */
function keycloak(): array
{
    return link('Keycloak', 'https://www.keycloak.org');
}

/**
 * @return FlowParticipant
 */
function backend(): array
{
    return [
        'id' => 'be',
        'color' => 'green',
        'title' => 'Backend (BE)',
        'subtitle' => 'API · OAuth 2.0 Resource Server · this library',
        'bullets' => [
            ['extracts the Bearer token from the ', m('Authorization'), ' header'],
            'resolves the discovery document, fetches and caches the JWKS',
            [
                'verifies signature, ',
                m('iss'),
                ', ',
                m('aud'),
                ', ',
                m('exp'),
                ', ',
                m('nbf'),
                ' (+ ',
                m('typ'),
                ', required claims)',
            ],
            ['responds 401 + ', m('WWW-Authenticate'), ', or passes the claims on'],
            'stateless: no session, no client secret, never sees a password',
        ],
    ];
}

/**
 * @return list<FlowLine>
 */
function discoveryBullets(): array
{
    return [
        'signs the tokens with its private key (RS256, ES256, ...)',
        ['publishes ', m('/.well-known/openid-configuration'), ' (discovery)'],
        ['publishes its public keys at the ', m('jwks_uri'), ' (JWKS)'],
    ];
}

/**
 * @param list<FlowLine> $request
 *
 * @return list<FlowItem>
 */
function apiCall(string $client, string $op, array $request): array
{
    return [
        ['kind' => 'arrow', 'from' => $client, 'to' => backend()['id'], 'lines' => $request],
        [
            'kind' => 'note',
            'lane' => backend()['id'],
            'lines' => [
                [b('new OidcAuthenticationMiddleware'), '(responseFactory, extractor, verifier, realm, logger)'],
                [src('Middleware'), ' · or via the service factories in ', src('ServiceFactory')],
                [b('new BearerTokenExtractor()'), src('Token', '  ')],
                ['reads the ', m('Authorization'), ' header: ', m('/^Bearer +(\S+)$/i'), ' → token'],
            ],
        ],
        [
            'kind' => 'note',
            'lane' => backend()['id'],
            'lines' => [[b('no token')], ['401 ', m('WWW-Authenticate: Bearer realm="api"'), ' · the handler is not called']],
            'error' => true,
        ],
        [
            'kind' => 'note',
            'lane' => backend()['id'],
            'lines' => [
                [b('new JwtTokenVerifier'), '(resolver, jwkSet, audience, ...)', src('Token', '   ')],
                ['asks the ', m('OidcConfigurationResolver'), ' first, lazily on the first token'],
            ],
        ],
        [
            'kind' => 'arrow',
            'from' => backend()['id'],
            'to' => $op,
            'lines' => [
                ['GET ', m('{issuer}/.well-known/openid-configuration')],
                [muted('cached for maxAge (1h), timeout / no redirects: PSR-18 client · mostly served from the cache')],
            ],
        ],
        [
            'kind' => 'arrow',
            'from' => $op,
            'to' => backend()['id'],
            'lines' => [['200 ', m('{ issuer, jwks_uri, authorization_endpoint, token_endpoint, ... }')]],
            'response' => true,
        ],
        [
            'kind' => 'note',
            'lane' => backend()['id'],
            'lines' => [
                [b('new OidcConfigurationResolver'), '(issuer, client, requestFactory)', src('Discovery', '   ')],
                [m('issuer'), ' must be exactly the configured one (trailing slash!)'],
                [m('jwks_uri'), ' must be http(s), and https if the issuer is https'],
                ['outage: last known configuration, retry after ', m('cooldown'), ' (30s)'],
                [rm('OidcConfigurationException'), r(' (never fetched) → rethrown → 5xx')],
            ],
        ],
        [
            'kind' => 'arrow',
            'from' => backend()['id'],
            'to' => $op,
            'lines' => [
                ['GET ', m('jwks_uri')],
                [muted('cached by the RemoteJwkSet for its maxAge (10min)')],
                [muted('unknown kid (key rotation) → refetch, max. once per its cooldown (30s)')],
            ],
        ],
        [
            'kind' => 'arrow',
            'from' => $op,
            'to' => backend()['id'],
            'lines' => [['200 ', m('{ keys: [ { kid, kty, alg, use, n, e }, ... ] }'), '  public keys only']],
            'response' => true,
        ],
        [
            'kind' => 'note',
            'lane' => backend()['id'],
            'lines' => [
                [b('verify the JWT'), ' with ', jwtLibrary()],
                [m('JWSVerifier'), ', header and claim checkers'],
                ['signature with the key named by the ', m('kid'), ' header (', m('RemoteJwkSet'), ')', src('Jwks', '  ')],
                ['asymmetric algorithms only, never ', m('HS*'), ' (', m('SUPPORTED_ALGORITHMS'), ')'],
                [m('iss'), ' == configuration.issuer · ', m('aud'), ' contains ', m('audience')],
                [
                    m('exp'),
                    ' and ',
                    m('nbf'),
                    ' (± ',
                    m('clockTolerance'),
                    ') · ',
                    m('typ'),
                    ' (e.g. ',
                    m('at+jwt'),
                    ') · ',
                    m('requiredClaims'),
                ],
                ['JWKS outage: last known keys for ', m('maxStale'), ' (1h),'],
                ['then ', rm('JwksException'), r(' → rethrown → 5xx')],
            ],
        ],
        [
            'kind' => 'note',
            'lane' => backend()['id'],
            'lines' => [
                [b('invalid token')],
                ['expired, wrong signature / ', m('iss'), ' / ', m('aud'), ', unknown ', m('kid'), ', ...'],
                ['→ ', m('InvalidTokenException'), ' (a custom ', m('TokenVerifierInterface'), ' throws it too)'],
                [
                    '401 ',
                    m(
                        'WWW-Authenticate: Bearer realm="api", error="invalid_token", error_description="The access token is invalid or expired"',
                    ),
                ],
                ['the real reason is only logged (level ', m('info'), '), never sent to the client'],
            ],
            'error' => true,
        ],
        [
            'kind' => 'note',
            'lane' => backend()['id'],
            'lines' => [
                [b('valid token → handler')],
                [m('$request->getAttribute(\'oidc\') =')],
                [m('[\'token\' => …, \'claims\' => […]]')],
                ['authorization (roles, ', m('scope'), ', ownership) is up to the handler'],
                [m('token'), ' can be forwarded to downstream APIs, treat it as sensitive'],
            ],
        ],
        [
            'kind' => 'arrow',
            'from' => backend()['id'],
            'to' => $client,
            'lines' => [
                ['200 ', m('{ ... }'), '  ·  or 401 with the challenge above (expose ', m('WWW-Authenticate'), ' via CORS)'],
            ],
            'response' => true,
        ],
    ];
}

const COMMON_SPECS = [
    ['OpenID Connect Core 1.0', ''],
    ['OpenID Connect Discovery 1.0', ''],
    ['RFC 6749', 'OAuth 2.0'],
    ['RFC 6750', 'Bearer'],
    ['RFC 7517', 'JWK'],
    ['RFC 7519', 'JWT'],
    ['RFC 9068', 'JWT access tokens'],
];

/**
 * the specs line of the legend: the common ones plus the flow specific ones, each name linked.
 *
 * @param array{0: key-of<SPEC>, 1: string} ...$additional
 *
 * @return list<FlowSegment|string>
 */
function specs(array ...$additional): array
{
    $line = ['Specs: '];

    foreach ([...COMMON_SPECS, ...$additional] as $i => [$name, $topic]) {
        if ($i > 0) {
            $line[] = ', ';
        }

        $line[] = spec($name);

        if ('' !== $topic) {
            $line[] = ' ('.$topic.')';
        }
    }

    return $line;
}
