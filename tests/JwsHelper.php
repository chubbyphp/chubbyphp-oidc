<?php

declare(strict_types=1);

namespace Chubbyphp\Tests\Oidc;

use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\MacAlgorithm;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;

/**
 * Generates key pairs and signs tokens without any header validation, so that malformed tokens can be tested too.
 *
 * @internal
 */
final class JwsHelper
{
    private const EC_CURVES = [
        'ES256' => ['prime256v1', 'P-256', 32],
        'ES384' => ['secp384r1', 'P-384', 48],
        'ES512' => ['secp521r1', 'P-521', 66],
    ];

    /**
     * @var array<string, array{JWK, array<string, mixed>}>
     */
    private static array $keyPairs = [];

    /**
     * Key generation (especially rsa) is expensive and the tests do not depend on unique key material: the key pair
     * of an algorithm and name gets generated once per process and is reused, so use different names where a test
     * needs different keys.
     *
     * @return array{JWK, array<string, mixed>} the private jwk (signing) and the public jwk data (jwks entry)
     */
    public static function keyPair(string $alg = 'RS256', string $name = 'key-1'): array
    {
        return self::$keyPairs[self::keyFamily($alg).'/'.$name] ??= self::generateKeyPair($alg);
    }

    /**
     * @param array<string, mixed>|string $payload         claims (json encoded) or a raw payload
     * @param array<string, mixed>        $protectedHeader
     * @param null|string                 $alg             the algorithm to sign with, default: the "alg" header
     */
    public static function sign(
        array|string $payload,
        JWK $privateJwk,
        array $protectedHeader,
        ?string $alg = null,
    ): string {
        $encodedProtectedHeader = Base64UrlSafe::encodeUnpadded((string) json_encode($protectedHeader));
        $encodedPayload = Base64UrlSafe::encodeUnpadded(\is_array($payload) ? (string) json_encode($payload) : $payload);

        $input = $encodedProtectedHeader.'.'.$encodedPayload;

        $algorithm = self::createAlgorithm($alg ?? (string) $protectedHeader['alg']);

        $signature = $algorithm instanceof MacAlgorithm
            ? $algorithm->hash($privateJwk, $input)
            : $algorithm->sign($privateJwk, $input);

        return $input.'.'.Base64UrlSafe::encodeUnpadded($signature);
    }

    /**
     * @param array<string, mixed>        $protectedHeader
     * @param array<string, mixed>|string $payload
     */
    public static function encodeUnsigned(array $protectedHeader, array|string $payload): string
    {
        return Base64UrlSafe::encodeUnpadded((string) json_encode($protectedHeader))
            .'.'.Base64UrlSafe::encodeUnpadded(\is_array($payload) ? (string) json_encode($payload) : $payload)
            .'.'.Base64UrlSafe::encodeUnpadded('signature');
    }

    /**
     * All rsa based algorithms (RS*, PS*) can share the same key material, the others need their own curve.
     */
    private static function keyFamily(string $alg): string
    {
        return match ($alg) {
            'ES256', 'ES384', 'ES512', 'EdDSA' => $alg,
            default => 'RSA',
        };
    }

    /**
     * @return array{JWK, array<string, mixed>}
     */
    private static function generateKeyPair(string $alg): array
    {
        return match ($alg) {
            'ES256', 'ES384', 'ES512' => self::generateEcKeyPair($alg),
            'EdDSA' => self::generateOkpKeyPair(),
            default => self::generateRsaKeyPair(),
        };
    }

    private static function createAlgorithm(string $alg): MacAlgorithm|SignatureAlgorithm
    {
        return match ($alg) {
            'EdDSA' => new EdDSA(),
            'ES256' => new ES256(),
            'ES384' => new ES384(),
            'ES512' => new ES512(),
            'HS256' => new HS256(),
            'PS256' => new PS256(),
            'PS384' => new PS384(),
            'PS512' => new PS512(),
            'RS256' => new RS256(),
            'RS384' => new RS384(),
            'RS512' => new RS512(),
            default => throw new \InvalidArgumentException(\sprintf('Unsupported algorithm "%s"', $alg)),
        };
    }

    /**
     * @return array{JWK, array<string, mixed>}
     */
    private static function generateRsaKeyPair(): array
    {
        /** @var \OpenSSLAsymmetricKey $resource */
        $resource = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);

        /** @var array{rsa: array{n: string, e: string, d: string, p: string, q: string, dmp1: string, dmq1: string, iqmp: string}} $details */
        $details = openssl_pkey_get_details($resource);

        $rsa = $details['rsa'];

        $publicJwkData = [
            'kty' => 'RSA',
            'n' => Base64UrlSafe::encodeUnpadded($rsa['n']),
            'e' => Base64UrlSafe::encodeUnpadded($rsa['e']),
        ];

        $privateJwk = new JWK($publicJwkData + [
            'd' => Base64UrlSafe::encodeUnpadded($rsa['d']),
            'p' => Base64UrlSafe::encodeUnpadded($rsa['p']),
            'q' => Base64UrlSafe::encodeUnpadded($rsa['q']),
            'dp' => Base64UrlSafe::encodeUnpadded($rsa['dmp1']),
            'dq' => Base64UrlSafe::encodeUnpadded($rsa['dmq1']),
            'qi' => Base64UrlSafe::encodeUnpadded($rsa['iqmp']),
        ]);

        return [$privateJwk, $publicJwkData];
    }

    /**
     * @return array{JWK, array<string, mixed>}
     */
    private static function generateEcKeyPair(string $alg): array
    {
        [$curveName, $crv, $length] = self::EC_CURVES[$alg];

        /** @var \OpenSSLAsymmetricKey $resource */
        $resource = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curveName]);

        /** @var array{ec: array{x: string, y: string, d: string}} $details */
        $details = openssl_pkey_get_details($resource);

        $ec = $details['ec'];

        // the coordinates are unsigned big endian integers, which have to be padded to the length of the curve
        $pad = static fn (string $value): string => str_pad($value, $length, "\0", STR_PAD_LEFT);

        $publicJwkData = [
            'kty' => 'EC',
            'crv' => $crv,
            'x' => Base64UrlSafe::encodeUnpadded($pad($ec['x'])),
            'y' => Base64UrlSafe::encodeUnpadded($pad($ec['y'])),
        ];

        $privateJwk = new JWK($publicJwkData + ['d' => Base64UrlSafe::encodeUnpadded($pad($ec['d']))]);

        return [$privateJwk, $publicJwkData];
    }

    /**
     * @return array{JWK, array<string, mixed>}
     */
    private static function generateOkpKeyPair(): array
    {
        $keyPair = sodium_crypto_sign_keypair();

        $publicJwkData = [
            'kty' => 'OKP',
            'crv' => 'Ed25519',
            'x' => Base64UrlSafe::encodeUnpadded(sodium_crypto_sign_publickey($keyPair)),
        ];

        // the sodium secret key is the concatenation of the 32 byte seed ("d") and the 32 byte public key ("x")
        $seed = substr(sodium_crypto_sign_secretkey($keyPair), 0, 32);

        $privateJwk = new JWK($publicJwkData + ['d' => Base64UrlSafe::encodeUnpadded($seed)]);

        return [$privateJwk, $publicJwkData];
    }
}
