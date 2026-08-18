<?php

declare(strict_types=1);

namespace Chubbyphp\Tests\Oidc\Unit\Token;

use Chubbyphp\Mock\MockMethod\WithReturn;
use Chubbyphp\Mock\MockObjectBuilder;
use Chubbyphp\Oidc\Token\BearerTokenExtractor;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

/**
 * @covers \Chubbyphp\Oidc\Token\BearerTokenExtractor
 *
 * @internal
 */
final class BearerTokenExtractorTest extends TestCase
{
    #[DataProvider('provideExtractTokenCases')]
    public function testExtractToken(string $authorization, ?string $expectedToken): void
    {
        $builder = new MockObjectBuilder();

        /** @var ServerRequestInterface $request */
        $request = $builder->create(ServerRequestInterface::class, [
            new WithReturn('getHeaderLine', ['authorization'], $authorization),
        ]);

        $tokenExtractor = new BearerTokenExtractor();

        self::assertSame($expectedToken, $tokenExtractor->extract($request));
    }

    /**
     * @return iterable<string, array{string, null|string}>
     */
    public static function provideExtractTokenCases(): iterable
    {
        yield 'without authorization header' => ['', null];

        yield 'with other authorization scheme' => ['Basic dXNlcjpwYXNzd29yZA==', null];

        yield 'without token' => ['Bearer', null];

        yield 'with invalid token' => ['Bearer some token', null];

        yield 'with prefixed authorization header' => ['prefix Bearer some-token', null];

        yield 'with token' => ['Bearer some-token', 'some-token'];

        yield 'with multiple spaces between scheme and token' => ['Bearer   some-token', 'some-token'];

        yield 'with lowercase scheme' => ['bearer some-token', 'some-token'];
    }
}
