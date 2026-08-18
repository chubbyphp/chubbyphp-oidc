<?php

declare(strict_types=1);

namespace Chubbyphp\Tests\Oidc\Unit\Clock;

use Chubbyphp\Oidc\Clock\SystemClock;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Chubbyphp\Oidc\Clock\SystemClock
 *
 * @internal
 */
final class SystemClockTest extends TestCase
{
    public function testNow(): void
    {
        $clock = new SystemClock();

        $before = time();

        $now = $clock->now();

        $after = time();

        self::assertGreaterThanOrEqual($before, $now->getTimestamp());
        self::assertLessThanOrEqual($after, $now->getTimestamp());
    }
}
