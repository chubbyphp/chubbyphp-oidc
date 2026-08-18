<?php

declare(strict_types=1);

namespace Chubbyphp\Oidc\Clock;

use Psr\Clock\ClockInterface;

final class SystemClock implements ClockInterface
{
    public function now(): \DateTimeImmutable
    {
        return new \DateTimeImmutable();
    }
}
