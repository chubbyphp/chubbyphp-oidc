<?php

declare(strict_types=1);

namespace Chubbyphp\Tests\Oidc;

use Psr\Clock\ClockInterface;

/**
 * @internal
 */
final class FrozenClock implements ClockInterface
{
    public function __construct(private int $timestamp) {}

    public function now(): \DateTimeImmutable
    {
        return new \DateTimeImmutable('@'.$this->timestamp);
    }

    public function getTimestamp(): int
    {
        return $this->timestamp;
    }

    public function setTimestamp(int $timestamp): void
    {
        $this->timestamp = $timestamp;
    }
}
