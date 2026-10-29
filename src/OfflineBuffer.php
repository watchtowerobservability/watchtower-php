<?php

declare(strict_types=1);

namespace Watchtower;

/**
 * Bounded buffer; drops the oldest item when full.
 * shortcut: in memory only (PHP requests are short lived), upgrade to a file spool for CLI workers.
 */
final class OfflineBuffer
{
    /** @var list<mixed> */
    private array $items = [];

    public function __construct(private readonly int $max = 64)
    {
    }

    public function push(mixed $item): void
    {
        if (count($this->items) >= max($this->max, 1)) {
            array_shift($this->items);
        }
        $this->items[] = $item;
    }

    /** @return list<mixed> */
    public function drain(): array
    {
        $out = $this->items;
        $this->items = [];
        return $out;
    }

    public function size(): int
    {
        return count($this->items);
    }
}
