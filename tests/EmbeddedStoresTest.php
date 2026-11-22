<?php

declare(strict_types=1);

namespace Watchtower\Tests;

use PHPUnit\Framework\TestCase;
use Watchtower\EmbeddedStores;

final class EmbeddedStoresTest extends TestCase
{
    public function testApcuReadings(): void
    {
        $r = EmbeddedStores::apcuReadings(
            ['num_hits' => 5, 'num_misses' => 2, 'expunges' => 1, 'num_entries' => 3, 'mem_size' => 900],
            ['num_seg' => 1, 'seg_size' => 1000, 'avail_mem' => 400],
        );
        self::assertSame(5, $r['wt.embedded.cache.hits']);
        self::assertSame(600, $r['wt.embedded.map.used']);
        self::assertSame(1000, $r['wt.embedded.map.size']);
    }

    public function testApcuReadingsTolerateMissingFields(): void
    {
        $r = EmbeddedStores::apcuReadings([], []);
        self::assertNull($r['wt.embedded.map.used']);
        self::assertNull($r['wt.embedded.keys']);
    }
}
