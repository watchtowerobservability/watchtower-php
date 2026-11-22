<?php

declare(strict_types=1);

namespace Watchtower;

use OpenTelemetry\API\Metrics\MeterInterface;
use OpenTelemetry\API\Metrics\ObserverInterface;

/**
 * wt.embedded.* health metrics for in-process and embedded stores: APCu, and SQLite (SQLite3 / PDO
 * sqlite) or any other file-backed engine by file and WAL size. Read when the meter provider
 * collects (PHP: at forceFlush/shutdown). Keys and values are never recorded.
 */
final class EmbeddedStores
{
    public const GAUGES = [
        'file.size' => 'By', 'wal.size' => 'By', 'map.size' => 'By', 'map.used' => 'By', 'memory.used' => 'By',
        'cache.size' => 'By', 'keys' => '{key}', 'free_pages' => '{page}', 'readers' => '{reader}',
    ];
    public const COUNTERS = [
        'cache.hits' => '{hit}', 'cache.misses' => '{miss}', 'cache.evictions' => '{key}',
        'lock.waits' => '{wait}', 'transactions' => '{transaction}',
    ];

    /** @param callable(): array<string, int|float|null> $read metric name => value */
    public static function observe(MeterInterface $meter, string $system, string $ns, callable $read): void
    {
        $attrs = ['db.system.name' => $system, 'db.namespace' => $ns];
        $cb = static function (string $name) use ($read, $attrs): \Closure {
            return static function (ObserverInterface $o) use ($name, $read, $attrs): void {
                try {
                    $v = $read()[$name] ?? null;
                } catch (\Throwable) {
                    return; // a closed store reports nothing
                }
                if (is_int($v) || is_float($v)) {
                    if ($v >= 0) {
                        $o->observe($v, $attrs);
                    }
                }
            };
        };
        foreach (self::GAUGES as $n => $unit) {
            $meter->createObservableGauge("wt.embedded.$n", $unit)->observe($cb("wt.embedded.$n"));
        }
        foreach (self::COUNTERS as $n => $unit) {
            $meter->createObservableCounter("wt.embedded.$n", $unit)->observe($cb("wt.embedded.$n"));
        }
    }

    /**
     * APCu readings from apcu_cache_info(true) and apcu_sma_info(true).
     *
     * @param array<string, mixed> $info
     * @param array<string, mixed> $sma
     * @return array<string, int|float|null>
     */
    public static function apcuReadings(array $info, array $sma): array
    {
        $total = isset($sma['num_seg'], $sma['seg_size']) ? $sma['num_seg'] * $sma['seg_size'] : null;
        return [
            'wt.embedded.cache.hits' => $info['num_hits'] ?? null,
            'wt.embedded.cache.misses' => $info['num_misses'] ?? null,
            'wt.embedded.cache.evictions' => $info['expunges'] ?? null,
            'wt.embedded.keys' => $info['num_entries'] ?? null,
            'wt.embedded.cache.size' => $info['mem_size'] ?? null,
            'wt.embedded.map.size' => $total,
            'wt.embedded.map.used' => $total !== null && isset($sma['avail_mem']) ? $total - $sma['avail_mem'] : null,
        ];
    }

    /** Hits, misses, expunges, entries and shared memory use of APCu (needs ext-apcu). */
    public static function apcu(MeterInterface $meter): void
    {
        self::observe($meter, 'apcu', 'apcu', static fn (): array => function_exists('apcu_cache_info')
            ? self::apcuReadings(apcu_cache_info(true) ?: [], apcu_sma_info(true) ?: [])
            : []);
    }

    /** File and WAL size: SQLite3/PDO sqlite (wal: $path . '-wal'), DuckDB ($path . '.wal'). */
    public static function files(MeterInterface $meter, string $system, string $path, ?string $wal = null): void
    {
        self::observe($meter, $system, $path, static function () use ($path, $wal): array {
            clearstatcache();
            return [
                'wt.embedded.file.size' => is_file($path) ? filesize($path) : null,
                'wt.embedded.wal.size' => $wal !== null && is_file($wal) ? filesize($wal) : null,
            ];
        });
    }
}
