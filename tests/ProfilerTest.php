<?php

declare(strict_types=1);

namespace Watchtower\Tests;

use PHPUnit\Framework\TestCase;
use Watchtower\Profiler;

final class ProfilerTest extends TestCase
{
    private const KEY = 'wtk_example_not_a_real_key'; // fake

    public function testFoldsRootFirstWithoutOwnFrames(): void
    {
        $trace = [
            ['function' => 'sample', 'class' => Profiler::class],
            ['function' => 'query', 'class' => 'App\\Db'],
            ['function' => 'handle'],
        ];
        $this->assertSame('{main};handle;App\\Db::query', Profiler::fold($trace));
    }

    public function testUrlBodyAndCollapsedMerge(): void
    {
        $p = new Profiler(self::KEY, 'http://127.0.0.1:9/', 'api', ['env' => 'prod']);
        $this->assertStringStartsWith('http://127.0.0.1:9/ingest?name=api.wall%7Benv%3Dprod%7D&from=1&until=2&format=folded', $p->ingestUrl(1, 2));
        $this->assertSame("a;b 2\n", Profiler::body(['a;b' => 2]));
        $this->assertStringNotContainsString(self::KEY, print_r($p, true));
        $p->addFolded("x;y 3\nx;y 1\n");
        $this->assertSame(['x;y' => 4], $p->counts());
        $p->flush();
        $this->assertSame(1, $p->dropped, 'the dead endpoint drops the upload');
        $p->withSpan('ab', 'cd', function () use ($p): void {
            $p->sample([['function' => 'work']]);
        });
        $this->assertSame(["span_id=ab,trace_id=cd\t{main};work" => 1], $p->counts());
        $this->expectException(\InvalidArgumentException::class);
        new Profiler('');
    }

    public function testAlarmModeSamplesALongRunningLoop(): void
    {
        if (!function_exists('pcntl_alarm')) {
            $this->markTestSkipped('pcntl is not loaded');
        }
        $p = new Profiler(self::KEY, 'http://127.0.0.1:9', 'api', [], 100, 3600.0);
        $p->start('alarm');
        $this->burnWatchtowerMarker(2.2);
        $counts = $p->counts();
        pcntl_alarm(0);
        pcntl_signal(SIGALRM, SIG_DFL);
        $this->assertGreaterThanOrEqual(2, array_sum($counts));
        $this->assertNotEmpty(array_filter(array_keys($counts), fn ($k) => str_contains($k, 'burnWatchtowerMarker')));
    }

    private function burnWatchtowerMarker(float $s): void
    {
        $end = microtime(true) + $s;
        $x = 0.0;
        while (microtime(true) < $end) {
            $x = sqrt($x + 1);
        }
    }
}
