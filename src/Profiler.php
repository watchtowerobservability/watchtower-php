<?php

declare(strict_types=1);

namespace Watchtower;

/**
 * Wall-clock profiler posting folded stacks to the gateway's Pyroscope-compatible /ingest as
 * `<service>.wall`. Three samplers, the best available wins:
 * - excimer (the extension, when loaded): native timer, `hz` samples a second.
 * - alarm (pcntl): `pcntl_alarm` + async signals, one `debug_backtrace()` a second. The rate is
 *   fixed at 1 Hz, so it needs long-running processes (CLI, queue workers, RoadRunner/Swoole) to
 *   collect useful profiles.
 * - ticks (opt-in): a tick function samples every 1/hz seconds, but only code in files with
 *   `declare(ticks=1)` triggers it, and it costs a function call per statement there. For targeted
 *   profiling only. Overhead of all modes is unmeasured.
 * Samples are posted every `period` seconds and at shutdown; failed uploads are dropped.
 * `withSpan()` labels samples taken inside it with a span, so a trace links to its exact profile.
 * `pcntl_alarm` replaces any SIGALRM the application uses: do not use alarm mode then.
 */
final class Profiler
{
    /** @var array<string, int> folded stack => samples */
    private array $counts = [];
    private float $since;
    private float $lastTick = 0.0;
    private ?object $excimer = null;
    private string $mode = 'off';
    private string $spanPrefix = '';
    public int $uploaded = 0;
    public int $dropped = 0;

    /** @param array<string, string> $tags */
    public function __construct(
        private readonly string $key,
        private readonly string $endpoint = Config::DEFAULT_ENDPOINT,
        private readonly string $service = 'app',
        private readonly array $tags = [],
        private readonly int $hz = 100,
        private readonly float $period = 15.0,
    ) {
        if ($key === '') {
            throw new \InvalidArgumentException('key is required');
        }
        $this->since = microtime(true);
    }

    public static function fromEnv(string $service = 'app'): self
    {
        $tags = array_filter(['env' => getenv('WT_ENVIRONMENT') ?: '', 'version' => getenv('WT_RELEASE') ?: '']);
        return new self((string) getenv('WT_INGEST_KEY'), getenv('WT_OTLP_ENDPOINT') ?: Config::DEFAULT_ENDPOINT,
            getenv('WT_SERVICE') ?: $service, $tags);
    }

    public function __debugInfo(): array
    {
        return ['service' => $this->service, 'mode' => $this->mode];
    }

    public function mode(): string
    {
        return $this->mode;
    }

    /** @param 'auto'|'excimer'|'alarm'|'ticks' $mode */
    public function start(string $mode = 'auto'): self
    {
        if ($mode === 'auto') {
            $mode = extension_loaded('excimer') ? 'excimer' : (function_exists('pcntl_alarm') ? 'alarm' : 'ticks');
        }
        if ($mode === 'excimer') {
            $p = new \ExcimerProfiler();
            $p->setPeriod(1 / max(1, $this->hz));
            $p->setEventType(EXCIMER_REAL);
            $p->setFlushCallback(fn ($log) => $this->addFolded($log->formatCollapsed()), max(1, (int) ($this->hz * $this->period)));
            $p->start();
            $this->excimer = $p;
        } elseif ($mode === 'alarm') {
            pcntl_async_signals(true);
            pcntl_signal(SIGALRM, function (): void {
                $this->sample(debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS));
                pcntl_alarm(1);
            });
            pcntl_alarm(1);
        } else {
            register_tick_function([$this, 'tick']);
        }
        $this->mode = $mode;
        register_shutdown_function([$this, 'stop']);
        return $this;
    }

    public function stop(): void
    {
        if ($this->mode === 'excimer' && $this->excimer !== null) {
            $this->excimer->stop();
            $this->addFolded($this->excimer->flush()->formatCollapsed());
        } elseif ($this->mode === 'alarm') {
            pcntl_alarm(0);
            pcntl_signal(SIGALRM, SIG_DFL);
        } elseif ($this->mode === 'ticks') {
            unregister_tick_function([$this, 'tick']);
        }
        $this->mode = 'off';
        $this->flush();
    }

    /** Runs $fn with samples labeled with the span (hex ids; PHP has one thread). */
    public function withSpan(string $spanId, string $traceId, callable $fn): mixed
    {
        $this->drainExcimer(); // excimer's log so far belongs to the previous span
        $before = $this->spanPrefix;
        $this->spanPrefix = "span_id=$spanId,trace_id=$traceId\t";
        try {
            return $fn();
        } finally {
            $this->drainExcimer();
            $this->spanPrefix = $before;
        }
    }

    private function drainExcimer(): void
    {
        if ($this->mode === 'excimer' && $this->excimer !== null) {
            $this->addFolded($this->excimer->flush()->formatCollapsed());
        }
    }

    /** @internal tick-mode sampler */
    public function tick(): void
    {
        $now = microtime(true);
        if ($now - $this->lastTick >= 1 / max(1, $this->hz)) {
            $this->lastTick = $now;
            $this->sample(debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS));
        }
    }

    /** Root-first `a;b;c` of a debug_backtrace() (innermost first), without this class's frames. */
    public static function fold(array $trace): string
    {
        $names = [];
        foreach ($trace as $f) {
            if (($f['class'] ?? '') === self::class || (str_starts_with($f['function'] ?? '', '{closure') && str_ends_with($f['file'] ?? '', 'Profiler.php'))) {
                continue;
            }
            $fn = $f['function'] ?? '?';
            $names[] = str_replace(';', ':', isset($f['class']) ? $f['class'] . '::' . $fn : $fn);
        }
        $names[] = '{main}';
        return implode(';', array_reverse($names));
    }

    public function sample(array $trace): void
    {
        $k = $this->spanPrefix . self::fold($trace);
        $this->counts[$k] = ($this->counts[$k] ?? 0) + 1;
        if (microtime(true) - $this->since >= $this->period) {
            $this->flush();
        }
    }

    /** Merges excimer's collapsed output ("a;b 3" lines). */
    public function addFolded(string $collapsed): void
    {
        foreach (explode("\n", $collapsed) as $line) {
            $sp = strrpos($line, ' ');
            if ($sp !== false) {
                $k = $this->spanPrefix . substr($line, 0, $sp);
                $this->counts[$k] = ($this->counts[$k] ?? 0) + (int) substr($line, $sp + 1);
            }
        }
        if (microtime(true) - $this->since >= $this->period) {
            $this->flush();
        }
    }

    /** @return array<string, int> */
    public function counts(): array
    {
        return $this->counts;
    }

    public function ingestUrl(int $from, int $until): string
    {
        $labels = [];
        foreach ($this->tags as $k => $v) {
            if ($v !== '') {
                $labels[] = "$k=$v";
            }
        }
        sort($labels);
        $rate = $this->mode === 'alarm' ? 1 : $this->hz;
        return rtrim($this->endpoint, '/') . '/ingest?' . http_build_query([
            'name' => $this->service . '.wall{' . implode(',', $labels) . '}', 'from' => $from, 'until' => $until,
            'format' => 'folded', 'sampleRate' => $rate, 'units' => 'samples', 'spyName' => 'watchtower-php',
        ], '', '&', PHP_QUERY_RFC3986);
    }

    public static function body(array $counts): string
    {
        $out = '';
        foreach ($counts as $k => $n) {
            $out .= "$k $n\n";
        }
        return $out;
    }

    /** Posts the collected samples (best effort) and starts a new window. */
    public function flush(): void
    {
        $counts = $this->counts;
        $from = (int) $this->since;
        $this->counts = [];
        $this->since = microtime(true);
        if ($counts === []) {
            return;
        }
        $ctx = stream_context_create(['http' => [
            'method' => 'POST', 'timeout' => 10, 'ignore_errors' => true,
            'header' => "Authorization: Bearer {$this->key}\r\nContent-Type: text/plain\r\n",
            'content' => self::body($counts),
        ]]);
        $sent = @file_get_contents($this->ingestUrl($from, (int) $this->since), false, $ctx) !== false;
        $headers = function_exists('http_get_last_response_headers') ? (http_get_last_response_headers() ?? []) : ($http_response_header ?? []);
        $ok = $sent && preg_match('#^HTTP/\S+ 2\d\d#', $headers[0] ?? '') === 1;
        $ok ? $this->uploaded++ : $this->dropped++;
    }
}
