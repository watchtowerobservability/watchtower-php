<?php

declare(strict_types=1);

namespace Watchtower;

use OpenTelemetry\API\Globals;
use OpenTelemetry\API\Trace\Span;
use OpenTelemetry\API\Trace\StatusCode;
use OpenTelemetry\Context\Context;

/**
 * Dynamic probes for PHP (PLT-044): the active probes of a service (GET /v1/probes/active, key
 * scope probes:read) attach to functions and methods at runtime through the OpenTelemetry PHP
 * extension's `OpenTelemetry\Instrumentation\hook()`, with no code change and no redeploy.
 *
 * Kinds: `log`/`snapshot` add a `probe.snapshot` span event with the arguments flattened to
 * `code.snapshot.*`; `metric` counts `probe.hits`; `span` wraps the call in a span `probe <fn>`;
 * `span_decoration` sets `capture.tags` (templates over the arguments) on the active span.
 *
 * shortcut: PHP has no line hooks, so `{file, line}` probes are skipped (functions only); the
 * per-minute rate limit is per worker process. Upgrade with an extension of our own if needed.
 * Probes are fetched at most every `ttl` seconds per host and cached in a file, so a request
 * pays no API call; hooks are installed when `start()` runs at bootstrap.
 */
final class Probes
{
    public const VALUE_MAX = 1024;

    /** @var array<string, array{0: int, 1: int}> probe id => [minute, hits] */
    private array $budget = [];

    /**
     * @param \Closure(?string, string, ?\Closure, ?\Closure): bool $hook the extension's hook()
     * @param \Closure(): float $now
     */
    public function __construct(private \Closure $hook, private ?\Closure $now = null)
    {
    }

    /** Fetch (or read the cache), then hook every active function probe; returns the hooked count. */
    public static function start(string $endpoint, string $key, string $service, string $env = '', int $ttl = 30): int
    {
        if (!function_exists('OpenTelemetry\Instrumentation\hook')) {
            return 0; // ext-opentelemetry is required for runtime attach
        }
        $defs = self::active($endpoint, $key, $service, $env, $ttl);
        return (new self(\Closure::fromCallable('OpenTelemetry\Instrumentation\hook')))->install($defs);
    }

    /** @return list<array<string, mixed>> */
    public static function active(string $endpoint, string $key, string $service, string $env, int $ttl): array
    {
        $cache = sys_get_temp_dir() . '/wt-probes-' . hash('sha256', $endpoint . "\0" . $service . "\0" . $env) . '.json';
        $st = @stat($cache);
        if ($st !== false && time() - $st['mtime'] < $ttl) {
            $raw = @file_get_contents($cache);
        } else {
            $url = rtrim($endpoint, '/') . '/v1/probes/active?' . http_build_query(['service' => $service, 'env' => $env, 'kinds' => 'log,snapshot,metric,span,span_decoration']);
            $ctx = stream_context_create(['http' => ['header' => "Authorization: Bearer {$key}\r\n", 'timeout' => 2, 'ignore_errors' => false]]);
            $raw = @file_get_contents($url, false, $ctx);
            if (is_string($raw)) {
                @file_put_contents($cache . '.tmp', $raw) && @rename($cache . '.tmp', $cache);
            } else {
                $raw = @file_get_contents($cache); // keep the last good set when the API is down
            }
        }
        $doc = is_string($raw) ? json_decode($raw, true) : null;
        return is_array($doc) && is_array($doc['probes'] ?? null) ? array_values($doc['probes']) : [];
    }

    /** @param list<array<string, mixed>> $defs */
    public function install(array $defs): int
    {
        $n = 0;
        foreach ($defs as $d) {
            $fn = (string) ($d['location']['function'] ?? '');
            if ($fn === '') {
                continue; // line probes need line hooks PHP does not have
            }
            try {
                $cond = new ProbeCondition((string) ($d['condition'] ?? ''));
            } catch (\InvalidArgumentException) {
                continue;
            }
            [$class, $func] = str_contains($fn, '::') ? explode('::', $fn, 2) : [null, $fn];
            [$pre, $post] = $this->handlers($d, $cond);
            if (($this->hook)($class, $func, $pre, $post)) {
                $n++;
            }
        }
        return $n;
    }

    /**
     * The pre/post hooks of one probe.
     *
     * @param array<string, mixed> $d
     * @return array{0: \Closure, 1: ?\Closure}
     */
    public function handlers(array $d, ProbeCondition $cond): array
    {
        $kind = (string) ($d['kind'] ?? 'snapshot');
        $id = (string) ($d['id'] ?? '');
        $stack = []; // [span, scope] of the calls in flight, innermost last
        $pre = function (mixed $obj, array $params, ?string $class, string $function, ?string $file = null, ?int $line = null) use ($d, $cond, $kind, $id, &$stack): void {
            $vars = self::named($class, $function, $params);
            if (!$this->allowed($d, $cond, $vars)) {
                if ($kind === 'span') {
                    $stack[] = null; // keeps post hooks paired with their calls
                }
                return;
            }
            $where = ['code.function' => $function, 'code.namespace' => (string) $class, 'code.filepath' => (string) $file, 'code.lineno' => (int) $line];
            match ($kind) {
                'span' => array_push($stack, self::openSpan($id, $function, $where)),
                'span_decoration' => Span::getCurrent()->setAttributes(self::tags($d, $vars)),
                'metric' => Globals::meterProvider()->getMeter('watchtower.probes')->createCounter('probe.hits')->add(1, ['probe.id' => $id]),
                default => Span::getCurrent()->addEvent('probe.snapshot', ['probe.id' => $id, 'probe.message' => self::render((string) ($d['message'] ?? ''), $vars)] + $where + self::capture($vars, $d)),
            };
        };
        $post = $kind !== 'span' ? null : static function (mixed $obj, array $params, mixed $ret, ?\Throwable $e = null) use (&$stack): void {
            $top = array_pop($stack);
            if ($top === null) {
                return;
            }
            [$span, $scope] = $top;
            if ($e !== null) {
                $span->recordException($e);
                $span->setStatus(StatusCode::STATUS_ERROR);
            }
            $scope->detach();
            $span->end();
        };
        return [$pre, $post];
    }

    /**
     * Start `probe <function>` as the current span.
     *
     * @param array<string, mixed> $where
     * @return array{0: \OpenTelemetry\API\Trace\SpanInterface, 1: \OpenTelemetry\Context\ScopeInterface}
     */
    private static function openSpan(string $id, string $function, array $where): array
    {
        $span = Globals::tracerProvider()->getTracer('watchtower.probes')->spanBuilder("probe {$function}")
            ->setAttributes(['probe.id' => $id] + $where)->startSpan();
        return [$span, $span->storeInContext(Context::getCurrent())->activate()];
    }

    /**
     * Not expired, inside the per-minute budget and the condition holds (counts the hit).
     *
     * @param array<string, mixed> $d
     * @param array<string, mixed> $vars
     */
    public function allowed(array $d, ProbeCondition $cond, array $vars): bool
    {
        $t = $this->now !== null ? ($this->now)() : microtime(true);
        if (isset($d['expires_at']) && $t >= (float) $d['expires_at']) {
            return false;
        }
        $id = (string) ($d['id'] ?? '');
        $minute = intdiv((int) $t, 60);
        [$win, $hits] = $this->budget[$id] ?? [$minute, 0];
        if ($win !== $minute) {
            $hits = 0;
        }
        if ($hits >= min((int) ($d['max_rate_per_min'] ?? 60) ?: 60, 60) || !$cond->matches($vars)) {
            return false;
        }
        $this->budget[$id] = [$minute, $hits + 1];
        return true;
    }

    /**
     * Positional hook params as name => value, from reflection (args beyond the signature are arg<N>).
     *
     * @param list<mixed> $params
     * @return array<string, mixed>
     */
    public static function named(?string $class, string $function, array $params): array
    {
        try {
            $ref = $class !== null && $class !== '' ? new \ReflectionMethod($class, $function) : new \ReflectionFunction($function);
            $names = array_map(static fn (\ReflectionParameter $p): string => $p->getName(), $ref->getParameters());
        } catch (\ReflectionException) {
            $names = [];
        }
        $out = [];
        foreach (array_values($params) as $i => $v) {
            $out[$names[$i] ?? "arg{$i}"] = $v;
        }
        return $out;
    }

    /**
     * Flatten to dotted names: nesting past locals_depth collapses, values cut to 1 KiB, total to max_bytes.
     *
     * @param array<string, mixed> $vars
     * @param array<string, mixed> $d
     * @return array<string, string>
     */
    public static function capture(array $vars, array $d): array
    {
        $depth = min((int) ($d['capture']['locals_depth'] ?? 3), 3);
        $max = min((int) ($d['capture']['max_bytes'] ?? 8192), 8192);
        $out = [];
        $used = 0;
        $put = static function (string $k, string $v) use (&$out, &$used, $max): void {
            $v = substr($v, 0, self::VALUE_MAX);
            if ($used + strlen($k) + strlen($v) <= $max) {
                $used += strlen($k) + strlen($v);
                $out["code.snapshot.{$k}"] = $v;
            }
        };
        $walk = static function (string $prefix, mixed $v, int $level) use (&$walk, $put, $depth): void {
            if (is_array($v) || is_object($v)) {
                if ($level > $depth) {
                    $put($prefix, '[depth limit]');
                    return;
                }
                $items = is_array($v) ? $v : get_object_vars($v);
                ksort($items);
                foreach ($items as $k => $x) {
                    $walk($prefix === '' ? (string) $k : "{$prefix}.{$k}", $x, $level + 1);
                }
                return;
            }
            $put($prefix, is_string($v) ? $v : (string) json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR));
        };
        $walk('', $vars, 0);
        return $out;
    }

    /** Fill `{a.b}` from the variables (missing names render empty), cut to 1 KiB. */
    public static function render(string $template, array $vars): string
    {
        $s = preg_replace_callback('/\{([A-Za-z_][\w.]*)\}/', static function (array $m) use ($vars): string {
            $v = ProbeCondition::lookup($vars, $m[1]);
            return is_scalar($v) ? (string) $v : ($v === null ? '' : (string) json_encode($v));
        }, $template);
        return substr((string) $s, 0, self::VALUE_MAX);
    }

    /**
     * @param array<string, mixed> $d
     * @param array<string, mixed> $vars
     * @return array<string, string>
     */
    public static function tags(array $d, array $vars): array
    {
        $out = [];
        foreach ($d['capture']['tags'] ?? [] as $t) {
            if (is_array($t) && ($t['name'] ?? '') !== '' && !str_starts_with((string) $t['name'], 'wt.')) {
                $out[(string) $t['name']] = self::render((string) ($t['value'] ?? ''), $vars);
            }
        }
        return $out;
    }
}
