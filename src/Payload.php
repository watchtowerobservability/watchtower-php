<?php

declare(strict_types=1);

namespace Watchtower;

use OpenTelemetry\API\Trace\Span;
use OpenTelemetry\API\Trace\SpanInterface;

/**
 * Payload and GraphQL capture (APM-016), driven by the capture rules set in Watchtower per
 * service and route (`GET /v1/capture-rules?service=`, an ingest key with scope `probes:read`).
 * Opt-in: nothing is fetched or recorded unless `WT_CAPTURE_RULES=1` (or `start()` is called at
 * bootstrap) and a rule matches the route. Only text-like bodies are kept, at most the rule's
 * `body_bytes` (hard cap 8 KiB), after the default secret and PII detectors (a port of the
 * pipeline's redact stage; ingest applies the project's detectors again). `start()` tees the
 * output buffer and records on the active span at shutdown. Rules are cached in a file for
 * `ttl` seconds, like Probes, so a request pays no API call.
 * shortcut: the route is the request path (plain PHP knows no route template); frameworks can
 * call `record()` with theirs.
 */
final class Payload
{
    public const HARD_MAX = 8192;
    private const R = '[REDACTED]';
    private const SECRET_KEYS = 'password|passwd|secret|token|access_token|refresh_token|client_secret|api_?key|authorization';
    private const PATTERNS = [
        '/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/',
        '/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/',
        '~bearer\s+[A-Za-z0-9._\~+/-]+=*~i',
        '/wt[ik]_[a-z0-9]{8}_[A-Za-z0-9_-]{43}/',
        '/(?:AKIA|ASIA)[0-9A-Z]{16}/',
        '/gh[pousr]_[A-Za-z0-9]{36,}/',
        '/[rs]k_(?:live|test)_[A-Za-z0-9]{16,}/',
        '/[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/',
        '/\b\d{3}-\d{2}-\d{4}\b/',
    ];

    /** @var list<array<string, mixed>> */
    private static array $rules = [];
    private static string $out = '';

    /** @param list<array<string, mixed>> $rules */
    public static function setRules(array $rules): void
    {
        self::$rules = array_values(array_filter($rules, 'is_array'));
    }

    /** Load the rules (file cache, `ttl` s) and, when any exist, capture this request at shutdown. */
    public static function start(string $endpoint, string $key, string $service, int $ttl = 60): void
    {
        self::setRules(self::fetch($endpoint, $key, $service, $ttl));
        if (self::$rules === [] || PHP_SAPI === 'cli') {
            return;
        }
        $req = (string) @file_get_contents('php://input', false, null, 0, self::HARD_MAX * 2);
        ob_start(static function (string $chunk): string {
            if (strlen(self::$out) < self::HARD_MAX * 2) {
                self::$out .= substr($chunk, 0, self::HARD_MAX * 2 - strlen(self::$out));
            }
            return $chunk;
        });
        register_shutdown_function(static function () use ($req): void {
            $resType = '';
            foreach (headers_list() as $h) {
                if (stripos($h, 'content-type:') === 0) {
                    $resType = trim(substr($h, 13));
                }
            }
            $path = (string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
            self::record(Span::getCurrent(), $path, (string) ($_SERVER['CONTENT_TYPE'] ?? ''), $req, $resType, self::$out);
        });
    }

    /** @return list<array<string, mixed>> */
    private static function fetch(string $endpoint, string $key, string $service, int $ttl): array
    {
        $cache = sys_get_temp_dir() . '/wt-capture-' . hash('sha256', $endpoint . "\0" . $service) . '.json';
        $st = @stat($cache);
        if ($st !== false && time() - $st['mtime'] < $ttl) {
            $raw = @file_get_contents($cache);
        } else {
            $url = rtrim($endpoint, '/') . '/v1/capture-rules?' . http_build_query(['service' => $service]);
            $ctx = stream_context_create(['http' => ['header' => "Authorization: Bearer {$key}\r\n", 'timeout' => 2]]);
            $raw = @file_get_contents($url, false, $ctx);
            if (is_string($raw)) {
                @file_put_contents($cache . '.tmp', $raw) && @rename($cache . '.tmp', $cache);
            }
        }
        $doc = is_string($raw) ? json_decode($raw, true) : null;
        return is_array($doc) && is_array($doc['rules'] ?? null) ? array_values($doc['rules']) : [];
    }

    /** `*` matches any run of characters (the edge's glob). */
    public static function glob(string $pat, string $s): bool
    {
        $re = implode('.*', array_map(static fn ($p) => preg_quote($p, '/'), explode('*', $pat)));
        return preg_match('/\A' . $re . '\z/s', $s) === 1;
    }

    /** @return array<string, mixed>|null */
    public static function ruleFor(string $route): ?array
    {
        foreach (self::$rules as $r) {
            $g = $r['route'] ?? null;
            if ($g === null || $g === '' || self::glob((string) $g, $route)) {
                return $r;
            }
        }
        return null;
    }

    private static function luhn(string $s): bool
    {
        $d = array_reverse(array_map('intval', str_split((string) preg_replace('/\D/', '', $s))));
        $sum = 0;
        foreach ($d as $i => $x) {
            $sum += $i % 2 === 1 ? ($x * 2 > 9 ? $x * 2 - 9 : $x * 2) : $x;
        }
        return count($d) >= 13 && $sum % 10 === 0;
    }

    /** Default secret and PII detectors: secret-named JSON and form fields, keys, tokens, emails, SSNs, Luhn-valid cards. */
    public static function redact(string $s): string
    {
        $k = self::SECRET_KEYS;
        $s = (string) preg_replace('/("(?:' . $k . ')"\s*:\s*)"(?:[^"\\\\]|\\\\.)*"/i', '$1"' . self::R . '"', $s);
        $s = (string) preg_replace('/\b((?:' . $k . ')=)[^&\s]*/i', '${1}' . self::R, $s);
        foreach (self::PATTERNS as $re) {
            $s = (string) preg_replace($re, self::R, $s);
        }
        return (string) preg_replace_callback('/\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,7}\b/', static fn ($m) => self::luhn($m[0]) ? self::R : $m[0], $s);
    }

    private static function cap(string $s, int $n): string
    {
        return function_exists('mb_strcut') ? mb_strcut($s, 0, $n, 'UTF-8') : substr($s, 0, $n);
    }

    /** Redacts a wider window than it keeps so a secret cut at the edge is still masked. */
    public static function excerpt(string $s, int $n): string
    {
        return self::cap(self::redact(self::cap($s, $n * 2)), $n);
    }

    /** @return array{0: string, 1: ?string}|null type and name; `{ ... }` is an anonymous query */
    public static function graphqlOp(string $doc): ?array
    {
        $d = (string) preg_replace('/#[^\n]*/', '', $doc);
        if (preg_match('/(?:\A|\})\s*(query|mutation|subscription)\b\s*([_A-Za-z][_0-9A-Za-z]*)?/', $d, $m) === 1) {
            return [$m[1], ($m[2] ?? '') !== '' ? $m[2] : null];
        }
        return str_starts_with(ltrim($d), '{') ? ['query', null] : null;
    }

    private static function text(string $body, string $type): ?string
    {
        if ($body === '' || ($type !== '' && preg_match('~json|\Atext/|xml|x-www-form-urlencoded|graphql~i', $type) !== 1)) {
            return null;
        }
        return $body;
    }

    /** Set the body and GraphQL attributes the rule matching the route asks for; no rule, nothing. */
    public static function record(SpanInterface $span, string $route, string $reqType, string $reqBody, string $resType, string $resBody): void
    {
        $rule = self::ruleFor($route);
        if ($rule === null || !$span->isRecording()) {
            return;
        }
        $n = min((int) ($rule['body_bytes'] ?? 0), self::HARD_MAX);
        $req = self::text($reqBody, $reqType);
        $res = self::text($resBody, $resType);
        if ($n > 0 && $req !== null) {
            $span->setAttribute('http.request.body', self::excerpt($req, $n));
        }
        if ($n > 0 && $res !== null) {
            $span->setAttribute('http.response.body', self::excerpt($res, $n));
        }
        [$doc, $name] = [null, null];
        if ($req !== null && stripos($reqType, 'graphql') !== false) {
            $doc = $req;
        } elseif ($req !== null) {
            $j = json_decode($req, true);
            if (is_array($j) && is_string($j['query'] ?? null)) {
                $doc = $j['query'];
                $name = is_string($j['operationName'] ?? null) ? $j['operationName'] : null;
            }
        }
        $op = $doc === null ? null : self::graphqlOp($doc);
        if ($op === null || $doc === null) {
            return;
        }
        $span->setAttribute('graphql.operation.type', $op[0]);
        if (($name ?? $op[1]) !== null) {
            $span->setAttribute('graphql.operation.name', $name ?? $op[1]);
        }
        if (!empty($rule['graphql_query'])) {
            $span->setAttribute('graphql.document', self::excerpt($doc, self::HARD_MAX));
        }
    }
}
