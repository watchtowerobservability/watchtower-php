<?php

declare(strict_types=1);

namespace Watchtower;

use OpenTelemetry\API\Trace\Span;

/**
 * App and API Protection in-app WAF, the same behavior as the Node, Python and Go agents.
 *
 * `Appsec::start()` loads the project's ruleset (GET /v1/appsec/ruleset, an ingestion key with
 * scope probes:read): the mode (`monitor` or `block`), the enabled pattern rules and the
 * denylist. It is fetched at most every `ttl` seconds per host and cached in a file, so a request
 * pays no API call. `Appsec::guard()` (call it at bootstrap, or use `AppsecMiddleware` in Laravel)
 * inspects the request: path, query, User-Agent and the other header values, percent-decoded once,
 * against the rules the worker runs over stored spans. A match is recorded on the current span
 * (`appsec.event`, `appsec.rule_id`, `appsec.category`, `appsec.blocked`); in `block` mode, and for
 * denylisted IPs or users in either mode, the request gets 403 problem+json and the app never runs.
 * Rules match case-insensitively; one PCRE cannot compile is skipped.
 *
 * shortcut: the ruleset cache is per host (a file), refreshed by the first request after `ttl`;
 * a long-lived worker (Swoole, RoadRunner) refreshes the same way. Trusts X-Forwarded-For for the
 * client IP: run behind a proxy that overwrites it.
 */
final class Appsec
{
    public const PROBLEM = '{"type":"about:blank","title":"Forbidden","status":403,"detail":"Request blocked by Watchtower App and API Protection"}';

    private string $mode = 'monitor';
    /** @var list<array{0: array<string, mixed>, 1: string}> rule, compiled pattern */
    private array $rules = [];
    /** @var array<string, float> */
    private array $ip = [];
    /** @var array<string, float> */
    private array $user = [];
    private static ?self $active = null;

    /** @param array<string, mixed>|null $ruleset the document the edge serves */
    public function __construct(?array $ruleset = null)
    {
        $r = $ruleset ?? [];
        $this->mode = ($r['mode'] ?? '') === 'block' ? 'block' : 'monitor';
        foreach ($r['rules'] ?? [] as $rule) {
            $rx = '~' . str_replace('~', '\~', (string) ($rule['pattern'] ?? '')) . '~i';
            if (is_array($rule) && ($rule['pattern'] ?? '') !== '' && @preg_match($rx, '') !== false) {
                $this->rules[] = [$rule, $rx];
            }
        }
        $deny = $r['denylist'] ?? [];
        $this->ip = self::expiry($deny['ip'] ?? []);
        $this->user = self::expiry($deny['user'] ?? []);
    }

    /** @param array<mixed> $entries @return array<string, float> */
    private static function expiry(array $entries): array
    {
        $out = [];
        foreach ($entries as $e) {
            if (is_array($e) && isset($e['value']) && $e['value'] !== '') {
                $out[(string) $e['value']] = isset($e['expires_at']) ? (float) $e['expires_at'] : INF;
            }
        }
        return $out;
    }

    public function isActive(): bool
    {
        return $this->rules !== [] || $this->ip !== [] || $this->user !== [];
    }

    public function userBlocked(?string $user, ?float $now = null): bool
    {
        return $user !== null && $user !== '' && ($this->user[$user] ?? 0.0) > ($now ?? microtime(true));
    }

    /**
     * Judge one request: `path`, `query`, `user_agent`, `headers`, `body`, `ip`, `user`.
     *
     * @param array<string, string|null> $req
     * @return array{action: string, rule_id?: string, category?: string, match?: string}
     */
    public function inspect(array $req, ?float $now = null): array
    {
        $now ??= microtime(true);
        $ip = $req['ip'] ?? '';
        if (($ip !== '' && ($this->ip[$ip] ?? 0.0) > $now) || $this->userBlocked($req['user'] ?? null, $now)) {
            return ['action' => 'block', 'rule_id' => 'denylist', 'category' => 'abuse'];
        }
        foreach ($this->rules as [$rule, $rx]) {
            foreach ($rule['fields'] ?? [] as $f) {
                $v = $req[$f] ?? '';
                if ($v !== '' && @preg_match($rx, $v, $m) === 1) {
                    return ['action' => $this->mode === 'block' ? 'block' : 'monitor',
                        'rule_id' => (string) ($rule['id'] ?? ''), 'category' => (string) ($rule['category'] ?? ''),
                        'match' => substr($m[0], 0, 200)];
                }
            }
        }
        return ['action' => 'allow'];
    }

    /**
     * The request fields from a `$_SERVER`-shaped array.
     *
     * @param array<string, mixed> $server
     * @return array<string, string|null>
     */
    public static function fromServer(array $server, ?string $user = null): array
    {
        $headers = [];
        foreach ($server as $k => $v) {
            if (is_string($v) && str_starts_with((string) $k, 'HTTP_')) {
                $headers[strtolower(str_replace('_', '-', substr((string) $k, 5)))] = $v;
            }
        }
        $xff = $headers['x-forwarded-for'] ?? '';
        $ip = $xff !== '' ? trim(explode(',', $xff)[0]) : ($headers['x-real-ip'] ?? (string) ($server['REMOTE_ADDR'] ?? ''));
        $path = explode('?', (string) ($server['REQUEST_URI'] ?? ''), 2)[0];
        unset($headers['user-agent']);
        return ['path' => rawurldecode($path), 'query' => urldecode((string) ($server['QUERY_STRING'] ?? '')),
            'user_agent' => (string) ($server['HTTP_USER_AGENT'] ?? ''), 'headers' => implode("\n", $headers),
            'ip' => $ip, 'user' => $user];
    }

    /** Record a decision on the current span. @param array<string, mixed> $d */
    public static function annotate(array $d, ?string $ip = null): void
    {
        if (!class_exists(Span::class)) {
            return;
        }
        $span = Span::getCurrent();
        if (!$span->isRecording()) {
            return;
        }
        if ($ip !== null && $ip !== '') {
            $span->setAttribute('appsec.client_ip', $ip);
        }
        if ($d['action'] === 'allow') {
            return;
        }
        $span->setAttributes(['appsec.event' => true, 'appsec.rule_id' => (string) ($d['rule_id'] ?? ''),
            'appsec.category' => (string) ($d['category'] ?? ''), 'appsec.blocked' => $d['action'] === 'block']);
    }

    /** Mark the current request as a login attempt; failed ones feed the account-takeover rules. */
    public static function trackLogin(string $login, bool $success): void
    {
        if (!class_exists(Span::class)) {
            return;
        }
        $span = Span::getCurrent();
        $span->setAttributes(['appsec.login' => $login, 'appsec.login.success' => $success]);
        if ($success) {
            $span->setAttribute('appsec.auth', true);
        }
    }

    /** Load the ruleset (cached for `$ttl` seconds) and make it the active one. */
    public static function start(string $endpoint, string $key, string $service, int $ttl = 30): self
    {
        return self::$active = new self(self::fetch($endpoint, $key, $service, $ttl));
    }

    /** @return array<string, mixed>|null */
    public static function fetch(string $endpoint, string $key, string $service, int $ttl): ?array
    {
        $cache = sys_get_temp_dir() . '/wt-appsec-' . hash('sha256', $endpoint . "\0" . $service) . '.json';
        $st = @stat($cache);
        $raw = $st !== false && time() - $st['mtime'] < $ttl ? @file_get_contents($cache) : false;
        if ($raw === false) {
            $url = rtrim($endpoint, '/') . '/v1/appsec/ruleset?' . http_build_query(['service' => $service]);
            $ctx = stream_context_create(['http' => ['header' => "Authorization: Bearer {$key}\r\n", 'timeout' => 2]]);
            $raw = @file_get_contents($url, false, $ctx, 0, 4 << 20);
            if ($raw === false) {
                $raw = @file_get_contents($cache); // a stale ruleset beats none
            } else {
                @file_put_contents($cache, $raw, LOCK_EX);
            }
        }
        $doc = $raw === false ? null : json_decode($raw, true);
        return is_array($doc) ? $doc : null;
    }

    /**
     * Inspect the current request and, when blocked, answer 403 problem+json and exit.
     *
     * @param array<string, mixed>|null $server defaults to `$_SERVER`
     */
    public static function guard(?string $user = null, ?array $server = null): void
    {
        $a = self::$active;
        if ($a === null || !$a->isActive()) {
            return;
        }
        $req = self::fromServer($server ?? $_SERVER, $user);
        $d = $a->inspect($req);
        self::annotate($d, $req['ip']);
        if ($d['action'] === 'block') {
            http_response_code(403);
            header('Content-Type: application/problem+json');
            echo self::PROBLEM;
            exit;
        }
    }

    /** Test hook: use `$a` as the active ruleset. */
    public static function use(?self $a): void
    {
        self::$active = $a;
    }
}
