# watchtowerobservability/sdk

[![CI](https://github.com/watchtowerobservability/watchtower-php/actions/workflows/ci.yml/badge.svg)](https://github.com/watchtowerobservability/watchtower-php/actions/workflows/ci.yml)

Thin Watchtower distribution over the OpenTelemetry PHP SDK: `Authorization: Bearer` key header, endpoint default, `wt.*`-safe attributes, redaction hook, offline buffer.

Status: 0.x, early. APIs may change between minor versions.

## Install

```sh
composer config repositories.watchtower vcs https://github.com/watchtowerobservability/watchtower-php
composer require watchtowerobservability/sdk
```

## Use

```php
$tp = Watchtower\Watchtower::init(Watchtower\Config::fromEnv('checkout'));
```

The ingest key is read from the environment (`WT_INGEST_KEY`); never commit it.

Logs and metrics use the official OpenTelemetry PHP logs and metrics SDKs over the same endpoint and key:

```php
$sdk = Watchtower\Watchtower::initAll(Watchtower\Config::fromEnv('checkout'));  // global tracer, logger and meter providers
$log = new Monolog\Logger('app', [Watchtower\Watchtower::monolog(Globals::loggerProvider())]);  // needs open-telemetry/opentelemetry-logger-monolog
```

Monolog records become OTLP log records with the active trace and span ids. `Watchtower::logs($cfg)` and
`Watchtower::metrics($cfg)` return the providers on their own. PHP has no background reader, so metrics are
exported on `forceFlush()` and at shutdown, with delta temporality unless
`OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE=cumulative`. Failed log batches are retried with the next
export like spans (in memory). `WATCHTOWER_LOGS=off` / `WATCHTOWER_METRICS=off` (or `OTEL_LOGS_EXPORTER` /
`OTEL_METRICS_EXPORTER=none`) turn a signal off. PHP has no official runtime metrics package yet.

## Profiling

```php
$profiler = Watchtower\Profiler::fromEnv('checkout')->start();   // stops and uploads at shutdown
```

A wall-clock profiler. Every 15 s and at shutdown it posts folded stacks to `/ingest` as `<service>.wall`. It uses the best sampler available:

| Mode | When | Rate | Cost per sample (not measured) |
|---|---|---|---|
| `excimer` | the excimer extension is loaded | `hz` (default 100) | native sampling in the extension |
| `alarm` | `pcntl` is loaded (CLI, workers) | 1 Hz (`pcntl_alarm`) | one `debug_backtrace()` a second |
| `ticks` | opt-in `start('ticks')` | `hz` | a function call per statement in files with `declare(ticks=1)`, so expect those files to slow noticeably |

Overhead has not been measured in any mode; test it under your own load. Alarm mode takes over `SIGALRM`, so do not use it if your app sets alarms. It suits long-running processes (queue workers, RoadRunner, Swoole). Short PHP-FPM requests collect few samples without excimer.

`$profiler->withSpan($spanId, $traceId, fn () => work())` labels samples taken inside it (hex ids), so a trace links to its exact profile.

## Dynamic probes

With the `opentelemetry` PHP extension loaded, `Watchtower\Probes::start($endpoint, $ingestKey, 'checkout')`
at bootstrap attaches the active probes of the service (log, snapshot, metric, span and span decoration) to
functions and methods (`App\Billing::charge`) with no code change. Line probes are skipped (PHP has no line
hooks). The key needs scope `probes:read`.

## Embedded and in-process stores

`EmbeddedStores::apcu($meter)` reports APCu hits, misses, expunges, entries and shared-memory use;
`EmbeddedStores::files($meter, 'sqlite', $path, $path . '-wal')` reports SQLite3 / PDO sqlite file and WAL size;
`EmbeddedStores::observe($meter, $system, $ns, $read)` takes any other store. Metrics are `wt.embedded.*`,
read when the meter provider flushes.

## Provenance

Every release artifact carries a GitHub build attestation. Verify one with
`gh attestation verify <file> --repo watchtowerobservability/watchtower-php`.

## License

Apache-2.0. Source of truth is the Watchtower monorepo; this repository is a published mirror.
