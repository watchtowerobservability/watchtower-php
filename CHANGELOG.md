# Changelog

## Unreleased

- Logs and metrics: `Watchtower::logs()`, `Watchtower::metrics()` (delta temporality by default) and `Watchtower::initAll()` (registers all three providers globally); `Watchtower::monolog()` wraps the official Monolog handler. `WATCHTOWER_LOGS` / `WATCHTOWER_METRICS` switch the signals, default on. Log batches use the same retry buffer as spans.

## 0.1.0

- Initial public release.
- Reads WT_OTLP_ENDPOINT, WT_SERVICE, WT_ENVIRONMENT and WT_RELEASE; WT_ENDPOINT is a deprecated alias.
