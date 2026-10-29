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

## Provenance

Every release artifact carries a GitHub build attestation. Verify one with
`gh attestation verify <file> --repo watchtowerobservability/watchtower-php`.

## License

Apache-2.0. Source of truth is the Watchtower monorepo; this repository is a published mirror.
