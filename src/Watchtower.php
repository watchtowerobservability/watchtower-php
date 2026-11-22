<?php

declare(strict_types=1);

namespace Watchtower;

use OpenTelemetry\API\Logs\LoggerProviderInterface;
use OpenTelemetry\Contrib\Logs\Monolog\Handler as MonologHandler;
use OpenTelemetry\Contrib\Otlp\LogsExporter;
use OpenTelemetry\Contrib\Otlp\MetricExporter;
use OpenTelemetry\Contrib\Otlp\SpanExporter;
use OpenTelemetry\SDK\Common\Attribute\Attributes;
use OpenTelemetry\SDK\Common\Export\Http\PsrTransportFactory;
use OpenTelemetry\SDK\Common\Export\TransportInterface;
use OpenTelemetry\SDK\Common\Time\ClockFactory;
use OpenTelemetry\SDK\Logs\LoggerProvider;
use OpenTelemetry\SDK\Logs\Processor\BatchLogRecordProcessor;
use OpenTelemetry\SDK\Metrics\Data\Temporality;
use OpenTelemetry\SDK\Metrics\MeterProvider;
use OpenTelemetry\SDK\Metrics\MetricReader\ExportingReader;
use OpenTelemetry\SDK\Resource\ResourceInfo;
use OpenTelemetry\SDK\Sdk;
use OpenTelemetry\SDK\Trace\SpanProcessor\BatchSpanProcessor;
use OpenTelemetry\SDK\Trace\TracerProvider;

final class Watchtower
{
    /** Builds a tracer provider exporting OTLP/HTTP protobuf to Watchtower. */
    public static function init(Config $cfg): TracerProvider
    {
        $exporter = new BufferingExporter(new SpanExporter(self::transport($cfg, 'traces')), new OfflineBuffer());
        $auth = $cfg->headers()['authorization'] ?? '';
        if (getenv('WT_CAPTURE_RULES') === '1' && $auth !== '') {
            Payload::start(getenv('WT_API_URL') ?: $cfg->endpoint, substr($auth, 7), $cfg->service);
        }
        return TracerProvider::builder()
            ->setResource(self::resource($cfg))
            ->addSpanProcessor(new RedactingProcessor(new BatchSpanProcessor($exporter, ClockFactory::getDefault()), $cfg->redactor))
            ->build();
    }

    /** Logger provider exporting OTLP/HTTP logs (buffered like spans), or null when logs are off (WATCHTOWER_LOGS). */
    public static function logs(Config $cfg): ?LoggerProvider
    {
        if (!self::on('WATCHTOWER_LOGS', 'OTEL_LOGS_EXPORTER')) {
            return null;
        }
        $exporter = new BufferingExporter(new LogsExporter(self::transport($cfg, 'logs')), new OfflineBuffer());
        return LoggerProvider::builder()
            ->setResource(self::resource($cfg))
            ->addLogRecordProcessor(new BatchLogRecordProcessor($exporter, ClockFactory::getDefault()))
            ->build();
    }

    /**
     * Meter provider exporting OTLP/HTTP metrics on forceFlush/shutdown (PHP has no background reader),
     * or null when metrics are off (WATCHTOWER_METRICS). Delta temporality unless
     * OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE=cumulative.
     */
    public static function metrics(Config $cfg): ?MeterProvider
    {
        if (!self::on('WATCHTOWER_METRICS', 'OTEL_METRICS_EXPORTER')) {
            return null;
        }
        $pref = strtolower(trim((string) getenv('OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE')));
        $exporter = new MetricExporter(self::transport($cfg, 'metrics'), $pref === 'cumulative' ? Temporality::CUMULATIVE : Temporality::DELTA);
        return MeterProvider::builder()
            ->setResource(self::resource($cfg))
            ->addReader(new ExportingReader($exporter))
            ->build();
    }

    /** Traces, logs and metrics registered as the global OpenTelemetry providers, flushed at shutdown. */
    public static function initAll(Config $cfg): Sdk
    {
        $b = Sdk::builder()->setTracerProvider(self::init($cfg))->setAutoShutdown(true);
        if (($lp = self::logs($cfg)) !== null) {
            $b->setLoggerProvider($lp);
        }
        if (($mp = self::metrics($cfg)) !== null) {
            $b->setMeterProvider($mp);
        }
        return $b->buildAndRegisterGlobal();
    }

    /**
     * Monolog handler from open-telemetry/opentelemetry-logger-monolog: records become OTLP log records
     * carrying the active trace and span ids.
     */
    public static function monolog(LoggerProviderInterface $lp, int|string $level = 'debug'): MonologHandler
    {
        $h = new MonologHandler($lp, $level);
        // debug_backtrace per record is not free: stamp code.filepath/code.lineno only when WATCHTOWER_LOG_CALLER=1
        if (getenv('WATCHTOWER_LOG_CALLER') === '1') {
            $h->pushProcessor(static function ($record) {
                $c = self::callerOf(debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 20));

                return $c === null ? $record : $record->with(context: $record->context + ['code.filepath' => $c[0], 'code.lineno' => $c[1]]);
            });
        }

        return $h;
    }

    /**
     * File and line where application code called the logger: the last of the leading Monolog,
     * OpenTelemetry or Watchtower frames, whose file/line is its call site.
     *
     * @param list<array<string, mixed>> $trace
     * @return array{0: string, 1: int}|null
     */
    public static function callerOf(array $trace): ?array
    {
        $ours = static fn (array $f): bool => preg_match('/^(Monolog|OpenTelemetry|Watchtower)\\\\/', (string) ($f['class'] ?? '')) === 1;
        foreach ($trace as $i => $f) {
            if ($ours($f) && isset($f['file']) && (!isset($trace[$i + 1]) || !$ours($trace[$i + 1]))) {
                return [(string) $f['file'], (int) ($f['line'] ?? 0)];
            }
        }

        return null;
    }

    /** WATCHTOWER_* switch: on unless off/false/0/no; OTEL_*_EXPORTER=none also turns it off. */
    public static function on(string $env, string $otelExporter): bool
    {
        if (strtolower(trim((string) getenv($otelExporter))) === 'none') {
            return false;
        }
        return !in_array(strtolower(trim((string) (getenv($env) ?: 'on'))), ['off', 'false', '0', 'no'], true);
    }

    private static function transport(Config $cfg, string $signal): TransportInterface
    {
        return PsrTransportFactory::discover()->create($cfg->endpoint . '/v1/' . $signal, 'application/x-protobuf', $cfg->headers());
    }

    private static function resource(Config $cfg): ResourceInfo
    {
        return ResourceInfo::create(Attributes::create($cfg->resourceAttributes()));
    }
}
