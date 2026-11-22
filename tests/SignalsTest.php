<?php

declare(strict_types=1);

namespace Watchtower\Tests;

use Monolog\Logger;
use OpenTelemetry\API\Trace\SpanContextInterface;
use OpenTelemetry\SDK\Trace\TracerProvider;
use PHPUnit\Framework\TestCase;
use Watchtower\Config;
use Watchtower\Watchtower;

/** Logs and metrics reach a fake OTLP endpoint (php -S); log records carry the active trace and span ids. */
final class SignalsTest extends TestCase
{
    /** @var resource|null */
    private $server;
    private string $log;
    private string $url;

    protected function setUp(): void
    {
        $probe = stream_socket_server('tcp://127.0.0.1:0');
        $port = (int) substr((string) stream_socket_get_name($probe, false), strrpos((string) stream_socket_get_name($probe, false), ':') + 1);
        fclose($probe);
        $this->log = tempnam(sys_get_temp_dir(), 'wt-otlp-');
        $this->url = "http://127.0.0.1:$port";
        $env = ['WT_OTLP_LOG' => $this->log] + getenv();
        $this->server = proc_open([PHP_BINARY, '-S', "127.0.0.1:$port", __DIR__ . '/fixtures/otlp_router.php'],
            [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes, null, $env);
        for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $port); $i++) {
            usleep(100_000);
        }
    }

    protected function tearDown(): void
    {
        if (is_resource($this->server)) {
            proc_terminate($this->server);
            proc_close($this->server);
        }
        @unlink($this->log);
    }

    /** @return list<array{0: string, 1: string, 2: string}> */
    private function requests(): array
    {
        $out = [];
        foreach (file($this->log, FILE_IGNORE_NEW_LINES) ?: [] as $line) {
            [$path, $auth, $body] = explode(' ', $line);
            $out[] = [$path, str_replace('_', ' ', $auth), (string) base64_decode($body)];
        }
        return $out;
    }

    private function body(string $path): string
    {
        return implode('', array_map(static fn ($r) => $r[2], array_filter($this->requests(), static fn ($r) => $r[0] === $path)));
    }

    public function testMonologRecordsCarryTraceIdsAndMetricsExport(): void
    {
        $cfg = new Config('svc', $this->url, 'wtk_example_not_a_real_key');
        $lp = Watchtower::logs($cfg);
        $mp = Watchtower::metrics($cfg);
        $this->assertNotNull($lp);
        $this->assertNotNull($mp);
        $logger = new Logger('app', [Watchtower::monolog($lp)]);
        $span = (new TracerProvider())->getTracer('t')->spanBuilder('op')->startSpan();
        $scope = $span->activate();
        try {
            $logger->warning('hello from monolog');
            $ctx = $span->getContext();
        } finally {
            $scope->detach();
            $span->end();
        }
        $mp->getMeter('t')->createCounter('jobs.done')->add(3);
        $lp->forceFlush();
        $mp->forceFlush();

        $logs = $this->body('/v1/logs');
        $this->assertStringContainsString('hello from monolog', $logs);
        $this->assertInstanceOf(SpanContextInterface::class, $ctx);
        $this->assertStringContainsString($ctx->getTraceIdBinary(), $logs, 'log record carries the trace id');
        $this->assertStringContainsString($ctx->getSpanIdBinary(), $logs, 'log record carries the span id');
        $this->assertStringContainsString('jobs.done', $this->body('/v1/metrics'));
        foreach ($this->requests() as [, $auth]) {
            $this->assertSame('Bearer wtk_example_not_a_real_key', $auth);
        }
    }

    public function testSwitches(): void
    {
        putenv('WATCHTOWER_METRICS=off');
        try {
            $this->assertNull(Watchtower::metrics(new Config('svc', $this->url)));
        } finally {
            putenv('WATCHTOWER_METRICS');
        }
        putenv('OTEL_LOGS_EXPORTER=none');
        try {
            $this->assertFalse(Watchtower::on('WATCHTOWER_LOGS', 'OTEL_LOGS_EXPORTER'));
        } finally {
            putenv('OTEL_LOGS_EXPORTER');
        }
        $this->assertTrue(Watchtower::on('WATCHTOWER_LOGS', 'OTEL_LOGS_EXPORTER'));
    }

    public function testCallerOfFindsTheApplicationCallSite(): void
    {
        $trace = [
            ['class' => 'Monolog\\Handler\\AbstractProcessingHandler', 'file' => '/vendor/monolog/Logger.php', 'line' => 1],
            ['class' => 'Monolog\\Logger', 'file' => '/srv/app/Cart.php', 'line' => 42],
            ['class' => 'App\\Cart', 'file' => '/srv/app/index.php', 'line' => 7],
        ];
        $this->assertSame(['/srv/app/Cart.php', 42], Watchtower::callerOf($trace));
        $this->assertNull(Watchtower::callerOf([]));
    }
}
