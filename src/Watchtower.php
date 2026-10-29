<?php

declare(strict_types=1);

namespace Watchtower;

use OpenTelemetry\Contrib\Otlp\SpanExporter;
use OpenTelemetry\SDK\Common\Attribute\Attributes;
use OpenTelemetry\SDK\Common\Export\Http\PsrTransportFactory;
use OpenTelemetry\SDK\Resource\ResourceInfo;
use OpenTelemetry\SDK\Trace\SpanProcessor\BatchSpanProcessor;
use OpenTelemetry\SDK\Trace\TracerProvider;
use OpenTelemetry\SDK\Common\Time\ClockFactory;

final class Watchtower
{
    /** Builds a tracer provider exporting OTLP/HTTP protobuf to Watchtower. */
    public static function init(Config $cfg): TracerProvider
    {
        $transport = PsrTransportFactory::discover()->create(
            $cfg->endpoint . '/v1/traces',
            'application/x-protobuf',
            $cfg->headers(),
        );
        $exporter = new BufferingExporter(new SpanExporter($transport), new OfflineBuffer());
        return TracerProvider::builder()
            ->setResource(ResourceInfo::create(Attributes::create($cfg->resourceAttributes())))
            ->addSpanProcessor(new RedactingProcessor(new BatchSpanProcessor($exporter, ClockFactory::getDefault()), $cfg->redactor))
            ->build();
    }
}
