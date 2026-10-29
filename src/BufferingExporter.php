<?php

declare(strict_types=1);

namespace Watchtower;

use OpenTelemetry\SDK\Common\Future\CancellationInterface;
use OpenTelemetry\SDK\Common\Future\CompletedFuture;
use OpenTelemetry\SDK\Common\Future\FutureInterface;
use OpenTelemetry\SDK\Trace\SpanExporterInterface;

/** Wraps the OTLP exporter; batches that fail are retried with the next export. */
final class BufferingExporter implements SpanExporterInterface
{
    public function __construct(private readonly SpanExporterInterface $inner, private readonly OfflineBuffer $buffer)
    {
    }

    public function export(iterable $batch, ?CancellationInterface $cancellation = null): FutureInterface
    {
        $ok = true;
        foreach ([...$this->buffer->drain(), $batch] as $b) {
            if (!$this->inner->export($b, $cancellation)->await()) {
                $this->buffer->push($b);
                $ok = false;
            }
        }
        return new CompletedFuture($ok);
    }

    public function shutdown(?CancellationInterface $cancellation = null): bool
    {
        return $this->inner->shutdown($cancellation);
    }

    public function forceFlush(?CancellationInterface $cancellation = null): bool
    {
        return $this->inner->forceFlush($cancellation);
    }
}
