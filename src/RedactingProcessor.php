<?php

declare(strict_types=1);

namespace Watchtower;

use OpenTelemetry\API\Trace\SpanInterface;
use OpenTelemetry\Context\ContextInterface;
use OpenTelemetry\SDK\Common\Future\CancellationInterface;
use OpenTelemetry\SDK\Trace\ReadableSpanInterface;
use OpenTelemetry\SDK\Trace\ReadWriteSpanInterface;
use OpenTelemetry\SDK\Trace\SpanProcessorInterface;

/**
 * Applies the redaction hook just before the span ends.
 * shortcut: the PHP API cannot delete an attribute, so a dropped one is overwritten with
 * "[redacted]"; upgrade when the SDK exposes attribute removal.
 */
final class RedactingProcessor implements SpanProcessorInterface
{
    public function __construct(private readonly SpanProcessorInterface $next, private readonly mixed $hook = null)
    {
    }

    public function onStart(ReadWriteSpanInterface $span, ContextInterface $parentContext): void
    {
        $this->next->onStart($span, $parentContext);
    }

    public function onEnding(ReadWriteSpanInterface $span): void
    {
        if ($this->hook === null) {
            return;
        }
        $attrs = $span->toSpanData()->getAttributes()->toArray();
        $kept = Config::redact($attrs, $this->hook);
        foreach ($attrs as $k => $_) {
            $span->setAttribute((string) $k, $kept[$k] ?? '[redacted]');
        }
    }

    public function onEnd(ReadableSpanInterface $span): void
    {
        $this->next->onEnd($span);
    }

    public function forceFlush(?CancellationInterface $cancellation = null): bool
    {
        return $this->next->forceFlush($cancellation);
    }

    public function shutdown(?CancellationInterface $cancellation = null): bool
    {
        return $this->next->shutdown($cancellation);
    }
}
