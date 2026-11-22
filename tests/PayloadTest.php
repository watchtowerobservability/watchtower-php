<?php

declare(strict_types=1);

namespace Watchtower\Tests;

use OpenTelemetry\SDK\Trace\SpanExporter\InMemoryExporter;
use OpenTelemetry\SDK\Trace\SpanProcessor\SimpleSpanProcessor;
use OpenTelemetry\SDK\Trace\TracerProvider;
use PHPUnit\Framework\TestCase;
use Watchtower\Payload;

final class PayloadTest extends TestCase
{
    private function attrs(callable $fn): array
    {
        $mem = new InMemoryExporter();
        $tp = new TracerProvider(new SimpleSpanProcessor($mem));
        $span = $tp->getTracer('t')->spanBuilder('req')->startSpan();
        $fn($span);
        $span->end();
        return $mem->getSpans()[0]->getAttributes()->toArray();
    }

    protected function tearDown(): void
    {
        Payload::setRules([]);
    }

    public function testBodiesAreCappedRedactedAndRouteScoped(): void
    {
        Payload::setRules([['route' => '/api/*', 'body_bytes' => 40]]);
        $body = '{"user":"a@b.io","password":"hunter2","card":"4111 1111 1111 1111"}';
        $a = $this->attrs(fn ($s) => Payload::record($s, '/api/login', 'application/json', $body, 'image/png', 'png'));
        $this->assertLessThanOrEqual(40, strlen($a['http.request.body']));
        $this->assertStringNotContainsString('hunter2', $a['http.request.body']);
        $this->assertStringNotContainsString('a@b.io', $a['http.request.body']);
        $this->assertArrayNotHasKey('http.response.body', $a);
        $this->assertSame([], $this->attrs(fn ($s) => Payload::record($s, '/health', 'text/plain', 'x', '', '')));
        $this->assertSame('4111 1111 1111 1112', Payload::redact('4111 1111 1111 1112'));
    }

    public function testGraphqlOperationAndDocument(): void
    {
        Payload::setRules([['graphql_query' => true]]);
        $q = json_encode(['query' => "# c\nmutation AddUser { add(email: \"x@y.io\") { id } }"]);
        $a = $this->attrs(fn ($s) => Payload::record($s, '/graphql', 'application/json', $q, '', ''));
        $this->assertSame('mutation', $a['graphql.operation.type']);
        $this->assertSame('AddUser', $a['graphql.operation.name']);
        $this->assertStringNotContainsString('x@y.io', $a['graphql.document']);
        $this->assertNull(Payload::graphqlOp('shoes'));
    }
}
