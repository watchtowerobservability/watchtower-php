<?php

declare(strict_types=1);

namespace Watchtower\Tests;

use PHPUnit\Framework\TestCase;
use Watchtower\Config;
use Watchtower\OfflineBuffer;

final class InitTest extends TestCase
{
    private const KEY = 'wtk_example_not_a_real_key'; // fake

    public function testExportsWithKeyHeader(): void
    {
        $c = new Config('svc', null, self::KEY);
        $this->assertSame(['authorization' => 'Bearer ' . self::KEY], $c->headers());
        $this->assertSame('http://localhost:4318', $c->endpoint);
        $this->assertStringNotContainsString(self::KEY, json_encode($c->__debugInfo()));
    }

    public function testWtAttributesDropped(): void
    {
        $c = new Config('svc', 'https://x.example/', null, ['wt.project_id' => 'p', 'env' => 'prod']);
        $this->assertSame(['service.name' => 'svc', 'env' => 'prod'], $c->resourceAttributes());
        $this->assertSame('https://x.example', $c->endpoint);
        $this->assertSame(['a' => 'b'], Config::redact(['wt.tenant' => 't', 'a' => 'b']));
    }

    public function testRedactionHookMasksAndDrops(): void
    {
        $hook = static fn (string $k, mixed $v) => match ($k) {
            'password' => null,
            'email' => '[redacted]',
            default => $v,
        };
        $this->assertSame(['email' => '[redacted]', 'n' => 1], Config::redact(['password' => 'x', 'email' => 'a@b.c', 'n' => 1], $hook));
    }

    public function testBufferDropsOldest(): void
    {
        $b = new OfflineBuffer(2);
        foreach ([1, 2, 3] as $i) {
            $b->push($i);
        }
        $this->assertSame([2, 3], $b->drain());
    }
}
