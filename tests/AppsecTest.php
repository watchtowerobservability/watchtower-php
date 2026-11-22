<?php

declare(strict_types=1);

namespace Watchtower\Tests;

use PHPUnit\Framework\TestCase;
use Watchtower\Appsec;

final class AppsecTest extends TestCase
{
    private function waf(string $mode = 'block'): Appsec
    {
        return new Appsec([
            'mode' => $mode,
            'rules' => [
                ['id' => 'sqli', 'category' => 'injection', 'pattern' => "union\\s+select|' or 1=1", 'fields' => ['path', 'query']],
                ['id' => 'bad', 'category' => 'x', 'pattern' => '(', 'fields' => ['path']],
            ],
            'denylist' => ['ip' => [['value' => '203.0.113.9', 'expires_at' => 4102444800]], 'user' => [['value' => 'mallory']]],
        ]);
    }

    /** @param array<string, string> $extra */
    private function server(string $query, array $extra = []): array
    {
        return array_merge(['REQUEST_URI' => "/items?{$query}", 'QUERY_STRING' => $query, 'REMOTE_ADDR' => '10.0.0.1'], $extra);
    }

    public function testPercentEncodedInjectionIsBlockedAndCleanRequestsPass(): void
    {
        $d = $this->waf()->inspect(Appsec::fromServer($this->server('q=1%27%20OR%201%3D1')));
        $this->assertSame(['block', 'sqli'], [$d['action'], $d['rule_id']]);
        $this->assertSame('allow', $this->waf()->inspect(Appsec::fromServer($this->server('q=shoes')))['action']);
    }

    public function testMonitorModeFlagsAndDenylistAlwaysBlocks(): void
    {
        $d = $this->waf('monitor')->inspect(Appsec::fromServer($this->server('q=1+union+select+1')));
        $this->assertSame('monitor', $d['action']);
        $d = $this->waf('monitor')->inspect(Appsec::fromServer($this->server('q=ok', ['HTTP_X_FORWARDED_FOR' => '203.0.113.9'])));
        $this->assertSame(['block', 'denylist'], [$d['action'], $d['rule_id']]);
        $this->assertTrue($this->waf()->userBlocked('mallory'));
        $this->assertFalse((new Appsec(null))->isActive());
    }
}
