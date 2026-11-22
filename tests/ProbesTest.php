<?php

declare(strict_types=1);

namespace Watchtower\Tests;

use PHPUnit\Framework\TestCase;
use Watchtower\ProbeCondition;
use Watchtower\Probes;

final class ProbesTest extends TestCase
{
    public function testConditionSubsetHasNoCalls(): void
    {
        $c = new ProbeCondition("user.plan == 'pro' && total >= 2 && !(region in ['eu'])");
        $this->assertTrue($c->matches(['user' => ['plan' => 'pro'], 'total' => 3, 'region' => 'us']));
        $this->assertFalse($c->matches(['user' => ['plan' => 'free'], 'total' => 3, 'region' => 'us']));
        $this->assertTrue((new ProbeCondition(''))->matches([]));
        $this->assertTrue((new ProbeCondition("name contains 'bo'"))->matches(['name' => 'bob']));
        foreach (["system('id')", 'a ==', 'a; b'] as $bad) {
            try {
                new ProbeCondition($bad);
                $this->fail("accepted {$bad}");
            } catch (\InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testInstallHooksFunctionProbesOnly(): void
    {
        $hooked = [];
        $p = new Probes(function (?string $class, string $fn, ?\Closure $pre, ?\Closure $post) use (&$hooked): bool {
            $hooked[] = [$class, $fn, $post !== null];
            return true;
        });
        $n = $p->install([
            ['id' => 'a', 'kind' => 'span', 'location' => ['function' => 'App\Billing::charge']],
            ['id' => 'b', 'kind' => 'snapshot', 'location' => ['function' => 'checkout']],
            ['id' => 'c', 'kind' => 'log', 'location' => ['file' => 'x.php', 'line' => 3]],
            ['id' => 'd', 'kind' => 'log', 'location' => ['function' => 'f'], 'condition' => 'len(x) > 1'],
        ]);
        $this->assertSame(2, $n);
        $this->assertSame([['App\Billing', 'charge', true], [null, 'checkout', false]], $hooked);
    }

    public function testArgumentsNamedCapturedAndRendered(): void
    {
        $vars = Probes::named(null, 'str_pad', ['ab', 5, 'x', 0, 'extra']);
        $this->assertSame(['string' => 'ab', 'length' => 5, 'pad_string' => 'x', 'pad_type' => 0, 'arg4' => 'extra'], $vars);
        $snap = Probes::capture(['u' => ['id' => 7, 'n' => ['a' => ['b' => ['c' => 1]]]], 's' => str_repeat('x', 5000)], ['capture' => ['locals_depth' => 2]]);
        $this->assertSame('7', $snap['code.snapshot.u.id']);
        $this->assertSame('[depth limit]', $snap['code.snapshot.u.n.a']);
        $this->assertSame(Probes::VALUE_MAX, strlen($snap['code.snapshot.s']));
        $this->assertSame('u7 paid 3', Probes::render('u{u.id} paid {amount}{missing}', ['u' => ['id' => 7], 'amount' => 3]));
        $tags = Probes::tags(['capture' => ['tags' => [['name' => 'user.id', 'value' => '{u.id}'], ['name' => 'wt.project_id', 'value' => 'x']]]], ['u' => ['id' => 7]]);
        $this->assertSame(['user.id' => '7'], $tags);
    }

    public function testRateLimitConditionAndExpiry(): void
    {
        $t = 120.0;
        $p = new Probes(static fn (): bool => true, static function () use (&$t): float {
            return $t;
        });
        $d = ['id' => 'r', 'max_rate_per_min' => 2, 'expires_at' => 500];
        $c = new ProbeCondition('n > 1');
        $this->assertFalse($p->allowed($d, $c, ['n' => 1]));
        $this->assertTrue($p->allowed($d, $c, ['n' => 2]));
        $this->assertTrue($p->allowed($d, $c, ['n' => 2]));
        $this->assertFalse($p->allowed($d, $c, ['n' => 2]), 'third hit in the minute');
        $t = 185.0;
        $this->assertTrue($p->allowed($d, $c, ['n' => 2]), 'a new minute');
        $t = 600.0;
        $this->assertFalse($p->allowed($d, $c, ['n' => 2]), 'expired');
    }

    public function testSpanHooksPairWithCallsEvenWhenSkipped(): void
    {
        $p = new Probes(static fn (): bool => true);
        [$pre, $post] = $p->handlers(['id' => 's', 'kind' => 'span'], new ProbeCondition('times > 1'));
        $this->assertNotNull($post);
        // Outer call skipped by its condition, inner call traced: posts close in reverse order.
        $pre(null, ['x', 1], null, 'str_repeat');
        $pre(null, ['x', 2], null, 'str_repeat');
        $post(null, [], null, new \RuntimeException('boom'));
        $post(null, [], null, null);
        $post(null, [], null, null); // an unpaired post is harmless
        $this->addToAssertionCount(1);
    }
}
