<?php

declare(strict_types=1);

namespace Watchtower;

/**
 * The probe condition subset shared with every Watchtower agent (comparisons, &&, ||, !, ==, in,
 * contains, literals, dotted names). It has no calls, so a probe can never run code.
 */
final class ProbeCondition
{
    private const TOKEN = '/\G\s*(&&|\|\||==|!=|<=|>=|[<>!()\[\],]|\'[^\']*\'|"[^"]*"|-?\d+(?:\.\d+)?|[A-Za-z_][\w.]*)/';

    /** @var list<string> */
    private array $toks = [];
    private int $i = 0;
    /** @var \Closure(array<string, mixed>): mixed */
    private \Closure $root;

    /** @throws \InvalidArgumentException outside the subset */
    public function __construct(string $src)
    {
        $src = rtrim($src);
        if (trim($src) === '') {
            $this->root = static fn (array $v): bool => true;
            return;
        }
        $pos = 0;
        while ($pos < strlen($src)) {
            if (preg_match(self::TOKEN, $src, $m, 0, $pos) !== 1) {
                throw new \InvalidArgumentException('bad condition');
            }
            $this->toks[] = $m[1];
            $pos += strlen($m[0]);
        }
        $this->root = $this->orExpr();
        if ($this->i !== count($this->toks)) {
            throw new \InvalidArgumentException('bad condition');
        }
    }

    /** @param array<string, mixed> $vars */
    public function matches(array $vars): bool
    {
        return (bool) ($this->root)($vars);
    }

    /** `a.b.c` over arrays and public properties; null when missing. */
    public static function lookup(mixed $v, string $name): mixed
    {
        foreach (explode('.', $name) as $k) {
            if (is_array($v)) {
                $v = $v[$k] ?? null;
            } elseif (is_object($v) && isset($v->{$k})) {
                $v = $v->{$k};
            } else {
                return null;
            }
        }
        return $v;
    }

    private function peek(): ?string
    {
        return $this->toks[$this->i] ?? null;
    }

    private function eat(string $s): bool
    {
        if ($this->peek() === $s) {
            $this->i++;
            return true;
        }
        return false;
    }

    private static function lit(string $x): mixed
    {
        return match (true) {
            $x === 'true' => true,
            $x === 'false' => false,
            $x === 'null' => null,
            $x[0] === "'" || $x[0] === '"' => substr($x, 1, -1),
            str_contains($x, '.') => (float) $x,
            default => (int) $x,
        };
    }

    private function atom(): \Closure
    {
        $x = $this->peek() ?? throw new \InvalidArgumentException('bad condition');
        $this->i++;
        if ($x === '(') {
            $e = $this->orExpr();
            if (!$this->eat(')')) {
                throw new \InvalidArgumentException('bad condition');
            }
            return $e;
        }
        if ($x === '[') {
            $items = [];
            while ($this->peek() !== ']') {
                $n = $this->peek() ?? throw new \InvalidArgumentException('bad condition');
                $this->i++;
                if ($n !== ',') {
                    $items[] = self::lit($n);
                }
            }
            $this->i++;
            return static fn (array $v): array => $items;
        }
        if (str_contains("'\"-0123456789", $x[0]) || in_array($x, ['true', 'false', 'null'], true)) {
            $val = self::lit($x);
            return static fn (array $v): mixed => $val;
        }
        if ($this->peek() === '(') {
            throw new \InvalidArgumentException('function calls are not allowed');
        }
        return static fn (array $v): mixed => self::lookup($v, $x);
    }

    private function cmp(): \Closure
    {
        $a = $this->atom();
        foreach (['==', '!=', '<=', '>=', '<', '>', 'in', 'contains'] as $op) {
            if ($this->eat($op)) {
                $b = $this->atom();
                return static fn (array $v): bool => self::compare($op, $a($v), $b($v));
            }
        }
        return $a;
    }

    private function notExpr(): \Closure
    {
        if ($this->eat('!')) {
            $n = $this->notExpr();
            return static fn (array $v): bool => !$n($v);
        }
        return $this->cmp();
    }

    private function andExpr(): \Closure
    {
        $left = $this->notExpr();
        while ($this->eat('&&')) {
            [$l, $r] = [$left, $this->notExpr()];
            $left = static fn (array $v): bool => (bool) $l($v) && (bool) $r($v);
        }
        return $left;
    }

    private function orExpr(): \Closure
    {
        $left = $this->andExpr();
        while ($this->eat('||')) {
            [$l, $r] = [$left, $this->andExpr()];
            $left = static fn (array $v): bool => (bool) $l($v) || (bool) $r($v);
        }
        return $left;
    }

    private static function compare(string $op, mixed $x, mixed $y): bool
    {
        return match ($op) {
            '==' => $x === $y || (is_numeric($x) && is_numeric($y) && $x == $y),
            '!=' => !self::compare('==', $x, $y),
            'in' => is_array($y) && in_array($x, $y, true),
            'contains' => is_string($x) && is_string($y) && str_contains($x, $y),
            default => (is_int($x) || is_float($x)) && (is_int($y) || is_float($y)) && match ($op) {
                '<' => $x < $y, '<=' => $x <= $y, '>' => $x > $y, default => $x >= $y,
            },
        };
    }
}
