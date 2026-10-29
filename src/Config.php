<?php

declare(strict_types=1);

namespace Watchtower;

/** Endpoint default, key header and wt.*-safe attributes. No product logic. */
final class Config
{
    public const DEFAULT_ENDPOINT = 'http://localhost:4318';

    public readonly string $endpoint;

    /** @param array<string, scalar> $resource @param (callable(string, mixed): mixed)|null $redactor null return drops/masks */
    public function __construct(
        public readonly string $service,
        ?string $endpoint = null,
        private readonly ?string $key = null,
        public readonly array $resource = [],
        public readonly mixed $redactor = null,
    ) {
        $this->endpoint = rtrim($endpoint ?? self::DEFAULT_ENDPOINT, '/');
    }

    /** Reads WT_ENDPOINT and WT_INGEST_KEY. */
    public static function fromEnv(string $service, array $resource = [], mixed $redactor = null): self
    {
        $e = getenv('WT_ENDPOINT');
        $k = getenv('WT_INGEST_KEY');
        return new self($service, $e === false || $e === '' ? null : $e, $k === false || $k === '' ? null : $k, $resource, $redactor);
    }

    /** @return array<string, string> */
    public function headers(): array
    {
        return $this->key === null ? [] : ['authorization' => 'Bearer ' . $this->key];
    }

    /** @return array<string, scalar> */
    public function resourceAttributes(): array
    {
        return ['service.name' => $this->service] + self::dropReserved($this->resource);
    }

    /** @param array<string, mixed> $attrs @return array<string, mixed> */
    public static function dropReserved(array $attrs): array
    {
        return array_filter($attrs, static fn ($k) => !str_starts_with((string) $k, 'wt.'), ARRAY_FILTER_USE_KEY);
    }

    /**
     * Drops wt.* and applies the hook; a null result from the hook drops the attribute.
     * @param array<string, mixed> $attrs @return array<string, mixed>
     */
    public static function redact(array $attrs, ?callable $hook = null): array
    {
        $out = [];
        foreach (self::dropReserved($attrs) as $k => $v) {
            $v = $hook === null ? $v : $hook((string) $k, $v);
            if ($v !== null) {
                $out[$k] = $v;
            }
        }
        return $out;
    }

    public function __debugInfo(): array
    {
        return ['service' => $this->service, 'endpoint' => $this->endpoint, 'key' => '***'];
    }
}
