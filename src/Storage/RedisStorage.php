<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Storage;

class RedisStorage implements StorageInterface
{
    private string $prefix;

    public function __construct(
        private \Redis $redis,
        string $prefix = 'security:',
    ) {
        $this->prefix = $prefix;
    }

    public function get(string $key): mixed
    {
        return self::decode($this->redis->get($this->prefix . $key));
    }

    private static function decode(mixed $value): mixed
    {
        if ($value === false || $value === null) {
            return null;
        }
        $decoded = json_decode((string) $value, true);
        // 'null' is a valid stored JSON value; only fall back to raw when it isn't
        return $decoded !== null || $value === 'null' ? $decoded : $value;
    }

    public function set(string $key, mixed $value): void
    {
        $encoded = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $this->redis->set($this->prefix . $key, $encoded !== false ? $encoded : (string) $value);
    }

    public function delete(string $key): void
    {
        $this->redis->del($this->prefix . $key);
    }

    public function has(string $key): bool
    {
        return $this->redis->exists($this->prefix . $key) > 0;
    }

    public function all(): array
    {
        $result = [];
        $prefixLen = strlen($this->prefix);
        $this->eachKey(function ($keys) use (&$result, $prefixLen) {
            if (empty($keys)) {
                return;
            }
            // One MGET per SCAN batch instead of a GET per key: at 5000 keys
            // that is a single round trip instead of 5000.
            $values = $this->redis->mGet($keys);
            foreach (array_values($keys) as $i => $fullKey) {
                $result[substr((string) $fullKey, $prefixLen)] = self::decode($values[$i] ?? null);
            }
        });
        return $result;
    }

    public function clear(): void
    {
        $this->eachKey(function ($keys) {
            if (!empty($keys)) {
                $this->redis->del($keys);
            }
        });
    }

    private function eachKey(callable $fn): void
    {
        $iterator = null;
        while (true) {
            $keys = $this->redis->scan($iterator, $this->prefix . '*');
            if ($keys === false) {
                break;
            }
            $fn($keys);
            if ($iterator === 0) {
                break;
            }
        }
    }
}
