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
        $value = $this->redis->get($this->prefix . $key);
        if ($value === false) {
            return null;
        }
        $decoded = json_decode($value, true);
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
        $iterator = null;

        while (true) {
            $keys = $this->redis->scan($iterator, $this->prefix . '*');
            if ($keys === false) {
                break;
            }
            foreach ($keys as $fullKey) {
                $shortKey = substr($fullKey, $prefixLen);
                $result[$shortKey] = $this->get($shortKey);
            }
            if ($iterator === 0) {
                break;
            }
        }

        return $result;
    }

    public function clear(): void
    {
        $iterator = null;
        while (true) {
            $keys = $this->redis->scan($iterator, $this->prefix . '*');
            if ($keys === false) {
                break;
            }
            if (!empty($keys)) {
                $this->redis->del($keys);
            }
            if ($iterator === 0) {
                break;
            }
        }
    }
}
