<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Storage;

class RedisStorage implements StorageInterface
{
    private \Redis $redis;
    private string $prefix;

    public function __construct(array $config)
    {
        if (!extension_loaded('redis')) {
            throw new \RuntimeException('Redis extension is not loaded. Install php-redis or choose a different storage type.');
        }

        $this->prefix = $config['prefix'] ?? 'security:';

        $this->redis = new \Redis();
        $host = $config['host'] ?? '127.0.0.1';
        $port = (int) ($config['port'] ?? 6379);
        $timeout = (float) ($config['timeout'] ?? 2.0);
        $password = $config['password'] ?? null;
        $database = (int) ($config['database'] ?? 0);

        $connected = @$this->redis->connect($host, $port, $timeout);
        if (!$connected) {
            throw new \RuntimeException("Failed to connect to Redis at {$host}:{$port}");
        }

        if ($password !== null && $password !== '') {
            $this->redis->auth($password);
        }

        if ($database !== 0) {
            $this->redis->select($database);
        }
    }

    public function get(string $key): mixed
    {
        $value = $this->redis->get($this->prefix . $key);
        if ($value === false) {
            return null;
        }
        $decoded = json_decode($value, true);
        return $decoded !== null ? $decoded : $value;
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
