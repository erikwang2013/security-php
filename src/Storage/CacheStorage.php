<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Storage;

class CacheStorage implements StorageInterface
{
    private string $dir;
    private string $prefix;

    public function __construct(array $config)
    {
        $this->prefix = $config['prefix'] ?? 'security_';
        $basePath = ($config['path'] ?? '') ?: sys_get_temp_dir();
        $this->dir = rtrim($basePath, '/') . '/security_cache';
    }

    public function get(string $key): mixed
    {
        $path = $this->path($key);
        if (!file_exists($path)) {
            return null;
        }

        $contents = @file_get_contents($path);
        if ($contents === false) {
            return null;
        }

        $data = @unserialize($contents);
        if ($data === false) {
            return null;
        }

        // Check expiry: stored as [expiry, value]
        if (is_array($data) && count($data) === 2 && isset($data[0], $data[1])) {
            if ($data[0] > 0 && $data[0] < time()) {
                @unlink($path);
                return null;
            }
            return $data[1];
        }

        return $data;
    }

    public function set(string $key, mixed $value): void
    {
        $this->ensureDir();
        $path = $this->path($key);
        $data = serialize([0, $value]); // [expiry=0 (never), value]

        $tmp = $path . '.' . uniqid('', true);
        if (@file_put_contents($tmp, $data, LOCK_EX) !== false) {
            @rename($tmp, $path);
        }
    }

    public function delete(string $key): void
    {
        $path = $this->path($key);
        if (file_exists($path)) {
            @unlink($path);
        }
    }

    public function has(string $key): bool
    {
        return $this->get($key) !== null;
    }

    public function all(): array
    {
        if (!is_dir($this->dir)) {
            return [];
        }

        $result = [];
        $files = glob($this->dir . '/' . $this->prefix . '*');
        if ($files === false) {
            return [];
        }

        foreach ($files as $file) {
            $name = basename($file);
            $key = substr($name, strlen($this->prefix));
            $value = $this->get($key);
            if ($value !== null) {
                $result[$key] = $value;
            }
        }

        return $result;
    }

    public function clear(): void
    {
        if (!is_dir($this->dir)) {
            return;
        }

        $files = glob($this->dir . '/' . $this->prefix . '*');
        if ($files === false) {
            return;
        }

        foreach ($files as $file) {
            @unlink($file);
        }
    }

    private function path(string $key): string
    {
        return $this->dir . '/' . $this->prefix . md5($key);
    }

    private function ensureDir(): void
    {
        if (!is_dir($this->dir)) {
            @mkdir($this->dir, 0755, true);
        }
    }
}
