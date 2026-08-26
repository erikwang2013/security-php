<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Storage;

class FileStorage implements StorageInterface
{
    private string $path;

    public function __construct(array $config)
    {
        $this->path = ($config['path'] ?? '') ?: sys_get_temp_dir() . '/security_storage.json';
    }

    public function get(string $key): mixed
    {
        $data = $this->read();
        return $data[$key] ?? null;
    }

    public function set(string $key, mixed $value): void
    {
        $this->mutate(static fn (array $data) => [$key => $value] + $data);
    }

    public function delete(string $key): void
    {
        $this->mutate(static function (array $data) use ($key) {
            unset($data[$key]);
            return $data;
        });
    }

    /**
     * Atomic read-modify-write under an exclusive lock.
     */
    private function mutate(callable $fn): void
    {
        $dir = dirname($this->path);
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }

        $fp = @fopen($this->path, 'c+');
        if ($fp === false) {
            return;
        }

        if (flock($fp, LOCK_EX)) {
            $raw = stream_get_contents($fp);
            $data = json_decode($raw !== false && $raw !== '' ? $raw : '{}', true);
            if (!is_array($data)) {
                $data = [];
            }
            $data = $fn($data);

            $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if ($json !== false) {
                ftruncate($fp, 0);
                rewind($fp);
                fwrite($fp, $json);
                fflush($fp);
            }
            flock($fp, LOCK_UN);
        }
        fclose($fp);
    }

    public function has(string $key): bool
    {
        $data = $this->read();
        return array_key_exists($key, $data);
    }

    public function all(): array
    {
        return $this->read();
    }

    public function clear(): void
    {
        if (file_exists($this->path)) {
            @unlink($this->path);
        }
    }

    private function read(): array
    {
        if (!file_exists($this->path)) {
            return [];
        }

        $contents = @file_get_contents($this->path);
        if ($contents === false || $contents === '') {
            return [];
        }

        $data = json_decode($contents, true);
        return is_array($data) ? $data : [];
    }
}
