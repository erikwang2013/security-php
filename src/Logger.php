<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security;

class Logger
{
    private string $path;
    private float $maxSize;
    private bool $enabled;
    private int $dedupWindow;
    private array $dedupCache = [];

    public function __construct(array $config)
    {
        $this->enabled = $config['enabled'] ?? true;
        $this->maxSize = (float) ($config['max_size'] ?? 10);
        $this->path = ($config['path'] ?? '') ?: sys_get_temp_dir() . '/security.log';
        $this->dedupWindow = (int) ($config['dedup_seconds'] ?? 5);
    }

    public function log(ThreatResult $threat, array $meta): void
    {
        if (!$this->enabled) {
            return;
        }

        if ($this->isDuplicate($threat, $meta)) {
            return;
        }

        $line = sprintf(
            "[%s] %s %s %s | %s | %s | field=%s payload=%s detail=%s",
            date('Y-m-d H:i:s'),
            $this->sanitize($meta['ip'] ?? '-'),
            $this->sanitize($meta['method'] ?? '-'),
            $this->sanitize($meta['uri'] ?? '-'),
            $this->sanitize($threat->type),
            $threat->severity,
            $this->sanitize($threat->field),
            $this->sanitize($this->truncate($threat->payload, 200)),
            $this->sanitize($threat->detail),
        );

        $fp = @fopen($this->path, 'a');
        if ($fp === false) {
            return;
        }

        $shouldRotate = false;
        if (flock($fp, LOCK_EX)) {
            $stat = fstat($fp);
            $shouldRotate = $stat !== false
                && $this->maxSize > 0
                && $stat['size'] >= (int) ($this->maxSize * 1024 * 1024);
            flock($fp, LOCK_UN);
        }
        fclose($fp);

        if ($shouldRotate) {
            // Rename without holding the lock; a concurrent writer may reopen the old file
            // briefly, but no data is lost — it is just written to the rotated file.
            @rename($this->path, $this->path . '.' . date('YmdHis'));
        }

        // Atomic single-write append (O_APPEND), safe against concurrent loggers
        @file_put_contents($this->path, $line . PHP_EOL, FILE_APPEND | LOCK_EX);
    }

    private function isDuplicate(ThreatResult $threat, array $meta): bool
    {
        if ($this->dedupWindow <= 0) {
            return false;
        }

        $key = md5($threat->type . $threat->field . ($meta['ip'] ?? ''));
        $now = time();

        // Clean expired entries
        foreach ($this->dedupCache as $k => $ts) {
            if ($ts < $now) {
                unset($this->dedupCache[$k]);
            }
        }

        // Prevent unbounded growth in long-running processes
        if (count($this->dedupCache) > 1000) {
            $this->dedupCache = array_slice($this->dedupCache, -500, preserve_keys: true);
        }

        if (isset($this->dedupCache[$key])) {
            return true;
        }

        $this->dedupCache[$key] = $now + $this->dedupWindow;
        return false;
    }

    private function sanitize(string $s): string
    {
        return str_replace(["\n", "\r", '|'], ['\\n', '\\r', ' '], $s);
    }

    private function truncate(string $s, int $max): string
    {
        return strlen($s) > $max ? substr($s, 0, $max) . '...' : $s;
    }
}
