<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security;

use Erikwang2013\Security\Storage\StorageInterface;

class IpBlacklist
{
    private int $maxAttempts;
    private int $windowSeconds;
    private int $banDurationSeconds;

    public function __construct(
        array $config,
        private StorageInterface $storage,
    ) {
        $this->maxAttempts = (int) ($config['max_attempts'] ?? 5);
        $this->windowSeconds = (int) ($config['window_seconds'] ?? 60);
        $this->banDurationSeconds = (int) ($config['ban_duration_seconds'] ?? 900);
    }

    public function isBanned(string $ip): bool
    {
        $entry = $this->storage->get($ip);
        if ($entry === null) {
            return false;
        }

        $now = time();
        if (($entry['banned_until'] ?? 0) > $now) {
            return true;
        }

        // Ban expired, clean up
        if (($entry['banned_until'] ?? 0) > 0 && $entry['banned_until'] <= $now) {
            $this->storage->delete($ip);
        }

        return false;
    }

    public function record(string $ip): ?array
    {
        $now = time();
        $entry = $this->storage->get($ip);

        // Reset if window expired
        if ($entry !== null && ($entry['last_seen'] ?? 0) < $now - $this->windowSeconds) {
            $entry = null;
        }

        if ($entry === null) {
            $entry = [
                'count' => 1,
                'first_seen' => $now,
                'last_seen' => $now,
                'banned_until' => 0,
            ];
        } else {
            $entry['count']++;
            $entry['last_seen'] = $now;
        }

        // Check if threshold exceeded
        if ($entry['count'] >= $this->maxAttempts) {
            $entry['banned_until'] = $now + $this->banDurationSeconds;
        }

        $this->storage->set($ip, $entry);

        return $entry['banned_until'] > $now ? $entry : null;
    }

    public function getBanInfo(string $ip): ?array
    {
        $entry = $this->storage->get($ip);
        if ($entry === null || ($entry['banned_until'] ?? 0) <= time()) {
            return null;
        }
        return $entry;
    }

    /**
     * Clear all data (for testing).
     */
    public function reset(): void
    {
        $this->storage->clear();
    }
}
