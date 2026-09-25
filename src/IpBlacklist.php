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
        return $this->check($ip) !== null;
    }

    /**
     * Single storage read: returns the ban entry if $ip is banned, null otherwise.
     * Expired bans are cleaned up.
     */
    public function check(string $ip): ?array
    {
        $entry = $this->storage->get($ip);
        // Anything but an array is foreign data: fail closed on the counter,
        // never report a ban from it
        if (!is_array($entry)) {
            return null;
        }

        $now = time();
        $bannedUntil = (int) ($entry['banned_until'] ?? 0);

        if ($bannedUntil > $now) {
            return $entry;
        }

        // Nothing worth keeping: the ban expired, or the counting window ran
        // out below the threshold. Without this the store grows by one key per
        // attacking IP forever.
        if ($bannedUntil > 0 || ($entry['last_seen'] ?? 0) < $now - $this->windowSeconds) {
            $this->storage->delete($ip);
        }

        return null;
    }

    public function record(string $ip): ?array
    {
        $now = time();
        $entry = $this->storage->get($ip);
        if (!is_array($entry)) {
            $entry = null;
        }

        $bannedUntil = (int) ($entry['banned_until'] ?? 0);
        $windowGone = $entry !== null && ($entry['last_seen'] ?? 0) < $now - $this->windowSeconds;

        if ($entry === null || $windowGone) {
            // New counting window. A ban that is still active outlives it —
            // resetting it to 0 here would lift the ban early.
            $entry = [
                'count' => 1,
                'first_seen' => $now,
                'last_seen' => $now,
                'banned_until' => max($bannedUntil, 0),
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
        return $this->check($ip);
    }

    /**
     * Clear all data (for testing).
     */
    public function reset(): void
    {
        $this->storage->clear();
    }
}
