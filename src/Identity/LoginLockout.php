<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Identity;

use Erikwang2013\Security\Storage\StorageInterface;
use Erikwang2013\Security\ThreatResult;

/**
 * Brute-force lockout across failed login attempts.
 *
 * recordLogin() covers the success branch; failures happen in the app's own
 * auth handler, downstream of the middleware, so they are recorded here.
 *
 * Storage keys and the threat payload carry sha256 digests only, so no
 * plaintext account id reaches storage or the log file — same convention as
 * SessionFingerprint and LoginBaseline.
 */
final class LoginLockout
{
    private StorageInterface $storage;
    private array $config;

    public function __construct(StorageInterface $storage, array $config)
    {
        $this->storage = $storage;
        // An app publishing an older config has no `lockout` block at all.
        // Without these defaults max_failures would be 0 and lock after the
        // very first failure.
        $this->config = array_merge([
            'max_failures'   => 5,
            'window_seconds' => 900,
            'lock_seconds'   => 900,
            'include_ip'     => false,
        ], $config);
    }

    /**
     * Record one failed attempt. Returns a threat when this attempt locked the
     * account, or when it was already locked — so the app can log it and stop
     * retrying instead of burning through credentials again.
     */
    public function recordFailed(string $userId, ?string $ip = null): ?ThreatResult
    {
        $key = $this->key($userId, $ip);
        $now = time();

        $record = $this->storage->get($key);
        $record = is_array($record) ? $record : ['failures' => [], 'locked_until' => 0];

        // ?? 0: a record written by an older version can lack the key, and a
        // warning here becomes a 500 under Laravel's error handler
        if ((int) ($record['locked_until'] ?? 0) > $now) {
            return $this->locked($userId);
        }

        // Failures outside the window have expired and must not re-lock
        $failures = array_values(array_filter(
            array_map('intval', $record['failures'] ?? []),
            fn (int $ts) => $ts >= $now - $this->config['window_seconds'],
        ));
        $failures[] = $now;
        $record['failures'] = $failures;
        $record['locked_until'] = 0;

        if (count($failures) >= $this->config['max_failures']) {
            $record['locked_until'] = $now + $this->config['lock_seconds'];
            // Clear so the window restarts cleanly once the lock expires
            $record['failures'] = [];
            $this->storage->set($key, $record);
            return $this->locked($userId);
        }

        $this->storage->set($key, $record);
        return null;
    }

    /**
     * Gate an auth attempt before it runs, so a locked account skips the
     * credential check instead of answering "wrong password" to every guess.
     */
    public function isLocked(string $userId, ?string $ip = null): bool
    {
        $record = $this->storage->get($this->key($userId, $ip));
        return is_array($record) && (int) $record['locked_until'] > time();
    }

    private function key(string $userId, ?string $ip): string
    {
        $digest = hash('sha256', $userId);

        // Per-IP keying narrows a lockout to the attacker's source at the cost
        // of an attacker resetting the counter by rotating IPs
        if (!empty($this->config['include_ip']) && $ip !== null && $ip !== '') {
            return 'ident:lock:ip:' . hash('sha256', $userId . '@' . $ip);
        }

        return 'ident:lock:' . $digest;
    }

    private function locked(string $userId): ThreatResult
    {
        return new ThreatResult(
            type: 'login_lockout',
            severity: 'high',
            field: '_login.lockout',
            payload: '#' . substr(hash('sha256', $userId), 0, 8),
            detail: 'Account locked after repeated failed login attempts',
            httpStatus: 429,
        );
    }
}
