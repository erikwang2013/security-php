<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Identity;

use Erikwang2013\Security\Storage\StorageInterface;
use Erikwang2013\Security\ThreatResult;

/**
 * The four identity-dimension checks, as one thing SecurityGuard can hold.
 *
 * SecurityGuard is already near the project's 500-line file cap, so this
 * facade keeps the wiring there to a handful of lines.
 *
 * Each check is gated by its own `detectors.<type>.enabled` flag, so the
 * block/log mode in `detectors.<type>.mode` and everything downstream of it
 * (blockDecision, Logger dedup, IP escalation) works without new code.
 */
final class IdentityGuard
{
    private SessionFingerprint $session;
    private LoginBaseline $login;
    private LoginLockout $lockout;
    private FieldSigner $tamper;
    private array $detectors;

    public function __construct(StorageInterface $storage, array $config, array $detectors = [])
    {
        $identity = $config['identity'] ?? [];
        $this->session = new SessionFingerprint($storage, $identity['session'] ?? []);
        $this->login = new LoginBaseline($storage, $identity['login'] ?? []);
        // lockout nests under login: both key off the account, unlike the
        // session fingerprint which keys off the credential itself
        $this->lockout = new LoginLockout($storage, $identity['login']['lockout'] ?? []);
        $this->tamper = new FieldSigner((string) ($config['signing_key'] ?? ''), $identity['tamper'] ?? []);
        $this->detectors = $detectors;
    }

    /**
     * Per-request checks. Runs on the flattened request body; $flatData must be
     * the unfiltered flatten, or a protected field that also sits in
     * whitelist_fields would look like a stripped signature.
     *
     * @return ThreatResult[]
     */
    public function check(array $flatData, array $meta): array
    {
        $threats = [];

        if ($this->on('session_hijack')) {
            $threat = $this->session->check($meta);
            if ($threat !== null) {
                $threats[] = $threat;
            }
        }

        if ($this->on('data_tamper')) {
            $threat = $this->tamper->verify($flatData);
            if ($threat !== null) {
                $threats[] = $threat;
            }
        }

        return $threats;
    }

    /**
     * Call from the success branch of login / token issuing. Never rewrites a
     * request; returns the threat for the caller to act on if it wants.
     */
    public function recordLogin(string $userId, ?string $location = null, array $meta = []): ?ThreatResult
    {
        return $this->on('unusual_login') ? $this->login->record($userId, $location, $meta) : null;
    }

    /**
     * Call from the failure branch of login. Returns a threat when this
     * attempt locked the account, or when it was already locked.
     */
    public function recordFailedLogin(string $userId, ?string $ip = null): ?ThreatResult
    {
        return $this->on('login_lockout') ? $this->lockout->recordFailed($userId, $ip) : null;
    }

    public function isLockedOut(string $userId, ?string $ip = null): bool
    {
        return $this->on('login_lockout') && $this->lockout->isLocked($userId, $ip);
    }

    /**
     * @param array<string, mixed> $fields flat dot-path => value
     */
    public function signFields(array $fields, ?int $ttl = null): string
    {
        return $this->tamper->sign($fields, $ttl);
    }

    public function verifyFields(array $flatData): ?ThreatResult
    {
        return $this->on('data_tamper') ? $this->tamper->verify($flatData) : null;
    }

    private function on(string $type): bool
    {
        return !empty($this->detectors[$type]['enabled']);
    }
}
