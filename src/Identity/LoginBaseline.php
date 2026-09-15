<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Identity;

use Erikwang2013\Security\Storage\StorageInterface;
use Erikwang2013\Security\ThreatResult;

/**
 * Flags a login from a place the account has never used before.
 *
 * Authentication-mechanism agnostic: it only takes a $userId, so cookie login
 * and token login share this one code path.
 *
 * Known limitation: the first login each account ever makes becomes the
 * baseline. If an attacker logs in before the real owner, the attacker's
 * location is "normal" until the owner shows up. No signal available to a
 * stateless middleware can tell those two apart.
 */
final class LoginBaseline
{
    private const KEY_PREFIX = 'ident:login:';

    public function __construct(
        private StorageInterface $storage,
        private array $config = [],
    ) {
    }

    /**
     * Record a successful login and report it when the place is new.
     * Call this from the success branch of your login / token-issuing code.
     */
    public function record(string $userId, ?string $location = null, array $meta = []): ?ThreatResult
    {
        if ($userId === '') {
            return null;
        }

        $place = $this->place($location, $meta);
        if ($place['hash'] === '') {
            return null; // no location to judge — stay silent rather than guess
        }

        $key = self::KEY_PREFIX . hash('sha256', $userId);
        $now = time();
        $entry = $this->storage->get($key);
        $points = $this->prune(
            is_array($entry) && is_array($entry['points'] ?? null) ? $entry['points'] : [],
            $now,
        );

        if (isset($points[$place['hash']])) {
            $points[$place['hash']]['last'] = $now;
            $points[$place['hash']]['hits'] = (int) ($points[$place['hash']]['hits'] ?? 0) + 1;
            $this->save($key, $points, $now);

            return null;
        }

        $known = count($points);
        $points[$place['hash']] = ['label' => $place['label'], 'first' => $now, 'last' => $now, 'hits' => 1];
        $this->save($key, $points, $now);

        if ($known === 0) {
            return null; // first login ever — this one defines the baseline
        }

        // The user id is an identifier, not a credential, so it goes in the log
        // verbatim: without it the alert is not actionable for whoever reads it.
        return new ThreatResult(
            type: 'unusual_login',
            severity: 'medium',
            field: '_login.user',
            payload: $userId,
            detail: '登录地异常：' . $place['label'] . '（该账号已知 ' . $known . ' 个常用地点）',
            httpStatus: 401,
        );
    }

    /**
     * "Place" is the app-supplied location when it has one, otherwise the
     * client's network. Taking an optional string keeps this dependency-free:
     * no GeoIP library, and no guessing from an IP we cannot resolve.
     *
     * @return array{hash: string, label: string}
     */
    private function place(?string $location, array $meta): array
    {
        $location = trim((string) $location);
        if ($location !== '') {
            return ['hash' => hash('sha256', 'loc:' . $location), 'label' => $location];
        }

        $prefix = IpPrefix::of((string) ($meta['ip'] ?? ''), (int) ($this->config['ip_bits'] ?? 24));
        if ($prefix === '') {
            return ['hash' => '', 'label' => ''];
        }

        return ['hash' => hash('sha256', 'net:' . $prefix), 'label' => $prefix . ' 网段'];
    }

    /**
     * Forget places the account has not used within ttl. This is what keeps the
     * per-user record bounded without a background sweep — a place that goes
     * unused long enough simply stops counting as "normal", which is also the
     * behaviour you want.
     */
    private function prune(array $points, int $now): array
    {
        $ttl = (int) ($this->config['ttl'] ?? 86400);
        if ($ttl <= 0) {
            return $points;
        }
        $deadline = $now - $ttl;
        foreach ($points as $hash => $point) {
            if (!is_array($point) || (int) ($point['last'] ?? 0) < $deadline) {
                unset($points[$hash]);
            }
        }

        return $points;
    }

    /**
     * Hard cap on remembered places, oldest-used first.
     */
    private function cap(array $points): array
    {
        $max = (int) ($this->config['max_points'] ?? 10);
        if ($max <= 0 || count($points) <= $max) {
            return $points;
        }

        uasort($points, static fn (array $a, array $b): int => (int) ($a['last'] ?? 0) <=> (int) ($b['last'] ?? 0));

        return array_slice($points, count($points) - $max, null, true);
    }

    private function save(string $key, array $points, int $now): void
    {
        $this->storage->set($key, ['points' => $this->cap($points), 'updated' => $now]);
    }
}
