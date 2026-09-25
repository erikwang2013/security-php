<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Identity;

use Erikwang2013\Security\Storage\StorageInterface;
use Erikwang2013\Security\ThreatResult;

/**
 * Detects session hijacking by binding a session to a fingerprint on first
 * sight and alerting when a later request presents the same session from a
 * different fingerprint.
 *
 * Cookie sessions and token sessions (Authorization: Bearer / X-Token) share
 * this one code path — only the extraction of the session identifier differs.
 */
final class SessionFingerprint
{
    private const KEY_PREFIX = 'ident:sess:';

    public function __construct(
        private StorageInterface $storage,
        private array $config = [],
    ) {
    }

    public function check(array $meta): ?ThreatResult
    {
        $threat = $this->evaluate($meta);
        $this->gc();

        return $threat;
    }

    private function evaluate(array $meta): ?ThreatResult
    {
        $sid = $this->extractSessionId($meta);
        if ($sid === '') {
            return null; // anonymous request — nothing to bind
        }

        $hash = hash('sha256', $sid);
        $key = self::KEY_PREFIX . $hash;
        $now = time();
        $ttl = (int) ($this->config['ttl'] ?? 7200);
        $current = $this->parts($meta);

        $entry = $this->storage->get($key);
        if (!is_array($entry) || (int) ($entry['seen'] ?? 0) + $ttl < $now) {
            // First sight, or the record went idle: this request sets the baseline.
            $this->storage->set($key, $current + ['seen' => $now]);

            return null;
        }

        if (hash_equals((string) ($entry['fp'] ?? ''), $current['fp'])) {
            // Refresh the idle timer at most once per half-TTL. Rewriting the
            // record on every request costs a whole-store rewrite on the file
            // backend (~15ms at 5000 sessions) for no change but the clock.
            // Cost: the idle window can run ttl + ttl/2 instead of ttl.
            if ((int) ($entry['seen'] ?? 0) + intdiv($ttl, 2) < $now) {
                $this->storage->set($key, $current + ['seen' => $now]);
            }

            return null;
        }

        // The baseline is deliberately NOT rotated here. Rotating would let the
        // first mismatching request overwrite it, so the real owner's next
        // request would be the only alert and the attacker would go quiet.
        // Keeping the original means every request from the attacker alerts;
        // Logger's dedup window collapses the repeats.
        return new ThreatResult(
            type: 'session_hijack',
            severity: 'high',
            field: '_session.id',
            payload: '#' . substr($hash, 0, 8),
            detail: '会话指纹与建立时不一致（' . $this->describe($entry, $current) . '），疑似会话或 Token 被盗用',
            httpStatus: 401,
        );
    }

    /**
     * Cookie first, then the configured token headers.
     *
     * Both sources are read from $meta rather than the flattened request body:
     * every middleware merges cookies into the body first, so a same-named
     * GET/POST parameter would shadow the real cookie.
     */
    private function extractSessionId(array $meta): string
    {
        $cookieName = (string) ($this->config['cookie'] ?? '');
        if ($cookieName !== '') {
            $value = $meta['cookies'][$cookieName] ?? '';
            if (is_string($value) && $value !== '') {
                return $value;
            }
        }

        // Normalize the key case: a missed lookup here would silently disable
        // hijack detection, so never depend on the caller's casing.
        $headers = [];
        foreach (is_array($meta['headers'] ?? null) ? $meta['headers'] : [] as $name => $value) {
            // PSR-7 hands back string[]; scalar maps come back as strings
            $headers[strtolower((string) $name)] = is_array($value)
                ? (string) ($value[0] ?? '')
                : (string) $value;
        }

        foreach ((array) ($this->config['headers'] ?? []) as $name) {
            $value = $headers[strtolower((string) $name)] ?? '';
            if (!is_string($value) || $value === '') {
                continue;
            }
            // Accept "Bearer <token>" as well as a bare token.
            if (preg_match('/^\s*bearer\s+(.+)$/i', $value, $m) === 1) {
                $value = trim($m[1]);
            }
            if ($value !== '') {
                return $value;
            }
        }

        return '';
    }

    /**
     * @return array{fp: string, ua: string, ip: string}
     */
    private function parts(array $meta): array
    {
        $bind = (array) ($this->config['bind'] ?? ['ua', 'ip']);

        $ua = in_array('ua', $bind, true)
            ? trim((string) ($meta['user_agent'] ?? ''))
            : '';
        $ip = in_array('ip', $bind, true)
            ? IpPrefix::of((string) ($meta['ip'] ?? ''), (int) ($this->config['ip_bits'] ?? 24))
            : '';

        return ['fp' => hash('sha256', $ua . '|' . $ip), 'ua' => $ua, 'ip' => $ip];
    }

    private function describe(array $entry, array $current): string
    {
        $changes = [];
        if (($entry['ua'] ?? '') !== '' && ($entry['ua'] ?? '') !== $current['ua']) {
            $changes[] = 'UA 变化';
        }
        if (($entry['ip'] ?? '') !== '' && ($entry['ip'] ?? '') !== $current['ip']) {
            $changes[] = 'IP 网段 ' . $entry['ip'] . ' → ' . $current['ip'];
        }

        return $changes === [] ? '绑定因子变化' : implode('；', $changes);
    }

    /**
     * Reclaim idle session records.
     *
     * StorageInterface has no TTL and no bulk delete, so expired entries would
     * pile up forever — and on FileStorage, which rewrites its whole map on
     * every set(), that leak also slows down every later write. Sampling the
     * sweep instead of running it per request keeps the common case at one
     * read plus one write.
     *
     * ponytail: 1-in-N sampled sweep with a bounded batch. If a site churns
     * sessions fast enough that this lags, point storage at Redis and give the
     * keys a real TTL.
     */
    private function gc(): void
    {
        $probability = (int) ($this->config['gc_probability'] ?? 100);
        if ($probability <= 0 || random_int(1, $probability) !== 1) {
            return;
        }

        $deadline = time() - (int) ($this->config['ttl'] ?? 7200);
        $batch = max(1, (int) ($this->config['gc_batch'] ?? 20));

        $deleted = 0;
        foreach ($this->storage->all() as $key => $entry) {
            $key = (string) $key;
            if (!str_starts_with($key, self::KEY_PREFIX)) {
                continue;
            }
            if (is_array($entry) && (int) ($entry['seen'] ?? 0) < $deadline) {
                $this->storage->delete($key);
                if (++$deleted >= $batch) {
                    return;
                }
            }
        }
    }
}
