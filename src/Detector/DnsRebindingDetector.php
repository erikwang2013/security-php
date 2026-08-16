<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Detector;

use Erikwang2013\Security\ThreatResult;

class DnsRebindingDetector extends AbstractRegexDetector
{
    public function name(): string
    {
        return 'dns_rebinding';
    }

    protected function patterns(): array
    {
        return [
            '/\r\nHost\s*:\s*\d+\.\d+\.\d+\.\d+/i'
                                                => ['severity' => 'critical', 'detail' => 'Host header with raw IP (rebinding)'],
            '/\r\nHost\s*:\s*127\.\d+\.\d+\.\d+/i'
                                                => ['severity' => 'critical', 'detail' => 'Host header loopback IP'],
            '/\r\nHost\s*:\s*10\.\d+\.\d+\.\d+/i'
                                                => ['severity' => 'critical', 'detail' => 'Host header private IP (10.x)'],
            '/\r\nHost\s*:\s*172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+/i'
                                                => ['severity' => 'critical', 'detail' => 'Host header private IP (172.16-31)'],
            '/\r\nHost\s*:\s*192\.168\.\d+\.\d+/i'
                                                => ['severity' => 'critical', 'detail' => 'Host header private IP (192.168)'],
            '/\r\nHost\s*:\s*\[::1\]/i' => ['severity' => 'critical', 'detail' => 'Host header IPv6 loopback'],
            '/\r\nHost\s*:\s*0\.0\.0\.0/i'
                                                => ['severity' => 'high',     'detail' => 'Host header all-interfaces IP'],
            '/\r\nHost\s*:\s*localhost\b/i'
                                                => ['severity' => 'high',     'detail' => 'Host header localhost (rebinding)'],
            '/\r\nHost\s*:\s*[^.\r]+\.[^.\r]+\.[^.\r]+\.[^.\r]+/i'
                                                => ['severity' => 'high',     'detail' => 'Host header with IP-like pattern'],
            '/\r\nHost\s*:\s*[^.\r]+\.[^.\r]+\.[^.\r]+/i'
                                                => ['severity' => 'medium',   'detail' => 'Host header short hostname (no TLD)'],
        ];
    }

    /**
     * The real Host header arrives via _server.HTTP_HOST, not as an injected
     * \r\nHost: line, so also check the bare value there. Anchored to that
     * exact field: a form value like ip=127.0.0.1 must not be flagged.
     */
    public function detect(array $data): array
    {
        $results = parent::detect($data);
        $host = $data['_server.HTTP_HOST'] ?? '';
        if (is_string($host) && $host !== '') {
            $severity = self::rebindingSeverity($host);
            if ($severity !== null) {
                $results[] = new ThreatResult(
                    type: 'dns_rebinding',
                    severity: $severity,
                    field: '_server.HTTP_HOST',
                    payload: $host,
                    detail: 'Host header resolves to internal address (DNS rebinding)',
                );
            }
        }
        return $results;
    }

    private static function rebindingSeverity(string $host): ?string
    {
        $host = trim($host);
        if ($host === '') {
            return null;
        }

        // Strip port (IPv4 / IPv6 with brackets)
        if (str_starts_with($host, '[')) {
            $end = strpos($host, ']');
            $host = $end !== false ? substr($host, 1, $end - 1) : $host;
        } else {
            $host = explode(':', $host)[0];
        }

        if ($host === 'localhost' || $host === '0.0.0.0' || $host === '::1') {
            return 'critical';
        }
        if (filter_var($host, FILTER_VALIDATE_IP) === false) {
            // Single-label hostname has no public TLD — DNS rebinding / SSRF vector
            return strpos($host, '.') === false ? 'medium' : null;
        }
        return 'critical';
    }
}
