<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Detector;

class DataLeakDetector extends AbstractRegexDetector
{
    public function name(): string
    {
        return 'data_leak';
    }

    protected function patterns(): array
    {
        return [
            // Credit card (Luhn-valid 16-digit format)
            '/\b(?:4\d{3}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}|'
            . '5[1-5]\d{2}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}|'
            . '3[47]\d{2}[ -]?\d{6}[ -]?\d{5}|'
            . '6011[ -]?\d{4}[ -]?\d{4}[ -]?\d{4})\b/'
                                                => ['severity' => 'high', 'detail' => 'Credit card number pattern detected'],
            // AWS Access Key
            '/\bAKIA[0-9A-Z]{16}\b/'   => ['severity' => 'critical', 'detail' => 'AWS Access Key ID exposed'],
            // AWS Secret Key
            '/\baws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']?[A-Za-z0-9\/+=]{20,}/i'
                                                => ['severity' => 'critical', 'detail' => 'AWS Secret Access Key exposed'],
            // Private key header
            '/-----BEGIN\s+(?:RSA\s+PRIVATE|EC|DSA|OPENSSH|PRIVATE)\s+KEY-----/i'
                                                => ['severity' => 'critical', 'detail' => 'Private key in request data'],
            // Generic API key / token
            '/\b(?:api[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*["\']?[A-Za-z0-9._\-]{16,}/i'
                                                => ['severity' => 'high',  'detail' => 'API key / access token exposed'],
            // Database connection string
            '/\b(?:mysql|postgres|sqlserver|mongodb|redis):\/\/[^@\s]+@/i'
                                                => ['severity' => 'critical', 'detail' => 'Database connection string with credentials'],
            // JWT secret
            '/\bjwt[_-]?secret\s*[:=]\s*["\']?[A-Za-z0-9._\-]{8,}/i'
                                                => ['severity' => 'critical', 'detail' => 'JWT secret key exposed'],
            // Password in URL
            '/[?&]\bpassword=[^&\s]+/i' => ['severity' => 'high',  'detail' => 'Password in URL query string'],
        ];
    }

    public function detect(array $data): array
    {
        $kept = [];
        foreach (parent::detect($data) as $threat) {
            // Credit-card lookalikes must pass Luhn on the original value
            if ($threat->detail === 'Credit card number pattern detected') {
                $raw = $data[$threat->field] ?? '';
                if (!is_string($raw) || !$this->hasValidLuhn($raw)) {
                    continue;
                }
            }
            $kept[] = $threat;
        }
        return $kept;
    }

    private function hasValidLuhn(string $raw): bool
    {
        preg_match_all('/\b(?:\d[ -]?){13,16}\b/', $raw, $matches);
        foreach ($matches[0] as $candidate) {
            $digits = preg_replace('/\D/', '', $candidate);
            if (strlen($digits) < 13) {
                continue;
            }
            $sum = 0;
            for ($i = strlen($digits) - 1, $j = 0; $i >= 0; $i--, $j++) {
                $d = (int) $digits[$i];
                if ($j % 2 === 1) {
                    $d *= 2;
                    if ($d > 9) {
                        $d -= 9;
                    }
                }
                $sum += $d;
            }
            if ($sum % 10 === 0) {
                return true;
            }
        }
        return false;
    }

    protected function transformPayload(string $payload): string
    {
        return strlen($payload) > 20 ? substr($payload, 0, 10) . '***' . substr($payload, -6) : '***MASKED***';
    }
}
