<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Identity;

use Erikwang2013\Security\ThreatResult;

/**
 * Detects tampering with fields the application asked to be protected.
 *
 * The app signs the values it hands to the browser; the browser hands the
 * token back on submit; any change to a protected value in between shows up as
 * a signature mismatch. This catches the case the regex detectors cannot see
 * by design: a value that is perfectly well-formed, just not the one the
 * server issued (price, quantity, user id, role).
 *
 * Disabled unless `signing_key` is configured, so upgrading an existing app
 * cannot start failing requests.
 */
final class FieldSigner
{
    public function __construct(
        private string $key,
        private array $config = [],
    ) {
    }

    /**
     * Issue a token covering $fields. Call it where the form is rendered.
     * Returns '' when signing is disabled or there is nothing to protect.
     *
     * @param array<string, mixed> $fields flat dot-path => value, e.g. ['order.price' => 100]
     */
    public function sign(array $fields, ?int $ttl = null): string
    {
        if (!$this->enabled() || $fields === []) {
            return '';
        }

        $ttl = $ttl ?? (int) ($this->config['ttl'] ?? 1800);
        $payload = self::b64encode((string) json_encode(
            ['f' => self::normalize($fields), 'e' => time() + $ttl],
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
        ));

        return $payload . '.' . self::b64encode(hash_hmac('sha256', $payload, $this->key, true));
    }

    /**
     * Verify the token carried by the request against the values it received.
     */
    public function verify(array $flatData): ?ThreatResult
    {
        if (!$this->enabled()) {
            return null;
        }

        $protected = array_values(array_filter(
            array_map('strval', (array) ($this->config['protected_fields'] ?? [])),
            static fn (string $name): bool => $name !== '',
        ));
        if ($protected === []) {
            return null; // nothing declared protected — nothing to verify
        }

        $field = (string) ($this->config['token_field'] ?? '_security_sig');
        $token = trim((string) ($flatData[$field] ?? ''));

        if ($token === '') {
            // Stripping attack: drop the token and the values look untouched.
            // Only the config knows which fields were supposed to be signed.
            foreach ($protected as $name) {
                if (isset($flatData[$name]) && (string) $flatData[$name] !== '') {
                    return $this->threat('未携带完整性签名但提交了受保护字段 ' . $name . '（可能被剥离）', $name);
                }
            }

            return null;
        }

        $parts = explode('.', $token);
        if (count($parts) !== 2) {
            return $this->threat('完整性签名格式无效', $field);
        }

        [$payload, $mac] = $parts;
        $expected = self::b64encode(hash_hmac('sha256', $payload, $this->key, true));
        if (!hash_equals($expected, $mac)) {
            return $this->threat('完整性签名校验失败（字段可能被篡改）', $field);
        }

        $decoded = json_decode((string) self::b64decode($payload), true);
        if (!is_array($decoded) || !is_array($decoded['f'] ?? null)) {
            return $this->threat('完整性签名内容无效', $field);
        }

        if ((int) ($decoded['e'] ?? 0) < time()) {
            return $this->threat('完整性签名已过期', $field);
        }

        $signed = $decoded['f'];
        foreach ($protected as $name) {
            if (!array_key_exists($name, $signed)) {
                // Protected field reached the server without ever being signed.
                if (isset($flatData[$name]) && (string) $flatData[$name] !== '') {
                    return $this->threat('受保护字段 ' . $name . ' 未被签名', $name);
                }
                continue;
            }

            if (!array_key_exists($name, $flatData)) {
                return $this->threat('已签名字段 ' . $name . ' 缺失', $name);
            }

            if ((string) $flatData[$name] !== (string) $signed[$name]) {
                return $this->threat('字段 ' . $name . ' 的值与签名不符', $name);
            }
        }

        return null;
    }

    private function enabled(): bool
    {
        return $this->key !== '';
    }

    private function threat(string $detail, string $field): ThreatResult
    {
        return new ThreatResult(
            type: 'data_tamper',
            severity: 'high',
            field: $field,
            payload: '',
            detail: $detail,
            httpStatus: 403,
        );
    }

    /**
     * Values are compared as strings on both sides: flattenData() stringifies
     * every scalar, and the browser posts everything as text anyway. Signing
     * an int 100 and posting "100" is the same value, not tampering.
     *
     * @param array<string, mixed> $fields
     * @return array<string, string>
     */
    private static function normalize(array $fields): array
    {
        $out = [];
        foreach ($fields as $name => $value) {
            if (is_scalar($value) || $value === null) {
                $out[(string) $name] = (string) $value;
            }
        }

        return $out;
    }

    private static function b64encode(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    private static function b64decode(string $encoded): ?string
    {
        $raw = base64_decode(strtr($encoded, '-_', '+/'), true);

        return $raw === false ? null : $raw;
    }
}
