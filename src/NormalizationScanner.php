<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security;

/**
 * Scans decoded variants of request values that carry an encoding signal, so
 * the regex detectors are not bypassed by URL encoding, fullwidth characters
 * or HTML entities.
 *
 * Values are never rewritten in place: the original scan has already run and
 * both can fire. Each variant is run through the same chain in a separate
 * pass, so a detector picks up the bypass without any change of its own.
 *
 * Every variant is gated on a cheap pre-check — a value without '%' never
 * calls urldecode() — so a request with no encoding pays nothing extra.
 */
final class NormalizationScanner
{
    /** @var array<string, string>|null fullwidth byte-sequence => ASCII, built once */
    private static ?array $fullwidthMap = null;

    /**
     * @return ThreatResult[]
     */
    public static function scan(DetectorChain $chain, array $data, array $config): array
    {
        if (empty($config['enabled'])) {
            return [];
        }

        // Group decoded values by variant so the chain runs once per variant,
        // not once per value
        $byVariant = [];
        foreach ($data as $key => $value) {
            if (!is_string($value) || $value === '') {
                continue;
            }
            foreach (self::variants($value, $config) as $variant => $decoded) {
                $byVariant[$variant][$key] = $decoded;
            }
        }

        $threats = [];
        foreach ($byVariant as $variant => $variantData) {
            foreach ($chain->scan($variantData) as $threat) {
                $threats[] = new ThreatResult(
                    type: $threat->type,
                    severity: $threat->severity,
                    field: $threat->field,
                    payload: $threat->payload,
                    // Lets a decoded hit be told apart from the original hit
                    // in the log line
                    detail: $threat->detail . ' [decoded:' . $variant . ']',
                    httpStatus: $threat->httpStatus,
                );
            }
        }

        return $threats;
    }

    /**
     * @return array<string, string> variant name => decoded value
     */
    private static function variants(string $value, array $config): array
    {
        $out = [];

        // The fullwidth-normalized form joins the raw value as a second base,
        // so a fullwidth-encoded payload (％3Cscript％3E) is caught too and not
        // just fullwidth letters like Ｓｅｌｅｃｔ
        $bases = [$value];
        if (!empty($config['fullwidth'])
            && preg_match('/[\x{FF01}-\x{FF5E}\x{FF60}]/u', $value) === 1) {
            $normalized = self::fullwidthToAscii($value);
            if ($normalized !== $value && $normalized !== '') {
                $out['fullwidth'] = $normalized;
                $bases[] = $normalized;
            }
        }

        foreach ($bases as $base) {
            foreach (self::encodingVariants($base, $config) as $variant => $decoded) {
                $out[$variant] ??= $decoded; // the less-transformed base wins
            }
        }

        return $out;
    }

    /**
     * @return array<string, string>
     */
    private static function encodingVariants(string $value, array $config): array
    {
        $out = [];

        if (!empty($config['urldecode']) && str_contains($value, '%')) {
            $decoded = urldecode($value);
            $variant = 'urldecode';
            // A second round catches double-encoded payloads (%2527)
            if ($decoded !== $value && str_contains($decoded, '%')) {
                $decoded = urldecode($decoded);
                $variant = 'urldecode2';
            }
            if ($decoded !== $value && $decoded !== '') {
                $out[$variant] = $decoded;
            }
        }

        if (!empty($config['entities']) && (str_contains($value, '&#') || str_contains($value, '&amp;'))) {
            $decoded = html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            $variant = 'entities';
            if ($decoded !== $value && (str_contains($decoded, '&#') || str_contains($decoded, '&amp;'))) {
                $decoded = html_entity_decode($decoded, ENT_QUOTES | ENT_HTML5, 'UTF-8');
                $variant = 'entities2';
            }
            if ($decoded !== $value && $decoded !== '') {
                $out[$variant] = $decoded;
            }
        }

        return $out;
    }

    /**
     * Fullwidth ASCII forms to halfwidth. Byte-level strtr so it needs no
     * mbstring extension.
     */
    private static function fullwidthToAscii(string $value): string
    {
        if (self::$fullwidthMap === null) {
            $map = [self::utf8(0xFF60) => ' ']; // U+FF60 fullwidth space
            for ($i = 0x21; $i <= 0x7E; $i++) {
                $map[self::utf8(0xFEE0 + $i)] = chr($i); // U+FF01-U+FF5E
            }
            self::$fullwidthMap = $map;
        }

        return strtr($value, self::$fullwidthMap);
    }

    private static function utf8(int $cp): string
    {
        return chr(0xE0 | ($cp >> 12))
            . chr(0x80 | (($cp >> 6) & 0x3F))
            . chr(0x80 | ($cp & 0x3F));
    }
}
