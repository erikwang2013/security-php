<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Identity;

/**
 * Normalizes an IP address to its network prefix.
 *
 * Used as a coarse "where" measure for session and login baselines: mobile
 * clients change address constantly inside one carrier network, so comparing
 * full addresses would flag every handover as a hijack. Comparing /24 (IPv4)
 * or /64 (IPv6) keeps the check useful without the noise.
 */
final class IpPrefix
{
    /**
     * @return string the prefix (e.g. "203.0.113.0"), or '' when $ip is not a valid address
     */
    public static function of(string $ip, int $v4Bits = 24, int $v6Bits = 64): string
    {
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return '';
        }

        // IPv4-mapped IPv6 (::ffff:203.0.113.5, how dual-stack sockets and
        // Swoole report v4 clients) has to be masked as IPv4 — otherwise every
        // mapped client collapses into the same ::/64 bucket and the IP factor
        // stops discriminating at all.
        if (strlen($bin) === 16 && substr($bin, 0, 12) === "\0\0\0\0\0\0\0\0\0\0\xff\xff") {
            $bin = substr($bin, 12);
        }

        $totalBits = strlen($bin) * 8;
        $bits = max(0, min($totalBits === 32 ? $v4Bits : $v6Bits, $totalBits));

        $mask = str_repeat("\xff", intdiv($bits, 8));
        if ($bits % 8 !== 0) {
            $mask .= chr((0xff << (8 - $bits % 8)) & 0xff);
        }
        $mask = str_pad($mask, strlen($bin), "\0");

        $masked = inet_ntop($bin & $mask);

        return $masked === false ? '' : $masked;
    }
}
