<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security;

use Erikwang2013\Security\Storage\FileStorage;
use Erikwang2013\Security\Storage\RedisStorage;
use Erikwang2013\Security\Storage\CacheStorage;
use Erikwang2013\Security\Storage\StorageInterface;

class SecurityGuard
{
    private static ?DetectorChain $chain = null;
    private static ?Logger $logger = null;
    private static ?array $config = null;
    private static ?IpBlacklist $ipBlacklist = null;

    /**
     * Initialize with config. Called once by middleware or bootstrap.
     */
    public static function init(array $config): void
    {
        self::$config = $config;

        if (empty($config['enabled'])) {
            return;
        }

        self::$chain = new DetectorChain();
        self::$logger = new Logger($config['log'] ?? []);

        $ipBlacklistConfig = $config['ip_blacklist'] ?? [];
        if (!empty($ipBlacklistConfig['enabled'])) {
            $storage = self::createStorage($config['storage'] ?? []);
            self::$ipBlacklist = new IpBlacklist($ipBlacklistConfig, $storage);
        }

        $detectorsConfig = $config['detectors'] ?? [];
        $detectorMap = [
            'xss'                => Detector\XssDetector::class,
            'sql_injection'      => Detector\SqlInjectionDetector::class,
            'command_injection'  => Detector\CommandInjectionDetector::class,
            'path_traversal'     => Detector\PathTraversalDetector::class,
            'upload'             => Detector\UploadDetector::class,
            'ssrf'               => Detector\SsrfDetector::class,
            'xxe'                => Detector\XxeDetector::class,
            'header_injection'   => Detector\HeaderInjectionDetector::class,
            'deserialization'    => Detector\DeserializationDetector::class,
            'ldap_injection'     => Detector\LdapInjectionDetector::class,
            'mail_header'        => Detector\MailHeaderDetector::class,
            'ssti'               => Detector\SstiDetector::class,
            'nosql_injection'    => Detector\NosqlInjectionDetector::class,
            'open_redirect'      => Detector\OpenRedirectDetector::class,
            'jwt_attack'         => Detector\JwtAttackDetector::class,
            'host_header'        => Detector\HostHeaderDetector::class,
            'request_smuggling'  => Detector\RequestSmugglingDetector::class,
            'graphql_injection'  => Detector\GraphqlInjectionDetector::class,
            'xpath_injection'    => Detector\XpathInjectionDetector::class,
            'jndi_injection'     => Detector\JndiInjectionDetector::class,
            'ssi_injection'      => Detector\SsiInjectionDetector::class,
            'csv_injection'      => Detector\CsvInjectionDetector::class,
            'data_leak'          => Detector\DataLeakDetector::class,
            'prototype_pollution'=> Detector\PrototypePollutionDetector::class,
            'websocket'          => Detector\WebSocketDetector::class,
            'cors'               => Detector\CorsDetector::class,
            'dns_rebinding'      => Detector\DnsRebindingDetector::class,
            'http_method'        => Detector\HttpMethodDetector::class,
            'body_size'          => Detector\BodySizeDetector::class,
            'content_type'       => Detector\ContentTypeDetector::class,
            'csrf_origin'        => Detector\CsrfOriginDetector::class,
        ];

        foreach ($detectorMap as $key => $class) {
            $cfg = $detectorsConfig[$key] ?? null;
            if ($cfg && !empty($cfg['enabled'])) {
                self::$chain->add(new $class());
            }
        }
    }

    /**
     * Full scan with request metadata.
     * Returns ThreatResult[]. Empty array = safe.
     */
    public static function guard(array $data, array $meta = []): array
    {
        if (self::$config === null) {
            $defaultConfig = require dirname(__DIR__) . '/config/security.php';
            self::init($defaultConfig);
        }

        if (empty(self::$config['enabled']) || self::$chain === null) {
            return [];
        }

        $ip = $meta['ip'] ?? '';
        if ($ip && self::isWhitelistedIp($ip)) {
            return [];
        }

        // IP blacklist check
        if ($ip && self::$ipBlacklist !== null && self::$ipBlacklist->isBanned($ip)) {
            $info = self::$ipBlacklist->getBanInfo($ip);
            $bannedUntil = $info['banned_until'] ?? 0;
            $banThreat = new ThreatResult(
                type: 'ip_blacklist',
                severity: 'high',
                field: '_server.REMOTE_ADDR',
                payload: $ip,
                detail: 'IP temporarily banned until ' . date('Y-m-d H:i:s', $bannedUntil),
                httpStatus: 403,
            );
            if (self::$logger !== null) {
                self::$logger->log($banThreat, $meta);
            }
            return [$banThreat];
        }

        $filtered = self::filterWhitelistFields(self::flattenData($data));

        // Inject $_SERVER values so detectors don't rely on superglobals
        $filtered['_server.REQUEST_METHOD'] = $_SERVER['REQUEST_METHOD'] ?? $meta['method'] ?? '';
        $filtered['_server.CONTENT_LENGTH'] = $_SERVER['CONTENT_LENGTH'] ?? '';
        $filtered['_server.CONTENT_TYPE']   = $_SERVER['CONTENT_TYPE'] ?? '';
        $filtered['_server.HTTP_ORIGIN']    = $_SERVER['HTTP_ORIGIN'] ?? '';
        $filtered['_server.HTTP_HOST']      = $_SERVER['HTTP_HOST'] ?? '';

        $oldLimit = ini_get('pcre.backtrack_limit');
        ini_set('pcre.backtrack_limit', '1000000');
        try {
            $threats = self::$chain->scan($filtered);
        } finally {
            if ($oldLimit !== false && $oldLimit !== '') {
                ini_set('pcre.backtrack_limit', $oldLimit);
            }
        }

        foreach ($threats as $threat) {
            if (self::$logger !== null) {
                self::$logger->log($threat, $meta);
            }
        }

        // Record IP for attack escalation
        if (!empty($threats) && $ip && self::$ipBlacklist !== null) {
            self::$ipBlacklist->record($ip);
        }

        return $threats;
    }

    /**
     * Check if any threat should cause a block.
     */
    public static function shouldBlock(array $threats): bool
    {
        $config = self::getConfig();
        $detectorsConfig = $config['detectors'] ?? [];
        foreach ($threats as $threat) {
            $mode = $detectorsConfig[$threat->type]['mode'] ?? 'log';
            if ($mode === 'block') {
                return true;
            }
        }
        return false;
    }

    /**
     * Get block HTTP status code.
     * When threats are provided, returns the first non-default status code among them.
     */
    public static function blockStatusCode(?array $threats = null): int
    {
        if ($threats !== null) {
            foreach ($threats as $threat) {
                if ($threat instanceof ThreatResult && $threat->httpStatus !== 403) {
                    return $threat->httpStatus;
                }
            }
        }
        return (int) (self::getConfig()['block_status_code'] ?? 403);
    }

    /**
     * Get block response message.
     */
    public static function blockMessage(): string
    {
        return (string) (self::getConfig()['block_message'] ?? 'Request blocked by security policy');
    }

    private static function getConfig(): array
    {
        if (self::$config === null) {
            $defaultConfig = require dirname(__DIR__) . '/config/security.php';
            self::init($defaultConfig);
        }
        return self::$config;
    }

    private static function isWhitelistedIp(string $ip): bool
    {
        $whitelist = self::$config['whitelist_ips'] ?? [];
        if (empty($whitelist)) {
            return false;
        }
        foreach ($whitelist as $allowed) {
            if (self::ipMatches($ip, $allowed)) {
                return true;
            }
        }
        return false;
    }

    private static function ipMatches(string $ip, string $cidr): bool
    {
        if (strpos($cidr, '/') === false) {
            return $ip === $cidr;
        }
        [$subnet, $bits] = explode('/', $cidr);
        $bits = (int) $bits;

        // Detect IPv4 vs IPv6
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            $ipBin = inet_pton($ip);
            $subnetBin = inet_pton($subnet);
            if ($ipBin === false || $subnetBin === false) {
                return false;
            }
            return self::matchCidrBinary($ipBin, $subnetBin, $bits, 128);
        }

        // IPv4
        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);
        if ($ipLong === false || $subnetLong === false) {
            return false;
        }
        $mask = -1 << (32 - $bits);
        return ($ipLong & $mask) === ($subnetLong & $mask);
    }

    private static function matchCidrBinary(string $ipBin, string $subnetBin, int $bits, int $totalBits): bool
    {
        $bytesToCompare = $bits >> 3;
        $remainingBits = $bits & 7;

        for ($i = 0; $i < $bytesToCompare; $i++) {
            if ($ipBin[$i] !== $subnetBin[$i]) {
                return false;
            }
        }

        if ($remainingBits > 0 && $bytesToCompare < strlen($ipBin)) {
            $mask = 0xFF << (8 - $remainingBits);
            if ((ord($ipBin[$bytesToCompare]) & $mask) !== (ord($subnetBin[$bytesToCompare]) & $mask)) {
                return false;
            }
        }

        return true;
    }

    private static function filterWhitelistFields(array $data): array
    {
        $whitelist = self::$config['whitelist_fields'] ?? [];
        if (empty($whitelist)) {
            return $data;
        }
        return array_diff_key($data, array_flip($whitelist));
    }

    private static function flattenData(array $data, string $prefix = ''): array
    {
        $flat = [];
        foreach ($data as $key => $value) {
            $path = $prefix === '' ? (string) $key : "{$prefix}.{$key}";
            if (is_array($value)) {
                $nested = self::flattenData($value, $path);
                foreach ($nested as $nk => $nv) {
                    // If nested path collides with a previously set top-level key,
                    // the nested value wins (more specific). No silent drops.
                    $flat[$nk] = $nv;
                }
                // Also keep a JSON representation for scanning (catches array-based attacks)
                $encoded = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
                if ($encoded !== false) {
                    $flat[$path] = $encoded;
                }
            } elseif (is_scalar($value)) {
                // Resolve collisions: if this path already exists (from a nested value),
                // append a suffix to preserve both values for scanning
                if (array_key_exists($path, $flat)) {
                    $suffix = 1;
                    while (array_key_exists("{$path}#{$suffix}", $flat)) {
                        $suffix++;
                    }
                    $flat["{$path}#{$suffix}"] = (string) $value;
                } else {
                    $flat[$path] = (string) $value;
                }
            }
        }
        return $flat;
    }

    /**
     * Get a configuration option for a specific detector.
     */
    public static function detectorOption(string $detector, string $option, mixed $default = null): mixed
    {
        $config = self::getConfig();
        return $config['detectors'][$detector][$option] ?? $default;
    }

    /**
     * Get the IpBlacklist instance (for testing).
     */
    public static function getIpBlacklist(): ?IpBlacklist
    {
        return self::$ipBlacklist;
    }

    /**
     * Create a storage adapter from config.
     */
    private static function createStorage(array $config): StorageInterface
    {
        $type = strtolower($config['type'] ?? 'file');

        return match ($type) {
            'redis' => new RedisStorage($config['redis'] ?? []),
            'cache' => new CacheStorage($config['cache'] ?? []),
            default => new FileStorage($config['file'] ?? []),
        };
    }

    /**
     * Reset state (for testing).
     */
    public static function reset(): void
    {
        self::$chain = null;
        self::$logger = null;
        self::$config = null;
        self::$ipBlacklist = null;
    }
}
