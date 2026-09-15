<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security;

use Erikwang2013\Security\Identity\IdentityGuard;
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
    private static ?array $whitelistFields = null;
    private static ?StorageInterface $storage = null;
    private static ?IdentityGuard $identity = null;

    /**
     * Initialize with config. Called once by middleware or bootstrap.
     */
    public static function init(array $config): void
    {
        self::$config = $config;
        self::$whitelistFields = array_flip($config['whitelist_fields'] ?? []);

        if (empty($config['enabled'])) {
            return;
        }

        self::$chain = new DetectorChain();
        self::$logger = new Logger($config['log'] ?? []);

        $identityConfig = $config['identity'] ?? [];

        // One shared instance: two FileStorage objects on the same path would
        // each hold a stale JSON map and overwrite each other's writes.
        $ipBlacklistConfig = $config['ip_blacklist'] ?? [];
        if (!empty($ipBlacklistConfig['enabled']) || !empty($identityConfig['enabled'])) {
            self::$storage = self::createStorage($config['storage'] ?? []);
        }

        if (!empty($ipBlacklistConfig['enabled']) && self::$storage !== null) {
            self::$ipBlacklist = new IpBlacklist($ipBlacklistConfig, self::$storage);
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

        // Identity checks live outside the regex chain: they need cross-request
        // state, which the stateless detectors deliberately do not have.
        if (!empty($identityConfig['enabled']) && self::$storage !== null) {
            self::$identity = new IdentityGuard(self::$storage, $config, $detectorsConfig);
        }
    }

    /**
     * Full scan with request metadata.
     * Returns ThreatResult[]. Empty array = safe.
     */
    public static function guard(array $data, array $meta = []): array
    {
        self::getConfig();

        if (empty(self::$config['enabled']) || self::$chain === null) {
            return [];
        }

        $ip = $meta['ip'] ?? '';
        // Resolve real client IP through trusted proxies before whitelist/blacklist checks
        if ($ip !== '' && !empty(self::$config['trusted_proxies'] ?? [])) {
            // The identity checks and the log line must see the same client the
            // blacklist does, or behind a proxy they would bind a session to the
            // proxy's network and the location signal could never fire.
            $meta['ip'] = $ip = self::resolveClientIp($ip, $meta);
        }
        if ($ip && self::isWhitelistedIp($ip)) {
            return [];
        }

        if ($ip && self::$ipBlacklist !== null) {
            $banInfo = self::$ipBlacklist->check($ip);
            if ($banInfo !== null) {
                $bannedUntil = $banInfo['banned_until'] ?? 0;
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
        }

        // $flat stays unfiltered: a protected field that also appears in
        // whitelist_fields must still reach the integrity check.
        $flat = self::flattenData($data);
        $filtered = self::filterWhitelistFields($flat);

        // Inject request metadata so detectors don't rely on superglobals
        // (CLI / Swoole / Octane environments have empty $_SERVER)
        $filtered['_server.REQUEST_METHOD'] = $meta['method'] ?? $_SERVER['REQUEST_METHOD'] ?? '';
        $filtered['_server.CONTENT_LENGTH'] = $meta['content_length'] ?? $_SERVER['CONTENT_LENGTH'] ?? '';
        $filtered['_server.CONTENT_TYPE']   = $meta['content_type'] ?? $_SERVER['CONTENT_TYPE'] ?? '';
        $filtered['_server.HTTP_ORIGIN']    = $meta['origin'] ?? $_SERVER['HTTP_ORIGIN'] ?? '';
        $filtered['_server.HTTP_HOST']      = $meta['host'] ?? $_SERVER['HTTP_HOST'] ?? '';
        $filtered['_server.TRANSFER_ENCODING'] = ($meta['transfer_encoding'] ?? '') !== ''
            ? 'Transfer-Encoding: ' . $meta['transfer_encoding']
            : '';

        $oldLimit = ini_get('pcre.backtrack_limit');
        if ($oldLimit !== '1000000') {
            ini_set('pcre.backtrack_limit', '1000000');
        }
        try {
            $threats = self::$chain->scan($filtered);
            // Decoded variants of values carrying an encoding signal. Runs
            // inside the same backtrack_limit guard as the original scan.
            $threats = array_merge(
                $threats,
                NormalizationScanner::scan(self::$chain, $filtered, self::$config['normalization'] ?? []),
            );
        } finally {
            // Guard false/'' like d155aa2: ini_set(false) would clear the limit
            if ($oldLimit !== false && $oldLimit !== '' && $oldLimit !== '1000000') {
                ini_set('pcre.backtrack_limit', $oldLimit);
            }
        }

        // Same list as the regex threats, so they share logging + block mode
        $threats = array_merge($threats, self::$identity?->check($flat, $meta) ?? []);

        foreach ($threats as $threat) {
            if (self::$logger !== null) {
                self::$logger->log($threat, $meta);
            }
        }

        // Record IP for attack escalation (log-mode threats don't count)
        if (!empty($threats) && $ip && self::$ipBlacklist !== null && self::shouldBlock($threats)) {
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
            if ($threat->type === 'ip_blacklist') {
                return true;
            }
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

    /**
     * Security response headers for middleware to append to every response.
     * Empty when disabled; blank values are opt-in placeholders, so CSP/HSTS
     * stay off until the site actually configures them.
     */
    public static function securityHeaders(): array
    {
        $cfg = self::getConfig()['security_headers'] ?? [];
        if (empty($cfg['enabled'])) {
            return [];
        }
        return array_filter($cfg['headers'] ?? [], fn ($value) => is_string($value) && $value !== '');
    }

    /**
     * Combined block decision: null = proceed, else [status, message].
     */
    public static function blockDecision(array $threats): ?array
    {
        if (empty($threats) || !self::shouldBlock($threats)) {
            return null;
        }
        return [
            'status' => self::blockStatusCode($threats),
            'message' => self::blockMessage(),
        ];
    }

    private static function getConfig(): array
    {
        if (self::$config === null) {
            $defaultConfig = require dirname(__DIR__) . '/config/security.php';
            self::init($defaultConfig);
        }
        return self::$config;
    }

    /**
     * Resolve the real client IP when the peer is a trusted reverse proxy.
     * No-op unless the remote address matches a configured trusted proxy.
     */
    private static function resolveClientIp(string $remoteAddr, array $meta): string
    {
        $trusted = self::$config['trusted_proxies'] ?? [];
        $isTrusted = false;
        foreach ($trusted as $entry) {
            if (self::ipMatches($remoteAddr, (string) $entry)) {
                $isTrusted = true;
                break;
            }
        }
        if (!$isTrusted) {
            return $remoteAddr;
        }

        $xff = trim($meta['x_forwarded_for'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '');
        if ($xff === '') {
            return $remoteAddr;
        }

        // Leftmost hop is the original client (standard XFF semantics)
        $first = trim(explode(',', $xff)[0]);
        if (str_starts_with($first, 'for=')) {
            $first = trim(substr($first, 4), " \t\"");
        }
        return filter_var($first, FILTER_VALIDATE_IP) !== false ? $first : $remoteAddr;
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

        // Reject malformed (/abc) or oversized (/33) prefixes before any bit shifting
        $isV6 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
        if ($bits < 1 || $bits > ($isV6 ? 128 : 32)) {
            return false;
        }

        // Detect IPv4 vs IPv6
        if ($isV6) {
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

    /**
     * Merge request sources without dropping shadowed values.
     *
     * `array_merge()` keeps one value per name, and whatever it drops never
     * reaches a detector — while the application may well read the dropped one.
     * Every framework prefers a different source (Laravel body-over-query,
     * Hyperf query-over-body, Webman post-over-get) and none of those matches
     * every way an app can read the same name, so a same-named field on two
     * sources used to be a hole in the whole regex family of detectors.
     *
     * The last source still owns the bare name, exactly as `array_merge()` left
     * it, so log fields, `whitelist_fields` entries and configs keep working
     * unchanged; whatever that displaces survives under `_<source>.<name>`, the
     * naming the threat list already uses for `_server.REMOTE_ADDR`. The change
     * is purely additive — nothing that used to be scanned stops being scanned.
     *
     * A name in `whitelist_fields` is exempt from *every* source: the whitelist
     * is a statement about the name, not about which source carried it.
     *
     * @param  array<string, mixed> $sources source label => values, in array_merge order
     * @return array<string, mixed>
     */
    public static function mergeRequestSources(array $sources): array
    {
        // Lazy config init: the whitelist has to be known here, and in the
        // non-framework path this runs before guard() would have initialised it.
        self::getConfig();
        $whitelist = self::$whitelistFields ?? [];

        $data = [];
        $owner = [];
        foreach ($sources as $source => $values) {
            if (!is_array($values)) {
                continue;
            }
            foreach ($values as $key => $value) {
                if (!array_key_exists($key, $data)) {
                    $data[$key] = $value;
                    $owner[$key] = $source;
                    continue;
                }
                // Identical values lose nothing, so the displaced copy is only
                // kept when it actually differs. A whitelisted name is skipped
                // by the detectors whatever it holds, so it needs no copy either.
                if ($data[$key] !== $value && !isset($whitelist[$key])) {
                    $data['_' . $owner[$key] . '.' . $key] = $data[$key];
                }
                $data[$key] = $value;
                $owner[$key] = $source;
            }
        }

        return $data;
    }

    private static function filterWhitelistFields(array $data): array
    {
        return array_diff_key($data, self::$whitelistFields ?? []);
    }

    private static function flattenData(array $data, string $prefix = ''): array
    {
        $flat = [];
        foreach ($data as $key => $value) {
            $path = $prefix === '' ? (string) $key : "{$prefix}.{$key}";
            if (is_array($value)) {
                $nested = self::flattenData($value, $path);
                foreach ($nested as $nk => $nv) {
                    $flat[self::uniqueKey($flat, $nk)] = $nv;
                }
                // Also keep a JSON representation for scanning (catches array-based attacks)
                $encoded = json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
                if ($encoded !== false) {
                    $flat[$path] = $encoded;
                }
            } elseif (is_scalar($value)) {
                // Collision source: the nested value's JSON repr already took $path
                $flat[self::uniqueKey($flat, $path)] = (string) $value;
            }
        }
        return $flat;
    }

    private static function uniqueKey(array $flat, string $path): string
    {
        if (!array_key_exists($path, $flat)) {
            return $path;
        }
        $suffix = 1;
        while (array_key_exists("{$path}#{$suffix}", $flat)) {
            $suffix++;
        }
        return "{$path}#{$suffix}";
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
     * Record a successful login for the unusual-location baseline, and return
     * the threat when the location is new so the caller can act on it.
     *
     * Call from the success branch of login / token issuing — cookie login and
     * token login use the same call; the baseline keys off the user id.
     */
    public static function recordLogin(string $userId, ?string $location = null, array $meta = []): ?ThreatResult
    {
        self::getConfig();

        $threat = self::$identity?->recordLogin($userId, $location, $meta);
        if ($threat !== null && self::$logger !== null) {
            // Runs from a controller, so nothing else would log it
            self::$logger->log($threat, $meta);
        }

        return $threat;
    }

    /**
     * Record one failed login. Returns a threat when this attempt locked the
     * account, or when it was already locked — call it from the failure branch
     * of login / token verification, which the middleware never sees.
     */
    public static function recordFailedLogin(string $userId, ?string $ip = null, array $meta = []): ?ThreatResult
    {
        self::getConfig();

        $threat = self::$identity?->recordFailedLogin($userId, $ip ?? ($meta['ip'] ?? null));
        if ($threat !== null && self::$logger !== null) {
            // Runs from a controller, so nothing else would log it
            self::$logger->log($threat, $meta);
        }

        return $threat;
    }

    /**
     * Gate an auth attempt before it runs; true means the account is locked.
     */
    public static function isLockedOut(string $userId, ?string $ip = null, array $meta = []): bool
    {
        self::getConfig();

        return self::$identity?->isLockedOut($userId, $ip ?? ($meta['ip'] ?? null)) ?? false;
    }

    /**
     * Sign protected field values for the client to send back. '' when unconfigured.
     *
     * @param array<string, mixed> $fields flat dot-path => value, e.g. ['order.price' => 100]
     */
    public static function signFields(array $fields, ?int $ttl = null): string
    {
        self::getConfig();

        return self::$identity === null ? '' : self::$identity->signFields($fields, $ttl);
    }

    /**
     * Verify protected field values standalone; guard() runs the same check per request.
     */
    public static function verifyFields(array $data, array $meta = []): ?ThreatResult
    {
        self::getConfig();

        $threat = self::$identity?->verifyFields(self::flattenData($data));
        if ($threat !== null && self::$logger !== null) {
            self::$logger->log($threat, $meta);
        }

        return $threat;
    }

    /**
     * Create a storage adapter from config.
     */
    private static function createStorage(array $config): StorageInterface
    {
        // Allow injecting a pre-made StorageInterface
        if (isset($config['instance']) && $config['instance'] instanceof StorageInterface) {
            return $config['instance'];
        }

        $type = strtolower($config['type'] ?? 'file');

        return match ($type) {
            'redis' => new RedisStorage(
                $config['redis_instance'] ?? new \Redis(),
                $config['redis']['prefix'] ?? 'security:',
            ),
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
        self::$whitelistFields = null;
        self::$storage = null;
        self::$identity = null;
    }
}
