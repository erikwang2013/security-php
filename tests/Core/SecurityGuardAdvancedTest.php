<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Tests\Core;

use Erikwang2013\Security\SecurityGuard;
use Erikwang2013\Security\Storage\CacheStorage;
use Erikwang2013\Security\Storage\FileStorage;
use Erikwang2013\Security\Storage\RedisStorage;
use Erikwang2013\Security\ThreatResult;
use PHPUnit\Framework\TestCase;

class SecurityGuardAdvancedTest extends TestCase
{
    private array $config;

    protected function setUp(): void
    {
        SecurityGuard::reset();
        // Shared default storage file (/tmp/security_storage.json) may hold
        // counts from previous runs — start clean.
        @unlink(sys_get_temp_dir() . '/security_storage.json');
        $this->config = require dirname(__DIR__, 2) . '/config/security.php';
    }

    protected function tearDown(): void
    {
        SecurityGuard::reset();
        @unlink(sys_get_temp_dir() . '/security_storage.json');
    }

    // ──────────────── TRUSTED PROXY / XFF RESOLUTION ────────────────

    public function testTrustedProxyResolvesRealClientFromXff(): void
    {
        $this->config['trusted_proxies'] = ['10.0.0.1'];
        $this->config['whitelist_ips'] = ['198.51.100.7'];
        SecurityGuard::init($this->config);

        $threats = SecurityGuard::guard(
            ['x' => '<script>alert(1)</script>'],
            ['ip' => '10.0.0.1', 'x_forwarded_for' => '198.51.100.7, 10.0.0.1'],
        );

        $this->assertEmpty($threats, 'XFF client IP matching whitelist must skip detection');
    }

    public function testTrustedProxyWithoutXffKeepsProxyIp(): void
    {
        $this->config['trusted_proxies'] = ['10.0.0.1'];
        $this->config['whitelist_ips'] = ['198.51.100.7'];
        SecurityGuard::init($this->config);

        $threats = SecurityGuard::guard(
            ['x' => '<script>alert(1)</script>'],
            ['ip' => '10.0.0.1'],
        );

        $this->assertNotEmpty($threats, 'Proxy IP without XFF must not be treated as the client');
    }

    public function testUntrustedProxyIsNotResolved(): void
    {
        $this->config['trusted_proxies'] = ['10.0.0.1'];
        $this->config['whitelist_ips'] = ['198.51.100.7'];
        SecurityGuard::init($this->config);

        $threats = SecurityGuard::guard(
            ['x' => '<script>alert(1)</script>'],
            ['ip' => '10.0.0.2', 'x_forwarded_for' => '198.51.100.7'],
        );

        $this->assertNotEmpty($threats, 'Spoofed XFF from an untrusted peer must be ignored');
    }

    public function testXffForSyntaxIsParsed(): void
    {
        $this->config['trusted_proxies'] = ['10.0.0.1'];
        $this->config['whitelist_ips'] = ['198.51.100.7'];
        SecurityGuard::init($this->config);

        $threats = SecurityGuard::guard(
            ['x' => '<script>alert(1)</script>'],
            ['ip' => '10.0.0.1', 'x_forwarded_for' => 'for="198.51.100.7"'],
        );

        $this->assertEmpty($threats, 'RFC 7239 for= syntax in XFF must be parsed');
    }

    public function testInvalidXffFallsBackToRemoteAddr(): void
    {
        $this->config['trusted_proxies'] = ['10.0.0.1'];
        $this->config['whitelist_ips'] = ['198.51.100.7'];
        SecurityGuard::init($this->config);

        $threats = SecurityGuard::guard(
            ['x' => '<script>alert(1)</script>'],
            ['ip' => '10.0.0.1', 'x_forwarded_for' => 'garbage'],
        );

        $this->assertNotEmpty($threats, 'Non-IP XFF value must not be trusted');
    }

    // ──────────────── SERVER METADATA INJECTION ────────────────

    public function testMetaMethodInjectedForDetectors(): void
    {
        SecurityGuard::init($this->config);
        $threats = SecurityGuard::guard(['x' => 'ok'], ['method' => 'TRACE']);

        $this->assertNotEmpty($threats);
        $this->assertSame('http_method', $threats[0]->type);
    }

    public function testMetaTransferEncodingInjected(): void
    {
        SecurityGuard::init($this->config);
        $threats = SecurityGuard::guard(['x' => 'ok'], ['transfer_encoding' => 'chunked']);

        $this->assertNotEmpty($threats);
        $this->assertContains('request_smuggling', array_column($threats, 'type'));
    }

    public function testMetaContentLengthInjected(): void
    {
        SecurityGuard::init($this->config);
        $threats = SecurityGuard::guard(['x' => 'ok'], ['content_length' => '20971520']);

        $this->assertNotEmpty($threats);
        $this->assertSame('body_size', $threats[0]->type);
    }

    public function testMetaContentTypeInjected(): void
    {
        SecurityGuard::init($this->config);
        $threats = SecurityGuard::guard(['x' => 'ok'], ['content_type' => 'application/octet-stream']);

        $this->assertNotEmpty($threats);
        $this->assertSame('content_type', $threats[0]->type);
    }

    public function testMetaOriginAndHostInjected(): void
    {
        SecurityGuard::init($this->config);
        $threats = SecurityGuard::guard(
            ['x' => 'ok'],
            ['origin' => 'https://evil.com', 'host' => 'good.com'],
        );

        $this->assertNotEmpty($threats);
        $this->assertSame('csrf_origin', $threats[0]->type);
    }

    // ──────────────── FLATTENING COLLISIONS ────────────────

    public function testFlattenCollisionSuffixPreservesBothValues(): void
    {
        SecurityGuard::init($this->config);
        $threats = SecurityGuard::guard([
            'user' => ['bio' => '<script>a</script>'],
            'user.bio' => '<script>b</script>',
        ]);

        $fields = array_column($threats, 'field');
        $this->assertContains('user.bio', $fields);
        $this->assertContains('user.bio#1', $fields, 'Colliding scalar path must be kept with a # suffix');
    }

    public function testFlattenKeepsJsonForArrayValues(): void
    {
        SecurityGuard::init($this->config);
        $threats = SecurityGuard::guard([
            'payload' => ['nested' => ['x' => '<script>alert(1)</script>']],
        ]);

        $this->assertNotEmpty($threats, 'Attack inside array must be caught via JSON representation');
    }

    // ──────────────── WHITELIST FIELDS ────────────────

    public function testCustomWhitelistFieldIsSkipped(): void
    {
        $this->config['whitelist_fields'] = ['custom_field'];
        SecurityGuard::init($this->config);

        $threats = SecurityGuard::guard(['custom_field' => '<script>alert(1)</script>']);
        $this->assertEmpty($threats);
    }

    // ──────────────── BLOCK MESSAGE / shouldBlock ────────────────

    public function testCustomBlockMessage(): void
    {
        $this->config['block_message'] = 'Blocked by custom policy';
        SecurityGuard::init($this->config);

        $this->assertSame('Blocked by custom policy', SecurityGuard::blockMessage());
    }

    public function testShouldBlockUnknownTypeDefaultsToLog(): void
    {
        SecurityGuard::init($this->config);
        $threat = new ThreatResult('unknown_type', 'critical', 'x', 'p', 'd');

        $this->assertFalse(SecurityGuard::shouldBlock([$threat]),
            'Detector type without mode config must default to log (no block)');
    }

    // ──────────────── DETECTOR OPTIONS ────────────────

    public function testDetectorOptionReadsNestedConfig(): void
    {
        $this->config['detectors']['http_method']['allowed_methods'] = ['GET'];
        SecurityGuard::init($this->config);

        $this->assertSame(['GET'], SecurityGuard::detectorOption('http_method', 'allowed_methods'));
        $this->assertNull(SecurityGuard::detectorOption('http_method', 'nope'));
        $this->assertSame('fallback', SecurityGuard::detectorOption('no_such', 'opt', 'fallback'));
    }

    public function testHttpMethodDetectorHonorsCustomAllowedMethods(): void
    {
        $this->config['detectors']['http_method']['allowed_methods'] = ['GET'];
        SecurityGuard::init($this->config);

        $threats = SecurityGuard::guard(['x' => 'ok'], ['method' => 'POST']);
        $this->assertNotEmpty($threats);
        $this->assertSame('http_method', $threats[0]->type);
    }

    public function testBodySizeDetectorHonorsCustomMaxSize(): void
    {
        $this->config['detectors']['body_size']['max_size'] = 1024;
        SecurityGuard::init($this->config);

        $threats = SecurityGuard::guard(['x' => 'ok'], ['content_length' => '2048']);
        $this->assertNotEmpty($threats);
        $this->assertSame('body_size', $threats[0]->type);
    }

    public function testContentTypeDetectorHonorsCustomAllowedTypes(): void
    {
        $this->config['detectors']['content_type']['allowed_types'] = ['application/octet-stream'];
        SecurityGuard::init($this->config);

        $threats = SecurityGuard::guard(['x' => 'ok'], ['content_type' => 'application/octet-stream']);
        $this->assertEmpty($threats, 'Custom allowed type must pass');
    }

    public function testCsrfOriginDetectorHonorsAllowedOrigins(): void
    {
        $this->config['detectors']['csrf_origin']['allowed_origins'] = ['api.trusted.com'];
        SecurityGuard::init($this->config);

        $threats = SecurityGuard::guard(
            ['x' => 'ok'],
            ['origin' => 'https://api.trusted.com', 'host' => 'good.com'],
        );
        $this->assertEmpty($threats, 'Origin in allowed_origins must pass even when Host differs');
    }

    // ──────────────── STORAGE BACKEND SELECTION ────────────────

    public function testStorageInstanceInjectionIsUsed(): void
    {
        $path = sys_get_temp_dir() . '/sec_guard_instance_' . uniqid() . '.json';
        $this->config['storage'] = ['instance' => new FileStorage(['path' => $path])];
        SecurityGuard::init($this->config);

        $blacklist = SecurityGuard::getIpBlacklist();
        $this->assertNotNull($blacklist);

        for ($i = 0; $i < 5; $i++) {
            $blacklist->record('198.51.100.50');
        }
        $this->assertTrue($blacklist->isBanned('198.51.100.50'));
        $this->assertFileExists($path, 'Records must land in the injected storage');

        $blacklist->reset();
    }

    public function testStorageTypeCacheIsUsed(): void
    {
        $dir = sys_get_temp_dir() . '/sec_guard_cache_' . uniqid();
        $this->config['storage'] = [
            'type' => 'cache',
            'cache' => ['path' => $dir, 'prefix' => 'sec_'],
        ];
        SecurityGuard::init($this->config);

        $blacklist = SecurityGuard::getIpBlacklist();
        $this->assertNotNull($blacklist);
        $blacklist->record('198.51.100.51');
        $this->assertFalse($blacklist->isBanned('198.51.100.51'));
        $blacklist->reset();
        $this->rmDir($dir);
    }

    public function testStorageTypeRedisIsUsed(): void
    {
        if (!class_exists('Redis')) {
            $this->markTestSkipped('ext-redis not available');
        }
        $redis = new \Redis();
        try {
            $redis->connect('127.0.0.1', 6379, 1);
            $redis->ping();
        } catch (\Throwable) {
            $this->markTestSkipped('Redis server not available at 127.0.0.1:6379');
        }

        $prefix = 'sec_guard_' . uniqid() . ':';
        $this->config['storage'] = [
            'type' => 'redis',
            'redis_instance' => $redis,
            'redis' => ['prefix' => $prefix],
        ];
        SecurityGuard::init($this->config);

        $blacklist = SecurityGuard::getIpBlacklist();
        $this->assertNotNull($blacklist);
        $blacklist->record('198.51.100.52');
        $this->assertFalse($blacklist->isBanned('198.51.100.52'));
        $blacklist->reset();

        // Prefix must be cleaned up after reset
        $this->assertEmpty((new RedisStorage($redis, $prefix))->all());
    }

    private function rmDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach (glob($dir . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($dir);
    }
}
