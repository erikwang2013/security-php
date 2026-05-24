<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Tests\Core;

use Erikwang2013\Security\IpBlacklist;
use Erikwang2013\Security\Storage\FileStorage;
use PHPUnit\Framework\TestCase;

class IpBlacklistTest extends TestCase
{
    private IpBlacklist $blacklist;
    private FileStorage $storage;

    protected function setUp(): void
    {
        $this->storage = new FileStorage([
            'path' => sys_get_temp_dir() . '/test_ip_blacklist.json',
        ]);
        $this->blacklist = new IpBlacklist([
            'enabled' => true,
            'max_attempts' => 5,
            'window_seconds' => 60,
            'ban_duration_seconds' => 900,
        ], $this->storage);
    }

    protected function tearDown(): void
    {
        $this->blacklist->reset();
    }

    public function testInitiallyNotBanned(): void
    {
        $this->assertFalse($this->blacklist->isBanned('192.168.1.1'));
    }

    public function testRecordDoesNotBanUnderThreshold(): void
    {
        for ($i = 0; $i < 4; $i++) {
            $result = $this->blacklist->record('10.0.0.1');
            $this->assertNull($result);
        }
        $this->assertFalse($this->blacklist->isBanned('10.0.0.1'));
    }

    public function testRecordBansOnThreshold(): void
    {
        for ($i = 0; $i < 4; $i++) {
            $this->blacklist->record('10.0.0.2');
        }
        // 5th attempt triggers ban
        $result = $this->blacklist->record('10.0.0.2');
        $this->assertNotNull($result);
        $this->assertGreaterThan(time(), $result['banned_until']);
        $this->assertTrue($this->blacklist->isBanned('10.0.0.2'));
    }

    public function testBanExpiresAfterDuration(): void
    {
        $storage = new FileStorage([
            'path' => sys_get_temp_dir() . '/test_ip_blacklist_expire.json',
        ]);
        $shortBan = new IpBlacklist([
            'enabled' => true,
            'max_attempts' => 2,
            'window_seconds' => 60,
            'ban_duration_seconds' => 0,
        ], $storage);

        $shortBan->record('10.0.0.3');
        $shortBan->record('10.0.0.3');

        $this->assertFalse($shortBan->isBanned('10.0.0.3'));
        $shortBan->reset();
    }

    public function testCounterResetsAfterWindowExpires(): void
    {
        $storage = new FileStorage([
            'path' => sys_get_temp_dir() . '/test_ip_blacklist_window.json',
        ]);
        $shortWindow = new IpBlacklist([
            'enabled' => true,
            'max_attempts' => 5,
            'window_seconds' => 0,
            'ban_duration_seconds' => 900,
        ], $storage);

        $shortWindow->record('10.0.0.4');
        // Window expired, counter should reset
        $result = $shortWindow->record('10.0.0.4');
        $this->assertNull($result);
        $this->assertFalse($shortWindow->isBanned('10.0.0.4'));
        $shortWindow->reset();
    }

    public function testMultipleIpsTrackedIndependently(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->blacklist->record('192.168.1.100');
        }
        $this->assertTrue($this->blacklist->isBanned('192.168.1.100'));
        $this->assertFalse($this->blacklist->isBanned('192.168.1.200'));

        $this->blacklist->record('192.168.1.200');
        $this->assertFalse($this->blacklist->isBanned('192.168.1.200'));
    }

    public function testGetBanInfoReturnsNullForUnbannedIp(): void
    {
        $this->assertNull($this->blacklist->getBanInfo('10.0.0.99'));
    }

    public function testGetBanInfoReturnsDataForBannedIp(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->blacklist->record('172.16.0.1');
        }
        $info = $this->blacklist->getBanInfo('172.16.0.1');
        $this->assertNotNull($info);
        $this->assertSame(5, $info['count']);
        $this->assertGreaterThan(time(), $info['banned_until']);
    }

    // ──────────────── STORAGE BACKEND TESTS ────────────────

    public function testFileStorageReadWrite(): void
    {
        $s = new FileStorage(['path' => sys_get_temp_dir() . '/test_fs.json']);
        $s->clear();

        $this->assertNull($s->get('key1'));
        $s->set('key1', ['count' => 1]);
        $this->assertSame(['count' => 1], $s->get('key1'));
        $this->assertTrue($s->has('key1'));
        $this->assertFalse($s->has('key2'));

        $s->delete('key1');
        $this->assertNull($s->get('key1'));

        $s->set('a', 1);
        $s->set('b', 2);
        $this->assertCount(2, $s->all());

        $s->clear();
        $this->assertCount(0, $s->all());
    }

    public function testCacheStorageReadWrite(): void
    {
        if (!function_exists('serialize')) {
            $this->markTestSkipped('serialize not available');
        }

        $s = new \Erikwang2013\Security\Storage\CacheStorage([
            'path' => sys_get_temp_dir(),
            'prefix' => 'test_cs_',
        ]);
        $s->clear();

        $this->assertNull($s->get('key1'));
        $s->set('key1', ['count' => 1]);
        $this->assertSame(['count' => 1], $s->get('key1'));
        $this->assertTrue($s->has('key1'));

        $s->delete('key1');
        $this->assertNull($s->get('key1'));

        $s->clear();
    }

    public function testIpBlacklistWithCacheStorage(): void
    {
        $storage = new \Erikwang2013\Security\Storage\CacheStorage([
            'path' => sys_get_temp_dir(),
            'prefix' => 'test_bl_cache_',
        ]);
        $bl = new IpBlacklist([
            'max_attempts' => 3,
            'window_seconds' => 60,
            'ban_duration_seconds' => 900,
        ], $storage);

        $this->assertFalse($bl->isBanned('10.10.10.10'));

        $bl->record('10.10.10.10');
        $bl->record('10.10.10.10');
        $this->assertFalse($bl->isBanned('10.10.10.10'));

        $result = $bl->record('10.10.10.10'); // 3rd → ban
        $this->assertNotNull($result);
        $this->assertTrue($bl->isBanned('10.10.10.10'));

        $bl->reset();
    }
}
