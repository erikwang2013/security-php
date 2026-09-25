<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Tests\Core;

use Erikwang2013\Security\Storage\CacheStorage;
use Erikwang2013\Security\Storage\FileStorage;
use Erikwang2013\Security\Storage\RedisStorage;
use PHPUnit\Framework\TestCase;

class StorageTest extends TestCase
{
    private string $tmpDir;

    protected function setUp(): void
    {
        $this->tmpDir = sys_get_temp_dir() . '/sec_storage_' . uniqid();
        @mkdir($this->tmpDir, 0755, true);
    }

    protected function tearDown(): void
    {
        $this->rmDir($this->tmpDir);
    }

    private function rmDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach (glob($dir . '/*') ?: [] as $file) {
            is_dir($file) ? $this->rmDir($file) : @unlink($file);
        }
        @rmdir($dir);
    }

    // ──────────────── FileStorage ────────────────

    public function testFileStorageHandlesCorruptJson(): void
    {
        $path = $this->tmpDir . '/corrupt.json';
        file_put_contents($path, 'not-json{{{');

        $s = new FileStorage(['path' => $path]);
        $this->assertNull($s->get('key'));
        $this->assertEmpty($s->all());
        $this->assertFalse($s->has('key'));

        // Write must recover from corrupt file instead of throwing
        $s->set('key', 'value');
        $this->assertSame('value', $s->get('key'));
    }

    public function testFileStorageDefaultsToTempDir(): void
    {
        $s = new FileStorage([]);
        $default = sys_get_temp_dir() . '/security_storage.json';
        @unlink($default);
        $s->set('k', 1);
        $this->assertSame(1, $s->get('k'));
        $s->clear();
        $this->assertFileDoesNotExist($default);
    }

    public function testFileStorageCreatesMissingDirectory(): void
    {
        $s = new FileStorage(['path' => $this->tmpDir . '/nested/dir/store.json']);
        $s->set('k', ['a' => 1]);
        $this->assertSame(['a' => 1], $s->get('k'));
    }

    // ──────────────── CacheStorage ────────────────

    public function testCacheStorageExpiredEntryIsDropped(): void
    {
        $s = new CacheStorage(['path' => $this->tmpDir, 'prefix' => 'p_']);
        $cacheDir = $this->tmpDir . '/security_cache';
        @mkdir($cacheDir, 0755, true);
        $key = 'expired_key';
        $path = $cacheDir . '/p_' . md5($key);
        file_put_contents($path, json_encode([time() - 10, 'stale']));

        $this->assertNull($s->get($key), 'Expired entry must return null');
        $this->assertFalse(file_exists($path), 'Expired entry file must be removed on read');
        $this->assertFalse($s->has($key));
    }

    public function testCacheStorageAllSkipsExpiredAndMissing(): void
    {
        $s = new CacheStorage(['path' => $this->tmpDir, 'prefix' => 'p_']);
        $s->set('good', 'v1');
        $s->set('good2', 'v2');
        file_put_contents($this->tmpDir . '/security_cache/p_' . md5('old'), json_encode([time() - 5, 'stale']));

        $all = $s->all();
        $this->assertSame(['good' => 'v1', 'good2' => 'v2'], $all);
    }

    public function testCacheStorageGetHandlesCorruptFile(): void
    {
        $s = new CacheStorage(['path' => $this->tmpDir, 'prefix' => 'p_']);
        @mkdir($this->tmpDir . '/security_cache', 0755, true);
        $path = $this->tmpDir . '/security_cache/p_' . md5('bad');
        file_put_contents($path, 'garbage');

        $this->assertNull($s->get('bad'));
        $this->assertFalse($s->has('bad'));
    }

    public function testCacheStorageDeleteMissingAndClearEmptyDirAreNoops(): void
    {
        $s = new CacheStorage(['path' => $this->tmpDir, 'prefix' => 'p_']);
        $s->delete('never_set');
        $s->clear();
        $s->set('k', 1);
        $s->clear();
        $this->assertEmpty($s->all());
        $this->assertNull($s->get('k'));
    }

    // ──────────────── RedisStorage ────────────────

    public function testRedisStorageReadWriteRoundTrip(): void
    {
        $redis = $this->redis();
        if ($redis === null) {
            $this->markTestSkipped('Redis server not available at 127.0.0.1:6379');
        }

        $prefix = 'sec_test_' . uniqid() . ':';
        $s = new RedisStorage($redis, $prefix);
        $s->clear();

        try {
            $this->assertNull($s->get('k1'));
            $s->set('k1', ['count' => 1]);
            $s->set('k2', 'string');
            $s->set('k3', 42);
            $this->assertSame(['count' => 1], $s->get('k1'));
            $this->assertSame('string', $s->get('k2'));
            $this->assertSame(42, $s->get('k3'));
            $this->assertTrue($s->has('k1'));
            $this->assertFalse($s->has('missing'));

            $all = $s->all();
            ksort($all);
            $this->assertSame(['k1' => ['count' => 1], 'k2' => 'string', 'k3' => 42], $all);

            $s->delete('k1');
            $this->assertNull($s->get('k1'));

            $s->clear();
            $this->assertEmpty($s->all());
        } finally {
            $s->clear();
        }
    }

    public function testRedisStoragePrefixIsolation(): void
    {
        $redis = $this->redis();
        if ($redis === null) {
            $this->markTestSkipped('Redis server not available at 127.0.0.1:6379');
        }

        $a = new RedisStorage($redis, 'sec_iso_a:');
        $b = new RedisStorage($redis, 'sec_iso_b:');
        $a->clear();
        $b->clear();

        try {
            $a->set('shared', 'from-a');
            $b->set('shared', 'from-b');
            $this->assertSame('from-a', $a->get('shared'));
            $this->assertSame('from-b', $b->get('shared'));
        } finally {
            $a->clear();
            $b->clear();
        }
    }

    /**
     * mutate() truncates the file in place, so a reader without a lock can
     * catch it mid-write and see an empty store. Every consumer reads that as
     * "no state yet": a fresh session baseline, a reset failure counter, a
     * missing ban.
     */
    public function testReadWaitsForAWriterInsteadOfSeeingAnEmptyStore(): void
    {
        $path = $this->tmpDir . '/lock.json';
        $storage = new FileStorage(['path' => $path]);
        $storage->set('key', ['fp' => 'baseline']);

        // A separate process holds the write lock with the file truncated, the
        // exact state a mid-write reader used to observe.
        $writer = sys_get_temp_dir() . '/sec_lock_writer_' . uniqid() . '.php';
        file_put_contents($writer, '<?php
            $fp = fopen($argv[1], "c+");
            flock($fp, LOCK_EX);
            ftruncate($fp, 0);
            usleep(300000);
            fwrite($fp, json_encode(["key" => ["fp" => "written"]]));
            fflush($fp);
            flock($fp, LOCK_UN);
            fclose($fp);
        ');

        $proc = proc_open([PHP_BINARY, '-n', $writer, $path], [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes);
        try {
            usleep(100000); // let the writer take the lock and truncate
            $read = $storage->get('key');

            $this->assertNotNull($read, '读到期中状态会被当成“没有数据”，这正是会话劫持漏报的成因');
            $this->assertSame(['fp' => 'written'], $read);
        } finally {
            if (is_resource($proc)) {
                proc_close($proc);
            }
            @unlink($writer);
        }
    }

    private function redis(): ?\Redis
    {
        if (!class_exists('Redis')) {
            return null;
        }
        $redis = new \Redis();
        try {
            $redis->connect('127.0.0.1', 6379, 1);
            $redis->ping();
            return $redis;
        } catch (\Throwable) {
            return null;
        }
    }
}
