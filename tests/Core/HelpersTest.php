<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Tests\Core;

use PHPUnit\Framework\TestCase;

class HelpersTest extends TestCase
{
    protected function setUp(): void
    {
        \Erikwang2013\Security\SecurityGuard::reset();
        @unlink(sys_get_temp_dir() . '/security_storage.json');
    }

    protected function tearDown(): void
    {
        \Erikwang2013\Security\SecurityGuard::reset();
        @unlink(sys_get_temp_dir() . '/security_storage.json');
    }

    public function testSecurityScanDetectsAttack(): void
    {
        $threats = security_scan(['comment' => '<script>alert(1)</script>']);

        $this->assertNotEmpty($threats);
        $this->assertSame('xss', $threats[0]->type);
    }

    public function testSecurityScanReturnsEmptyForSafeData(): void
    {
        $this->assertSame([], security_scan(['name' => 'John Doe', 'age' => '30']));
    }

    public function testSecurityIsSafe(): void
    {
        $this->assertTrue(security_is_safe(['name' => 'John']));
        $this->assertFalse(security_is_safe(['x' => '<script>alert(1)</script>']));
    }

    public function testSecurityScanCurrentRequestReadsSuperglobals(): void
    {
        $_COOKIE = ['session' => 'abc123'];
        $_GET = ['q' => 'hello'];
        $_POST = ['comment' => '<script>alert(1)</script>'];
        $_FILES = [
            'avatar' => ['name' => 'photo.jpg', 'tmp_name' => '/tmp/phpXYZ', 'size' => 1, 'error' => 0],
        ];
        $_SERVER = [
            'REMOTE_ADDR' => '203.0.113.9',
            'REQUEST_METHOD' => 'POST',
            'REQUEST_URI' => '/api/comment',
            'HTTP_HOST' => 'example.com',
        ];

        try {
            $threats = security_scan_current_request();
        } finally {
            $_COOKIE = [];
            $_GET = [];
            $_POST = [];
            $_FILES = [];
            $_SERVER = [];
        }

        $this->assertNotEmpty($threats);
        $this->assertSame('xss', $threats[0]->type);
    }

    public function testSecurityScanCurrentRequestSafe(): void
    {
        $_GET = ['q' => 'hello'];
        $_POST = ['name' => 'John'];
        $_COOKIE = [];
        $_FILES = [];
        $_SERVER = ['REMOTE_ADDR' => '203.0.113.9', 'REQUEST_METHOD' => 'GET'];

        try {
            $this->assertSame([], security_scan_current_request());
        } finally {
            $_GET = [];
            $_POST = [];
            $_COOKIE = [];
            $_FILES = [];
            $_SERVER = [];
        }
    }

    public function testSecurityGuardDiesWithBlockMessageOnAttack(): void
    {
        [$output, $exitCode] = $this->runSubprocess('blocked');

        $this->assertSame(0, $exitCode);
        $this->assertStringContainsString('Request blocked by security policy', $output);
        $this->assertStringNotContainsString('NOT-BLOCKED', $output, 'security_guard() must terminate before the echo');
    }

    public function testSecurityGuardPassesSafeRequest(): void
    {
        [$output, $exitCode] = $this->runSubprocess('safe');

        $this->assertSame(0, $exitCode);
        $this->assertSame('NOT-BLOCKED', $output);
    }

    /**
     * security_guard() calls die() — run it in a separate PHP process.
     *
     * @return array{0: string, 1: int}
     */
    private function runSubprocess(string $scenario): array
    {
        $script = sys_get_temp_dir() . '/sec_helpers_' . uniqid() . '.php';
        $autoload = var_export(dirname(__DIR__, 2) . '/vendor/autoload.php', true);

        $body = $scenario === 'blocked'
            ? '$_GET = ["x" => "<script>alert(1)</script>"];'
            : '$_GET = ["name" => "John"];';

        file_put_contents($script, <<<PHP
        <?php
        require {$autoload};
        @unlink(sys_get_temp_dir() . '/security_storage.json');
        \$_COOKIE = [];
        \$_POST = [];
        \$_FILES = [];
        \$_SERVER = ['REMOTE_ADDR' => '203.0.113.9', 'REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/'];
        {$body}
        security_guard();
        echo 'NOT-BLOCKED';
        PHP);

        $output = [];
        $exitCode = 0;
        exec(PHP_BINARY . ' ' . escapeshellarg($script) . ' 2>&1', $output, $exitCode);
        @unlink($script);
        @unlink(sys_get_temp_dir() . '/security_storage.json');

        return [implode("\n", $output), $exitCode];
    }
}
