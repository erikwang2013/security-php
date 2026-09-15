<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Tests\Core;

use Erikwang2013\Security\SecurityGuard;
use Erikwang2013\Security\Storage\FileStorage;
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

    /**
     * The non-framework path must feed the identity layer the same request
     * metadata the middlewares do. Before this, session_hijack was silently
     * dead here: extractSessionId() reads $meta['cookies'] / $meta['headers'],
     * found neither, and returned null on every request.
     */
    public function testSecurityScanCurrentRequestFeedsSessionIdentity(): void
    {
        $storagePath = sys_get_temp_dir() . '/security_helpers_identity.json';
        @unlink($storagePath);

        $config = require dirname(__DIR__, 2) . '/config/security.php';
        $config['storage'] = ['instance' => new FileStorage(['path' => $storagePath])];
        $config['log']['enabled'] = false;
        SecurityGuard::reset();
        SecurityGuard::init($config);

        $cookie = $config['identity']['session']['cookie'];
        $this->assertNotSame('', $cookie, 'config must name a session cookie for this test');

        $_COOKIE = [$cookie => 'sess-abc'];
        $_GET = [];
        $_POST = [];
        $_FILES = [];
        $_SERVER = [
            'REMOTE_ADDR' => '203.0.113.9',
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/',
            'HTTP_USER_AGENT' => 'UA-one',
        ];

        try {
            // First sight sets the fingerprint baseline.
            $this->assertSame([], security_scan_current_request());
            // Same fingerprint → still clean.
            $this->assertSame([], security_scan_current_request());

            // Same session id, different User-Agent → hijack.
            $_SERVER['HTTP_USER_AGENT'] = 'UA-two';
            $threats = security_scan_current_request();
        } finally {
            $_COOKIE = [];
            $_GET = [];
            $_POST = [];
            $_FILES = [];
            $_SERVER = [];
            @unlink($storagePath);
            SecurityGuard::reset();
        }

        $this->assertNotEmpty($threats, 'session_hijack must fire on the non-framework path');
        $this->assertSame('session_hijack', $threats[0]->type);
        $this->assertSame(401, $threats[0]->httpStatus);
    }

    /**
     * A token login (no cookie) must take the same path — the middleware reads
     * Authorization / X-Token / X-Auth-Token and so must this.
     */
    public function testSecurityScanCurrentRequestFeedsTokenSessionIdentity(): void
    {
        $storagePath = sys_get_temp_dir() . '/security_helpers_token.json';
        @unlink($storagePath);

        $config = require dirname(__DIR__, 2) . '/config/security.php';
        $config['storage'] = ['instance' => new FileStorage(['path' => $storagePath])];
        $config['log']['enabled'] = false;
        SecurityGuard::reset();
        SecurityGuard::init($config);

        $_COOKIE = [];
        $_GET = [];
        $_POST = [];
        $_FILES = [];
        $_SERVER = [
            'REMOTE_ADDR' => '203.0.113.9',
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/',
            'HTTP_USER_AGENT' => 'UA-one',
            'HTTP_AUTHORIZATION' => 'Bearer tok-abc',
        ];

        try {
            $this->assertSame([], security_scan_current_request());

            $_SERVER['HTTP_USER_AGENT'] = 'UA-two';
            $threats = security_scan_current_request();
        } finally {
            $_COOKIE = [];
            $_GET = [];
            $_POST = [];
            $_FILES = [];
            $_SERVER = [];
            @unlink($storagePath);
            SecurityGuard::reset();
        }

        $this->assertNotEmpty($threats, 'a Bearer token must identify the session too');
        $this->assertSame('session_hijack', $threats[0]->type);
    }

    /**
     * Cookies must reach $meta as the raw superglobal, not via the merged body:
     * a same-named GET/POST field would otherwise shadow the real cookie.
     */
    public function testCookieIsReadFromMetaNotFromShadowedBody(): void
    {
        $storagePath = sys_get_temp_dir() . '/security_helpers_shadow.json';
        @unlink($storagePath);

        $config = require dirname(__DIR__, 2) . '/config/security.php';
        $config['storage'] = ['instance' => new FileStorage(['path' => $storagePath])];
        $config['log']['enabled'] = false;
        SecurityGuard::reset();
        SecurityGuard::init($config);

        $cookie = $config['identity']['session']['cookie'];

        $_COOKIE = [$cookie => 'real-session'];
        $_GET = [$cookie => 'attacker-supplied']; // would shadow in $data
        $_POST = [];
        $_FILES = [];
        $_SERVER = [
            'REMOTE_ADDR' => '203.0.113.9',
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/',
            'HTTP_USER_AGENT' => 'UA-one',
        ];

        try {
            $this->assertSame([], security_scan_current_request());

            $_SERVER['HTTP_USER_AGENT'] = 'UA-two';
            $threats = security_scan_current_request();
        } finally {
            $_COOKIE = [];
            $_GET = [];
            $_POST = [];
            $_FILES = [];
            $_SERVER = [];
            @unlink($storagePath);
            SecurityGuard::reset();
        }

        $this->assertNotEmpty($threats, 'the real cookie must win over the same-named query field');
        $this->assertSame('session_hijack', $threats[0]->type);
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
     * security_guard() must emit the configured security headers on both the
     * blocked and the passing response, matching the four middlewares.
     *
     * header() is a no-op under the CLI SAPI, so this drives PHP's built-in
     * server — the only place the header() call in the helper is observable.
     */
    public function testSecurityGuardEmitsSecurityHeadersOnBothPaths(): void
    {
        [$headers, $body] = $this->requestOverHttp('$_GET = ["name" => "John"];');
        $this->assertSame('NOT-BLOCKED', $body);
        $this->assertSame('nosniff', $headers['x-content-type-options'] ?? null);
        $this->assertSame('SAMEORIGIN', $headers['x-frame-options'] ?? null);

        [$headers, $body] = $this->requestOverHttp('$_GET = ["x" => "<script>alert(1)</script>"];');
        $this->assertStringContainsString('Request blocked by security policy', $body);
        $this->assertSame(
            'nosniff',
            $headers['x-content-type-options'] ?? null,
            'a blocked response must carry the security headers too'
        );
        $this->assertSame('SAMEORIGIN', $headers['x-frame-options'] ?? null);
    }

    /**
     * Serve one request through PHP's built-in server.
     *
     * @return array{0: array<string, string>, 1: string} lower-cased headers, body
     */
    private function requestOverHttp(string $setup): array
    {
        $router = sys_get_temp_dir() . '/sec_helpers_router_' . uniqid() . '.php';
        $autoload = var_export(dirname(__DIR__, 2) . '/vendor/autoload.php', true);

        file_put_contents($router, <<<PHP
        <?php
        require {$autoload};
        @unlink(sys_get_temp_dir() . '/security_storage.json');
        \$_COOKIE = [];
        \$_POST = [];
        \$_FILES = [];
        \$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
        // The built-in server's own Host is 127.0.0.1:<port>, which the
        // dns_rebinding detector rightly flags. Use a public host as a real
        // deployment would.
        \$_SERVER['HTTP_HOST'] = 'example.com';
        {$setup}
        security_guard();
        echo 'NOT-BLOCKED';
        PHP);

        $context = stream_context_create(['http' => ['timeout' => 2, 'ignore_errors' => true]]);
        $body = false;
        $deadline = microtime(true) + 10;

        try {
            // A random high port can still be taken; give up to three a chance.
            for ($attempt = 0; $attempt < 3 && microtime(true) < $deadline; $attempt++) {
                $port = random_int(20000, 60000);
                // Array form, not a string: a string command goes through
                // /bin/sh, and proc_terminate() would then kill the shell and
                // leak the php -S behind it.
                $proc = proc_open(
                    [PHP_BINARY, '-S', "127.0.0.1:{$port}", $router],
                    [['pipe', 'r'], ['file', '/dev/null', 'w'], ['file', '/dev/null', 'w']],
                    $pipes
                );
                if (!is_resource($proc)) {
                    continue;
                }

                try {
                    $body = false;
                    for ($i = 0; $i < 20 && microtime(true) < $deadline; $i++) {
                        $body = @file_get_contents("http://127.0.0.1:{$port}/", false, $context);
                        if ($body !== false) {
                            break;
                        }
                        usleep(50000);
                    }
                } finally {
                    proc_terminate($proc, 9);
                    proc_close($proc);
                }

                if ($body !== false) {
                    break;
                }
            }
        } finally {
            @unlink($router);
            @unlink(sys_get_temp_dir() . '/security_storage.json');
        }

        if ($body === false) {
            $this->markTestSkipped('PHP built-in server could not be reached in this environment');
        }

        $headers = [];
        foreach ($http_response_header ?? [] as $line) {
            if (str_contains($line, ':')) {
                [$name, $value] = explode(':', $line, 2);
                $headers[strtolower(trim($name))] = trim($value);
            }
        }

        return [$headers, (string) $body];
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
