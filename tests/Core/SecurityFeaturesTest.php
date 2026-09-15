<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Tests\Core;

use Erikwang2013\Security\SecurityGuard;
use Erikwang2013\Security\Storage\FileStorage;
use Erikwang2013\Security\ThreatResult;
use PHPUnit\Framework\TestCase;

/**
 * 三项防御纵深：安全响应头、编码归一化、登录暴力破解锁定。
 *
 * 全部经 SecurityGuard 的公开接口断言而非直接调内部类 —— config 开关、
 * block/log 模式、日志脱敏与检测逻辑本身一样是交付物。
 */
class SecurityFeaturesTest extends TestCase
{
    private array $config;
    private string $storagePath;
    private string $logPath;

    protected function setUp(): void
    {
        SecurityGuard::reset();
        @unlink(sys_get_temp_dir() . '/security_storage.json');

        $this->storagePath = sys_get_temp_dir() . '/security_features_test.json';
        $this->logPath = sys_get_temp_dir() . '/security_features_test.log';
        @unlink($this->storagePath);
        @unlink($this->logPath);

        $this->config = require dirname(__DIR__, 2) . '/config/security.php';
        $this->config['storage'] = ['instance' => new FileStorage(['path' => $this->storagePath])];
        $this->config['log']['path'] = $this->logPath;
    }

    protected function tearDown(): void
    {
        SecurityGuard::reset();
        @unlink($this->storagePath);
        @unlink($this->logPath);
        @unlink(sys_get_temp_dir() . '/security_storage.json');
    }

    private function boot(): void
    {
        SecurityGuard::reset();
        SecurityGuard::init($this->config);
    }

    /**
     * @param array<string, mixed> $overrides
     * @return array<string, mixed>
     */
    private function meta(array $overrides = []): array
    {
        return array_merge([
            'ip'         => '203.0.113.5',
            'method'     => 'POST',
            'uri'        => '/order',
            'user_agent' => 'Mozilla/5.0 (Test)',
            'cookies'    => [],
            'headers'    => [],
        ], $overrides);
    }

    private function storage(): FileStorage
    {
        return new FileStorage(['path' => $this->storagePath]);
    }

    private function lockKey(string $userId): string
    {
        return 'ident:lock:' . hash('sha256', $userId);
    }

    /**
     * Write a lockout record directly so window/lock expiry can be asserted
     * deterministically without sleeping through real seconds.
     */
    private function writeLock(string $userId, array $record): void
    {
        $this->storage()->set($this->lockKey($userId), $record);
    }

    private function storedRaw(): string
    {
        return file_exists($this->storagePath) ? file_get_contents($this->storagePath) : '';
    }

    private function loggedRaw(): string
    {
        return file_exists($this->logPath) ? file_get_contents($this->logPath) : '';
    }

    /**
     * @param ThreatResult[] $threats
     * @return ThreatResult[]
     */
    private function typeThreats(array $threats, string $type): array
    {
        return array_values(array_filter(
            $threats,
            static fn (ThreatResult $threat): bool => $threat->type === $type,
        ));
    }

    // ──────────────── 安全响应头 ────────────────

    public function testSecurityHeadersReturnsConfiguredHeaders(): void
    {
        $this->boot();

        $headers = SecurityGuard::securityHeaders();
        $this->assertSame('nosniff', $headers['X-Content-Type-Options']);
        $this->assertSame('SAMEORIGIN', $headers['X-Frame-Options']);
        $this->assertSame('strict-origin-when-cross-origin', $headers['Referrer-Policy']);
    }

    public function testSecurityHeadersSkipsBlankPlaceholders(): void
    {
        $this->boot();

        // CSP / HSTS ship blank so they stay opt-in per site
        $headers = SecurityGuard::securityHeaders();
        $this->assertArrayNotHasKey('Content-Security-Policy', $headers);
        $this->assertArrayNotHasKey('Strict-Transport-Security', $headers);
        $this->assertArrayNotHasKey('Permissions-Policy', $headers);
    }

    public function testSecurityHeadersEmptyWhenDisabled(): void
    {
        $this->config['security_headers']['enabled'] = false;
        $this->boot();

        $this->assertSame([], SecurityGuard::securityHeaders());
    }

    public function testSecurityHeadersSendsBlankValueOnceConfigured(): void
    {
        $this->config['security_headers']['headers']['Content-Security-Policy'] = "default-src 'self'";
        $this->boot();

        $this->assertSame("default-src 'self'", SecurityGuard::securityHeaders()['Content-Security-Policy']);
    }

    // ──────────────── 编码归一化 ────────────────

    public function testNormalizationCatchesUrlEncodedXss(): void
    {
        $this->boot();

        $threats = $this->typeThreats(
            SecurityGuard::guard(['comment' => '%3Cscript%3Ealert(1)%3C/script%3E'], $this->meta()),
            'xss',
        );

        $this->assertNotEmpty($threats);
        $this->assertStringContainsString('[decoded:urldecode]', $threats[0]->detail);
    }

    public function testNormalizationCatchesDoubleEncodedPayload(): void
    {
        $this->boot();

        $threats = $this->typeThreats(
            SecurityGuard::guard(['comment' => '%253Cscript%253E'], $this->meta()),
            'xss',
        );

        $this->assertNotEmpty($threats);
        $this->assertStringContainsString('[decoded:urldecode2]', $threats[0]->detail);
    }

    public function testNormalizationCatchesFullwidthBypass(): void
    {
        $this->boot();

        $threats = $this->typeThreats(
            SecurityGuard::guard(['comment' => '＜script＞alert(1)＜/script＞'], $this->meta()),
            'xss',
        );

        $this->assertNotEmpty($threats);
        $this->assertStringContainsString('[decoded:fullwidth]', $threats[0]->detail);
    }

    public function testNormalizationCatchesFullwidthEncodedPayload(): void
    {
        // Fullwidth percent signs: the fullwidth pass must feed the urldecode
        // pass, not be a dead end of its own
        $this->boot();

        $threats = $this->typeThreats(
            SecurityGuard::guard(['comment' => '％3Cscript％3E'], $this->meta()),
            'xss',
        );

        $this->assertNotEmpty($threats);
        $this->assertStringContainsString('[decoded:urldecode]', $threats[0]->detail);
    }

    public function testNormalizationCatchesHtmlEntityBypass(): void
    {
        $this->boot();

        $threats = $this->typeThreats(
            SecurityGuard::guard(['comment' => '&#60;script&#62;alert(1)&#60;/script&#62;'], $this->meta()),
            'xss',
        );

        $this->assertNotEmpty($threats);
        $this->assertStringContainsString('[decoded:entities]', $threats[0]->detail);
    }

    public function testNormalizationDoesNotFalsePositiveOnLegitPercentText(): void
    {
        $this->boot();

        $values = [
            ['url' => 'https://example.com/search?q=100%25%20complete'],
            ['note' => 'completion 100% done, no encoding here'],
            ['title' => '中文标题 with %E4%B8%AD mixed'],
        ];

        foreach ($values as $payload) {
            $this->assertSame([], $this->typeThreats(SecurityGuard::guard($payload, $this->meta()), 'xss'),
                'no xss hit expected for ' . json_encode($payload, JSON_UNESCAPED_UNICODE));
        }
    }

    public function testNormalizationDisabledYieldsNoExtraThreats(): void
    {
        $this->config['normalization']['enabled'] = false;
        $this->boot();

        // The raw urlencoded value does not match the literal <script> pattern
        $this->assertSame([], $this->typeThreats(
            SecurityGuard::guard(['comment' => '%3Cscript%3Ealert(1)%3C/script%3E'], $this->meta()),
            'xss',
        ));
    }

    public function testNormalizationRunsUnderTheBacktrackLimit(): void
    {
        $this->boot();

        // The variant scan sits inside guard()'s backtrack_limit try block, so
        // a pathological pattern cannot take the request down with it
        $this->assertIsArray(SecurityGuard::guard(['a' => str_repeat('%3C', 20000)], $this->meta()));
        $this->assertSame('1000000', ini_get('pcre.backtrack_limit'));
    }

    public function testNormalizationLeavesIdentityChecksUntouched(): void
    {
        // The variant scan must not rewrite the flattened body that the
        // integrity check reads
        $this->config['identity']['tamper']['protected_fields'] = ['order.price'];
        $this->config['signing_key'] = 'test-key-12345';
        $this->boot();

        $data = ['order.price' => '100', 'note' => '％3Cscript％3E'];
        $data['_security_sig'] = SecurityGuard::signFields(['order.price' => '100']);

        $this->assertSame([], $this->typeThreats(SecurityGuard::guard($data, $this->meta()), 'data_tamper'),
            'a valid signature must survive the variant pass');
    }

    // ──────────────── 登录暴力破解锁定 ────────────────

    public function testLockoutEngagesAfterMaxFailures(): void
    {
        $this->config['identity']['login']['lockout']['max_failures'] = 3;
        $this->boot();

        $this->assertNull(SecurityGuard::recordFailedLogin('alice', '203.0.113.9'));
        $this->assertNull(SecurityGuard::recordFailedLogin('alice', '203.0.113.9'));

        $threat = SecurityGuard::recordFailedLogin('alice', '203.0.113.9');
        $this->assertNotNull($threat);
        $this->assertSame('login_lockout', $threat->type);
        $this->assertTrue(SecurityGuard::isLockedOut('alice', '203.0.113.9'));
    }

    public function testLockoutReportsWhileAlreadyLocked(): void
    {
        $this->config['identity']['login']['lockout']['max_failures'] = 1;
        $this->boot();

        $this->assertNotNull(SecurityGuard::recordFailedLogin('bob'));
        // Second failure while locked must still report, so the app can log it
        $this->assertNotNull(SecurityGuard::recordFailedLogin('bob'));
    }

    public function testLockoutStatusIs429(): void
    {
        $this->config['identity']['login']['lockout']['max_failures'] = 1;
        $this->boot();

        $threat = SecurityGuard::recordFailedLogin('carol');
        $this->assertSame(429, $threat->httpStatus);
        $this->assertSame(429, SecurityGuard::blockStatusCode([$threat]));
    }

    public function testLockoutWindowPrunesExpiredFailures(): void
    {
        $this->config['identity']['login']['lockout']['max_failures'] = 2;
        $this->config['identity']['login']['lockout']['window_seconds'] = 60;
        $this->boot();

        // One failure from 10 minutes ago must not count towards the lock
        $this->writeLock('dave', ['failures' => [time() - 600], 'locked_until' => 0]);

        $this->assertNull(SecurityGuard::recordFailedLogin('dave', '203.0.113.9'));
        $this->assertFalse(SecurityGuard::isLockedOut('dave', '203.0.113.9'));
    }

    public function testLockoutExpiryLiftsTheLock(): void
    {
        $this->config['identity']['login']['lockout']['max_failures'] = 1;
        $this->config['identity']['login']['lockout']['lock_seconds'] = 900;
        $this->boot();

        $this->writeLock('erin', ['failures' => [], 'locked_until' => time() + 900]);
        $this->assertTrue(SecurityGuard::isLockedOut('erin'));

        $this->writeLock('erin', ['failures' => [], 'locked_until' => time() - 1]);
        $this->assertFalse(SecurityGuard::isLockedOut('erin'));
    }

    public function testLockoutIsIndependentPerAccount(): void
    {
        $this->config['identity']['login']['lockout']['max_failures'] = 1;
        $this->boot();

        $this->assertNotNull(SecurityGuard::recordFailedLogin('frank'));
        $this->assertTrue(SecurityGuard::isLockedOut('frank'));
        $this->assertFalse(SecurityGuard::isLockedOut('grace'));
    }

    public function testLockoutCanKeyPerAccountAndIp(): void
    {
        $this->config['identity']['login']['lockout']['max_failures'] = 1;
        $this->config['identity']['login']['lockout']['include_ip'] = true;
        $this->boot();

        $this->assertNotNull(SecurityGuard::recordFailedLogin('heidi', '203.0.113.9'));
        $this->assertTrue(SecurityGuard::isLockedOut('heidi', '203.0.113.9'));
        $this->assertFalse(SecurityGuard::isLockedOut('heidi', '198.51.100.4'));
    }

    public function testLockoutPersistsNoPlaintextAccount(): void
    {
        $this->config['identity']['login']['lockout']['max_failures'] = 1;
        $this->config['log']['enabled'] = true;
        $this->boot();

        $account = 'alice@example.com';
        $this->assertNotNull(SecurityGuard::recordFailedLogin($account, '203.0.113.9', ['ip' => '203.0.113.9']));

        // Storage keys and values, and the log line, must carry no plaintext
        $this->assertStringNotContainsString($account, $this->storedRaw());
        $this->assertStringContainsString('ident:lock:' . hash('sha256', $account), $this->storedRaw());

        $logged = $this->loggedRaw();
        $this->assertStringNotContainsString($account, $logged);
        $this->assertMatchesRegularExpression('/login_lockout/', $logged);
        $this->assertMatchesRegularExpression('/#[0-9a-f]{8}\b/', $logged);
    }

    public function testLockoutUsesIpFromMetaWhenUnspecified(): void
    {
        $this->config['identity']['login']['lockout']['max_failures'] = 1;
        $this->config['identity']['login']['lockout']['include_ip'] = true;
        $this->boot();

        SecurityGuard::recordFailedLogin('ivan', null, ['ip' => '203.0.113.77']);
        $this->assertTrue(SecurityGuard::isLockedOut('ivan', null, ['ip' => '203.0.113.77']));
    }

    public function testLockoutDisabledByDetectorFlag(): void
    {
        $this->config['detectors']['login_lockout']['enabled'] = false;
        $this->config['identity']['login']['lockout']['max_failures'] = 1;
        $this->boot();

        $this->assertNull(SecurityGuard::recordFailedLogin('judy'));
        $this->assertFalse(SecurityGuard::isLockedOut('judy'));
    }

    public function testLockoutDisabledWhenIdentityIsOff(): void
    {
        $this->config['identity']['enabled'] = false;
        $this->config['identity']['login']['lockout']['max_failures'] = 1;
        $this->boot();

        $this->assertNull(SecurityGuard::recordFailedLogin('karen'));
        $this->assertFalse(SecurityGuard::isLockedOut('karen'));
    }

    public function testLockoutBlockModeIsEnforced(): void
    {
        $this->config['detectors']['login_lockout']['mode'] = 'block';
        $this->config['detectors']['login_lockout']['enabled'] = true;
        $this->config['identity']['login']['lockout']['max_failures'] = 1;
        $this->boot();

        $threat = SecurityGuard::recordFailedLogin('leo');
        $this->assertNotNull($threat);
        $this->assertTrue(SecurityGuard::shouldBlock([$threat]));
    }
}
