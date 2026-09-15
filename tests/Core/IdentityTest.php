<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Tests\Core;

use Erikwang2013\Security\Identity\FieldSigner;
use Erikwang2013\Security\SecurityGuard;
use Erikwang2013\Security\Storage\FileStorage;
use Erikwang2013\Security\ThreatResult;
use PHPUnit\Framework\TestCase;

/**
 * 身份维度检测：会话劫持 / 异地登录 / 数据篡改。
 *
 * 全部经 SecurityGuard::guard() 走完整管线，而不是直接调 Identity 类：
 * detectors.<type>.enabled 开关、401/403 分流、日志落盘，和检测逻辑本身
 * 一样是这次交付的一部分。
 */
class IdentityTest extends TestCase
{
    private const IDENTITY_TYPES = ['session_hijack', 'unusual_login', 'data_tamper'];

    private array $config;
    private string $storagePath;
    private string $logPath;

    protected function setUp(): void
    {
        SecurityGuard::reset();
        @unlink(sys_get_temp_dir() . '/security_storage.json');

        $this->storagePath = sys_get_temp_dir() . '/security_identity_test.json';
        $this->logPath = sys_get_temp_dir() . '/security_identity_test.log';
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

    /**
     * @param ThreatResult[] $threats
     * @return string[]
     */
    private function identityTypes(array $threats): array
    {
        return array_values(array_map(
            static fn (ThreatResult $threat): string => $threat->type,
            array_filter(
                $threats,
                static fn (ThreatResult $threat): bool => in_array($threat->type, self::IDENTITY_TYPES, true),
            ),
        ));
    }

    /**
     * @param ThreatResult[] $threats
     */
    private function identityThreat(array $threats): ?ThreatResult
    {
        foreach ($threats as $threat) {
            if (in_array($threat->type, self::IDENTITY_TYPES, true)) {
                return $threat;
            }
        }

        return null;
    }

    private function storedRaw(): string
    {
        return (string) @file_get_contents($this->storagePath);
    }

    private function loggedRaw(): string
    {
        return (string) @file_get_contents($this->logPath);
    }

    // ---------------------------------------------------------------- 会话劫持（Cookie）

    public function testCookieSessionBaselineIsSilentThenSameFingerprintPasses(): void
    {
        $this->boot();
        $cookies = ['laravel_session' => 'sess-abc'];

        $this->assertSame([], $this->identityTypes(SecurityGuard::guard([], $this->meta(['cookies' => $cookies]))));
        $this->assertSame([], $this->identityTypes(SecurityGuard::guard([], $this->meta(['cookies' => $cookies]))));
    }

    public function testChangedUserAgentHitsTheSessionBaseline(): void
    {
        $this->boot();
        $cookies = ['laravel_session' => 'sess-abc'];
        SecurityGuard::guard([], $this->meta(['cookies' => $cookies]));

        $threat = $this->identityThreat(
            SecurityGuard::guard([], $this->meta(['cookies' => $cookies, 'user_agent' => 'curl/8']))
        );

        $this->assertNotNull($threat);
        $this->assertSame('session_hijack', $threat->type);
        $this->assertSame('high', $threat->severity);
        $this->assertSame(401, $threat->httpStatus);
    }

    public function testSameSubnetIsNotALocationChange(): void
    {
        $this->boot();
        $cookies = ['laravel_session' => 'sess-abc'];
        SecurityGuard::guard([], $this->meta(['cookies' => $cookies, 'ip' => '203.0.113.5']));

        $this->assertSame([], $this->identityTypes(
            SecurityGuard::guard([], $this->meta(['cookies' => $cookies, 'ip' => '203.0.113.200']))
        ));
    }

    public function testDifferentSubnetHitsTheSessionBaseline(): void
    {
        $this->boot();
        $cookies = ['laravel_session' => 'sess-abc'];
        SecurityGuard::guard([], $this->meta(['cookies' => $cookies, 'ip' => '203.0.113.5']));

        $this->assertSame(['session_hijack'], $this->identityTypes(
            SecurityGuard::guard([], $this->meta(['cookies' => $cookies, 'ip' => '198.51.100.7']))
        ));
    }

    public function testBaselineIsNotRotatedSoEveryAttackerRequestFlags(): void
    {
        $this->boot();
        $cookies = ['laravel_session' => 'sess-abc'];
        SecurityGuard::guard([], $this->meta(['cookies' => $cookies]));

        $attacker = $this->meta(['cookies' => $cookies, 'user_agent' => 'curl/8']);

        // 若命中后用攻击者指纹覆盖基线，第二次就只剩真实用户告警了
        $this->assertSame(['session_hijack'], $this->identityTypes(SecurityGuard::guard([], $attacker)));
        $this->assertSame(['session_hijack'], $this->identityTypes(SecurityGuard::guard([], $attacker)));
    }

    // ---------------------------------------------------------------- 会话劫持（Token）

    public function testAuthorizationBearerTokenIsTrackedAsSessionIdentity(): void
    {
        $this->boot();
        $headers = ['authorization' => 'Bearer tok-xyz'];

        $this->assertSame([], $this->identityTypes(SecurityGuard::guard([], $this->meta(['headers' => $headers]))));
        $this->assertSame(['session_hijack'], $this->identityTypes(
            SecurityGuard::guard([], $this->meta(['headers' => $headers, 'user_agent' => 'curl/8']))
        ));
    }

    public function testBearerPrefixIsCaseInsensitive(): void
    {
        $this->boot();
        SecurityGuard::guard([], $this->meta(['headers' => ['authorization' => 'Bearer tok-xyz']]));

        // 同一 token、前缀大小写不同 → 同一会话，换了 UA 才告警
        $this->assertSame(['session_hijack'], $this->identityTypes(
            SecurityGuard::guard([], $this->meta([
                'headers'    => ['authorization' => 'bearer tok-xyz'],
                'user_agent' => 'curl/8',
            ]))
        ));
    }

    public function testCustomTokenHeaderIsTracked(): void
    {
        $this->boot();
        $headers = ['x-token' => 'tok-custom'];

        $this->assertSame([], $this->identityTypes(SecurityGuard::guard([], $this->meta(['headers' => $headers]))));
        $this->assertSame(['session_hijack'], $this->identityTypes(
            SecurityGuard::guard([], $this->meta(['headers' => $headers, 'user_agent' => 'curl/8']))
        ));
    }

    public function testTokenHeaderNameIsMatchedRegardlessOfCase(): void
    {
        $this->boot();
        SecurityGuard::guard([], $this->meta(['headers' => ['x-token' => 'tok-custom']]));

        // 中间件给的键名大小写必须不影响查找，否则劫持检测会静默失效
        $this->assertSame(['session_hijack'], $this->identityTypes(
            SecurityGuard::guard([], $this->meta([
                'headers'    => ['X-Token' => 'tok-custom'],
                'user_agent' => 'curl/8',
            ]))
        ));
    }

    public function testPsr7StyleHeaderArraysAreAccepted(): void
    {
        $this->boot();
        SecurityGuard::guard([], $this->meta(['headers' => ['Authorization' => ['Bearer tok-xyz']]]));

        $this->assertSame(['session_hijack'], $this->identityTypes(
            SecurityGuard::guard([], $this->meta([
                'headers'    => ['Authorization' => ['Bearer tok-xyz']],
                'user_agent' => 'curl/8',
            ]))
        ));
    }

    public function testCookieWinsOverTokenWhenBothArePresent(): void
    {
        $this->boot();
        SecurityGuard::guard([], $this->meta([
            'cookies' => ['laravel_session' => 'sess-abc'],
            'headers' => ['authorization' => 'Bearer tok-xyz'],
        ]));

        // 同一 Cookie、不同 Token：会话身份仍以 Cookie 为准
        $this->assertSame([], $this->identityTypes(SecurityGuard::guard([], $this->meta([
            'cookies' => ['laravel_session' => 'sess-abc'],
            'headers' => ['authorization' => 'Bearer tok-other'],
        ]))));
    }

    public function testAnonymousRequestProducesNoSessionThreatAndNoRecord(): void
    {
        $this->boot();

        $this->assertSame([], $this->identityTypes(SecurityGuard::guard([], $this->meta())));
        $this->assertStringNotContainsString('ident:sess:', $this->storedRaw());
    }

    public function testIdleSessionRebuildsTheBaseline(): void
    {
        // ttl 为负 → 任何既有记录都算过期，相当于浏览器升级后重新绑定
        $this->config['identity']['session']['ttl'] = -1;
        $this->boot();
        $cookies = ['laravel_session' => 'sess-abc'];

        SecurityGuard::guard([], $this->meta(['cookies' => $cookies]));

        $this->assertSame([], $this->identityTypes(
            SecurityGuard::guard([], $this->meta(['cookies' => $cookies, 'user_agent' => 'curl/8']))
        ));
    }

    public function testSessionFingerprintFollowsTheProxyResolvedClientIp(): void
    {
        $this->config['trusted_proxies'] = ['10.0.0.1'];
        $this->boot();
        $cookies = ['laravel_session' => 'sess-abc'];

        // peer 始终是代理，真实客户端在 XFF 里换了网段
        SecurityGuard::guard([], $this->meta([
            'cookies' => $cookies, 'ip' => '10.0.0.1', 'x_forwarded_for' => '203.0.113.5',
        ]));

        // 绑定到 peer 而不是真实客户端的话，这里会静默放行
        $this->assertSame(['session_hijack'], $this->identityTypes(SecurityGuard::guard([], $this->meta([
            'cookies' => $cookies, 'ip' => '10.0.0.1', 'x_forwarded_for' => '198.51.100.7',
        ]))));
    }

    public function testRawSessionIdAndTokenNeverReachStorageOrLog(): void
    {
        $this->boot();
        $cookies = ['laravel_session' => 'sess-supersecret'];
        $headers = ['authorization' => 'Bearer tok-supersecret'];

        SecurityGuard::guard([], $this->meta(['cookies' => $cookies, 'headers' => $headers]));
        $threat = $this->identityThreat(SecurityGuard::guard([], $this->meta([
            'cookies'    => $cookies,
            'headers'    => $headers,
            'user_agent' => 'curl/8',
        ])));

        $this->assertNotNull($threat);

        $storage = $this->storedRaw();
        $log = $this->loggedRaw();

        $this->assertStringNotContainsString('sess-supersecret', $storage);
        $this->assertStringNotContainsString('tok-supersecret', $storage);
        $this->assertStringNotContainsString('sess-supersecret', $log);
        $this->assertStringNotContainsString('tok-supersecret', $log);

        // 落盘的是摘要，日志里只有摘要前 8 位
        $this->assertStringContainsString(hash('sha256', 'sess-supersecret'), $storage);
        $this->assertMatchesRegularExpression('/payload=#[0-9a-f]{8} /', $log);
        $this->assertSame('#' . substr(hash('sha256', 'sess-supersecret'), 0, 8), $threat->payload);
    }

    // ---------------------------------------------------------------- 异地登录

    public function testFirstLoginEverIsSilent(): void
    {
        $this->boot();

        $this->assertNull(SecurityGuard::recordLogin('u1', null, ['ip' => '203.0.113.5']));
    }

    public function testSameSubnetLoginPassesAndNewSubnetFlags(): void
    {
        $this->boot();

        SecurityGuard::recordLogin('u1', null, ['ip' => '203.0.113.5']);
        $this->assertNull(SecurityGuard::recordLogin('u1', null, ['ip' => '203.0.113.99']));

        $threat = SecurityGuard::recordLogin('u1', null, ['ip' => '198.51.100.7']);

        $this->assertNotNull($threat);
        $this->assertSame('unusual_login', $threat->type);
        $this->assertSame('medium', $threat->severity);
        $this->assertSame(401, $threat->httpStatus);
        $this->assertSame('u1', $threat->payload);
        $this->assertStringContainsString('198.51.100.0', $threat->detail);
    }

    public function testBaselinesArePerUser(): void
    {
        $this->boot();
        SecurityGuard::recordLogin('u1', null, ['ip' => '203.0.113.5']);

        // u2 是另一个账号，它的首次登录同样不告警
        $this->assertNull(SecurityGuard::recordLogin('u2', null, ['ip' => '198.51.100.7']));
    }

    public function testExplicitCityOverridesTheNetwork(): void
    {
        $this->boot();

        SecurityGuard::recordLogin('u1', '杭州', []);
        // 城市相同、网段完全不同（如换网络） → 仍是熟悉的地点
        $this->assertNull(SecurityGuard::recordLogin('u1', '杭州', ['ip' => '198.51.100.7']));

        $threat = SecurityGuard::recordLogin('u1', '北京', []);

        $this->assertNotNull($threat);
        $this->assertStringContainsString('北京', $threat->detail);
    }

    public function testMaxPointsEvictsTheLeastRecentlyUsedPlace(): void
    {
        $this->config['identity']['login']['max_points'] = 2;
        $this->config['identity']['login']['ttl'] = 0; // 关掉过期清理，单测容量淘汰
        $this->boot();

        $this->assertNull(SecurityGuard::recordLogin('u1', 'A'));    // 基线
        $this->assertNotNull(SecurityGuard::recordLogin('u1', 'B')); // 新地点
        $this->assertNotNull(SecurityGuard::recordLogin('u1', 'C')); // 新地点，A 被挤出
        $this->assertNotNull(SecurityGuard::recordLogin('u1', 'A')); // A 已被遗忘 → 再次告警
    }

    public function testLoginWithoutLocationOrUsableIpStaysSilent(): void
    {
        $this->boot();

        // 无从判断地点时不猜、不告警
        $this->assertNull(SecurityGuard::recordLogin('u1'));
        $this->assertNull(SecurityGuard::recordLogin('u1'));
    }

    // ---------------------------------------------------------------- 数据篡改

    private function bootTamper(): void
    {
        $this->config['signing_key'] = 'test-signing-key';
        $this->config['identity']['tamper']['protected_fields'] = ['order.price', 'order.qty'];
        $this->boot();
    }

    public function testValidSignaturePasses(): void
    {
        $this->bootTamper();

        $token = SecurityGuard::signFields(['order.price' => 100, 'order.qty' => 2]);

        $this->assertSame([], $this->identityTypes(SecurityGuard::guard(
            ['order' => ['price' => '100', 'qty' => '2'], '_security_sig' => $token],
            $this->meta()
        )));
    }

    public function testChangedValueIsFlagged(): void
    {
        $this->bootTamper();

        $token = SecurityGuard::signFields(['order.price' => 100]);
        $threat = $this->identityThreat(SecurityGuard::guard(
            ['order' => ['price' => '1'], '_security_sig' => $token],
            $this->meta()
        ));

        $this->assertNotNull($threat);
        $this->assertSame('data_tamper', $threat->type);
        $this->assertSame('high', $threat->severity);
        $this->assertSame(403, $threat->httpStatus);
        $this->assertSame('order.price', $threat->field);
    }

    public function testStrippedSignatureIsFlagged(): void
    {
        $this->bootTamper();

        $threat = $this->identityThreat(
            SecurityGuard::guard(['order' => ['price' => '100']], $this->meta())
        );

        $this->assertNotNull($threat);
        $this->assertSame('data_tamper', $threat->type);
        $this->assertStringContainsString('剥离', $threat->detail);
    }

    public function testMalformedSignatureIsFlagged(): void
    {
        $this->bootTamper();

        $threat = $this->identityThreat(SecurityGuard::guard(
            ['order' => ['price' => '100'], '_security_sig' => 'not-a-token'],
            $this->meta()
        ));

        $this->assertNotNull($threat);
        $this->assertStringContainsString('格式无效', $threat->detail);
    }

    public function testSignatureFromAWrongKeyIsFlagged(): void
    {
        $this->bootTamper();

        // 用另一把密钥签的 token：值没动，但签名对不上
        $forged = (new FieldSigner('other-key', []))->sign(['order.price' => 100]);
        $threat = $this->identityThreat(SecurityGuard::guard(
            ['order' => ['price' => '100'], '_security_sig' => $forged],
            $this->meta()
        ));

        $this->assertNotNull($threat);
        $this->assertStringContainsString('校验失败', $threat->detail);
    }

    public function testExpiredSignatureIsFlagged(): void
    {
        $this->bootTamper();

        $token = SecurityGuard::signFields(['order.price' => 100], -1);
        $threat = $this->identityThreat(SecurityGuard::guard(
            ['order' => ['price' => '100'], '_security_sig' => $token],
            $this->meta()
        ));

        $this->assertNotNull($threat);
        $this->assertStringContainsString('过期', $threat->detail);
    }

    public function testDroppedSignedFieldIsFlagged(): void
    {
        $this->bootTamper();

        $token = SecurityGuard::signFields(['order.price' => 100, 'order.qty' => 2]);
        $threat = $this->identityThreat(SecurityGuard::guard(
            ['order' => ['price' => '100'], '_security_sig' => $token],
            $this->meta()
        ));

        $this->assertNotNull($threat);
        $this->assertSame('order.qty', $threat->field);
        $this->assertStringContainsString('缺失', $threat->detail);
    }

    public function testTamperDetectionIsDisabledWithoutASigningKey(): void
    {
        $this->config['signing_key'] = '';
        $this->config['identity']['tamper']['protected_fields'] = ['order.price'];
        $this->boot();

        $this->assertSame('', SecurityGuard::signFields(['order.price' => 100]));
        $this->assertSame([], $this->identityTypes(
            SecurityGuard::guard(['order' => ['price' => '999999']], $this->meta())
        ));
    }

    public function testTamperDetectionIsSilentWhenNoFieldIsProtected(): void
    {
        $this->config['signing_key'] = 'test-signing-key';
        $this->boot(); // protected_fields 默认空

        $this->assertSame([], $this->identityTypes(
            SecurityGuard::guard(['order' => ['price' => '999999']], $this->meta())
        ));
    }

    public function testTamperCheckSeesFieldsThatAreAlsoWhitelisted(): void
    {
        $this->config['signing_key'] = 'test-signing-key';
        $this->config['identity']['tamper']['protected_fields'] = ['csrf_token'];
        $this->config['whitelist_fields'] = ['csrf_token'];
        $this->boot();

        // 被保护字段同时进了白名单：正则链会跳过它，完整性校验不能也跳过
        $token = SecurityGuard::signFields(['csrf_token' => 'abc']);
        $this->assertSame([], $this->identityTypes(SecurityGuard::guard(
            ['csrf_token' => 'abc', '_security_sig' => $token],
            $this->meta()
        )));

        $threat = $this->identityThreat(
            SecurityGuard::guard(['csrf_token' => 'evil'], $this->meta())
        );
        $this->assertNotNull($threat);
        $this->assertSame('data_tamper', $threat->type);
    }

    // ---------------------------------------------------------------- 拦截接线

    public function testShippedDefaultOnlyLogsIdentityThreats(): void
    {
        $this->boot();
        $cookies = ['laravel_session' => 'sess-abc'];
        SecurityGuard::guard([], $this->meta(['cookies' => $cookies]));

        $threats = SecurityGuard::guard([], $this->meta(['cookies' => $cookies, 'user_agent' => 'curl/8']));

        $this->assertNotEmpty($this->identityTypes($threats));
        // 出厂默认 mode=log：观察期不拦截
        $this->assertNull(SecurityGuard::blockDecision($threats));
    }

    public function testBlockedIdentityThreatsAnswer401AndTamperAnswers403(): void
    {
        $this->config['detectors']['session_hijack']['mode'] = 'block';
        $this->config['detectors']['data_tamper']['mode'] = 'block';
        $this->config['signing_key'] = 'test-signing-key';
        $this->config['identity']['tamper']['protected_fields'] = ['order.price'];
        $this->boot();

        $cookies = ['laravel_session' => 'sess-abc'];
        SecurityGuard::guard([], $this->meta(['cookies' => $cookies]));
        $hijack = SecurityGuard::guard([], $this->meta(['cookies' => $cookies, 'user_agent' => 'curl/8']));

        // 登录态不可信 → 重新认证，而不是禁止访问
        $this->assertSame(401, SecurityGuard::blockStatusCode($hijack));
        $this->assertSame(401, SecurityGuard::blockDecision($hijack)['status']);

        $tamper = SecurityGuard::guard(['order' => ['price' => '1']], $this->meta());
        $this->assertSame(403, SecurityGuard::blockStatusCode($tamper));
        $this->assertSame(403, SecurityGuard::blockDecision($tamper)['status']);
    }

    public function testDisabledDetectorSkipsItsCheck(): void
    {
        $this->config['detectors']['session_hijack']['enabled'] = false;
        $this->config['detectors']['unusual_login']['enabled'] = false;
        $this->boot();

        $cookies = ['laravel_session' => 'sess-abc'];
        SecurityGuard::guard([], $this->meta(['cookies' => $cookies]));
        $this->assertSame([], $this->identityTypes(
            SecurityGuard::guard([], $this->meta(['cookies' => $cookies, 'user_agent' => 'curl/8']))
        ));
        $this->assertNull(SecurityGuard::recordLogin('u1', null, ['ip' => '203.0.113.5']));
        $this->assertNull(SecurityGuard::recordLogin('u1', null, ['ip' => '198.51.100.7']));
    }

    public function testIdentityDisabledDisablesEverything(): void
    {
        $this->config['identity']['enabled'] = false;
        $this->boot();

        $cookies = ['laravel_session' => 'sess-abc'];
        SecurityGuard::guard([], $this->meta(['cookies' => $cookies]));
        $this->assertSame([], $this->identityTypes(
            SecurityGuard::guard([], $this->meta(['cookies' => $cookies, 'user_agent' => 'curl/8']))
        ));
        $this->assertSame('', SecurityGuard::signFields(['a' => 1]));
    }
}
