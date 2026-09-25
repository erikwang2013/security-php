<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Tests\Core;

use Erikwang2013\Security\SecurityGuard;
use Erikwang2013\Security\ThreatResult;
use PHPUnit\Framework\TestCase;

/**
 * The block response stays text/plain for everyone except a client that asked
 * for HTML — the API contract must not change for API consumers.
 */
class BlockPageTest extends TestCase
{
    private array $config;

    protected function setUp(): void
    {
        SecurityGuard::reset();
        $this->config = require dirname(__DIR__, 2) . '/config/security.php';
    }

    protected function tearDown(): void
    {
        SecurityGuard::reset();
    }

    private function threat(int $status = 403): ThreatResult
    {
        return new ThreatResult('sql_injection', 'high', 'id', "1' OR 1=1", 'SQL comment', $status);
    }

    public function testBrowserGetsHtmlPageWithMascot(): void
    {
        SecurityGuard::init($this->config);

        [$type, $body] = SecurityGuard::blockResponse([$this->threat()], [
            'accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9',
        ]);

        $this->assertSame('text/html; charset=utf-8', $type);
        $this->assertStringContainsString('<svg', $body, '拦截页要带上项目宠物小盾');
        $this->assertStringContainsString('sql_injection', $body, '命中的检测器名称要显示出来');
        $this->assertStringContainsString('403', $body);
    }

    public function testNonBrowserClientsKeepPlainText(): void
    {
        SecurityGuard::init($this->config);

        foreach (['', '*/*', 'application/json', 'text/plain'] as $accept) {
            [$type, $body] = SecurityGuard::blockResponse([$this->threat()], ['accept' => $accept]);

            $this->assertSame('text/plain; charset=utf-8', $type, "Accept: '{$accept}'");
            $this->assertSame('Request blocked by security policy', $body, "Accept: '{$accept}'");
        }
    }

    public function testHtmlPageCanBeDisabled(): void
    {
        $this->config['block_page'] = ['enabled' => false];
        SecurityGuard::init($this->config);

        [$type] = SecurityGuard::blockResponse([$this->threat()], ['accept' => 'text/html']);

        $this->assertSame('text/plain; charset=utf-8', $type);
    }

    public function testConfigWithoutTheKeyStillGetsThePage(): void
    {
        // A config file published before block_page existed has no such key
        unset($this->config['block_page']);
        SecurityGuard::init($this->config);

        [$type] = SecurityGuard::blockResponse([$this->threat()], ['accept' => 'text/html']);

        $this->assertSame('text/html; charset=utf-8', $type);
    }

    public function testBlockMessageAndTypesAreEscaped(): void
    {
        $this->config['block_message'] = '<img src=x onerror=alert(1)>';
        SecurityGuard::init($this->config);

        [, $body] = SecurityGuard::blockResponse(
            [new ThreatResult('xss<script>', 'high', 'q', '<script>', 'Script tag')],
            ['accept' => 'text/html'],
        );

        $this->assertStringNotContainsString('<img', $body, '配置里的消息不能当 HTML 渲染');
        $this->assertStringContainsString('&lt;img', $body);
        $this->assertStringNotContainsString('xss<script>', $body);
    }

    public function testDetectorStatusDrivesTheReasonLine(): void
    {
        SecurityGuard::init($this->config);
        $threat = new ThreatResult('http_method', 'high', '_server.REQUEST_METHOD', 'TRACE', 'Method not allowed', 405);

        [, $body] = SecurityGuard::blockResponse([$threat], ['accept' => 'text/html']);

        $this->assertStringContainsString('405', $body);
        $this->assertStringContainsString('请求方法不被允许', $body);
    }
}
