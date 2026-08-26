<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Tests\Detector;

use Erikwang2013\Security\Detector\AbstractRegexDetector;
use Erikwang2013\Security\Detector\CorsDetector;
use Erikwang2013\Security\Detector\DataLeakDetector;
use Erikwang2013\Security\Detector\DnsRebindingDetector;
use Erikwang2013\Security\Detector\JwtAttackDetector;
use Erikwang2013\Security\Detector\PrototypePollutionDetector;
use Erikwang2013\Security\Detector\RequestSmugglingDetector;
use Erikwang2013\Security\Detector\UploadDetector;
use Erikwang2013\Security\Detector\WebSocketDetector;
use PHPUnit\Framework\TestCase;

class DetectorEdgeCasesTest extends TestCase
{
    // ──────────────── AbstractRegexDetector ────────────────

    public function testRegexDetectorFindsAttackInHeadOfLargePayload(): void
    {
        $detector = new TruncTestDetector();
        $result = $detector->detect(['x' => 'attack-marker' . str_repeat('a', 70000)]);

        $this->assertNotEmpty($result, 'Attack near the start of a >64KB payload must be detected');
    }

    public function testRegexDetectorFindsAttackInTailOfLargePayload(): void
    {
        $detector = new TruncTestDetector();
        $result = $detector->detect(['x' => str_repeat('a', 70000) . 'attack-marker']);

        $this->assertNotEmpty($result, 'Attack near the end of a >64KB payload must be detected');
    }

    public function testRegexDetectorBlindInMiddleGapOfHugePayload(): void
    {
        $detector = new TruncTestDetector();
        $result = $detector->detect(['x' => str_repeat('a', 70000) . 'attack-marker' . str_repeat('a', 70000)]);

        $this->assertEmpty($result, 'Attack fully inside the truncated middle gap is invisible (documented 64KB head+tail scan)');
    }

    public function testRegexDetectorSkipsInvalidPatternAndContinues(): void
    {
        $logFile = sys_get_temp_dir() . '/sec_errlog_' . uniqid() . '.log';
        $oldLog = ini_get('error_log');
        ini_set('error_log', $logFile);
        // preg_match() itself emits an E_WARNING for the invalid pattern before
        // the detector's error_log() fallback runs; swallow it here so the
        // detector's own handling can be asserted (see test report — the
        // warning is uncaught in production and trips failOnWarning builds).
        set_error_handler(static fn () => true, E_WARNING);
        try {
            $detector = new BadRegexDetector();
            $result = $detector->detect(['x' => 'valid-marker here']);
        } finally {
            restore_error_handler();
            ini_set('error_log', $oldLog);
        }

        $this->assertNotEmpty($result, 'Valid patterns must still run after an invalid one');
        $this->assertSame('bad_regex', $result[0]->type);
        $this->assertFileExists($logFile);
        $this->assertStringContainsString('Invalid regex pattern', (string) file_get_contents($logFile));
        @unlink($logFile);
    }

    public function testRegexDetectorPriorityDefaultsToZero(): void
    {
        $this->assertSame(0, (new TruncTestDetector())->priority());
    }

    public function testRegexDetectorReportsFieldAndPayload(): void
    {
        $result = (new TruncTestDetector())->detect(['comment' => 'x attack-marker y']);

        $this->assertCount(1, $result);
        $this->assertSame('comment', $result[0]->field);
        $this->assertSame('x attack-marker y', $result[0]->payload);
        $this->assertSame('high', $result[0]->severity);
    }

    // ──────────────── DataLeakDetector ────────────────

    public function testDataLeakRejectsCardWithoutValidLuhn(): void
    {
        $detector = new DataLeakDetector();
        $result = $detector->detect(['x' => '4111-1111-1111-1112']);

        $this->assertEmpty($result, 'Card-shaped number failing Luhn must be filtered out');
    }

    public function testDataLeakKeepsOnlyLuhnValidCardAmongMultiple(): void
    {
        $detector = new DataLeakDetector();
        $result = $detector->detect([
            'bad' => '4111-1111-1111-1112',
            'good' => '4111-1111-1111-1111',
        ]);

        $this->assertCount(1, $result);
        $this->assertSame('good', $result[0]->field);
    }

    public function testDataLeakMasksLongSecrets(): void
    {
        $detector = new DataLeakDetector();
        $result = $detector->detect([
            'x' => 'aws_secret_access_key = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"',
        ]);

        $this->assertNotEmpty($result);
        $this->assertStringStartsWith('aws_secret', $result[0]->payload);
        $this->assertStringContainsString('***', $result[0]->payload);
        $this->assertStringEndsWith('6789"', $result[0]->payload);
        $this->assertStringNotContainsString('AbCdEfGhIjKl', $result[0]->payload, 'Full secret must not appear');
    }

    // ──────────────── JwtAttackDetector ────────────────

    public function testJwtHeaderThatIsNotJsonIsSkipped(): void
    {
        $detector = new JwtAttackDetector();
        $header = $this->b64('not json');
        $result = $detector->detect(['x' => "{$header}.eyJhZG1pbiI6dHJ1ZX0.c2ln"]);

        $this->assertEmpty($result, 'JWT with undecodable header JSON must not trigger');
    }

    public function testJwtUppercaseNoneAlgDetected(): void
    {
        $detector = new JwtAttackDetector();
        $header = $this->b64('{"alg":"NONE"}');
        $result = $detector->detect(['x' => "{$header}.eyJhZG1pbiI6dHJ1ZX0."]);

        $this->assertNotEmpty($result);
        $this->assertSame('critical', $result[0]->severity);
    }

    public function testJwtKidWithPipeDetected(): void
    {
        $detector = new JwtAttackDetector();
        $header = $this->b64('{"alg":"HS256","kid":"a|b"}');
        $result = $detector->detect(['x' => "{$header}.eyJ1c2VyIjoiYWRtaW4ifQ.sig"]);

        $this->assertNotEmpty($result);
        $this->assertSame('critical', $result[0]->severity);
    }

    public function testJwtKidWithTraversalDetected(): void
    {
        $detector = new JwtAttackDetector();
        $header = $this->b64('{"alg":"HS256","kid":"../../etc/passwd"}');
        $result = $detector->detect(['x' => "{$header}.eyJ1c2VyIjoiYWRtaW4ifQ.sig"]);

        $this->assertNotEmpty($result);
    }

    public function testJwtHmacWithPlainKidIsNotFlagged(): void
    {
        $detector = new JwtAttackDetector();
        $header = $this->b64('{"alg":"HS256","kid":"key1"}');
        $result = $detector->detect(['x' => "{$header}.eyJ1c2VyIjoiYWRtaW4ifQ.sig"]);

        $this->assertEmpty($result, 'HMAC JWT with a plain kid must pass');
    }

    public function testJwtEmptySignatureDetected(): void
    {
        $detector = new JwtAttackDetector();
        $header = $this->b64('{"alg":"RS256"}');
        $result = $detector->detect(['x' => "{$header}.eyJ1c2VyIjoiam9obiJ9."]);

        $this->assertNotEmpty($result);
        $this->assertSame('critical', $result[0]->severity);
    }

    // ──────────────── PrototypePollutionDetector ────────────────

    public function testProtoPollutionDirectKeyWithStringValue(): void
    {
        $detector = new PrototypePollutionDetector();
        $result = $detector->detect(['constructor' => 'just a string']);

        $this->assertNotEmpty($result);
        $this->assertSame('critical', $result[0]->severity);
        $this->assertSame('{payload encoding failed}', $result[0]->payload);
    }

    public function testProtoPollutionDefineSetterDetected(): void
    {
        $detector = new PrototypePollutionDetector();
        $result = $detector->detect(['x' => 'obj.__defineSetter__("x",fn)']);

        $this->assertNotEmpty($result);
    }

    public function testProtoPollutionObjectStaticMethodDetected(): void
    {
        $detector = new PrototypePollutionDetector();
        $result = $detector->detect(['x' => 'Object.create(proto)']);

        $this->assertNotEmpty($result);
    }

    public function testProtoPollutionMethodOverrideAssignmentDetected(): void
    {
        $detector = new PrototypePollutionDetector();
        $result = $detector->detect(['x' => 'obj.toString=function(){}']);

        $this->assertNotEmpty($result);
        $this->assertSame('high', $result[0]->severity);
    }

    // ──────────────── DnsRebindingDetector ────────────────

    public function testDnsRebindingHostWithPortStripped(): void
    {
        $detector = new DnsRebindingDetector();
        $result = $detector->detect(['_server.HTTP_HOST' => '127.0.0.1:8080']);

        $this->assertNotEmpty($result);
        $this->assertSame('critical', $result[0]->severity);
    }

    public function testDnsRebindingIpv6WithPortStripped(): void
    {
        $detector = new DnsRebindingDetector();
        $result = $detector->detect(['_server.HTTP_HOST' => '[::1]:8080']);

        $this->assertNotEmpty($result);
        $this->assertSame('critical', $result[0]->severity);
    }

    public function testDnsRebindingSingleLabelHostnameIsMedium(): void
    {
        $detector = new DnsRebindingDetector();
        $result = $detector->detect(['_server.HTTP_HOST' => 'intranet']);

        $this->assertNotEmpty($result);
        $this->assertSame('medium', $result[0]->severity);
    }

    public function testDnsRebindingDotLocalHostnameIsNotFlagged(): void
    {
        $detector = new DnsRebindingDetector();
        $result = $detector->detect(['_server.HTTP_HOST' => 'myhost.local']);

        $this->assertEmpty($result);
    }

    public function testDnsRebindingRawIpInOtherFieldIsNotFlagged(): void
    {
        $detector = new DnsRebindingDetector();
        $result = $detector->detect(['ip' => '127.0.0.1']);

        $this->assertEmpty($result, 'Bare IP in a form field must not trigger host checks');
    }

    // ──────────────── UploadDetector ────────────────

    public function testUploadFlagsExtensionWhenTmpFileMissing(): void
    {
        $detector = new UploadDetector();
        $result = $detector->detect(['file' => ['name' => 'evil.php', 'tmp_name' => '/nonexistent/file.php']]);

        $this->assertNotEmpty($result);
        $this->assertSame('high', $result[0]->severity);
        $this->assertStringContainsString('php', $result[0]->detail);
    }

    public function testUploadAllowsCaseInsensitiveSafeExtension(): void
    {
        $detector = new UploadDetector();
        $result = $detector->detect(['file' => ['name' => 'photo.JPG', 'tmp_name' => '/nonexistent/x']]);

        $this->assertEmpty($result);
    }

    public function testUploadAllowsExtensionlessName(): void
    {
        $detector = new UploadDetector();
        $result = $detector->detect(['file' => ['name' => 'README', 'tmp_name' => '/nonexistent/x']]);

        $this->assertEmpty($result);
    }

    public function testUploadFlagsDotfileExtension(): void
    {
        $detector = new UploadDetector();
        $result = $detector->detect(['file' => ['name' => '.env', 'tmp_name' => '/nonexistent/x']]);

        $this->assertNotEmpty($result);
    }

    public function testUploadFlagsOneBadFileInMultiUpload(): void
    {
        $detector = new UploadDetector();
        $result = $detector->detect([
            'files' => [
                'name' => ['ok.jpg', 'shell.php'],
                'tmp_name' => ['/tmp/a', '/tmp/b'],
                'size' => [1, 1],
                'error' => [0, 0],
            ],
        ]);

        $this->assertNotEmpty($result);
        $this->assertSame('upload', $result[0]->type);
    }

    public function testUploadFlagsNestedMultiFileArray(): void
    {
        $detector = new UploadDetector();
        $result = $detector->detect([
            'files' => [
                'name' => [['shell.php'], ['ok.jpg']],
                'tmp_name' => [['/tmp/a'], ['/tmp/b']],
                'size' => [[1], [1]],
                'error' => [[0], [0]],
            ],
        ]);

        $this->assertNotEmpty($result, 'files[i][j] deep nesting must be flattened and scanned');
    }

    // ──────────────── RequestSmugglingDetector ────────────────

    public function testSmugglingObscuredTransferEncodingDetected(): void
    {
        $detector = new RequestSmugglingDetector();
        $result = $detector->detect(['x' => 'Transfer-Encoding: x']);

        $this->assertNotEmpty($result);
    }

    public function testSmugglingFoldedHeaderDetected(): void
    {
        $detector = new RequestSmugglingDetector();
        $result = $detector->detect(["x" => "Foo: bar\n Content-Length: 5"]);

        $this->assertNotEmpty($result);
        $this->assertSame('medium', $result[0]->severity);
    }

    public function testSmugglingInjectedContentLengthDetected(): void
    {
        $detector = new RequestSmugglingDetector();
        $result = $detector->detect(['x' => "foo\r\nContent-Length: 5"]);

        $this->assertNotEmpty($result);
    }

    public function testSmugglingDualTransferEncodingIsCritical(): void
    {
        $detector = new RequestSmugglingDetector();
        $result = $detector->detect(['x' => "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity"]);

        $this->assertNotEmpty($result);
        $this->assertContains('critical', array_column($result, 'severity'));
    }

    // ──────────────── WebSocketDetector ────────────────

    public function testWebSocketRawUrlDetected(): void
    {
        $detector = new WebSocketDetector();
        $result = $detector->detect(['x' => 'ws://evil.com/socket']);

        $this->assertNotEmpty($result);
        $this->assertSame('medium', $result[0]->severity);
    }

    public function testWebSocketSecKeyInjectionDetected(): void
    {
        $detector = new WebSocketDetector();
        $result = $detector->detect(['x' => "foo\r\nSec-WebSocket-Key: abc"]);

        $this->assertNotEmpty($result);
        $this->assertSame('high', $result[0]->severity);
    }

    public function testWebSocketLegitimateOriginNotFlagged(): void
    {
        $detector = new WebSocketDetector();
        $result = $detector->detect(['x' => "foo\r\nOrigin: https://example.com\r\n"]);

        $this->assertEmpty($result, 'Legitimate https origin must pass the suspicious-origin pattern');
    }

    // ──────────────── CorsDetector ────────────────

    public function testCorsMaxAgeInjectionIsLowSeverity(): void
    {
        $detector = new CorsDetector();
        $result = $detector->detect(['x' => "foo\r\nAccess-Control-Max-Age: 3600"]);

        $this->assertNotEmpty($result);
        $this->assertSame('low', $result[0]->severity);
    }

    public function testCorsPreflightRequestMethodInjection(): void
    {
        $detector = new CorsDetector();
        $result = $detector->detect(['x' => "foo\r\nAccess-Control-Request-Method: DELETE"]);

        $this->assertNotEmpty($result);
        $this->assertSame('medium', $result[0]->severity);
    }

    // ──────────────── helpers ────────────────

    private function b64(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}

/**
 * Detector used to exercise AbstractRegexDetector truncation behavior.
 */
class TruncTestDetector extends AbstractRegexDetector
{
    public function name(): string
    {
        return 'trunc_test';
    }

    protected function patterns(): array
    {
        return ['/attack-marker/' => ['severity' => 'high', 'detail' => 'marker found']];
    }
}

/**
 * Detector with one invalid regex to exercise the error_log + continue path.
 */
class BadRegexDetector extends AbstractRegexDetector
{
    public function name(): string
    {
        return 'bad_regex';
    }

    protected function patterns(): array
    {
        return [
            '/(unclosed/' => ['severity' => 'high', 'detail' => 'broken'],
            '/valid-marker/' => ['severity' => 'high', 'detail' => 'ok'],
        ];
    }
}
