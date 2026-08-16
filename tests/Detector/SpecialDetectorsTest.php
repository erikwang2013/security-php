<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Tests\Detector;

use Erikwang2013\Security\Detector\UploadDetector;
use Erikwang2013\Security\Detector\JwtAttackDetector;
use Erikwang2013\Security\Detector\DataLeakDetector;
use Erikwang2013\Security\Detector\PrototypePollutionDetector;
use PHPUnit\Framework\TestCase;

class SpecialDetectorsTest extends TestCase
{
    // UploadDetector
    public function testUploadBlocksPhpExtension(): void
    {
        $detector = new UploadDetector();
        $result = $detector->detect([
            'file' => ['name' => 'shell.php', 'tmp_name' => '/tmp/phpXXX'],
        ]);
        $this->assertNotEmpty($result);
        $this->assertSame('upload', $result[0]->type);
    }

    public function testUploadBlocksPhpContent(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'test_');
        file_put_contents($tmp, '<?php system($_GET["cmd"]); ?>');

        $detector = new UploadDetector();
        $result = $detector->detect([
            'file' => ['name' => 'image.jpg', 'tmp_name' => $tmp],
        ]);
        unlink($tmp);

        $this->assertNotEmpty($result);
        $this->assertSame('critical', $result[0]->severity);
    }

    public function testUploadAllowsSafeImage(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'test_');
        file_put_contents($tmp, 'fake image data');

        $detector = new UploadDetector();
        $result = $detector->detect([
            'file' => ['name' => 'photo.jpg', 'tmp_name' => $tmp],
        ]);
        unlink($tmp);

        $this->assertEmpty($result, 'Safe jpg upload should pass');
    }

    public function testUploadSkipsNonFileArrays(): void
    {
        $detector = new UploadDetector();
        $result = $detector->detect(['data' => 'just a string']);
        $this->assertEmpty($result);
    }

    public function testUploadBlocksPhpTagPastFirstKBInDisguisedName(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'test_');
        $fh = fopen($tmp, 'wb');
        fwrite($fh, str_repeat('A', 2048)); // PHP tag starts at byte 2048, beyond the old 1024-byte check
        fwrite($fh, '<?php system($_GET["cmd"]); ?>');
        fclose($fh);

        $detector = new UploadDetector();
        $result = $detector->detect([
            'file' => ['name' => 'x.php.jpg', 'tmp_name' => $tmp],
        ]);
        unlink($tmp);

        $this->assertNotEmpty($result, 'PHP tag at byte 2048 in x.php.jpg should be detected');
        $this->assertSame('critical', $result[0]->severity);
    }

    public function testUploadAllowsSafeTarGz(): void
    {
        $tmp = tempnam(sys_get_temp_dir(), 'test_');
        file_put_contents($tmp, str_repeat('B', 4096));

        $detector = new UploadDetector();
        $result = $detector->detect([
            'file' => ['name' => 'x.tar.gz', 'tmp_name' => $tmp],
        ]);
        unlink($tmp);

        $this->assertEmpty($result, 'Safe tar.gz upload should pass');
    }

    // JwtAttackDetector
    public function testJwtAlgNoneDetected(): void
    {
        $detector = new JwtAttackDetector();
        // header: {"alg":"none"} → base64url: eyJhbGciOiJub25lIn0
        $result = $detector->detect(['token' => 'eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0.']);
        $this->assertNotEmpty($result);
    }

    public function testJwtWithHmacKidPathTraversal(): void
    {
        $detector = new JwtAttackDetector();
        // header: {"alg":"HS256","kid":"../../etc/passwd"} → base64url
        $result = $detector->detect(['token' => 'eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLy4uL2V0Yy9wYXNzd2QifQ.eyJ1c2VyIjoiYWRtaW4ifQ.sig']);
        $this->assertNotEmpty($result);
    }

    public function testJwtNormalTokenNotDetected(): void
    {
        $detector = new JwtAttackDetector();
        $result = $detector->detect(['token' => 'eyJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoiam9obiJ9.sig123']);
        $this->assertEmpty($result, 'Normal RS256 JWT should not trigger');
    }

    // DataLeakDetector
    public function testDataLeakMasksPayload(): void
    {
        $detector = new DataLeakDetector();
        $result = $detector->detect(['x' => 'AKIAIOSFODNN7EXAMPLE']);
        $this->assertNotEmpty($result);
        $this->assertStringContainsString('***', $result[0]->payload, 'Payload should be masked');
        $this->assertStringNotContainsString('AKIA', $result[0]->payload, 'Real key should not appear in masked payload');
    }

    // PrototypePollutionDetector
    public function testProtoPollutionDirectKey(): void
    {
        $detector = new PrototypePollutionDetector();
        $result = $detector->detect(['__proto__' => ['isAdmin' => true]]);
        $this->assertNotEmpty($result);
        $this->assertSame('prototype_pollution', $result[0]->type);
    }

    public function testProtoPollutionConstructorKey(): void
    {
        $detector = new PrototypePollutionDetector();
        $result = $detector->detect(['constructor' => ['prototype' => ['isAdmin' => true]]]);
        $this->assertNotEmpty($result);
    }

    public function testProtoPollutionInString(): void
    {
        $detector = new PrototypePollutionDetector();
        $result = $detector->detect(['data' => 'obj["__proto__"]["isAdmin"] = true']);
        $this->assertNotEmpty($result);
    }

    public function testProtoPollutionNormalKeysPass(): void
    {
        $detector = new PrototypePollutionDetector();
        $result = $detector->detect(['name' => 'John', 'proto' => 'test']);
        $this->assertEmpty($result);
    }
}
