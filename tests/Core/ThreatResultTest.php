<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Tests\Core;

use Erikwang2013\Security\ThreatResult;
use PHPUnit\Framework\TestCase;

class ThreatResultTest extends TestCase
{
    public function testConstructorAssignsAllProperties(): void
    {
        $t = new ThreatResult(
            type: 'xss',
            severity: 'critical',
            field: 'comment',
            payload: '<script>alert(1)</script>',
            detail: 'Script tag',
        );

        $this->assertSame('xss', $t->type);
        $this->assertSame('critical', $t->severity);
        $this->assertSame('comment', $t->field);
        $this->assertSame('<script>alert(1)</script>', $t->payload);
        $this->assertSame('Script tag', $t->detail);
        $this->assertSame(403, $t->httpStatus, 'httpStatus must default to 403');
    }

    public function testHttpStatusCanBeOverridden(): void
    {
        $t = new ThreatResult(
            type: 'body_size',
            severity: 'medium',
            field: '_server.CONTENT_LENGTH',
            payload: '20971520',
            detail: 'too large',
            httpStatus: 413,
        );

        $this->assertSame(413, $t->httpStatus);
    }
}
