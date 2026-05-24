<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Detector;

use Erikwang2013\Security\DetectorInterface;
use Erikwang2013\Security\SecurityGuard;
use Erikwang2013\Security\ThreatResult;

class BodySizeDetector implements DetectorInterface
{
    private const DEFAULT_MAX_SIZE = 10485760; // 10 MB

    public function name(): string
    {
        return 'body_size';
    }

    public function detect(array $data): ?ThreatResult
    {
        $contentLength = $_SERVER['CONTENT_LENGTH'] ?? null;
        if ($contentLength === null || $contentLength === '') {
            return null;
        }

        $size = (int) $contentLength;
        $maxSize = (int) SecurityGuard::detectorOption('body_size', 'max_size', self::DEFAULT_MAX_SIZE);

        if ($size > $maxSize) {
            return new ThreatResult(
                type: 'body_size',
                severity: 'medium',
                field: '_server.CONTENT_LENGTH',
                payload: (string) $size,
                detail: "Request body too large: {$size} bytes (max: {$maxSize})",
                httpStatus: 413,
            );
        }

        return null;
    }
}
