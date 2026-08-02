<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Detector;

use Erikwang2013\Security\DetectorInterface;
use Erikwang2013\Security\SecurityGuard;
use Erikwang2013\Security\ThreatResult;

class ContentTypeDetector implements DetectorInterface
{
    private const DEFAULT_ALLOWED = [
        'application/x-www-form-urlencoded',
        'multipart/form-data',
        'application/json',
        'text/plain',
        'application/xml',
        'text/xml',
    ];

    public function name(): string
    {
        return 'content_type';
    }

    public function priority(): int
    {
        return -25;
    }

    public function detect(array $data): array
    {
        $contentType = $data['_server.CONTENT_TYPE'] ?? '';
        if ($contentType === '') {
            return [];
        }

        $allowed = SecurityGuard::detectorOption('content_type', 'allowed_types', self::DEFAULT_ALLOWED);
        $typeOnly = strtolower(trim(explode(';', $contentType)[0]));
        $baseAllowed = array_map('strtolower', $allowed);

        if (!in_array($typeOnly, $baseAllowed, true)) {
            return [new ThreatResult(
                type: 'content_type',
                severity: 'medium',
                field: '_server.CONTENT_TYPE',
                payload: $contentType,
                detail: "Unsupported Content-Type: {$contentType}",
                httpStatus: 415,
            )];
        }

        return [];
    }
}
