<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Detector;

use Erikwang2013\Security\DetectorInterface;
use Erikwang2013\Security\SecurityGuard;
use Erikwang2013\Security\ThreatResult;

class HttpMethodDetector implements DetectorInterface
{
    private const DEFAULT_ALLOWED = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH'];

    public function name(): string
    {
        return 'http_method';
    }

    public function priority(): int
    {
        return -20;
    }

    public function detect(array $data): array
    {
        $method = $data['_server.REQUEST_METHOD'] ?? '';
        if ($method === '') {
            return [];
        }

        $method = strtoupper($method);
        $allowed = SecurityGuard::detectorOption('http_method', 'allowed_methods', self::DEFAULT_ALLOWED);

        if (!in_array($method, $allowed, true)) {
            return [new ThreatResult(
                type: 'http_method',
                severity: 'medium',
                field: '_server.REQUEST_METHOD',
                payload: $method,
                detail: 'HTTP method not allowed: ' . $method,
                httpStatus: 405,
            )];
        }

        return [];
    }
}
