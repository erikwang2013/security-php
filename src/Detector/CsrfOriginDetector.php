<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Detector;

use Erikwang2013\Security\DetectorInterface;
use Erikwang2013\Security\SecurityGuard;
use Erikwang2013\Security\ThreatResult;

class CsrfOriginDetector implements DetectorInterface
{
    public function name(): string
    {
        return 'csrf_origin';
    }

    public function detect(array $data): ?ThreatResult
    {
        $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
        if ($origin === '') {
            return null;
        }

        $host = $_SERVER['HTTP_HOST'] ?? '';
        if ($host === '') {
            return null;
        }

        $originHost = parse_url($origin, PHP_URL_HOST);
        if ($originHost === false || $originHost === null) {
            return null;
        }

        // Check allowed origins from config
        $allowed = SecurityGuard::detectorOption('csrf_origin', 'allowed_origins', null);
        if (is_array($allowed)) {
            foreach ($allowed as $allowedOrigin) {
                if (strtolower($originHost) === strtolower($allowedOrigin)) {
                    return null;
                }
            }
        }

        // Default: Origin must match Host
        if (strtolower($originHost) === strtolower($host)) {
            return null;
        }

        return new ThreatResult(
            type: 'csrf_origin',
            severity: 'high',
            field: '_server.HTTP_ORIGIN',
            payload: $origin,
            detail: "CSRF: Origin {$origin} does not match Host {$host}",
            httpStatus: 403,
        );
    }
}
