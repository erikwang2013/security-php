<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Detector;

class RequestSmugglingDetector extends AbstractRegexDetector
{
    public function name(): string
    {
        return 'request_smuggling';
    }

    protected function patterns(): array
    {
        return [
            '/Transfer-Encoding\s*:\s*chunked/i'
                                                => ['severity' => 'high',     'detail' => 'Transfer-Encoding chunked (smuggling indicator)'],
            '/(?:Transfer-Encoding\s*:[^\r\n]*\r?\n\s*Transfer-Encoding\s*:|Transfer-Encoding\s*:[^\r\n]*\r?\n\s*Content-Length\s*:|Content-Length\s*:[^\r\n]*\r?\n\s*Transfer-Encoding\s*:)/i'
                                                => ['severity' => 'critical', 'detail' => 'Multiple Transfer-Encoding headers'],
            '/(?:Transfer-Encoding\s*:[^\r\n]*\r?\n\s*Content-Length\s*:\s*0|Content-Length\s*:\s*0\r?\n\s*Transfer-Encoding\s*:)/i'
                                                => ['severity' => 'high',     'detail' => 'Zero-length body with T-E header'],
            '/Transfer-Encoding\s*:\s*x/ix'
                                                => ['severity' => 'high',     'detail' => 'Obscured Transfer-Encoding value'],
            '/\n\s+(?:Content-Length|Transfer-Encoding)\s*:/i'
                                                => ['severity' => 'medium',   'detail' => 'Folded/split TE/CL header (obfuscation)'],
            '/Transfer-Encoding\s*:\s*\b(?:chunked|identity|gzip|compress|deflate)\b/i'
                                                => ['severity' => 'medium',   'detail' => 'TE with encoding values'],
            '/\r\nTransfer-Encoding\s*:/i'
                                                => ['severity' => 'critical', 'detail' => 'Injected Transfer-Encoding header'],
            '/\r\nContent-Length\s*:\s*\d+/i'
                                                => ['severity' => 'high',     'detail' => 'Injected Content-Length header'],
        ];
    }
}
