<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security;

class ThreatResult
{
    public function __construct(
        public string $type,
        public string $severity,
        public string $field,
        public string $payload,
        public string $detail,
        public int $httpStatus = 403,
    ) {}
}
