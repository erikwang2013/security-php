<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security;

interface DetectorInterface
{
    /**
     * Unique name matching config detector key (e.g. 'xss', 'sql_injection').
     */
    public function name(): string;

    /**
     * Scan flat key=>value array for attack patterns.
     * Returns all ThreatResults found (empty array = safe).
     */
    public function detect(array $data): array;

    /**
     * Execution priority. Lower runs first. Default 0.
     * Cheap checks (body_size, http_method) should have negative priorities.
     */
    public function priority(): int;
}
