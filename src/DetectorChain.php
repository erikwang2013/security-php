<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security;

class DetectorChain
{
    private array $detectors = [];

    public function add(DetectorInterface $detector): self
    {
        $this->detectors[] = $detector;
        return $this;
    }

    /**
     * Run all registered detectors against the data.
     * Returns all threats found (empty array = safe).
     */
    public function scan(array $data): array
    {
        // Sort by priority (lower runs first)
        usort($this->detectors, fn($a, $b) => $a->priority() <=> $b->priority());

        $threats = [];
        foreach ($this->detectors as $detector) {
            foreach ($detector->detect($data) as $result) {
                $threats[] = $result;
            }
        }
        return $threats;
    }

    /**
     * Get registered detector count.
     */
    public function count(): int
    {
        return count($this->detectors);
    }
}
