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
        $priority = $detector->priority();
        $index = count($this->detectors);
        foreach ($this->detectors as $i => $existing) {
            if ($existing->priority() > $priority) {
                $index = $i;
                break;
            }
        }
        array_splice($this->detectors, $index, 0, [$detector]);
        return $this;
    }

    /**
     * Run all registered detectors against the data.
     * Returns all threats found (empty array = safe).
     */
    public function scan(array $data): array
    {
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
