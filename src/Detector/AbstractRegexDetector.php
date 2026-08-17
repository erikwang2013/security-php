<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Detector;

use Erikwang2013\Security\DetectorInterface;
use Erikwang2013\Security\ThreatResult;

abstract class AbstractRegexDetector implements DetectorInterface
{
    private const MAX_SCAN_LENGTH = 65536; // 64KB

    abstract public function name(): string;

    /**
     * @return array<string, array{severity: string, detail: string}>
     */
    abstract protected function patterns(): array;

    public function detect(array $data): array
    {
        $threats = [];
        foreach ($data as $field => $value) {
            if (!is_string($value)) {
                continue;
            }
            // Scan head and tail; patterns spanning the middle gap stay invisible.
            // ponytail: >128KB payloads can hide attacks across the truncation seam,
            // switch to chunked scanning with overlap if that matters.
            $scanValue = strlen($value) > self::MAX_SCAN_LENGTH
                ? substr($value, 0, self::MAX_SCAN_LENGTH) . "\n--TRUNC--\n" . substr($value, -self::MAX_SCAN_LENGTH)
                : $value;

            foreach ($this->patterns() as $pattern => $info) {
                $result = preg_match($pattern, $scanValue);
                if ($result === false) {
                    error_log(sprintf(
                        'Security: Invalid regex pattern in detector "%s": %s',
                        $this->name(),
                        $pattern,
                    ));
                    continue;
                }
                if ($result === 1) {
                    $threats[] = new ThreatResult(
                        type: $this->name(),
                        severity: $info['severity'],
                        field: (string) $field,
                        payload: $this->transformPayload($value),
                        detail: $info['detail'],
                    );
                }
            }
        }
        return $threats;
    }

    public function priority(): int
    {
        return 0;
    }

    /**
     * Hook for subclasses to transform payload before logging.
     * Override to mask sensitive data, truncate, etc.
     */
    protected function transformPayload(string $payload): string
    {
        return $payload;
    }
}
