<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Detector;

use Erikwang2013\Security\DetectorInterface;
use Erikwang2013\Security\ThreatResult;

class UploadDetector implements DetectorInterface
{
    public function name(): string
    {
        return 'upload';
    }

    public function priority(): int
    {
        return 0;
    }

    private const SAFE_EXTENSIONS = [
        'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp',
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'txt', 'csv', 'md', 'json',
        'zip', 'tar', 'gz', 'rar', '7z',
        'mp3', 'mp4', 'avi', 'mov', 'wav', 'flac',
    ];

    public function detect(array $data): array
    {
        foreach ($this->normalizeFiles($data) as $field => $file) {
            $name = $file['name'] ?? 'unknown';
            $tmpPath = $file['tmp_name'] ?? null;

            if ($tmpPath && file_exists($tmpPath)) {
                $head = file_get_contents($tmpPath, false, null, 0, 1048576);
                if ($head !== false && preg_match('/<\?(?:php|=)/i', $head)) {
                    return [new ThreatResult(
                        type: 'upload',
                        severity: 'critical',
                        field: (string) $field,
                        payload: $name,
                        detail: 'PHP code detected in file content',
                    )];
                }
            }

            // Each dotted segment must be whitelisted (blocks x.php.jpg double-extension bypass)
            $parts = explode('.', strtolower($name));
            array_shift($parts);
            foreach ($parts as $seg) {
                if ($seg !== '' && !in_array($seg, self::SAFE_EXTENSIONS, true)) {
                    return [new ThreatResult(
                        type: 'upload',
                        severity: 'high',
                        field: (string) $field,
                        payload: $name,
                        detail: "Forbidden file extension: .{$seg}",
                    )];
                }
            }
        }

        return [];
    }

    /**
     * Flatten PHP $_FILES-style arrays into [field => upload-entry] pairs.
     * Multi-file input (name/tmp_name as arrays) expands to "field[i]";
     * deeper nesting recurses with the same bracket-key scheme.
     */
    private function normalizeFiles(array $data): array
    {
        $flat = [];
        foreach ($data as $key => $value) {
            if (is_array($value['name'] ?? null) || is_array($value['tmp_name'] ?? null)) {
                $names = (array) ($value['name'] ?? []);
                foreach ($names as $i => $name) {
                    $tmpName = $value['tmp_name'][$i] ?? '';
                    $sub = [
                        'name' => $name,
                        'tmp_name' => $tmpName,
                        'type' => $value['type'][$i] ?? '',
                        'size' => $value['size'][$i] ?? 0,
                        'error' => $value['error'][$i] ?? 0,
                    ];
                    if (is_array($name) || is_array($tmpName)) {
                        $flat += $this->normalizeFiles(["{$key}[{$i}]" => $sub]);
                    } elseif ($tmpName !== '') {
                        $flat["{$key}[{$i}]"] = $sub;
                    }
                }
            } elseif (is_array($value)
                && isset($value['name'], $value['tmp_name'])
                && is_string($value['tmp_name'])
                && $value['tmp_name'] !== ''
            ) {
                $flat[$key] = $value;
            }
        }

        return $flat;
    }
}
