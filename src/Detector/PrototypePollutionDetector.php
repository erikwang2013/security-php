<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Detector;

use Erikwang2013\Security\ThreatResult;

class PrototypePollutionDetector extends AbstractRegexDetector
{
    public function name(): string
    {
        return 'prototype_pollution';
    }

    protected function patterns(): array
    {
        return [
            '/\.?__proto__\.?/'         => ['severity' => 'critical', 'detail' => 'Prototype pollution: __proto__ access'],
            '/\.?constructor\.prototype\.?/'
                                                => ['severity' => 'critical', 'detail' => 'Prototype pollution: constructor.prototype'],
            '/["\']constructor["\']\s*:/i' => ['severity' => 'critical', 'detail' => 'Prototype pollution: constructor JSON key'],
            '/["\']prototype["\']\s*:/i'   => ['severity' => 'high', 'detail' => 'Prototype pollution: prototype JSON key'],
            '/\.?__defineGetter__\.?/'  => ['severity' => 'high',     'detail' => 'Prototype pollution: __defineGetter__'],
            '/\.?__defineSetter__\.?/'  => ['severity' => 'high',     'detail' => 'Prototype pollution: __defineSetter__'],
            '/\.?__lookupGetter__\.?/'  => ['severity' => 'medium',   'detail' => 'Prototype pollution: __lookupGetter__'],
            '/\.?__lookupSetter__\.?/'  => ['severity' => 'medium',   'detail' => 'Prototype pollution: __lookupSetter__'],
            '/Object\.(?:define|create|setPrototypeOf)/'
                                                => ['severity' => 'medium',   'detail' => 'Prototype pollution: Object static method use'],
            '/\.(?:toString|valueOf)\s*=\s*(?:function\b|\()/i'
                                                => ['severity' => 'high',     'detail' => 'Prototype pollution: method override assignment'],
        ];
    }

    public function detect(array $data): array
    {
        foreach ($data as $field => $value) {
            if ($field === '__proto__' || $field === 'constructor') {
                $encoded = is_array($value) ? json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : null;
                return [new ThreatResult(
                    type: 'prototype_pollution',
                    severity: 'critical',
                    field: (string) $field,
                    payload: is_string($encoded) ? $encoded : '{payload encoding failed}',
                    detail: "Prototype pollution: direct {$field} key in input",
                )];
            }
        }

        return parent::detect($data);
    }
}
