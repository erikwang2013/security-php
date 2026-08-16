<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Detector;

class XssDetector extends AbstractRegexDetector
{
    public function name(): string
    {
        return 'xss';
    }

    protected function patterns(): array
    {
        return [
            '/<script\b/i'              => ['severity' => 'critical', 'detail' => 'Script tag injection'],
            '/<iframe\b/i'              => ['severity' => 'high',     'detail' => 'Iframe injection'],
            // Explicit handler list so words like "online" or "connection" are not flagged
            '/\bon(?:click|dblclick|contextmenu|auxclick|error|load|focus|blur|focusin|focusout|change|input|submit|reset|select|keyup|keydown|keypress|mousedown|mouseup|mousemove|mouseover|mouseout|mouseenter|mouseleave|wheel|touchstart|touchend|touchmove|touchcancel|pointerdown|pointerup|pointermove|pointerover|pointerout|pointerenter|pointerleave|drag|dragstart|dragend|dragenter|dragover|dragleave|drop|copy|cut|paste|scroll|resize|toggle|play|pause|progress)\s*=/i'
                                        => ['severity' => 'high',     'detail' => 'Event handler injection'],
            '/<svg\b.*\bon/i'          => ['severity' => 'high',     'detail' => 'SVG with event handler'],
            '/<style\b[^>]*>/i'        => ['severity' => 'medium',   'detail' => 'CSS tag injection (XSS vector)'],
            '/style\s*=\s*"[^"]*\b(?:expression|javascript)\b/i'
                                        => ['severity' => 'high',     'detail' => 'CSS XSS via style attribute'],
            '/javascript\s*:/i'         => ['severity' => 'high',     'detail' => 'JavaScript URI scheme'],
            '/<embed\b/i'               => ['severity' => 'medium',   'detail' => 'Embed tag injection'],
            '/<object\b/i'              => ['severity' => 'medium',   'detail' => 'Object tag injection'],
            '/<link\b/i'                => ['severity' => 'medium',   'detail' => 'Link tag injection'],
            '/<meta\b/i'                => ['severity' => 'low',      'detail' => 'Meta tag injection'],
            '/expression\s*\(/i'        => ['severity' => 'medium',   'detail' => 'CSS expression injection'],
            '/<svg\b/i'                 => ['severity' => 'low',      'detail' => 'SVG tag injection'],
        ];
    }
}
