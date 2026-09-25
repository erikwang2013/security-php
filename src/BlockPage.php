<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security;

/**
 * HTML block page for browsers, starring the project mascot 小盾 (docs/mascot.svg).
 *
 * Non-browser clients keep the plain-text block_message — an API consumer has no
 * use for markup, and the middlewares must stay cheap on the hot path.
 */
class BlockPage
{
    /** HTTP status → short reason line */
    private const REASONS = [
        401 => '未授权访问',
        403 => '禁止访问',
        405 => '请求方法不被允许',
        413 => '请求体过大',
        415 => '内容类型不被支持',
        429 => '请求过于频繁',
    ];

    /**
     * Only an explicit text/html in Accept gets the page. Browsers navigating
     * send it; curl, fetch() and most API clients do not.
     */
    public static function wantsHtml(string $accept): bool
    {
        return $accept !== '' && stripos($accept, 'text/html') !== false;
    }

    /**
     * @param string[] $types detector names to list, e.g. ['sql_injection']
     */
    public static function render(int $status, string $message, array $types): string
    {
        $reason = self::REASONS[$status] ?? '请求已被拦截';
        // No mb_* here: the library stays on a plain PHP 8 install with no
        // extra extension. ENT_SUBSTITUTE keeps a broken byte from blanking
        // the whole string.
        $escape = static fn (string $value): string => htmlspecialchars(
            $value,
            ENT_QUOTES | ENT_SUBSTITUTE,
            'UTF-8',
        );

        $title = $status . ' · ' . $reason;
        $message = $escape($message);

        $chips = '';
        foreach (array_slice(array_unique($types), 0, 8) as $type) {
            $chips .= '<li>' . $escape((string) $type) . '</li>';
        }
        $hit = $chips === ''
            ? ''
            : '<p class="label">命中的检测器</p><ul>' . $chips . '</ul>';

        $mascot = self::mascot();

        return <<<HTML
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="robots" content="noindex">
        <title>{$title}</title>
        <style>
        :root{--bg:#f6f8fc;--card:#fff;--ink:#0f172a;--muted:#64748b;--line:#e2e8f0;--chip:#eff6ff;--chipink:#1e40af}
        @media (prefers-color-scheme:dark){:root{--bg:#0b1220;--card:#111a2e;--ink:#e8eefc;--muted:#94a3b8;--line:#243352;--chip:#16233d;--chipink:#bfd4ff}}
        *{box-sizing:border-box}
        body{margin:0;padding:24px;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--ink);font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
        .card{width:100%;max-width:520px;padding:32px;background:var(--card);border:1px solid var(--line);border-radius:16px;text-align:center}
        h1{margin:10px 0 4px;font-size:19px}
        .status{margin:0 0 18px;color:var(--muted);font:13px ui-monospace,SFMono-Regular,Menlo,monospace}
        .label{margin:0 0 8px;color:var(--muted);font-size:12.5px}
        ul{display:flex;flex-wrap:wrap;gap:8px;justify-content:center;margin:0;padding:0;list-style:none}
        li{padding:4px 12px;background:var(--chip);color:var(--chipink);border-radius:999px;font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace}
        .hint{margin:18px 0 0;color:var(--muted);font-size:12.5px}
        </style>
        </head>
        <body>
        <main class="card">
        {$mascot}
        <h1>{$reason}</h1>
        <p class="status">{$status} — {$message}</p>
        {$hit}
        <p class="hint">若你认为这是误判，请把上面的状态码与检测器名称提供给站点管理员。</p>
        </main>
        </body>
        </html>
        HTML;
    }

    /**
     * Inline copy of docs/mascot.svg — same character, kept in the library so the
     * page needs no file access. Change both when the design changes.
     */
    public static function mascot(): string
    {
        return <<<'SVG'
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200" width="104" height="104" role="img" aria-label="小盾">
        <defs><linearGradient id="spShield" x1="0" y1="0" x2="0.35" y2="1"><stop offset="0" stop-color="#5B9BFF"/><stop offset="1" stop-color="#1E4FD8"/></linearGradient></defs>
        <path d="M100 18 C118 28 142 37 160 41 C165 42 168 46 168 51 C168 106 148 152 100 180 C52 152 32 106 32 51 C32 46 35 42 40 41 C58 37 82 28 100 18 Z" fill="url(#spShield)"/>
        <path d="M100 32 C116 40 138 48 155 52 C158 53 160 56 160 60 C160 106 143 146 100 171 C57 146 40 106 40 60 C40 56 42 53 45 52 C62 48 84 40 100 32 Z" fill="none" stroke="#FFFFFF" stroke-opacity="0.28" stroke-width="3"/>
        <ellipse cx="76" cy="84" rx="11" ry="13" fill="#FFFFFF"/><ellipse cx="124" cy="84" rx="11" ry="13" fill="#FFFFFF"/>
        <circle cx="78" cy="86" r="5.5" fill="#12305F"/><circle cx="126" cy="86" r="5.5" fill="#12305F"/>
        <circle cx="75.5" cy="82.5" r="2" fill="#FFFFFF"/><circle cx="123.5" cy="82.5" r="2" fill="#FFFFFF"/>
        <circle cx="58" cy="101" r="7" fill="#FF8FA3" opacity="0.38"/><circle cx="142" cy="101" r="7" fill="#FF8FA3" opacity="0.38"/>
        <path d="M88 103 Q100 115 112 103" fill="none" stroke="#12305F" stroke-width="4.5" stroke-linecap="round"/>
        <circle cx="100" cy="139" r="15" fill="#FFFFFF" fill-opacity="0.18" stroke="#FFFFFF" stroke-width="4.5"/>
        <path d="M110.5 149.5 L119 158" stroke="#FFFFFF" stroke-width="6" stroke-linecap="round"/>
        </svg>
        SVG;
    }
}
