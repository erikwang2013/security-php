<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 *
 * Scan cost per request, by request shape.
 *
 *   php scripts/benchmark.php [iterations]     # default 200
 *
 * Every case uses its own client IP: the IP escalation blacklist bans an IP
 * after 5 block-mode threats, and a banned IP short-circuits the whole scan,
 * which would make the attack case look like the fastest one.
 */

if (PHP_SAPI !== 'cli') {
    exit(1);
}

require dirname(__DIR__) . '/vendor/autoload.php';

use Erikwang2013\Security\SecurityGuard;

$iterations = max(1, (int) ($argv[1] ?? 200));
$config = require dirname(__DIR__) . '/config/security.php';

// Fresh state: a leftover ban file from a previous run changes the numbers
@unlink(sys_get_temp_dir() . '/security_storage.json');

$cases = [
    '3 个小字段' => [
        'username' => 'erik', 'q' => 'hello world', 'page' => '3',
    ],
    '典型表单 · 10 字段' => [
        'username' => 'erik.wang', 'password' => 'correct horse battery staple',
        'email' => 'erik@example.com', 'remember' => '1',
        'profile' => ['name' => 'Erik', 'bio' => 'I build things with PHP and MySQL since 2014.', 'city' => 'Hangzhou'],
        'q' => 'best php security library 2026', 'page' => '3',
        'comment' => str_repeat('这是一条正常的评论，包含标点符号和中文。', 20),
    ],
    '含 128KB 大字段' => [
        'title' => 'report', 'body' => str_repeat('Lorem ipsum dolor sit amet, consectetur adipiscing elit. ', 2300),
    ],
    '命中 SQL 注入' => [
        'username' => 'erik', 'password' => "x' OR '1'='1", 'page' => '3',
    ],
];

printf("PHP %s · %d iterations per case\n\n", PHP_VERSION, $iterations);
printf("%-22s %10s %10s %8s\n", '用例', 'ms/请求', '字段数', '威胁数');

/** Leaf count, the number of values a detector actually looks at */
$fieldCount = static function (array $data) use (&$fieldCount): int {
    $n = 0;
    foreach ($data as $value) {
        $n += is_array($value) ? $fieldCount($value) : 1;
    }
    return $n;
};

$ipSuffix = 10;
foreach ($cases as $label => $data) {
    // Distinct IP per case so no case inherits another's ban
    $meta = ['ip' => '198.51.100.' . $ipSuffix++];

    // Warm up, then measure in separate passes and keep the best — the first
    // pass pays for opcode/JIT warmup, not for the scan
    for ($i = 0; $i < 20; $i++) {
        SecurityGuard::guard($data, $meta);
    }

    $best = INF;
    for ($pass = 0; $pass < 3; $pass++) {
        $start = microtime(true);
        for ($i = 0; $i < $iterations; $i++) {
            SecurityGuard::guard($data, $meta);
        }
        $best = min($best, (microtime(true) - $start) / $iterations * 1000);
    }

    printf(
        "%-22s %10.3f %10d %8d\n",
        $label,
        $best,
        $fieldCount($data),
        count(SecurityGuard::guard($data, $meta)),
    );
}

echo "\n字段数只算请求自身携带的值，_server.* 元数据另计\n";
