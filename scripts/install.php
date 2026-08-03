<?php

declare(strict_types=1);

/**
 * Composer post-install script.
 *
 * Detects the target framework and copies config/security.php to the
 * framework-appropriate config directory. Never overwrites existing files.
 *
 * Called from composer.json: scripts.post-install-cmd
 */

$projectRoot = dirname(__DIR__, 4); // vendor/erikwang2013/security-php/scripts → project root
$sourceConfig = __DIR__ . '/../config/security.php';

if (!file_exists($sourceConfig)) {
    return;
}

$targets = [];

// Laravel
if (isLaravel($projectRoot)) {
    $targets[] = $projectRoot . '/config/security.php';
}

// Webman
if (isWebman($projectRoot)) {
    $targets[] = $projectRoot . '/config/plugin/erikwang2013/security-php/app.php';
}

// ThinkPHP
if (isThinkPHP($projectRoot)) {
    $targets[] = $projectRoot . '/config/security.php';
}

// Hyperf
if (isHyperf($projectRoot)) {
    $targets[] = $projectRoot . '/config/autoload/security.php';
}

foreach ($targets as $target) {
    $targetDir = dirname($target);
    if (!is_dir($targetDir)) {
        @mkdir($targetDir, 0755, true);
    }

    if (!file_exists($target)) {
        copy($sourceConfig, $target);
        echo "[security-php] Config published to: {$target}\n";
    }
}

// ──────────────── detectors ────────────────

function isLaravel(string $root): bool
{
    return file_exists($root . '/artisan')
        && file_exists($root . '/bootstrap/app.php');
}

function isWebman(string $root): bool
{
    return file_exists($root . '/start.php')
        && is_dir($root . '/config/plugin');
}

function isThinkPHP(string $root): bool
{
    return file_exists($root . '/think')
        && file_exists($root . '/app/AppService.php');
}

function isHyperf(string $root): bool
{
    return file_exists($root . '/bin/hyperf.php')
        && is_dir($root . '/config/autoload');
}
