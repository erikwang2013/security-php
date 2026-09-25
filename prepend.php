<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 *
 * auto_prepend_file entry point for plain PHP projects: every request is
 * scanned before the application runs, with no change to the app code.
 *
 *   php.ini / pool config   auto_prepend_file = /path/to/security-php/prepend.php
 *   .htaccess               php_value auto_prepend_file "/path/to/security-php/prepend.php"
 *   nginx + php-fpm         fastcgi_param PHP_VALUE "auto_prepend_file=/path/to/security-php/prepend.php"
 *
 * Config comes from <package>/config/security.php; set the SECURITY_CONFIG
 * environment variable to point at your own copy instead, so a composer
 * update cannot overwrite your settings.
 *
 * Works with or without Composer — the autoloader lives in src/helpers.php.
 */

// CLI (cron, queue workers, scripts) is not an HTTP request: nothing to scan
if (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg') {
    return;
}

require __DIR__ . '/src/helpers.php';

$securityConfig = getenv('SECURITY_CONFIG');
if (is_string($securityConfig) && $securityConfig !== '' && is_file($securityConfig)) {
    \Erikwang2013\Security\SecurityGuard::init(require $securityConfig);
}

security_guard();
