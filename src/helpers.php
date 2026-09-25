<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 *
 * Global helper functions for manual security scanning.
 * No framework dependency — works with plain PHP arrays.
 *
 * This file is also the entry point of a Composer-free install: copy src/ and
 * config/ into the project and `require 'src/helpers.php'`. In a Composer
 * install the PSR-4 map is already registered, the class below resolves, and
 * nothing extra happens here.
 */

use Erikwang2013\Security\SecurityGuard;

if (!class_exists(SecurityGuard::class)) {
    // No Composer: bring our own PSR-4 loader. Longest prefix wins, so the
    // middleware/ tree stays reachable for a framework copied in whole.
    spl_autoload_register(static function (string $class): void {
        $maps = [
            'Erikwang2013\\Security\\Middleware\\' => dirname(__DIR__) . '/middleware/',
            'Erikwang2013\\Security\\' => __DIR__ . '/',
        ];
        foreach ($maps as $prefix => $dir) {
            if (str_starts_with($class, $prefix)) {
                $file = $dir . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
                if (is_file($file)) {
                    require $file;
                }
                return;
            }
        }
    });
}

if (!function_exists('security_scan')) {
    /**
     * Scan an arbitrary key=>value array for security threats.
     * Returns ThreatResult[] — empty array means safe.
     */
    function security_scan(array $data): array
    {
        return SecurityGuard::guard($data);
    }
}

if (!function_exists('security_scan_current_request')) {
    /**
     * Scan the current HTTP request superglobals.
     * Extracts GET, POST, COOKIE, and FILES automatically.
     */
    function security_scan_current_request(): array
    {
        $files = [];
        foreach ($_FILES as $key => $file) {
            $files[$key] = [
                'name'     => $file['name'] ?? '',
                'tmp_name' => $file['tmp_name'] ?? '',
            ];
        }

        // Every source keeps its value in the scan even when the names collide.
        $data = SecurityGuard::mergeRequestSources([
            'cookie' => $_COOKIE,
            'get'    => $_GET,
            'post'   => $_POST,
            'file'   => $files,
        ]);

        // Apache+CGI keeps Authorization out of $_SERVER; getallheaders() is the
        // documented way back to it. Every other header arrives as HTTP_*.
        $header = static function (string $serverKey, string $name): string {
            $value = $_SERVER[$serverKey] ?? '';
            if ($value !== '' || !function_exists('getallheaders')) {
                return (string) $value;
            }
            foreach (getallheaders() as $key => $val) {
                if (strcasecmp((string) $key, $name) === 0) {
                    return (string) $val;
                }
            }

            return '';
        };

        return SecurityGuard::guard($data, [
            'ip'              => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
            'method'          => $_SERVER['REQUEST_METHOD'] ?? 'GET',
            'uri'             => $_SERVER['REQUEST_URI'] ?? '/',
            'content_length'  => $_SERVER['CONTENT_LENGTH'] ?? '',
            'content_type'    => $_SERVER['CONTENT_TYPE'] ?? '',
            'origin'          => $_SERVER['HTTP_ORIGIN'] ?? '',
            'host'            => $_SERVER['HTTP_HOST'] ?? '',
            'accept'          => $_SERVER['HTTP_ACCEPT'] ?? '',
            'x_forwarded_for' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '',
            'transfer_encoding' => $_SERVER['HTTP_TRANSFER_ENCODING'] ?? '',
            // Session identity is read from here, not from $data: the merge above
            // puts cookies first, so a same-named query/post field would
            // otherwise shadow the real cookie.
            'cookies'         => $_COOKIE,
            'user_agent'      => $header('HTTP_USER_AGENT', 'User-Agent'),
            // Keep these names in sync with identity.session.headers
            'headers'         => [
                'authorization' => $header('HTTP_AUTHORIZATION', 'Authorization'),
                'x-token'       => $header('HTTP_X_TOKEN', 'X-Token'),
                'x-auth-token'  => $header('HTTP_X_AUTH_TOKEN', 'X-Auth-Token'),
            ],
        ]);
    }
}

if (!function_exists('security_is_safe')) {
    /**
     * Quick check: is the given data safe?
     */
    function security_is_safe(array $data): bool
    {
        return security_scan($data) === [];
    }
}

if (!function_exists('security_guard')) {
    /**
     * Scan current request and die with 403 if any detector is in block mode.
     * Suitable for non-framework projects or bootstrap files.
     *
     * Sets the configured security headers first, so they land on both the
     * blocked and the passing response — same as the framework middlewares.
     */
    function security_guard(): void
    {
        foreach (SecurityGuard::securityHeaders() as $name => $value) {
            header($name . ': ' . $value);
        }

        $threats = security_scan_current_request();

        $block = SecurityGuard::blockDecision($threats);
        if ($block !== null) {
            http_response_code($block['status']);
            // HTML page for browsers, plain text for everything else
            [$contentType, $body] = SecurityGuard::blockResponse($threats, [
                'accept' => $_SERVER['HTTP_ACCEPT'] ?? '',
            ]);
            header('Content-Type: ' . $contentType);
            die($body);
        }
    }
}
