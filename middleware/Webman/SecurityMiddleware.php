<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Middleware\Webman;

use Erikwang2013\Security\SecurityGuard;
use Webman\MiddlewareInterface;
use Webman\Http\Request;
use Webman\Http\Response;

class SecurityMiddleware implements MiddlewareInterface
{
    private static bool $initialized = false;

    public function process(Request $request, callable $next): Response
    {
        if (!self::$initialized) {
            self::$initialized = true;

            // Webman plugin config path: config/plugin/erikwang2013/security-php/app.php
            $publishPath = config_path() . '/plugin/erikwang2013/security-php/app.php';
            if (file_exists($publishPath)) {
                SecurityGuard::init(require $publishPath);
            } else {
                SecurityGuard::init(require dirname(__DIR__, 2) . '/config/security.php');
            }
        }

        $data = array_merge(
            $request->cookie() ?? [],
            $request->get() ?? [],
            $request->post() ?? [],
        );

        foreach ($request->file() ?? [] as $key => $file) {
            if ($file instanceof \Webman\Http\UploadFile) {
                $data[$key] = [
                    'name'     => $file->getUploadName() ?? '',
                    'tmp_name' => $file->getUploadTmpPath() ?? '',
                ];
            } elseif (is_array($file) && isset($file['tmp_name'], $file['name'])) {
                $data[$key] = [
                    'name'     => $file['name'],
                    'tmp_name' => $file['tmp_name'],
                ];
            }
        }

        $threats = SecurityGuard::guard($data, [
            'ip'              => $request->getRealIp() ?? '0.0.0.0',
            'method'          => $request->method(),
            'uri'             => $request->path(),
            'content_length'  => $request->header('content-length') ?? '',
            'content_type'    => $request->header('content-type') ?? '',
            'origin'          => $request->header('origin') ?? '',
            'host'            => $request->header('host') ?? '',
            'x_forwarded_for' => $request->header('x-forwarded-for') ?? '',
            'transfer_encoding' => $request->header('transfer-encoding') ?? '',
        ]);

        if (!empty($threats) && SecurityGuard::shouldBlock($threats)) {
            return new Response(
                SecurityGuard::blockStatusCode($threats),
                ['Content-Type' => 'text/plain; charset=utf-8'],
                SecurityGuard::blockMessage()
            );
        }

        return $next($request);
    }
}
