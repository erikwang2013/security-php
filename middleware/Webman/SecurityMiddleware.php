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

        $cookies = $request->cookie() ?? [];

        $files = [];
        foreach ($request->file() ?? [] as $key => $file) {
            if ($file instanceof \Webman\Http\UploadFile) {
                $files[$key] = [
                    'name'     => $file->getUploadName() ?? '',
                    'tmp_name' => $file->getUploadTmpPath() ?? '',
                ];
            } elseif (is_array($file) && isset($file['tmp_name'], $file['name'])) {
                $files[$key] = [
                    'name'     => $file['name'],
                    'tmp_name' => $file['tmp_name'],
                ];
            }
        }

        // Every source keeps its value in the scan even when the names collide.
        $data = SecurityGuard::mergeRequestSources([
            'cookie' => $cookies,
            'get'    => $request->get() ?? [],
            'post'   => $request->post() ?? [],
            'file'   => $files,
        ]);

        $meta = [
            'ip'              => $request->getRealIp() ?? '0.0.0.0',
            'method'          => $request->method(),
            'uri'             => $request->path(),
            'content_length'  => $request->header('content-length') ?? '',
            'content_type'    => $request->header('content-type') ?? '',
            'origin'          => $request->header('origin') ?? '',
            'host'            => $request->header('host') ?? '',
            'accept'          => $request->header('accept') ?? '',
            'x_forwarded_for' => $request->header('x-forwarded-for') ?? '',
            'transfer_encoding' => $request->header('transfer-encoding') ?? '',
            // Session identity comes from the request, not from $data: the
            // merge above puts cookies first, so a same-named query/post field
            // would otherwise shadow the real cookie.
            'cookies'         => $cookies,
            'user_agent'      => $request->header('user-agent') ?? '',
            // Keep these names in sync with identity.session.headers
            'headers'         => [
                'authorization' => (string) ($request->header('authorization') ?? ''),
                'x-token'       => (string) ($request->header('x-token') ?? ''),
                'x-auth-token'  => (string) ($request->header('x-auth-token') ?? ''),
            ],
        ];

        $threats = SecurityGuard::guard($data, $meta);

        $securityHeaders = SecurityGuard::securityHeaders();

        $block = SecurityGuard::blockDecision($threats);
        if ($block !== null) {
            [$contentType, $body] = SecurityGuard::blockResponse($threats, $meta);
            return new Response(
                $block['status'],
                array_merge(['Content-Type' => $contentType], $securityHeaders),
                $body
            );
        }

        // PSR-7: withHeader() is immutable, so reassign on each iteration
        $response = $next($request);
        foreach ($securityHeaders as $name => $value) {
            $response = $response->withHeader($name, $value);
        }
        return $response;
    }
}
