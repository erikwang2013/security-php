<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Middleware\Thinkphp;

use think\Request;
use think\Response;
use Erikwang2013\Security\SecurityGuard;

class SecurityMiddleware
{
    private static bool $initialized = false;

    public function handle(Request $request, callable $next): Response
    {
        if (!self::$initialized) {
            self::$initialized = true;

            // ThinkPHP config path: config/security.php
            $publishPath = app()->getRootPath() . 'config/security.php';
            if (file_exists($publishPath)) {
                SecurityGuard::init(require $publishPath);
            } else {
                SecurityGuard::init(require dirname(__DIR__, 2) . '/config/security.php');
            }
        }

        $cookies = $request->cookie() ?? [];
        $data = array_merge(
            $cookies,
            $request->param() ?? [],
        );

        $files = $request->file();
        if (!empty($files)) {
            foreach ($files as $key => $file) {
                if ($file instanceof \think\File) {
                    $data[$key] = [
                        'name'     => $file->getOriginalName(),
                        'tmp_name' => $file->getPathname(),
                    ];
                }
            }
        }

        $threats = SecurityGuard::guard($data, [
            'ip'              => $request->ip() ?? '0.0.0.0',
            'method'          => $request->method(),
            'uri'             => $request->pathinfo(),
            'content_length'  => $request->header('content-length', ''),
            'content_type'    => $request->header('content-type', ''),
            'origin'          => $request->header('origin', ''),
            'host'            => $request->header('host', ''),
            'x_forwarded_for' => $request->header('x-forwarded-for', ''),
            'transfer_encoding' => $request->header('transfer-encoding', ''),
            // Session identity comes from the request, not from $data: the
            // merge above puts cookies first, so a same-named query/post field
            // would otherwise shadow the real cookie.
            'cookies'         => $cookies,
            'user_agent'      => $request->header('user-agent', ''),
            // Keep these names in sync with identity.session.headers
            'headers'         => [
                'authorization' => (string) $request->header('authorization', ''),
                'x-token'       => (string) $request->header('x-token', ''),
                'x-auth-token'  => (string) $request->header('x-auth-token', ''),
            ],
        ]);

        $securityHeaders = SecurityGuard::securityHeaders();

        $block = SecurityGuard::blockDecision($threats);
        if ($block !== null) {
            // false disables ThinkPHP's htmlspecialchars, which would corrupt a
            // CSP value containing single quotes
            return Response::create(
                $block['message'],
                'text/plain; charset=utf-8',
                $block['status']
            )->header($securityHeaders, false);
        }

        $response = $next($request);
        if ($securityHeaders !== []) {
            $response->header($securityHeaders, false);
        }
        return $response;
    }
}
