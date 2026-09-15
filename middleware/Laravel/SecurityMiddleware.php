<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Middleware\Laravel;

use Closure;
use Erikwang2013\Security\SecurityGuard;
use Illuminate\Http\Request;

class SecurityMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        $cookies = $request->cookie() ?? [];
        // `all()` has already collapsed query against body on Laravel's own
        // precedence; this keeps cookie and file values from being dropped on
        // top of that. See SecurityGuard::mergeRequestSources().
        $data = SecurityGuard::mergeRequestSources([
            'cookie' => $cookies,
            'all'    => $request->all(),
            'file'   => $this->extractFiles($request),
        ]);

        $threats = SecurityGuard::guard($data, [
            'ip'              => $request->server('REMOTE_ADDR', '0.0.0.0'),
            'method'          => $request->method(),
            'uri'             => $request->path(),
            'content_length'  => $request->header('Content-Length', ''),
            'content_type'    => $request->header('Content-Type', ''),
            'origin'          => $request->header('Origin', ''),
            'host'            => $request->header('Host', ''),
            'x_forwarded_for' => $request->header('X-Forwarded-For', ''),
            'transfer_encoding' => $request->header('Transfer-Encoding', ''),
            // Session identity comes from the request, not from $data: the
            // merge above puts cookies first, so a same-named query/post field
            // would otherwise shadow the real cookie.
            'cookies'         => $cookies,
            'user_agent'      => $request->header('User-Agent', ''),
            // Keep these names in sync with identity.session.headers
            'headers'         => [
                'authorization' => (string) $request->header('Authorization', ''),
                'x-token'       => (string) $request->header('X-Token', ''),
                'x-auth-token'  => (string) $request->header('X-Auth-Token', ''),
            ],
        ]);

        $securityHeaders = SecurityGuard::securityHeaders();

        $block = SecurityGuard::blockDecision($threats);
        if ($block !== null) {
            return response(
                $block['message'],
                $block['status'],
                array_merge(['Content-Type' => 'text/plain; charset=utf-8'], $securityHeaders)
            );
        }

        // Symfony Response: headers->set() mutates in place
        $response = $next($request);
        foreach ($securityHeaders as $name => $value) {
            $response->headers->set($name, $value);
        }
        return $response;
    }

    private function extractFiles(Request $request): array
    {
        $files = [];
        foreach ($request->allFiles() as $key => $file) {
            if ($file instanceof \Illuminate\Http\UploadedFile) {
                $files[$key] = [
                    'name'     => $file->getClientOriginalName(),
                    'tmp_name' => $file->getPathname(),
                ];
            }
        }
        return $files;
    }
}
