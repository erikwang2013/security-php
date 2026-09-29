<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Middleware\Yii2;

use Erikwang2013\Security\SecurityGuard;
use yii\base\Application;
use yii\base\BootstrapInterface;
use yii\web\Application as WebApplication;
use yii\web\Request;
use yii\web\Response;

/**
 * Yii2 has no PSR-15 middleware, so the equivalent of one is a bootstrap
 * component. Attaching to the application's request events covers every
 * request — a controller behavior or ActionFilter would only cover the
 * controllers that opted in.
 *
 *     // config/web.php
 *     'bootstrap' => [\Erikwang2013\Security\Middleware\Yii2\SecurityBootstrap::class],
 */
class SecurityBootstrap implements BootstrapInterface
{
    private static bool $initialized = false;

    public function bootstrap($app): void
    {
        // Console applications have no request/response components to guard.
        if (!$app instanceof WebApplication) {
            return;
        }

        // Before handleRequest(); EVENT_AFTER_REQUEST fires after it returns
        // and before the response is sent, which is where the headers go.
        $app->on(Application::EVENT_BEFORE_REQUEST, static function () use ($app): void {
            self::scan($app);
        });

        $app->on(Application::EVENT_AFTER_REQUEST, static function () use ($app): void {
            self::applySecurityHeaders($app);
        });
    }

    private static function scan(WebApplication $app): void
    {
        self::initOnce($app);

        $request = $app->getRequest();
        $cookies = $request->getCookies()->toArray();

        // Every source keeps its value in the scan even when the names collide.
        $data = SecurityGuard::mergeRequestSources([
            'cookie' => $cookies,
            'get'    => $request->get(),
            'post'   => self::bodyParams($request),
            // Yii2 has no request-level uploads API — its own UploadedFile
            // reads $_FILES as well, so that is the source here too.
            'file'   => $_FILES,
        ]);

        $meta = [
            // The peer address, not a forwarded one: trusted_proxies resolves
            // X-Forwarded-For downstream, in SecurityGuard::resolveClientIp().
            'ip'              => $request->getRemoteIP() ?: '0.0.0.0',
            'method'          => $request->getMethod(),
            'uri'             => self::pathInfo($request),
            'content_length'  => (string) $request->getHeaders()->get('Content-Length'),
            'content_type'    => (string) $request->getHeaders()->get('Content-Type'),
            'origin'          => (string) $request->getHeaders()->get('Origin'),
            'host'            => (string) $request->getHeaders()->get('Host'),
            'accept'          => (string) $request->getHeaders()->get('Accept'),
            'x_forwarded_for' => (string) $request->getHeaders()->get('X-Forwarded-For'),
            'transfer_encoding' => (string) $request->getHeaders()->get('Transfer-Encoding'),
            // Session identity comes from the request, not from $data: the
            // merge above puts cookies first, so a same-named query/post field
            // would otherwise shadow the real cookie.
            'cookies'         => $cookies,
            'user_agent'      => (string) $request->getHeaders()->get('User-Agent'),
            // Keep these names in sync with identity.session.headers
            'headers'         => [
                'authorization' => (string) $request->getHeaders()->get('Authorization'),
                'x-token'       => (string) $request->getHeaders()->get('X-Token'),
                'x-auth-token'  => (string) $request->getHeaders()->get('X-Auth-Token'),
            ],
        ];

        $threats = SecurityGuard::guard($data, $meta);

        $block = SecurityGuard::blockDecision($threats);
        if ($block === null) {
            return;
        }

        [$contentType, $body] = SecurityGuard::blockResponse($threats, $meta);

        // end() sends this response and stops the application: exit() in
        // production, ExitException under YII_ENV_TEST. It also triggers
        // EVENT_AFTER_REQUEST, so applySecurityHeaders() runs for this response
        // too — setting them here as well keeps the block path readable.
        $response = $app->getResponse();
        $response->setStatusCode($block['status']);
        // FORMAT_RAW sends $content verbatim instead of formatting it
        $response->format = Response::FORMAT_RAW;
        $response->content = $body;
        $response->getHeaders()->set('Content-Type', $contentType);
        foreach (SecurityGuard::securityHeaders() as $name => $value) {
            $response->getHeaders()->set($name, $value);
        }

        $app->end();
    }

    private static function applySecurityHeaders(WebApplication $app): void
    {
        $securityHeaders = SecurityGuard::securityHeaders();
        if ($securityHeaders === []) {
            return;
        }

        $response = $app->getResponse();
        foreach ($securityHeaders as $name => $value) {
            $response->getHeaders()->set($name, $value);
        }
    }

    private static function initOnce(WebApplication $app): void
    {
        if (self::$initialized) {
            return;
        }
        self::$initialized = true;

        foreach (self::configCandidates($app) as $path) {
            if (is_file($path)) {
                SecurityGuard::init(require $path);
                return;
            }
        }

        SecurityGuard::init(require dirname(__DIR__, 2) . '/config/security.php');
    }

    /**
     * @return string[] published config paths, most specific first
     */
    private static function configCandidates(WebApplication $app): array
    {
        // Basic template: <app>/config/security.php (@app is the app root)
        $candidates = [$app->getBasePath() . '/config/security.php'];

        // Advanced template keeps shared config in @common, not in @app
        $common = \Yii::getAlias('@common', false);
        if (is_string($common) && $common !== '') {
            $candidates[] = $common . '/config/security.php';
        }

        return $candidates;
    }

    /**
     * getBodyParams() parses JSON and XML bodies and throws on malformed
     * input. The app may never read the body at all (a GET route), so that
     * exception must not become a request the security layer fails.
     */
    private static function bodyParams(Request $request): array
    {
        try {
            return $request->getBodyParams();
        } catch (\Throwable) {
            return $request->post();
        }
    }

    /**
     * getPathInfo() throws InvalidConfigException when the URL cannot be
     * resolved against the script/base URL, and apps with pretty URLs turned
     * off never call it at all. Same reasoning as bodyParams(): resolve it
     * best-effort, never fail the request over it.
     */
    private static function pathInfo(Request $request): string
    {
        try {
            return (string) $request->getPathInfo();
        } catch (\Throwable) {
            return '';
        }
    }
}
