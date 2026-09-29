<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Middleware\Yii3;

use Erikwang2013\Security\SecurityGuard;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\UploadedFileInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Yii3 is PSR-15/PSR-17 throughout: both factories below are already bound in
 * the container (config/web/di/psr17.php), so registering the class name is
 * enough to have it constructed.
 *
 *     // config/web/di/application.php — MiddlewareDispatcher::withMiddlewares()
 *     SecurityMiddleware::class,
 *
 * $configFile stays null for the bundled defaults; point it at the published
 * config to customize:
 *
 *     SecurityMiddleware::class => [
 *         '__construct()' => ['configFile' => dirname(__DIR__, 2) . '/config/security.php'],
 *     ],
 */
class SecurityMiddleware implements MiddlewareInterface
{
    private static bool $initialized = false;

    public function __construct(
        private ResponseFactoryInterface $responseFactory,
        private StreamFactoryInterface $streamFactory,
        private ?string $configFile = null,
    ) {}

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!self::$initialized) {
            self::$initialized = true;

            $configFile = $this->configFile ?? dirname(__DIR__, 2) . '/config/security.php';
            if (!is_file($configFile)) {
                throw new \RuntimeException('Security PHP: config file not found at ' . $configFile);
            }

            SecurityGuard::init(require $configFile);
        }

        $cookies = $request->getCookieParams();

        $files = [];
        foreach ($request->getUploadedFiles() as $key => $file) {
            if ($file instanceof UploadedFileInterface) {
                $files[$key] = [
                    'name'     => $file->getClientFilename() ?? '',
                    'tmp_name' => $file->getStream()->getMetadata('uri') ?? '',
                ];
            }
        }

        // Every source keeps its value in the scan even when the names collide.
        // getParsedBody() is null until a body parser ran — without
        // yiisoft/request-body-parser in the stack only form bodies are parsed.
        $data = SecurityGuard::mergeRequestSources([
            'cookie' => $cookies,
            'body'   => $request->getParsedBody() ?? [],
            'query'  => $request->getQueryParams(),
            'file'   => $files,
        ]);

        $meta = [
            'ip'              => $request->getServerParams()['remote_addr'] ?? '0.0.0.0',
            'method'          => $request->getMethod(),
            'uri'             => $request->getUri()->getPath(),
            'content_length'  => $request->getHeaderLine('Content-Length'),
            'content_type'    => $request->getHeaderLine('Content-Type'),
            'origin'          => $request->getHeaderLine('Origin'),
            'host'            => $request->getHeaderLine('Host'),
            'accept'          => $request->getHeaderLine('Accept'),
            'x_forwarded_for' => $request->getHeaderLine('X-Forwarded-For'),
            'transfer_encoding' => $request->getHeaderLine('Transfer-Encoding'),
            // Session identity comes from the request, not from $data: the
            // merge above puts cookies first, so a same-named query/body field
            // would otherwise shadow the real cookie.
            'cookies'         => $cookies,
            'user_agent'      => $request->getHeaderLine('User-Agent'),
            // Keep these names in sync with identity.session.headers
            'headers'         => [
                'authorization' => $request->getHeaderLine('Authorization'),
                'x-token'       => $request->getHeaderLine('X-Token'),
                'x-auth-token'  => $request->getHeaderLine('X-Auth-Token'),
            ],
        ];

        $threats = SecurityGuard::guard($data, $meta);

        $securityHeaders = SecurityGuard::securityHeaders();

        $block = SecurityGuard::blockDecision($threats);
        if ($block !== null) {
            [$contentType, $body] = SecurityGuard::blockResponse($threats, $meta);
            // PSR-7: withHeader() is immutable, so reassign on each iteration
            $response = $this->responseFactory
                ->createResponse($block['status'])
                ->withHeader('Content-Type', $contentType)
                ->withBody($this->streamFactory->createStream($body));
            foreach ($securityHeaders as $name => $value) {
                $response = $response->withHeader($name, $value);
            }
            return $response;
        }

        $response = $handler->handle($request);
        foreach ($securityHeaders as $name => $value) {
            $response = $response->withHeader($name, $value);
        }
        return $response;
    }
}
