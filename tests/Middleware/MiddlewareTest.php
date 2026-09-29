<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 *
 * Framework adapters are tested with minimal local stubs — none of the
 * frameworks (nor psr/http-message) are installed as dev dependencies.
 * Every stub is guarded so a real framework class wins when present.
 */

namespace Erikwang2013\Security\Tests\Middleware {

    use Erikwang2013\Security\Middleware\Hyperf\SecurityMiddleware as HyperfMiddleware;
    use Erikwang2013\Security\Middleware\Laravel\SecurityMiddleware as LaravelMiddleware;
    use Erikwang2013\Security\Middleware\Thinkphp\SecurityMiddleware as ThinkphpMiddleware;
    use Erikwang2013\Security\Middleware\Webman\SecurityMiddleware as WebmanMiddleware;
    use Erikwang2013\Security\Middleware\Yii2\SecurityBootstrap as Yii2Bootstrap;
    use Erikwang2013\Security\Middleware\Yii3\SecurityMiddleware as Yii3Middleware;
    use Erikwang2013\Security\SecurityGuard;
    use PHPUnit\Framework\Attributes\RunInSeparateProcess;
    use PHPUnit\Framework\TestCase;

    class MiddlewareTest extends TestCase
    {
        protected function setUp(): void
        {
            SecurityGuard::reset();
            @unlink(sys_get_temp_dir() . '/security_storage.json');
        }

        protected function tearDown(): void
        {
            SecurityGuard::reset();
            @unlink(sys_get_temp_dir() . '/security_storage.json');
        }

        // ──────────────── Laravel ────────────────

        public function testLaravelMiddlewareBlocksAttack(): void
        {
            $request = new \Illuminate\Http\Request(
                input: ['comment' => '<script>alert(1)</script>'],
                server: ['REMOTE_ADDR' => '203.0.113.10'],
                method: 'POST',
            );
            $middleware = new LaravelMiddleware();

            $nextCalled = false;
            $response = $middleware->handle($request, function () use (&$nextCalled) {
                $nextCalled = true;
                return 'NEXT';
            });

            $this->assertFalse($nextCalled, 'Blocked request must not reach the next middleware');
            $this->assertSame(403, $response->getStatusCode());
            $this->assertSame('Request blocked by security policy', $response->getContent());
            // Security headers land on the block response as well
            $this->assertSame('nosniff', $response->getHeaders()['X-Content-Type-Options']);
        }

        public function testLaravelMiddlewarePassesSafeRequest(): void
        {
            $request = new \Illuminate\Http\Request(
                input: ['name' => 'John', 'email' => 'john@example.com'],
                server: ['REMOTE_ADDR' => '203.0.113.11'],
            );
            $middleware = new LaravelMiddleware();

            $response = $middleware->handle($request, fn () => new FakeResponse('', 200, []));

            $this->assertSame(200, $response->getStatusCode());
            // Headers are appended to pass-through responses too
            $this->assertSame('nosniff', $response->getHeaders()['X-Content-Type-Options']);
            $this->assertSame('SAMEORIGIN', $response->getHeaders()['X-Frame-Options']);
        }

        public function testLaravelMiddlewareBlocksPhpUpload(): void
        {
            $request = new \Illuminate\Http\Request(
                input: ['title' => 'safe'],
                files: ['avatar' => new \Illuminate\Http\UploadedFile('shell.php', '/tmp/phpXXX')],
                server: ['REMOTE_ADDR' => '203.0.113.12'],
            );
            $middleware = new LaravelMiddleware();

            $response = $middleware->handle($request, fn () => 'NEXT');

            $this->assertSame(403, $response->getStatusCode());
            $this->assertSame('Request blocked by security policy', $response->getContent());
        }

        // ──────────────── Webman ────────────────

        public function testWebmanMiddlewareBlocksAttack(): void
        {
            $request = new \Webman\Http\Request(
                post: ['comment' => '<script>alert(1)</script>'],
                realIp: '203.0.113.20',
                method: 'POST',
            );
            $middleware = new WebmanMiddleware();

            $nextCalled = false;
            $response = $middleware->process($request, function () use (&$nextCalled) {
                $nextCalled = true;
                return new \Webman\Http\Response(200, [], 'NEXT');
            });

            $this->assertFalse($nextCalled);
            $this->assertSame(403, $response->getStatusCode());
            $this->assertSame('Request blocked by security policy', $response->getBody());
        }

        public function testWebmanMiddlewarePassesSafeRequest(): void
        {
            $request = new \Webman\Http\Request(post: ['name' => 'John'], realIp: '203.0.113.21');
            $middleware = new WebmanMiddleware();

            $response = $middleware->process($request, fn () => new \Webman\Http\Response(200, [], 'NEXT'));

            $this->assertSame(200, $response->getStatusCode());
            $this->assertSame('NEXT', $response->getBody());
            $this->assertSame('nosniff', $response->getHeaders()['X-Content-Type-Options']);
        }

        public function testWebmanMiddlewareBlocksPhpUpload(): void
        {
            $request = new \Webman\Http\Request(
                post: ['title' => 'safe'],
                files: ['avatar' => new \Webman\Http\UploadFile('evil.php', '/tmp/phpXXX')],
                realIp: '203.0.113.22',
            );
            $middleware = new WebmanMiddleware();

            $response = $middleware->process($request, fn () => new \Webman\Http\Response(200, [], 'NEXT'));

            $this->assertSame(403, $response->getStatusCode());
        }

        // ──────────────── ThinkPHP ────────────────

        public function testThinkphpMiddlewareBlocksAttack(): void
        {
            $request = new \think\Request(
                param: ['comment' => '<script>alert(1)</script>'],
                ip: '203.0.113.30',
                method: 'POST',
            );
            $middleware = new ThinkphpMiddleware();

            $nextCalled = false;
            $response = $middleware->handle($request, function () use (&$nextCalled) {
                $nextCalled = true;
                return 'NEXT';
            });

            $this->assertFalse($nextCalled);
            $this->assertInstanceOf(\think\Response::class, $response);
            $this->assertSame(403, $response->getCode());
            $this->assertSame('Request blocked by security policy', $response->getContent());
        }

        public function testThinkphpMiddlewarePassesSafeRequest(): void
        {
            $request = new \think\Request(param: ['name' => 'John'], ip: '203.0.113.31');
            $middleware = new ThinkphpMiddleware();

            $response = $middleware->handle($request, fn () => new \think\Response('NEXT', '', 200));

            $this->assertSame('NEXT', $response->getContent());
            $this->assertSame('nosniff', $response->getHeaders()['X-Content-Type-Options']);
        }

        // ──────────────── Hyperf ────────────────

        public function testHyperfMiddlewareBlocksAttack(): void
        {
            $request = new PsrTestRequest(
                body: ['comment' => '<script>alert(1)</script>'],
                server: ['remote_addr' => '203.0.113.40'],
                method: 'POST',
            );
            $middleware = new HyperfMiddleware();

            $handler = new PsrTestHandler();
            $response = $middleware->process($request, $handler);

            $this->assertFalse($handler->called, 'Blocked request must not reach the handler');
            $this->assertSame(403, $response->getStatusCode());
            $this->assertSame('Request blocked by security policy', (string) $response->getBody());
        }

        public function testHyperfMiddlewarePassesSafeRequest(): void
        {
            $request = new PsrTestRequest(
                body: ['name' => 'John'],
                server: ['remote_addr' => '203.0.113.41'],
            );
            $middleware = new HyperfMiddleware();

            $handler = new PsrTestHandler();
            $response = $middleware->process($request, $handler);

            $this->assertTrue($handler->called);
            $this->assertSame(200, $response->getStatusCode());
            $this->assertSame('nosniff', $response->getHeaders()['X-Content-Type-Options']);
        }

        // ──────── Same-named fields across sources must all be scanned ────────
        // array_merge() kept one value per name and the dropped one never
        // reached a detector. Every framework prefers a different source, so
        // a shadowed payload was a hole in the whole regex detector family.

        public function testWebmanMiddlewareScansCookieShadowedByQuery(): void
        {
            $request = new \Webman\Http\Request(
                get: ['evil' => '1'],
                cookies: ['evil' => '<script>alert(1)</script>'],
                realIp: '203.0.113.23',
            );

            $response = (new WebmanMiddleware())->process($request, fn () => new \Webman\Http\Response(200, [], 'NEXT'));

            $this->assertSame(403, $response->getStatusCode(), 'Cookie payload shadowed by ?evil=1 must still be scanned');
        }

        public function testLaravelMiddlewareScansCookieShadowedByInput(): void
        {
            $request = new \Illuminate\Http\Request(
                input: ['evil' => '1'],
                cookies: ['evil' => '<script>alert(1)</script>'],
                server: ['REMOTE_ADDR' => '203.0.113.13'],
            );

            $response = (new LaravelMiddleware())->handle($request, fn () => new FakeResponse('', 200, []));

            $this->assertSame(403, $response->getStatusCode(), 'Cookie payload shadowed by a same-named body field must still be scanned');
        }

        public function testThinkphpMiddlewareScansCookieShadowedByParam(): void
        {
            $request = new \think\Request(
                param: ['evil' => '1'],
                cookies: ['evil' => '<script>alert(1)</script>'],
                ip: '203.0.113.32',
            );

            $response = (new ThinkphpMiddleware())->handle($request, fn () => new \think\Response('NEXT', '', 200));

            $this->assertSame(403, $response->getCode(), 'Cookie payload shadowed by a same-named param must still be scanned');
        }

        public function testHyperfMiddlewareScansBodyShadowedByQuery(): void
        {
            // Hyperf's own precedence puts query over body — the opposite of
            // $_REQUEST — and that is the value this adapter keeps bare.
            $request = new PsrTestRequest(
                body: ['evil' => '<script>alert(1)</script>'],
                query: ['evil' => '1'],
                server: ['remote_addr' => '203.0.113.42'],
            );

            $response = (new HyperfMiddleware())->process($request, new PsrTestHandler());

            $this->assertSame(403, $response->getStatusCode(), 'Body payload shadowed by ?evil=1 must still be scanned');
        }

        // ──────────────── Yii2 ────────────────
        // Yii2 has no middleware: the adapter is a bootstrap component on the
        // application's request events. The stub's end() mirrors the real one —
        // response sent, then the request stops (ExitException under YII_ENV_TEST).

        public function testYii2BootstrapBlocksAttack(): void
        {
            $app = $this->yii2App(query: ['comment' => '<script>alert(1)</script>'], ip: '203.0.113.50');

            $this->assertTrue($this->yii2Request($app), 'Blocked request must stop the application');

            $response = $app->getResponse();
            $this->assertSame(403, $response->getStatusCode());
            $this->assertSame('Request blocked by security policy', $response->content);
            $this->assertSame('raw', $response->format, 'FORMAT_RAW is what sends the block page verbatim');
            $this->assertSame('text/plain; charset=utf-8', $response->getHeaders()->get('Content-Type'));
            // Security headers land on the block response as well
            $this->assertSame('nosniff', $response->getHeaders()->get('X-Content-Type-Options'));
        }

        public function testYii2BootstrapPassesSafeRequest(): void
        {
            $app = $this->yii2App(query: ['name' => 'John'], ip: '203.0.113.51');

            $this->assertFalse($this->yii2Request($app));
            $this->assertSame('nosniff', $app->getResponse()->getHeaders()->get('X-Content-Type-Options'));
            $this->assertSame('SAMEORIGIN', $app->getResponse()->getHeaders()->get('X-Frame-Options'));
        }

        public function testYii2BootstrapBlocksPhpUpload(): void
        {
            $_FILES = ['avatar' => ['name' => 'shell.php', 'tmp_name' => '/tmp/phpXXX', 'size' => 1, 'error' => 0]];

            try {
                $app = $this->yii2App(query: ['title' => 'safe'], ip: '203.0.113.52');

                $this->assertTrue($this->yii2Request($app));
                $this->assertSame(403, $app->getResponse()->getStatusCode());
            } finally {
                // Never leak a fake upload into the next test
                $_FILES = [];
            }
        }

        public function testYii2BootstrapScansCookieShadowedByQuery(): void
        {
            $app = $this->yii2App(
                query: ['evil' => '1'],
                cookies: ['evil' => '<script>alert(1)</script>'],
                ip: '203.0.113.53',
            );

            $this->assertTrue($this->yii2Request($app), 'Cookie payload shadowed by ?evil=1 must still be scanned');
        }

        public function testYii2BootstrapSurvivesUnparsableBodyAndUrl(): void
        {
            // getBodyParams() throws on malformed JSON and getPathInfo() when
            // the URL cannot be resolved. Neither may turn a request the app
            // would have served into a 500 — the form body is still scanned.
            $app = new \yii\web\Application('/app', new \yii\web\Request(
                query: [],
                body: ['evil' => '<script>alert(1)</script>'],
                headers: [],
                remoteIp: '203.0.113.54',
                throws: true,
            ));
            (new Yii2Bootstrap())->bootstrap($app);

            $this->assertTrue($this->yii2Request($app));
        }

        /**
         * Advanced-template layout: @app has no config/security.php, so the
         * published one under @common must be the one that loads. Separate
         * process because the adapter's init flag is static per process.
         */
        #[RunInSeparateProcess]
        public function testYii2BootstrapLoadsConfigFromCommonAlias(): void
        {
            $common = sys_get_temp_dir() . '/sec_yii2_common_' . uniqid();
            @mkdir($common . '/config', 0755, true);
            file_put_contents($common . '/config/security.php', <<<'PHP'
                <?php return [
                    'enabled' => true,
                    'block_message' => 'CONFIG-FROM-COMMON',
                    'detectors' => ['xss' => ['enabled' => true, 'mode' => 'block']],
                ];
                PHP);
            \Yii::$aliases['@common'] = $common;

            try {
                $app = new \yii\web\Application('/not-an-app-root', new \yii\web\Request(
                    query: ['comment' => '<script>alert(1)</script>'],
                    remoteIp: '203.0.113.55',
                ));
                (new Yii2Bootstrap())->bootstrap($app);

                $this->assertTrue($this->yii2Request($app));
                $this->assertSame('CONFIG-FROM-COMMON', $app->getResponse()->content);
            } finally {
                \Yii::$aliases = [];
                @unlink($common . '/config/security.php');
                @rmdir($common . '/config');
                @rmdir($common);
            }
        }

        public function testYii2BootstrapSkipsConsoleApplication(): void
        {
            $app = new \yii\console\Application();

            (new Yii2Bootstrap())->bootstrap($app);

            $this->assertSame([], $app->triggered, 'Console requests have no request component and must not be hooked');
        }

        // ──────────────── Yii3 ────────────────

        public function testYii3MiddlewareBlocksAttack(): void
        {
            $request = new PsrTestRequest(
                body: ['comment' => '<script>alert(1)</script>'],
                server: ['remote_addr' => '203.0.113.60'],
                method: 'POST',
            );
            $middleware = $this->yii3Middleware();

            $handler = new PsrTestHandler();
            $response = $middleware->process($request, $handler);

            $this->assertFalse($handler->called, 'Blocked request must not reach the handler');
            $this->assertSame(403, $response->getStatusCode());
            $this->assertSame('Request blocked by security policy', (string) $response->getBody());
            $this->assertSame('nosniff', $response->getHeaders()['X-Content-Type-Options']);
        }

        public function testYii3MiddlewarePassesSafeRequest(): void
        {
            $request = new PsrTestRequest(
                body: ['name' => 'John'],
                server: ['remote_addr' => '203.0.113.61'],
            );

            $handler = new PsrTestHandler();
            $response = ($this->yii3Middleware())->process($request, $handler);

            $this->assertTrue($handler->called);
            $this->assertSame(200, $response->getStatusCode());
            $this->assertSame('nosniff', $response->getHeaders()['X-Content-Type-Options']);
        }

        public function testYii3MiddlewareBlocksPhpUpload(): void
        {
            $request = new PsrTestRequest(
                body: ['title' => 'safe'],
                files: ['avatar' => new PsrTestUpload('shell.php')],
                server: ['remote_addr' => '203.0.113.62'],
            );

            $response = ($this->yii3Middleware())->process($request, new PsrTestHandler());

            $this->assertSame(403, $response->getStatusCode());
        }

        public function testYii3MiddlewareScansCookieShadowedByQuery(): void
        {
            $request = new PsrTestRequest(
                query: ['evil' => '1'],
                cookies: ['evil' => '<script>alert(1)</script>'],
                server: ['remote_addr' => '203.0.113.63'],
            );

            $response = ($this->yii3Middleware())->process($request, new PsrTestHandler());

            $this->assertSame(403, $response->getStatusCode(), 'Cookie payload shadowed by ?evil=1 must still be scanned');
        }

        /** One stub satisfies both PSR-17 interfaces the container would inject */
        private function yii3Middleware(): Yii3Middleware
        {
            $factory = new Psr17TestFactory();

            return new Yii3Middleware($factory, $factory);
        }

        private function yii2App(array $query = [], array $cookies = [], string $ip = '0.0.0.0'): \yii\web\Application
        {
            $app = new \yii\web\Application('/app', new \yii\web\Request(
                query: $query,
                cookies: $cookies,
                remoteIp: $ip,
            ));
            (new Yii2Bootstrap())->bootstrap($app);

            return $app;
        }

        /**
         * Drives Yii2's request events like Application::run() does.
         *
         * @return bool true when the adapter stopped the application
         */
        private function yii2Request(\yii\web\Application $app): bool
        {
            try {
                $app->trigger(\yii\base\Application::EVENT_BEFORE_REQUEST);
            } catch (\yii\base\ExitException) {
                return true;
            }

            $app->trigger(\yii\base\Application::EVENT_AFTER_REQUEST);

            return false;
        }
    }

    /**
     * Minimal stand-in for Symfony\Component\HttpFoundation\HeaderBag
     */
    class HeaderBag
    {
        public function __construct(private array $headers = []) {}

        public function set(string $name, string $value): void
        {
            $this->headers[$name] = $value;
        }

        public function all(): array { return $this->headers; }
    }

    class FakeResponse
    {
        public HeaderBag $headers;

        public function __construct(
            private string $content = '',
            private int $statusCode = 200,
            array $headers = [],
        ) {
            $this->headers = new HeaderBag($headers);
        }

        public function getContent(): string
        {
            return $this->content;
        }

        public function getStatusCode(): int
        {
            return $this->statusCode;
        }

        public function getHeaders(): array
        {
            return $this->headers->all();
        }
    }
}

// ──────────────── Laravel stubs ────────────────

namespace Illuminate\Http {
    if (!class_exists(Request::class)) {
        class Request
        {
            public function __construct(
                private array $input = [],
                private array $cookies = [],
                private array $files = [],
                private array $server = [],
                private array $headers = [],
                private string $method = 'GET',
                private string $path = '/',
            ) {}

            public function cookie(): array { return $this->cookies; }
            public function all(): array { return $this->input; }
            public function allFiles(): array { return $this->files; }
            public function server(string $key, ?string $default = null): ?string { return $this->server[$key] ?? $default; }
            public function method(): string { return $this->method; }
            public function path(): string { return $this->path; }
            public function header(string $key, ?string $default = null): ?string
            {
                foreach ($this->headers as $k => $v) {
                    if (strcasecmp((string) $k, $key) === 0) {
                        return $v;
                    }
                }
                return $default;
            }
        }
    }

    if (!class_exists(UploadedFile::class)) {
        class UploadedFile
        {
            public function __construct(
                private string $clientName,
                private string $pathname,
            ) {}

            public function getClientOriginalName(): string { return $this->clientName; }
            public function getPathname(): string { return $this->pathname; }
        }
    }
}

// ──────────────── Webman stubs ────────────────

namespace Webman {
    if (!interface_exists(MiddlewareInterface::class)) {
        interface MiddlewareInterface
        {
            public function process(\Webman\Http\Request $request, callable $next): \Webman\Http\Response;
        }
    }
}

namespace Webman\Http {
    if (!class_exists(Request::class)) {
        class Request
        {
            public function __construct(
                private array $get = [],
                private array $post = [],
                private array $cookies = [],
                private array $files = [],
                private array $headers = [],
                private string $realIp = '0.0.0.0',
                private string $method = 'GET',
                private string $path = '/',
            ) {}

            public function cookie(): array { return $this->cookies; }
            public function get(): array { return $this->get; }
            public function post(): array { return $this->post; }
            public function file(): array { return $this->files; }
            public function getRealIp(): string { return $this->realIp; }
            public function method(): string { return $this->method; }
            public function path(): string { return $this->path; }
            public function header(string $key): ?string
            {
                foreach ($this->headers as $k => $v) {
                    if (strcasecmp((string) $k, $key) === 0) {
                        return $v;
                    }
                }
                return null;
            }
        }
    }

    if (!class_exists(Response::class)) {
        class Response
        {
            public function __construct(
                private int $status = 200,
                private array $headers = [],
                private string $body = '',
            ) {}

            public function withHeader(string $name, string $value): self
            {
                $this->headers[$name] = $value;
                return $this;
            }

            public function getStatusCode(): int { return $this->status; }
            public function getHeaders(): array { return $this->headers; }
            public function getBody(): string { return $this->body; }
        }
    }

    if (!class_exists(UploadFile::class)) {
        class UploadFile
        {
            public function __construct(
                private string $uploadName,
                private string $uploadTmpPath,
            ) {}

            public function getUploadName(): string { return $this->uploadName; }
            public function getUploadTmpPath(): string { return $this->uploadTmpPath; }
        }
    }
}

// ──────────────── ThinkPHP stubs ────────────────

namespace think {
    if (!class_exists(Request::class)) {
        class Request
        {
            public function __construct(
                private array $param = [],
                private array $cookies = [],
                private array $files = [],
                private array $headers = [],
                private string $ip = '0.0.0.0',
                private string $method = 'GET',
                private string $pathinfo = '/',
            ) {}

            public function cookie(): array { return $this->cookies; }
            public function param(): array { return $this->param; }
            public function file(): array { return $this->files; }
            public function ip(): string { return $this->ip; }
            public function method(): string { return $this->method; }
            public function pathinfo(): string { return $this->pathinfo; }
            public function header(string $key, ?string $default = null): ?string
            {
                foreach ($this->headers as $k => $v) {
                    if (strcasecmp((string) $k, $key) === 0) {
                        return $v;
                    }
                }
                return $default;
            }
        }
    }

    if (!class_exists(Response::class)) {
        class Response
        {
            public function __construct(
                private string $content = '',
                private string $type = '',
                private int $code = 200,
                private array $headers = [],
            ) {}

            public static function create(string $data = '', string $type = '', int $code = 200): self
            {
                return new self($data, $type, $code);
            }

            /**
             * $filterValue false disables htmlspecialchars so a CSP value with
             * single quotes is not escaped
             */
            public function header(array $header = [], bool $filterValue = true): self
            {
                $this->headers = array_merge($this->headers, $header);
                return $this;
            }

            public function getContent(): string { return $this->content; }
            public function getType(): string { return $this->type; }
            public function getCode(): int { return $this->code; }
            public function getHeaders(): array { return $this->headers; }
        }
    }

    if (!class_exists(File::class)) {
        class File
        {
            public function __construct(
                private string $originalName,
                private string $pathname,
            ) {}

            public function getOriginalName(): string { return $this->originalName; }
            public function getPathname(): string { return $this->pathname; }
        }
    }
}

// ──────────────── Yii2 stubs ────────────────

namespace yii\base {
    if (!interface_exists(BootstrapInterface::class)) {
        interface BootstrapInterface
        {
            public function bootstrap($app);
        }
    }

    if (!class_exists(InvalidConfigException::class)) {
        class InvalidConfigException extends \Exception {}
    }

    if (!class_exists(ExitException::class)) {
        /** The exit status rides in a property, not in the message */
        class ExitException extends \Exception
        {
            public function __construct(public int $statusCode = 0)
            {
                parent::__construct('Application ended with status ' . $statusCode);
            }
        }
    }

    if (!class_exists(Application::class)) {
        class Application
        {
            public const EVENT_BEFORE_REQUEST = 'beforeRequest';
            public const EVENT_AFTER_REQUEST  = 'afterRequest';

            /** @var string[] fired event names, in order */
            public array $triggered = [];
            public bool $ended = false;

            private array $handlers = [];
            private ?\yii\web\Response $response = null;

            public function on(string $name, callable $handler): void
            {
                $this->handlers[$name][] = $handler;
            }

            public function trigger(string $name): void
            {
                $this->triggered[] = $name;
                foreach ($this->handlers[$name] ?? [] as $handler) {
                    $handler();
                }
            }

            public function getResponse(): \yii\web\Response
            {
                return $this->response ??= new \yii\web\Response();
            }

            /**
             * Mirrors Application::end(): the response is sent and the request
             * stops — exit() in production, ExitException under YII_ENV_TEST.
             * EVENT_AFTER_REQUEST fires first unless it already has.
             */
            public function end(int $status = 0): void
            {
                $this->ended = true;
                if (!in_array(self::EVENT_AFTER_REQUEST, $this->triggered, true)) {
                    $this->trigger(self::EVENT_AFTER_REQUEST);
                }
                throw new ExitException($status);
            }
        }
    }
}

namespace yii\console {
    if (!class_exists(Application::class)) {
        class Application extends \yii\base\Application {}
    }
}

namespace yii\web {
    if (!class_exists(Application::class)) {
        class Application extends \yii\base\Application
        {
            public function __construct(
                private string $basePath = '/app',
                private ?Request $request = null,
            ) {}

            public function getBasePath(): string { return $this->basePath; }
            public function getRequest(): Request { return $this->request ??= new Request(); }
        }
    }

    if (!class_exists(Request::class)) {
        class Request
        {
            public function __construct(
                private array $query = [],
                private array $body = [],
                private array $cookies = [],
                private array $headers = [],
                private string $remoteIp = '0.0.0.0',
                private string $method = 'GET',
                private string $pathInfo = '/',
                private bool $throws = false,
            ) {}

            public function get(): array { return $this->query; }
            public function post(): array { return $this->body; }

            /** $throws = true stands in for malformed JSON / an unresolvable URL */
            public function getBodyParams(): array
            {
                if ($this->throws) {
                    throw new \InvalidArgumentException('Invalid JSON data in request body');
                }
                return $this->body;
            }

            public function getPathInfo(): string
            {
                if ($this->throws) {
                    throw new InvalidConfigException('Unable to determine the path info of the current request.');
                }
                return $this->pathInfo;
            }

            public function getCookies(): CookieCollection { return new CookieCollection($this->cookies); }
            public function getHeaders(): HeaderCollection { return new HeaderCollection($this->headers); }
            public function getRemoteIP(): string { return $this->remoteIp; }
            public function getMethod(): string { return $this->method; }
        }
    }

    if (!class_exists(Response::class)) {
        class Response
        {
            public const FORMAT_RAW = 'raw';

            public ?string $content = null;
            public string $format = 'html';

            private int $statusCode = 200;
            private ?HeaderCollection $headers = null;

            public function setStatusCode(int $value): self
            {
                $this->statusCode = $value;
                return $this;
            }

            public function getStatusCode(): int { return $this->statusCode; }
            public function getHeaders(): HeaderCollection { return $this->headers ??= new HeaderCollection(); }
        }
    }

    if (!class_exists(HeaderCollection::class)) {
        class HeaderCollection
        {
            public function __construct(private array $headers = []) {}

            public function set(string $name, string $value = ''): void
            {
                $this->headers[$name] = $value;
            }

            public function get(string $name, ?string $default = null): ?string
            {
                foreach ($this->headers as $key => $value) {
                    if (strcasecmp((string) $key, $name) === 0) {
                        return (string) $value;
                    }
                }
                return $default;
            }
        }
    }

    if (!class_exists(CookieCollection::class)) {
        class CookieCollection
        {
            public function __construct(private array $cookies = []) {}

            public function toArray(): array { return $this->cookies; }
        }
    }
}

// ──────────────── PSR-7 / PSR-15 / PSR-17 stubs (Hyperf + Yii3) ────────────────

namespace Psr\Http\Message {
    if (!interface_exists(UriInterface::class)) {
        interface UriInterface
        {
            public function getPath(): string;
        }
    }

    if (!interface_exists(ServerRequestInterface::class)) {
        interface ServerRequestInterface
        {
            public function getCookieParams(): array;
            public function getParsedBody();
            public function getQueryParams(): array;
            public function getUploadedFiles(): array;
            public function getServerParams(): array;
            public function getMethod(): string;
            public function getUri(): UriInterface;
            public function getHeaderLine(string $name): string;
        }
    }

    if (!interface_exists(ResponseInterface::class)) {
        interface ResponseInterface
        {
            public function withStatus(int $code, string $reasonPhrase = ''): ResponseInterface;
            public function withHeader(string $name, string $value): ResponseInterface;
            public function withBody($body): ResponseInterface;
        }
    }

    if (!interface_exists(StreamInterface::class)) {
        interface StreamInterface
        {
            public function __toString(): string;
            public function getMetadata(string $key = ''): mixed;
        }
    }

    if (!interface_exists(UploadedFileInterface::class)) {
        interface UploadedFileInterface
        {
            public function getClientFilename(): ?string;
            public function getStream(): StreamInterface;
        }
    }

    if (!interface_exists(ResponseFactoryInterface::class)) {
        interface ResponseFactoryInterface
        {
            public function createResponse(int $code = 200, string $reasonPhrase = ''): ResponseInterface;
        }
    }

    if (!interface_exists(StreamFactoryInterface::class)) {
        interface StreamFactoryInterface
        {
            public function createStream(string $content = ''): StreamInterface;
        }
    }
}

namespace Psr\Http\Server {
    if (!interface_exists(RequestHandlerInterface::class)) {
        interface RequestHandlerInterface
        {
            public function handle(\Psr\Http\Message\ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface;
        }
    }

    if (!interface_exists(MiddlewareInterface::class)) {
        interface MiddlewareInterface
        {
            public function process(
                \Psr\Http\Message\ServerRequestInterface $request,
                RequestHandlerInterface $handler,
            ): \Psr\Http\Message\ResponseInterface;
        }
    }
}

namespace Hyperf\HttpMessage\Upload {
    if (!class_exists(UploadedFile::class)) {
        class UploadedFile
        {
            public function __construct(private string $clientFilename) {}

            public function getClientFilename(): string { return $this->clientFilename; }

            public function getStream(): object
            {
                return new class {
                    public function getMetadata(string $key): ?string
                    {
                        return $key === 'uri' ? '/tmp/hyperf_upload' : null;
                    }
                };
            }
        }
    }
}

namespace Hyperf\HttpMessage\Stream {
    if (!class_exists(SwooleStream::class)) {
        class SwooleStream
        {
            public function __construct(private string $content) {}

            public function __toString(): string
            {
                return $this->content;
            }
        }
    }
}

namespace Hyperf\HttpMessage\Server {
    if (!class_exists(Response::class)) {
        class Response implements \Psr\Http\Message\ResponseInterface
        {
            private int $status = 200;
            private array $headers = [];
            private $body = '';

            public function withStatus(int $code, string $reasonPhrase = ''): \Psr\Http\Message\ResponseInterface
            {
                $this->status = $code;
                return $this;
            }

            public function withHeader(string $name, string $value): \Psr\Http\Message\ResponseInterface
            {
                $this->headers[$name] = $value;
                return $this;
            }

            public function withBody($body): \Psr\Http\Message\ResponseInterface
            {
                $this->body = $body;
                return $this;
            }

            public function getStatusCode(): int { return $this->status; }
            public function getHeaders(): array { return $this->headers; }
            public function getBody() { return $this->body; }
        }
    }
}

namespace {
    if (!defined('BASE_PATH')) {
        define('BASE_PATH', sys_get_temp_dir() . '/sec_mw_hyperf');
    }

    if (!class_exists(Yii::class)) {
        /**
         * Only the alias lookup the Yii2 adapter needs (@common in the
         * advanced template); @app comes from Application::getBasePath().
         */
        class Yii
        {
            public static array $aliases = [];

            public static function getAlias(string $alias, bool $throwException = true): string|false
            {
                if (isset(self::$aliases[$alias])) {
                    return self::$aliases[$alias];
                }
                if ($throwException) {
                    throw new \Exception("Invalid alias: {$alias}");
                }
                return false;
            }
        }
    }

    if (!function_exists('response')) {
        /**
         * Minimal stand-in for Laravel's response() helper.
         */
        function response(string $content = '', int $status = 200, array $headers = []): \Erikwang2013\Security\Tests\Middleware\FakeResponse
        {
            return new \Erikwang2013\Security\Tests\Middleware\FakeResponse($content, $status, $headers);
        }
    }

    if (!function_exists('config_path')) {
        function config_path(): string
        {
            return sys_get_temp_dir() . '/sec_mw_webman_config';
        }
    }

    if (!function_exists('app')) {
        /**
         * Minimal stand-in for ThinkPHP's app() helper.
         */
        function app(): object
        {
            return new class {
                public function getRootPath(): string
                {
                    return sys_get_temp_dir() . '/sec_mw_thinkphp/';
                }
            };
        }
    }
}

namespace Erikwang2013\Security\Tests\Middleware {
    if (!class_exists(PsrTestRequest::class)) {
        class PsrTestRequest implements \Psr\Http\Message\ServerRequestInterface
        {
            public function __construct(
                private array $body = [],
                private array $query = [],
                private array $cookies = [],
                private array $files = [],
                private array $server = [],
                private array $headers = [],
                private string $method = 'GET',
                private string $path = '/',
            ) {}

            public function getCookieParams(): array { return $this->cookies; }
            public function getParsedBody() { return $this->body; }
            public function getQueryParams(): array { return $this->query; }
            public function getUploadedFiles(): array { return $this->files; }
            public function getServerParams(): array { return $this->server; }
            public function getMethod(): string { return $this->method; }
            public function getUri(): \Psr\Http\Message\UriInterface
            {
                return new class($this->path) implements \Psr\Http\Message\UriInterface {
                    public function __construct(private string $path) {}
                    public function getPath(): string { return $this->path; }
                };
            }
            public function getHeaderLine(string $name): string
            {
                foreach ($this->headers as $k => $v) {
                    if (strcasecmp((string) $k, $name) === 0) {
                        return (string) $v;
                    }
                }
                return '';
            }
        }
    }

    if (!class_exists(PsrTestHandler::class)) {
        class PsrTestHandler implements \Psr\Http\Server\RequestHandlerInterface
        {
            public bool $called = false;

            public function handle(\Psr\Http\Message\ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface
            {
                $this->called = true;
                return new \Hyperf\HttpMessage\Server\Response();
            }
        }
    }

    if (!class_exists(Psr17TestFactory::class)) {
        /**
         * The PSR-17 pair Yii3 binds in its container. The response it hands
         * out is the plain PSR-7 stub from the Hyperf block — same interface,
         * reused instead of duplicated.
         */
        class Psr17TestFactory implements \Psr\Http\Message\ResponseFactoryInterface, \Psr\Http\Message\StreamFactoryInterface
        {
            public function createResponse(int $code = 200, string $reasonPhrase = ''): \Psr\Http\Message\ResponseInterface
            {
                return (new \Hyperf\HttpMessage\Server\Response())->withStatus($code);
            }

            public function createStream(string $content = ''): \Psr\Http\Message\StreamInterface
            {
                return new Psr17TestStream($content);
            }
        }
    }

    if (!class_exists(Psr17TestStream::class)) {
        class Psr17TestStream implements \Psr\Http\Message\StreamInterface
        {
            public function __construct(
                private string $content = '',
                private string $uri = '/tmp/psr7_upload',
            ) {}

            public function __toString(): string { return $this->content; }

            public function getMetadata(string $key = ''): mixed
            {
                return $key === 'uri' ? $this->uri : null;
            }
        }
    }

    if (!class_exists(PsrTestUpload::class)) {
        class PsrTestUpload implements \Psr\Http\Message\UploadedFileInterface
        {
            public function __construct(private string $clientFilename) {}

            public function getClientFilename(): ?string { return $this->clientFilename; }

            public function getStream(): \Psr\Http\Message\StreamInterface
            {
                return new Psr17TestStream();
            }
        }
    }
}
