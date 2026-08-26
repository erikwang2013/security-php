<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 *
 * Framework adapters are tested with minimal local stubs — none of the four
 * frameworks (nor psr/http-message) are installed as dev dependencies.
 * Every stub is guarded so a real framework class wins when present.
 */

namespace Erikwang2013\Security\Tests\Middleware {

    use Erikwang2013\Security\Middleware\Hyperf\SecurityMiddleware as HyperfMiddleware;
    use Erikwang2013\Security\Middleware\Laravel\SecurityMiddleware as LaravelMiddleware;
    use Erikwang2013\Security\Middleware\Thinkphp\SecurityMiddleware as ThinkphpMiddleware;
    use Erikwang2013\Security\Middleware\Webman\SecurityMiddleware as WebmanMiddleware;
    use Erikwang2013\Security\SecurityGuard;
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
        }

        public function testLaravelMiddlewarePassesSafeRequest(): void
        {
            $request = new \Illuminate\Http\Request(
                input: ['name' => 'John', 'email' => 'john@example.com'],
                server: ['REMOTE_ADDR' => '203.0.113.11'],
            );
            $middleware = new LaravelMiddleware();

            $response = $middleware->handle($request, fn () => 'NEXT');

            $this->assertSame('NEXT', $response);
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

            $response = $middleware->handle($request, fn () => 'NEXT');

            $this->assertSame('NEXT', $response);
        }

        // ──────────────── Hyperf ────────────────

        public function testHyperfMiddlewareBlocksAttack(): void
        {
            $request = new \HyperfTestRequest(
                body: ['comment' => '<script>alert(1)</script>'],
                server: ['remote_addr' => '203.0.113.40'],
                method: 'POST',
            );
            $middleware = new HyperfMiddleware();

            $handler = new \HyperfTestHandler();
            $response = $middleware->process($request, $handler);

            $this->assertFalse($handler->called, 'Blocked request must not reach the handler');
            $this->assertSame(403, $response->getStatusCode());
            $this->assertSame('Request blocked by security policy', (string) $response->getBody());
        }

        public function testHyperfMiddlewarePassesSafeRequest(): void
        {
            $request = new \HyperfTestRequest(
                body: ['name' => 'John'],
                server: ['remote_addr' => '203.0.113.41'],
            );
            $middleware = new HyperfMiddleware();

            $handler = new \HyperfTestHandler();
            $response = $middleware->process($request, $handler);

            $this->assertTrue($handler->called);
            $this->assertSame(200, $response->getStatusCode());
        }
    }

    class FakeResponse
    {
        public function __construct(
            private string $content = '',
            private int $statusCode = 200,
            private array $headers = [],
        ) {}

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
            return $this->headers;
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
            ) {}

            public static function create(string $data = '', string $type = '', int $code = 200): self
            {
                return new self($data, $type, $code);
            }

            public function getContent(): string { return $this->content; }
            public function getType(): string { return $this->type; }
            public function getCode(): int { return $this->code; }
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

// ──────────────── Hyperf / PSR-7 stubs ────────────────

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
    if (!class_exists(HyperfTestRequest::class)) {
        class HyperfTestRequest implements \Psr\Http\Message\ServerRequestInterface
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

    if (!class_exists(HyperfTestHandler::class)) {
        class HyperfTestHandler implements \Psr\Http\Server\RequestHandlerInterface
        {
            public bool $called = false;

            public function handle(\Psr\Http\Message\ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface
            {
                $this->called = true;
                return new \Hyperf\HttpMessage\Server\Response();
            }
        }
    }
}
