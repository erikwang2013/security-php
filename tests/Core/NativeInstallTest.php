<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Tests\Core;

use PHPUnit\Framework\TestCase;

/**
 * The Composer-free path: copy src/ + config/, require src/helpers.php, done.
 * Also covers prepend.php, the auto_prepend_file entry for plain PHP apps.
 *
 * Everything here runs in a subprocess, because the Composer autoloader of
 * this test run would otherwise mask exactly the thing being tested.
 */
class NativeInstallTest extends TestCase
{
    private string $package;

    protected function setUp(): void
    {
        $this->package = dirname(__DIR__, 2);
        @unlink(sys_get_temp_dir() . '/security_storage.json');
    }

    protected function tearDown(): void
    {
        @unlink(sys_get_temp_dir() . '/security_storage.json');
    }

    /**
     * @param list<string> $args
     * @return array{0: string, 1: int}
     */
    private function runPhp(array $args): array
    {
        $proc = proc_open(
            array_merge([PHP_BINARY], $args),
            [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']],
            $pipes,
        );
        if (!is_resource($proc)) {
            $this->fail('could not start subprocess');
        }

        fclose($pipes[0]);
        $stdout = (string) stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exit = proc_close($proc);

        return [$stdout, $exit];
    }

    /**
     * No Composer: requiring helpers.php alone has to define the global
     * functions and autoload the library classes.
     */
    public function testHelpersFileAloneIsEnoughWithoutComposer(): void
    {
        $helpers = var_export($this->package . '/src/helpers.php', true);
        $code = <<<PHP
        require {$helpers};
        \$threats = security_scan(['q' => "1' OR '1'='1"]);
        \$types = array_map(static fn (\$t) => \$t->type, \$threats);
        echo in_array('sql_injection', \$types, true) ? 'DETECTED' : 'MISSED';
        echo '|' . (class_exists(Erikwang2013\\Security\\Detector\\XssDetector::class) ? 'AUTOLOADED' : 'NO-AUTOLOAD');
        PHP;

        // -n: no php.ini, i.e. not even the ini that this test run uses
        [$out, $exit] = $this->runPhp(['-n', '-r', $code]);

        $this->assertSame('DETECTED|AUTOLOADED', $out);
        $this->assertSame(0, $exit);
    }

    /**
     * prepend.php exists to be run by the web SAPI, not by cron or a queue
     * worker — under CLI it must do nothing at all.
     */
    public function testPrependDoesNothingUnderCli(): void
    {
        $prepend = var_export($this->package . '/prepend.php', true);

        $code = "require {$prepend}; echo function_exists('security_guard') ? 'LOADED' : 'NOOP';";
        [$out, $exit] = $this->runPhp(['-n', '-r', $code]);

        $this->assertSame('NOOP', $out, 'CLI 下 prepend.php 必须直接返回，连库都不该加载');
        $this->assertSame(0, $exit);
    }

    /**
     * The whole point of auto_prepend_file: an application that knows nothing
     * about security-php still gets its requests scanned.
     */
    public function testAutoPrependFileBlocksAnAttackForAnUnawareApp(): void
    {
        // A docroot, not the router form: `php -S host:port router.php` runs
        // the router without auto_prepend, which would test nothing.
        $docroot = sys_get_temp_dir() . '/sec_prepend_docroot_' . uniqid();
        mkdir($docroot, 0755, true);
        file_put_contents($docroot . '/index.php', "<?php echo 'APP-RAN';");

        $port = random_int(20000, 60000);
        $proc = proc_open(
            [
                PHP_BINARY, '-n',
                '-d', 'auto_prepend_file=' . $this->package . '/prepend.php',
                '-S', "127.0.0.1:{$port}", '-t', $docroot,
            ],
            [['pipe', 'r'], ['file', '/dev/null', 'w'], ['file', '/dev/null', 'w']],
            $pipes,
        );

        try {
            $this->assertIsResource($proc);
            $context = stream_context_create(['http' => ['timeout' => 2, 'ignore_errors' => true, 'header' => "Host: example.com\r\n"]]);

            $get = static function (string $query) use ($port, $context): string {
                for ($i = 0; $i < 20; $i++) {
                    $body = @file_get_contents("http://127.0.0.1:{$port}/index.php{$query}", false, $context);
                    if ($body !== false) {
                        return $body;
                    }
                    usleep(50000);
                }
                return '';
            };

            $safe = $get('?q=hello');
            $this->assertStringContainsString('APP-RAN', $safe, '正常请求必须照常执行');

            $blocked = $get('?q=' . urlencode('<script>alert(1)</script>'));

            $this->assertStringNotContainsString('APP-RAN', $blocked, '被拦截的请求不能执行应用代码');
            $this->assertStringContainsString('Request blocked by security policy', $blocked);
        } finally {
            if (is_resource($proc)) {
                proc_terminate($proc, 9);
                proc_close($proc);
            }
            @unlink($docroot . '/index.php');
            @rmdir($docroot);
        }
    }

    /**
     * A missing config/ must say what is wrong instead of leaking a path in an
     * uncatchable compile error.
     */
    public function testMissingConfigRaisesAClearError(): void
    {
        $copy = sys_get_temp_dir() . '/sec_noconfig_' . uniqid();
        mkdir($copy, 0755, true);
        // src/ only — no config/
        foreach (['helpers.php', 'SecurityGuard.php', 'DetectorChain.php', 'DetectorInterface.php', 'ThreatResult.php', 'Logger.php'] as $file) {
            copy($this->package . '/src/' . $file, $copy . '/' . $file);
        }

        try {
            $helpers = var_export($copy . '/helpers.php', true);
            [$out, $exit] = $this->runPhp(['-n', '-r', "require {$helpers}; try { security_scan(['a' => 'b']); } catch (Throwable \$e) { echo get_class(\$e) . ':' . \$e->getMessage(); }"]);

            $this->assertStringContainsString('RuntimeException', $out);
            $this->assertStringContainsString('config file not found', $out);
            $this->assertSame(0, $exit, '异常可捕获，不应是致命错误');
        } finally {
            foreach (glob($copy . '/*') ?: [] as $file) {
                @unlink($file);
            }
            @rmdir($copy);
        }
    }
}
