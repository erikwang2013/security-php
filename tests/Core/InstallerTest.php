<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 *
 * Composer classes are not installed (composer/composer is not a dependency),
 * so this file ships minimal stubs for the interfaces/classes the plugin
 * touches. All stubs are guarded so real Composer classes win when present.
 */

namespace Erikwang2013\Security\Tests\Core {

    use Erikwang2013\Security\Composer\Installer;
    use PHPUnit\Framework\TestCase;

    class InstallerTest extends TestCase
    {
        private string $root;
        private string $sourceConfig;

        protected function setUp(): void
        {
            $this->root = sys_get_temp_dir() . '/sec_installer_' . uniqid();
            @mkdir($this->root, 0755, true);
            $this->sourceConfig = dirname(__DIR__, 2) . '/config/security.php';
        }

        protected function tearDown(): void
        {
            $this->rmDir($this->root);
        }

        public function testGetSubscribedEventsRegistersInstallAndUpdate(): void
        {
            $events = Installer::getSubscribedEvents();

            $this->assertSame('onPackageInstall', $events['post-package-install']);
            $this->assertSame('onPackageUpdate', $events['post-package-update']);
        }

        public function testActivatePublishesConfigForLaravelProject(): void
        {
            @mkdir($this->root . '/bootstrap', 0755, true);
            file_put_contents($this->root . '/artisan', '<?php');
            file_put_contents($this->root . '/bootstrap/app.php', '<?php');

            $io = new \Composer\IO\BufferIO();
            $composer = new \Composer\Composer($this->root . '/vendor');
            $installer = new Installer();
            $installer->activate($composer, $io);

            $target = $this->root . '/config/security.php';
            $this->assertFileExists($target, 'Laravel target must be published');
            $this->assertSame(file_get_contents($this->sourceConfig), file_get_contents($target));
            $this->assertNotEmpty($io->messages, 'Publish confirmation must be written to IO');
            $this->assertStringContainsString('Config published', $io->messages[0]);
            $this->assertSame($installer, $composer->getEventDispatcher()->getSubscriber(),
                'Plugin must register itself as event subscriber');
        }

        public function testActivatePublishesToAllDetectedFrameworks(): void
        {
            // Webman
            file_put_contents($this->root . '/start.php', '<?php');
            // ThinkPHP
            file_put_contents($this->root . '/think', '<?php');
            @mkdir($this->root . '/app', 0755, true);
            // Hyperf
            @mkdir($this->root . '/bin', 0755, true);
            file_put_contents($this->root . '/bin/hyperf.php', '<?php');
            @mkdir($this->root . '/config/autoload', 0755, true);

            (new Installer())->activate(new \Composer\Composer($this->root . '/vendor'), new \Composer\IO\BufferIO());

            $this->assertFileExists($this->root . '/config/security.php', 'Laravel/ThinkPHP target');
            $this->assertFileExists($this->root . '/config/plugin/erikwang2013/security-php/app.php', 'Webman target');
            $this->assertFileExists($this->root . '/config/autoload/security.php', 'Hyperf target');
        }

        public function testActivateDoesNotPublishForUnknownProject(): void
        {
            (new Installer())->activate(new \Composer\Composer($this->root . '/vendor'), new \Composer\IO\BufferIO());

            $this->assertSame([], glob($this->root . '/config/**/*.php') ?: []);
            $this->assertFileDoesNotExist($this->root . '/config/security.php');
        }

        public function testActivateDoesNotOverwriteExistingConfig(): void
        {
            @mkdir($this->root . '/bootstrap', 0755, true);
            file_put_contents($this->root . '/artisan', '<?php');
            file_put_contents($this->root . '/bootstrap/app.php', '<?php');
            @mkdir($this->root . '/config', 0755, true);
            file_put_contents($this->root . '/config/security.php', 'CUSTOM CONFIG');

            (new Installer())->activate(new \Composer\Composer($this->root . '/vendor'), new \Composer\IO\BufferIO());

            $this->assertSame('CUSTOM CONFIG', file_get_contents($this->root . '/config/security.php'));
        }

        public function testOnPackageInstallPublishesOnlyForOwnPackage(): void
        {
            $composer = new \Composer\Composer($this->root . '/vendor');

            // activate() first, exactly like Composer does before firing events
            // (src note: onPackageInstall reads $this->io, which is only set by activate()).
            $io = new \Composer\IO\BufferIO();
            $installer = new Installer();
            $installer->activate($composer, $io);

            // Different package → no publish
            $event = new \Composer\Installer\PackageEvent(
                new \Composer\Installer\InstallOperation(new \Composer\Installer\Package('other/vendor')),
                $composer,
            );
            $installer->onPackageInstall($event);
            $this->assertFileDoesNotExist($this->root . '/config/security.php');

            // Own package → publish
            @mkdir($this->root . '/bootstrap', 0755, true);
            file_put_contents($this->root . '/artisan', '<?php');
            file_put_contents($this->root . '/bootstrap/app.php', '<?php');
            $event = new \Composer\Installer\PackageEvent(
                new \Composer\Installer\InstallOperation(new \Composer\Installer\Package('erikwang2013/security-php')),
                $composer,
            );
            $installer->onPackageInstall($event);
            $this->assertFileExists($this->root . '/config/security.php');
        }

        public function testOnPackageUpdateUsesTargetPackage(): void
        {
            @mkdir($this->root . '/bootstrap', 0755, true);
            file_put_contents($this->root . '/artisan', '<?php');
            file_put_contents($this->root . '/bootstrap/app.php', '<?php');

            $composer = new \Composer\Composer($this->root . '/vendor');
            $io = new \Composer\IO\BufferIO();
            $installer = new Installer();
            $installer->activate($composer, $io);

            $event = new \Composer\Installer\PackageEvent(
                new \Composer\Installer\UpdateOperation(new \Composer\Installer\Package('erikwang2013/security-php')),
                $composer,
            );
            $installer->onPackageUpdate($event);

            $this->assertFileExists($this->root . '/config/security.php');
        }

        public function testFrameworkDetectorFunctions(): void
        {
            $this->assertFalse(\Erikwang2013\Security\Composer\isLaravel($this->root));
            $this->assertFalse(\Erikwang2013\Security\Composer\isWebman($this->root));
            $this->assertFalse(\Erikwang2013\Security\Composer\isThinkPHP($this->root));
            $this->assertFalse(\Erikwang2013\Security\Composer\isHyperf($this->root));

            file_put_contents($this->root . '/artisan', '<?php');
            $this->assertFalse(\Erikwang2013\Security\Composer\isLaravel($this->root), 'artisan alone is not enough');

            @mkdir($this->root . '/bootstrap', 0755, true);
            file_put_contents($this->root . '/bootstrap/app.php', '<?php');
            $this->assertTrue(\Erikwang2013\Security\Composer\isLaravel($this->root));

            file_put_contents($this->root . '/start.php', '<?php');
            $this->assertTrue(\Erikwang2013\Security\Composer\isWebman($this->root));

            file_put_contents($this->root . '/think', '<?php');
            $this->assertFalse(\Erikwang2013\Security\Composer\isThinkPHP($this->root), 'think alone is not enough');
            @mkdir($this->root . '/app', 0755, true);
            $this->assertTrue(\Erikwang2013\Security\Composer\isThinkPHP($this->root));

            @mkdir($this->root . '/bin', 0755, true);
            file_put_contents($this->root . '/bin/hyperf.php', '<?php');
            $this->assertFalse(\Erikwang2013\Security\Composer\isHyperf($this->root), 'hyperf.php alone is not enough');
            @mkdir($this->root . '/config/autoload', 0755, true);
            $this->assertTrue(\Erikwang2013\Security\Composer\isHyperf($this->root));
        }

        private function rmDir(string $dir): void
        {
            if (!is_dir($dir)) {
                return;
            }
            $it = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::CHILD_FIRST,
            );
            foreach ($it as $file) {
                $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
            }
            @rmdir($dir);
        }
    }
}

// ──────────────── Composer class stubs (guarded) ────────────────

namespace Composer {
    if (!class_exists(Composer::class)) {
        class Composer
        {
            private EventDispatcher $dispatcher;

            public function __construct(private string $vendorDir = '/tmp/vendor')
            {
                $this->dispatcher = new EventDispatcher();
            }

            public function getEventDispatcher(): EventDispatcher
            {
                return $this->dispatcher;
            }

            public function getConfig(): Config
            {
                return new Config($this->vendorDir);
            }
        }
    }

    if (!class_exists(Config::class)) {
        class Config
        {
            public function __construct(private string $vendorDir) {}

            public function get(string $key): string
            {
                return $this->vendorDir;
            }
        }
    }

    if (!class_exists(EventDispatcher::class)) {
        class EventDispatcher
        {
            private ?object $subscriber = null;

            public function addSubscriber(object $subscriber): void
            {
                $this->subscriber = $subscriber;
            }

            public function getSubscriber(): ?object
            {
                return $this->subscriber;
            }
        }
    }
}

namespace Composer\IO {
    if (!interface_exists(IOInterface::class)) {
        interface IOInterface
        {
            public function write(string $message): void;
        }
    }

    if (!class_exists(BufferIO::class)) {
        class BufferIO implements IOInterface
        {
            public array $messages = [];

            public function write(string $message): void
            {
                $this->messages[] = $message;
            }
        }
    }
}

namespace Composer\Plugin {
    if (!interface_exists(PluginInterface::class)) {
        interface PluginInterface
        {
            public function activate(\Composer\Composer $composer, \Composer\IO\IOInterface $io): void;

            public function deactivate(\Composer\Composer $composer, \Composer\IO\IOInterface $io): void;

            public function uninstall(\Composer\Composer $composer, \Composer\IO\IOInterface $io): void;
        }
    }
}

namespace Composer\EventDispatcher {
    if (!interface_exists(EventSubscriberInterface::class)) {
        interface EventSubscriberInterface
        {
            public static function getSubscribedEvents(): array;
        }
    }

    if (!class_exists(PackageEvent::class)) {
        class PackageEvent
        {
            public function __construct(
                private object $operation,
                private \Composer\Composer $composer,
            ) {}

            public function getOperation(): object
            {
                return $this->operation;
            }

            public function getComposer(): \Composer\Composer
            {
                return $this->composer;
            }
        }
    }
}

namespace Composer\Installer {
    if (!class_exists(PackageEvents::class)) {
        class PackageEvents
        {
            public const POST_PACKAGE_INSTALL = 'post-package-install';
            public const POST_PACKAGE_UPDATE = 'post-package-update';
        }
    }

    if (!class_exists(PackageEvent::class)) {
        class PackageEvent extends \Composer\EventDispatcher\PackageEvent {}
    }

    if (!class_exists(InstallOperation::class)) {
        class InstallOperation
        {
            public function __construct(private object $package) {}

            public function getPackage(): object
            {
                return $this->package;
            }
        }
    }

    if (!class_exists(UpdateOperation::class)) {
        class UpdateOperation
        {
            public function __construct(private object $targetPackage) {}

            public function getTargetPackage(): object
            {
                return $this->targetPackage;
            }
        }
    }

    if (!class_exists(Package::class)) {
        class Package
        {
            public function __construct(private string $name) {}

            public function getName(): string
            {
                return $this->name;
            }
        }
    }
}
