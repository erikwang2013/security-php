<?php

declare(strict_types=1);

namespace Erikwang2013\Security\Composer;

use Composer\Composer;
use Composer\IO\IOInterface;
use Composer\Plugin\PluginInterface;
use Composer\EventDispatcher\EventSubscriberInterface;
use Composer\Installer\PackageEvent;
use Composer\Installer\PackageEvents;

class Installer implements PluginInterface, EventSubscriberInterface
{
    private const PACKAGE_NAME = 'erikwang2013/security-php';

    private ?IOInterface $io = null;

    public function activate(Composer $composer, IOInterface $io): void
    {
        $this->io = $io;
        $composer->getEventDispatcher()->addSubscriber($this);
        $this->publishConfig($composer);
    }

    public function deactivate(Composer $composer, IOInterface $io): void {}

    public function uninstall(Composer $composer, IOInterface $io): void {}

    public static function getSubscribedEvents(): array
    {
        return [
            PackageEvents::POST_PACKAGE_INSTALL => 'onPackageInstall',
            PackageEvents::POST_PACKAGE_UPDATE  => 'onPackageUpdate',
        ];
    }

    public function onPackageInstall(PackageEvent $event): void
    {
        $package = method_exists($event->getOperation(), 'getPackage')
            ? $event->getOperation()->getPackage()
            : null;

        if ($package && $package->getName() === self::PACKAGE_NAME) {
            $this->publishConfig($event->getComposer());
        }
    }

    public function onPackageUpdate(PackageEvent $event): void
    {
        $package = method_exists($event->getOperation(), 'getTargetPackage')
            ? $event->getOperation()->getTargetPackage()
            : null;

        if ($package && $package->getName() === self::PACKAGE_NAME) {
            $this->publishConfig($event->getComposer());
        }
    }

    private function publishConfig(Composer $composer): void
    {
        $sourceConfig = dirname(__DIR__, 2) . '/config/security.php';

        if (!file_exists($sourceConfig)) {
            return;
        }

        $projectRoot = dirname($composer->getConfig()->get('vendor-dir'));
        $targets = $this->detectTargets($projectRoot);

        foreach ($targets as $target) {
            $targetDir = dirname($target);
            if (!is_dir($targetDir)) {
                @mkdir($targetDir, 0755, true);
            }

            if (!file_exists($target)) {
                copy($sourceConfig, $target);
                $this->io?->write("<info>[security-php] Config published to: {$target}</info>");
            }
        }
    }

    private function detectTargets(string $projectRoot): array
    {
        $targets = [];

        if (isLaravel($projectRoot)) {
            $targets[] = $projectRoot . '/config/security.php';
        }

        if (isWebman($projectRoot)) {
            $targets[] = $projectRoot . '/config/plugin/erikwang2013/security-php/app.php';
        }

        if (isThinkPHP($projectRoot)) {
            $targets[] = $projectRoot . '/config/security.php';
        }

        if (isHyperf($projectRoot)) {
            $targets[] = $projectRoot . '/config/autoload/security.php';
        }

        return $targets;
    }
}

// ──────────────── framework detectors ────────────────
// Guarded with function_exists: composer's plugin loader may eval() this
// file more than once per process (Cannot redeclare otherwise).

if (!function_exists(__NAMESPACE__ . '\\isLaravel')) {
    function isLaravel(string $root): bool
    {
        return file_exists($root . '/artisan')
            && file_exists($root . '/bootstrap/app.php');
    }
}

if (!function_exists(__NAMESPACE__ . '\\isWebman')) {
    function isWebman(string $root): bool
    {
        return file_exists($root . '/start.php');
    }
}

if (!function_exists(__NAMESPACE__ . '\\isThinkPHP')) {
    function isThinkPHP(string $root): bool
    {
        return file_exists($root . '/think')
            && is_dir($root . '/app');
    }
}

if (!function_exists(__NAMESPACE__ . '\\isHyperf')) {
    function isHyperf(string $root): bool
    {
        return file_exists($root . '/bin/hyperf.php')
            && is_dir($root . '/config/autoload');
    }
}
