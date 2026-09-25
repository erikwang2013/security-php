<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Tests\Detector;

use Erikwang2013\Security\Detector\AbstractRegexDetector;
use Erikwang2013\Security\Detector\XssDetector;
use PHPUnit\Framework\TestCase;

/**
 * The prefilter in AbstractRegexDetector skips a detector's patterns when one
 * combined alternation cannot match. That is a fast path, never a decision
 * maker — these tests pin the two properties it relies on:
 *
 *   1. the gate matches exactly when some individual pattern matches;
 *   2. empty values are never a threat, so skipping them loses nothing.
 *
 * A silent false negative is the failure mode worth fearing here, so the
 * corpus is deliberately wide: every string literal in the test suite, every
 * pattern body, and the payloads the detectors are known to catch.
 */
class PrefilterTest extends TestCase
{
    /** @return list<class-string<AbstractRegexDetector>> */
    private static function detectors(): array
    {
        $classes = [];
        foreach (glob(dirname(__DIR__, 2) . '/src/Detector/*.php') as $file) {
            $class = 'Erikwang2013\\Security\\Detector\\' . basename($file, '.php');
            if (!class_exists($class)) {
                continue;
            }
            $reflection = new \ReflectionClass($class);
            if ($reflection->isAbstract() || !$reflection->isSubclassOf(AbstractRegexDetector::class)) {
                continue;
            }
            $classes[] = $class;
        }
        return $classes;
    }

    /** @param class-string<AbstractRegexDetector> $class */
    private static function patternsOf(string $class): array
    {
        $method = new \ReflectionMethod($class, 'patterns');
        $method->setAccessible(true);
        return $method->invoke(new $class());
    }

    /**
     * Every string literal that appears in the test suite — the closest thing
     * to a real corpus this package has — plus pattern bodies and junk.
     *
     * @return list<string>
     */
    private static function corpus(): array
    {
        $samples = [];
        foreach (glob(dirname(__DIR__) . '/*/*.php') as $file) {
            preg_match_all(
                '/\'((?:[^\'\\\\]|\\\\.){2,80})\'|"((?:[^"\\\\]|\\\\.){2,80})"/',
                (string) file_get_contents($file),
                $matches,
                PREG_SET_ORDER,
            );
            foreach ($matches as $match) {
                $samples[] = stripcslashes($match[1] !== '' ? $match[1] : $match[2]);
            }
        }

        foreach (self::detectors() as $class) {
            foreach (array_keys(self::patternsOf($class)) as $pattern) {
                $end = strrpos($pattern, $pattern[0]);
                $samples[] = substr($pattern, 1, $end - 1);
            }
        }

        return array_merge(array_values(array_unique($samples)), [
            '', 'a', '1', 'GET', 'hello world', '这是一个正常的评论，包含标点符号和中文。',
            '<script>alert(1)</script>', "1' OR '1'='1", '../../etc/passwd',
            str_repeat('a', 4096) . '<script>x</script>',
        ]);
    }

    public function testGateMatchesWheneverAnyIndividualPatternMatches(): void
    {
        $corpus = self::corpus();
        $checked = 0;

        foreach (self::detectors() as $class) {
            $detector = new $class();
            $patterns = array_keys(self::patternsOf($class));
            $gates = array_column($detector->groups(), 'gate');

            // No pattern may be dropped while grouping
            $grouped = [];
            foreach ($detector->groups() as $group) {
                $grouped = array_merge($grouped, array_keys($group['patterns']));
            }
            sort($grouped);
            $expected = $patterns;
            sort($expected);
            $this->assertSame($expected, $grouped, "$class 分组后保留了全部 pattern");

            foreach ($corpus as $sample) {
                $anyIndividual = false;
                foreach ($patterns as $pattern) {
                    if (@preg_match($pattern, $sample) === 1) {
                        $anyIndividual = true;
                        break;
                    }
                }

                $anyGate = false;
                foreach ($gates as $gate) {
                    if ($gate !== null && @preg_match($gate, $sample) === 1) {
                        $anyGate = true;
                        break;
                    }
                }

                $checked++;
                $this->assertSame(
                    $anyIndividual,
                    $anyGate,
                    sprintf('%s：预筛结果必须与逐个 pattern 一致，样本=%s', $class, var_export($sample, true)),
                );
            }
        }

        $this->assertGreaterThan(5000, $checked, '语料太小，测不出问题');
    }

    /**
     * The prefilter skips values over GATE_MAX_LENGTH — the detectors must
     * still catch attacks hidden in them.
     */
    public function testAttackInAValueLargerThanTheGateLimitIsStillCaught(): void
    {
        $detector = new XssDetector();
        $payload = str_repeat('filler text ', 2000) . '<script>alert(1)</script>';

        $this->assertGreaterThan(8192, strlen($payload));

        $threats = $detector->detect(['body' => $payload]);

        $this->assertCount(1, $threats, '大字段必须绕过预筛后仍然命中');
        $this->assertSame('xss', $threats[0]->type);
    }

    public function testEmptyValuesAreSkippedAndNoPatternMatchesThem(): void
    {
        foreach (self::detectors() as $class) {
            foreach (array_keys(self::patternsOf($class)) as $pattern) {
                $this->assertSame(
                    0,
                    @preg_match($pattern, ''),
                    "$class 的 pattern 匹配空字符串，会让空字段一律告警：$pattern",
                );
            }

            $detector = new $class();
            $this->assertSame([], $detector->detect(['field' => '']), "$class 跳过空值后不应产生威胁");
        }
    }

    /**
     * A pattern that cannot be folded into the combined form must not lose its
     * gate — the detector falls back to running it directly.
     */
    public function testUnparsablePatternRunsWithoutAGate(): void
    {
        $detector = new class extends AbstractRegexDetector {
            public function name(): string
            {
                return 'unparsable';
            }

            protected function patterns(): array
            {
                return [
                    // '~' is the gate's own delimiter, so this body cannot be combined
                    '~<script>~i' => ['severity' => 'high', 'detail' => 'script tag'],
                    '/on\w+\s*=/i' => ['severity' => 'high', 'detail' => 'handler'],
                ];
            }
        };

        // The group holding the unparsable pattern carries no gate, so it runs
        // in full; the combinable pattern keeps its own gate.
        $ungated = [];
        foreach ($detector->groups() as $group) {
            if ($group['gate'] === null) {
                $ungated = array_merge($ungated, array_keys($group['patterns']));
            }
        }
        $this->assertSame(['~<script>~i'], $ungated, '只有不可合并的分组不应带预筛');

        $this->assertCount(1, $detector->detect(['q' => '<script>alert(1)</script>']));
        $this->assertCount(1, $detector->detect(['q' => 'onerror=alert(1)']), '带预筛的分组同样要命中');
    }
}
