<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Detector;

use Erikwang2013\Security\DetectorInterface;
use Erikwang2013\Security\ThreatResult;

abstract class AbstractRegexDetector implements DetectorInterface
{
    private const MAX_SCAN_LENGTH = 65536; // 64KB

    /**
     * Longest value the prefilter is used on. A combined alternation has to be
     * attempted at every position, while the individual patterns keep their
     * literal-prefix skip optimisation and win from roughly 16KB up — measured
     * 4x faster below 1KB with the gate, 1.3x slower above 64KB.
     * ponytail: fixed threshold; make it adaptive if payload sizes shift.
     */
    private const GATE_MAX_LENGTH = 8192;

    /**
     * Patterns grouped by flag set, each group carrying a prefilter.
     * Built once per instance — detectors are stateless and patterns() is pure.
     *
     * @var list<array{gate: ?string, patterns: array<string, array{severity: string, detail: string}>}>|null
     */
    private ?array $groups = null;

    abstract public function name(): string;

    /**
     * @return array<string, array{severity: string, detail: string}>
     */
    abstract protected function patterns(): array;

    public function detect(array $data): array
    {
        $threats = [];
        $groups = $this->groups();

        foreach ($data as $field => $value) {
            // Empty values are skipped: no pattern in this library matches an
            // empty subject (asserted by DetectorChainTest), and the request
            // metadata always contributes a few blank fields.
            if (!is_string($value) || $value === '') {
                continue;
            }
            // Scan head and tail; patterns spanning the middle gap stay invisible.
            // ponytail: >128KB payloads can hide attacks across the truncation seam,
            // switch to chunked scanning with overlap if that matters.
            $scanValue = strlen($value) > self::MAX_SCAN_LENGTH
                ? substr($value, 0, self::MAX_SCAN_LENGTH) . "\n--TRUNC--\n" . substr($value, -self::MAX_SCAN_LENGTH)
                : $value;

            $useGate = strlen($scanValue) <= self::GATE_MAX_LENGTH;

            foreach ($groups as $group) {
                // One preg_match stands in for the whole group. Only a
                // definitive 0 may skip the individual patterns: false means
                // the gate hit a limit or failed to compile, and then every
                // pattern still has to run as before.
                if ($useGate && $group['gate'] !== null && preg_match($group['gate'], $scanValue) === 0) {
                    continue;
                }

                foreach ($group['patterns'] as $pattern => $info) {
                    try {
                        $result = preg_match($pattern, $scanValue);
                    } catch (\ValueError $e) {
                        $this->logInvalidPattern($pattern);
                        continue;
                    }
                    if ($result === false) {
                        $this->logInvalidPattern($pattern);
                        continue;
                    }
                    if ($result === 1) {
                        $threats[] = new ThreatResult(
                            type: $this->name(),
                            severity: $info['severity'],
                            field: (string) $field,
                            payload: $this->transformPayload($value),
                            detail: $info['detail'],
                        );
                    }
                }
            }
        }
        return $threats;
    }

    public function priority(): int
    {
        return 0;
    }

    /**
     * The prefilter groups, for tests that assert the gate is equivalent to
     * running every pattern. Not part of the public API.
     *
     * @internal
     * @return list<array{gate: ?string, patterns: array<string, array{severity: string, detail: string}>}>
     */
    public function groups(): array
    {
        if ($this->groups !== null) {
            return $this->groups;
        }

        $byFlags = [];
        foreach ($this->patterns() as $pattern => $info) {
            $parsed = self::parse($pattern);
            // Unparsable patterns cannot be folded into an alternation; they
            // share the '' group, which carries no gate and always runs.
            $key = $parsed === null ? '' : $parsed['flags'];
            $byFlags[$key]['bodies'][] = $parsed['body'] ?? null;
            $byFlags[$key]['patterns'][$pattern] = $info;
        }

        $groups = [];
        foreach ($byFlags as $flags => $group) {
            $groups[] = [
                'gate' => self::combine($group['bodies'], (string) $flags),
                'patterns' => $group['patterns'],
            ];
        }

        return $this->groups = $groups;
    }

    /**
     * Wrap every body in a non-capturing group and join with |. An alternation
     * matches exactly when one of its branches does, so the gate can only ever
     * say "nothing here" — the individual patterns keep deciding severity,
     * detail and payload.
     *
     * @param array<int, ?string> $bodies null = a pattern that cannot be combined
     */
    private static function combine(array $bodies, string $flags): ?string
    {
        foreach ($bodies as $body) {
            if ($body === null) {
                return null;
            }
        }
        if ($bodies === []) {
            return null;
        }

        $gate = '~' . implode('|', array_map(
            static fn (string $body): string => '(?:' . $body . ')',
            $bodies,
        )) . '~' . $flags;

        // Probe once here so a broken combination costs a silent fallback
        // instead of a warning on every request.
        return @preg_match($gate, '') === false ? null : $gate;
    }

    /**
     * Split a delimited pattern into body and flags.
     * Returns null when it cannot be embedded in an alternation safely.
     *
     * @return array{body: string, flags: string}|null
     */
    private static function parse(string $pattern): ?array
    {
        $delimiter = $pattern[0] ?? '';
        // '~' is the delimiter of the combined form; alphanumerics and '\'
        // are not usable delimiters to begin with.
        if ($delimiter === '' || $delimiter === '~' || $delimiter === '\\' || ctype_alnum($delimiter)) {
            return null;
        }

        $end = strrpos($pattern, $delimiter);
        if ($end === false || $end === 0) {
            return null;
        }

        $body = substr($pattern, 1, $end - 1);
        if ($body === '' || str_contains($body, '~')) {
            return null;
        }

        // An odd number of trailing backslashes would escape the ')' that
        // closes the wrapper
        if ((strlen($body) - strlen(rtrim($body, '\\'))) % 2 === 1) {
            return null;
        }

        return ['body' => $body, 'flags' => substr($pattern, $end + 1)];
    }

    private function logInvalidPattern(string $pattern): void
    {
        error_log(sprintf(
            'Security: Invalid regex pattern in detector "%s": %s',
            $this->name(),
            $pattern,
        ));
    }

    /**
     * Hook for subclasses to transform payload before logging.
     * Override to mask sensitive data, truncate, etc.
     */
    protected function transformPayload(string $payload): string
    {
        return $payload;
    }
}
