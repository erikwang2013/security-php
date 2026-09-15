# Security PHP

> [中文文档](README.md)

A PHP security attack detection plugin with 31 stateless threat detectors and 4 cross-request identity checks, compatible with Laravel, Webman, ThinkPHP, and Hyperf.

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

---

## Overview

Security PHP is a lightweight PHP security middleware that detects common web attack payloads through regex pattern matching and structural analysis. Each detector is independently configurable (enable/disable + block/log mode), with IP whitelisting (IPv4/IPv6 CIDR), IP attack escalation blacklist (5 attempts/60s → 15min ban), field whitelisting, log rotation, and deduplication. Detectors can return custom HTTP status codes (405/413/415, etc.). Persistent data supports File/Redis/Cache storage backends, switchable via config. Beyond the stateless regex checks, the `identity` module adds **session hijack / unusual login / data tamper / login brute-force lockout** detection — cross-request checks that cover both cookie sessions and session tokens (see "Identity Detection"). It also ships encoding normalization (defeating URL-encoding, fullwidth-character and HTML-entity bypasses) and security response header injection.

### Supported Attack Types

#### Injection Attacks

| Detector | Coverage |
|---|---|
| `xss` | Cross-site scripting — `<script>`, event handlers `on[a-z]+=`, SVG/CSS injection, `javascript:` URI |
| `sql_injection` | SQL injection — UNION SELECT (incl. `/**/`, `(` bypass), sleep/benchmark/pg_sleep, boolean blind, schema enumeration, stored procedures |
| `command_injection` | Command injection — backticks, `$()`, pipes, `/dev/tcp`, PHP execution functions, chained commands |
| `nosql_injection` | NoSQL injection — MongoDB `$ne`/`$gt`/`$regex`/`$where` operators, auth bypass |
| `ldap_injection` | LDAP injection — filter operators `(|)`, `(&)`, `(!)`, wildcards, attribute enumeration, hex escape |
| `xpath_injection` | XPATH injection — boolean bypass `1=1`, `|` union, `count/string/substring` blind extraction |
| `jndi_injection` | JNDI/Log4Shell — `${jndi:ldap://`, `${lower:j}` obfuscation, `${env:}` env lookup |
| `ssi_injection` | Server-Side Includes — `<!--#exec cmd=`, `<!--#include file=`, `<!--#echo var=` |
| `graphql_injection` | GraphQL injection — introspection `__schema`/`__type`, deep nesting DoS, mutation detection |
| `ssti` | Server-Side Template Injection — Jinja2 `{{}}`, FreeMarker `${}`, ERB `<% %>`, Python MRO traversal |

#### Protocol & Request Attacks

| Detector | Coverage |
|---|---|
| `ssrf` | Server-Side Request Forgery — private IPs, cloud metadata (169.254.169.254), IPv6 loopback, gopher/dict schemes |
| `xxe` | XML External Entity — `<!ENTITY` SYSTEM/PUBLIC, parameter entities, DOCTYPE declarations |
| `header_injection` | HTTP header injection — CRLF (`%0d%0a` / `\r\n`), Set-Cookie/Location/Content-Length injection |
| `host_header` | Host header attacks — CRLF Host injection, `X-Forwarded-Host`/`X-Original-URL` poisoning |
| `request_smuggling` | HTTP request smuggling — TE/CL inconsistency, dual Transfer-Encoding, folded header obfuscation |
| `open_redirect` | Open redirect — protocol-relative `//evil.com`, `javascript:`/`data:` pseudo-protocols |
| `cors` | CORS bypass — `Origin: null`, `Access-Control-Allow-*` header injection, preflight poisoning |
| `websocket` | WebSocket hijacking — Upgrade header injection, null Origin bypass, `ws://` URL detection |
| `dns_rebinding` | DNS rebinding — Host header with private IPs, localhost, short hostnames without TLDs |

#### HTTP Protocol Validation

| Detector | Coverage |
|---|---|
| `http_method` | HTTP method validation — only allows configured methods (GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH), returns **405** |
| `body_size` | Request body size limit — returns **413** when exceeding configured max (default 10MB) |
| `content_type` | Content-Type validation — only allows configured MIME types, returns **415** |
| `csrf_origin` | CSRF Origin check — validates Origin header against Host, supports additional cross-origin whitelist |
| `ip_blacklist` | IP attack escalation blacklist — auto-bans IP after N attacks within window (default 5/60s → 15min ban), persisted via pluggable storage backends (File/Redis/Cache) |

#### Data & Serialization Attacks

| Detector | Coverage |
|---|---|
| `deserialization` | PHP deserialization — `O:digit:` / `C:digit:` serialized objects, `unserialize()` calls, magic methods |
| `csv_injection` | CSV formula injection — `=cmd|`, `=powershell`, `HYPERLINK()` Excel formula attacks |
| `mail_header` | Email header injection — Bcc/Cc/From/To injection, MIME multipart injection |
| `jwt_attack` | JWT attacks — **structural header decoding**: `alg: none` bypass, `kid` path traversal, empty signature |
| `prototype_pollution` | JS prototype pollution — `__proto__`/`constructor` key detection, `__defineGetter__`/`__defineSetter__` |

#### Identity & Integrity (requires app integration, see "Identity Detection")

| Detector | Coverage |
|---|---|
| `session_hijack` | Session hijacking — binds the session identifier to a fingerprint (UA + IP subnet) on first sight; a later change in that fingerprint alerts with **401**. Cookie sessions and `Authorization: Bearer` / `X-Token` sessions share one code path |
| `unusual_login` | Unusual login location — remembers where each account usually logs in from; a new place alerts with **401** |
| `data_tamper` | Data tampering — verifies the HMAC signature of protected fields; a changed value, or a stripped / forged / expired signature, alerts with **403** |
| `login_lockout` | Login brute-force lockout — locks the account once failed attempts in a sliding window reach the threshold; locked requests get **429** without reaching your auth logic |

#### File & Sensitive Data

| Detector | Coverage |
|---|---|
| `path_traversal` | Path traversal — `../`/`..\\`, `php://filter`/`php://input`, null byte, URL-encoded bypasses |
| `upload` | Malicious file upload — extension whitelist + PHP tag (`<?php`, `<?=`) content scanning |
| `data_leak` | Sensitive data exposure — credit card numbers, AWS access keys, private key headers, DB connection strings, API tokens, JWT secrets |

---

## Installation

```bash
composer require erikwang2013/security-php
```

Requires PHP >= 8.0.

---

## Usage

### Quick Start (Global Functions)

```php
<?php
require 'vendor/autoload.php';

// Scan current request (auto-extracts GET/POST/COOKIE/FILES)
$threats = security_scan_current_request();

if (!empty($threats)) {
    foreach ($threats as $threat) {
        echo "Threat detected: {$threat->type} - {$threat->detail}\n";
    }
}

// Or one-liner: scan + auto-block
security_guard();
```

### Laravel

Auto-discovered on install. Publish config:

```bash
php artisan vendor:publish --tag=security-config
```

The middleware alias `security` is registered automatically. Use in routes:

```php
Route::middleware('security')->group(function () {
    Route::post('/api', [ApiController::class, 'handle']);
});
```

Or register globally in `app/Http/Kernel.php`:

```php
protected $middleware = [
    \Erikwang2013\Security\Middleware\Laravel\SecurityMiddleware::class,
];
```

### Webman

Publish the config (copy defaults to the Webman plugin directory):

```bash
cp vendor/erikwang2013/security-php/config/security.php config/plugin/erikwang2013/security-php/app.php
```

Customize `config/plugin/erikwang2013/security-php/app.php` as needed, then register in `config/middleware.php`:

```php
return [
    \Erikwang2013\Security\Middleware\Webman\SecurityMiddleware::class,
];
```

### ThinkPHP

Publish the config:

```bash
cp vendor/erikwang2013/security-php/config/security.php config/security.php
```

Customize `config/security.php` as needed, then register in `app/middleware.php`:

```php
return [
    \Erikwang2013\Security\Middleware\Thinkphp\SecurityMiddleware::class,
];
```

### Hyperf

Publish the config:

```bash
cp vendor/erikwang2013/security-php/config/security.php config/autoload/security.php
```

Customize `config/autoload/security.php` as needed, then register in `config/autoload/middlewares.php`:

```php
return [
    'http' => [
        \Erikwang2013\Security\Middleware\Hyperf\SecurityMiddleware::class,
    ],
];
```

### Manual Usage

```php
use Erikwang2013\Security\SecurityGuard;

$config = require 'config/security.php';
SecurityGuard::init($config);

$threats = SecurityGuard::guard(['input' => '<script>alert(1)</script>']);

if (!empty($threats) && SecurityGuard::shouldBlock($threats)) {
    http_response_code(SecurityGuard::blockStatusCode());
    die(SecurityGuard::blockMessage());
}
```

---

## Configuration

The config file lives at `config/security.php`. All options are documented with inline comments.

### Master Switch

```php
'enabled' => true,  // false to disable all detection
```

### Per-Detector Configuration

```php
'detectors' => [
    'xss' => [
        'enabled' => true,   // enable this detector
        'mode'    => 'block', // 'block' = intercept | 'log' = record only
    ],
    // ...
],
```

> **Note**: `header_injection`, `ssti`, and `nosql_injection` default to `log` mode to avoid false positives on legitimate content (multi-paragraph text, frontend templates, shell variables). Switch to `block` after verifying your use case.

### Block Response

```php
'block_status_code' => 403,   // default HTTP status. When a detector specifies a custom code (405/413/415),
                              // SecurityGuard::blockStatusCode($threats) prioritizes the detector's code
'block_message'     => 'Request blocked by security policy',
```

### Security Headers

```php
'security_headers' => [
    'enabled' => true,
    'headers' => [
        'X-Content-Type-Options'    => 'nosniff',   // disable browser MIME sniffing
        'X-Frame-Options'           => 'SAMEORIGIN',// clickjacking: SAMEORIGIN = same-origin only, DENY = block all
        'Referrer-Policy'           => 'strict-origin-when-cross-origin',
        'Permissions-Policy'        => '',          // e.g. geolocation=(), camera=(), microphone=()
        'Content-Security-Policy'   => '',          // e.g. default-src 'self'; script-src 'self'
        'Strict-Transport-Security' => '',          // e.g. max-age=31536000; includeSubDomains
    ],
],
```

Headers whose value is an empty string are skipped, so you can turn them on one at a time. The middleware injects them on **both normal and blocked responses**; when calling the guard manually, fetch them with `SecurityGuard::securityHeaders()` and write them yourself.

### Logging

```php
'log' => [
    'enabled'       => true,
    'path'          => '',      // empty = system temp directory
    'max_size'      => 10,      // MB, auto-rotates. 0 to disable rotation
    'dedup_seconds' => 5,       // dedup window — same attack within N seconds logged once per request
],
```

Log format:
```
[2026-05-21 14:22:32] 192.168.1.1 POST /api/login | sql_injection | critical | field=username payload=admin'-- detail=SQL comment termination
```

### IP Whitelist

```php
'whitelist_ips' => [
    '127.0.0.1',           // single IP
    '10.0.0.0/8',          // CIDR block
    '192.168.1.0/24',      // /24 subnet
    '::1',                 // IPv6 address
    'fe80::/10',           // IPv6 CIDR
],
```

### Field Whitelist

```php
'whitelist_fields' => ['_token', '_method', 'csrf_token'],
```

### Encoding Normalization

```php
'normalization' => [
    'enabled'   => true,
    'urldecode' => true, // decode values containing %
    'fullwidth' => true, // fullwidth ASCII → halfwidth
    'entities'  => true, // decode HTML entities when the value contains &# or &amp;
],
```

Regex detectors only ever see the raw value, so an attacker encoding a payload once (`%3Cscript%3E`), twice (`%2527`), or reshaping it (fullwidth `Ｓｅｌｅｃｔ`, entity `&#60;script&#62;`) slips past. With this on, values carrying an encoding signal are decoded one extra time and **both the decoded form and the original are scanned**; a decoded hit is tagged `[decoded:xxx]` in the log `detail`.

Each variant runs a cheap pre-check first (no `%` in the value means `urldecode` is never called), so unencoded requests pay nothing. **The trade-off**: legitimate text containing `%` (forms carrying URLs, search terms) can gain hits after decoding, so high-false-positive detectors are best left in `log` mode.

### Identity Detection

Session hijacking, unusual login, data tampering and login brute-force lockout share the `identity` block and `storage` (File/Redis/Cache — use Redis or Cache when running on more than one machine):

```php
'identity' => [
    'enabled' => true,
    'session' => [
        'cookie'  => 'laravel_session',                      // session cookie name; empty = token only
        'headers' => ['authorization', 'x-token', 'x-auth-token'], // token sources, first non-empty wins
        'bind'    => ['ua', 'ip'],                           // fingerprint factors, default UA + IP subnet
        'ip_bits' => 24,                                     // subnet size the IP is normalised to
        'ttl'     => 7200,                                   // idle time after which the binding is redone
    ],
    'login' => [
        'ttl'        => 86400, // how long a login location is remembered
        'max_points' => 10,    // locations kept per account, least-recently-used evicted first

        'lockout' => [             // brute-force lockout
            'max_failures'   => 5, // failed attempts within the window that trigger a lock
            'window_seconds' => 900, // how long a failure stays counted
            'lock_seconds'   => 900, // lock duration
            'include_ip'     => false, // true = count per user_id + IP, narrowing the lock to the attacker's source
        ],
    ],
    'tamper' => [
        'token_field'      => '_security_sig', // field carrying the signature
        'protected_fields' => [],              // dot-path list, e.g. order.price
        'ttl'              => 1800,            // signature lifetime in seconds
    ],
],

'signing_key' => getenv('SECURITY_SIGNING_KEY') ?: '', // empty = data tamper detection off
```

**Token login**: cookie sessions and token sessions run the same code — only "where the session identifier comes from" differs. `Authorization: Bearer <token>` (the `bearer` prefix is case-insensitive) and custom `X-Token` / `X-Auth-Token` headers are read in `session.headers` order, and a matching cookie wins. **API, mini-program and mobile-app clients with no cookies are covered with no extra configuration**; set `session.cookie => ''` to drop the cookie path entirely.

**Three integration points** (without them the matching check stays silent — no false positives):

```php
// 1. Call after a successful login / token issue. Cookie and token login are identical here.
//    Optional second argument is a city string (when the app already has GeoIP);
//    otherwise the IP subnet is used.
$threat = SecurityGuard::recordLogin($userId, 'Hangzhou');
if ($threat !== null) { /* login from a new place — step up verification */ }

// 2. Sign when rendering the form; the middleware verifies it on submit.
$token = SecurityGuard::signFields(['order.price' => $price, 'order.qty' => $qty]);
// <input type="hidden" name="_security_sig" value="<?= $token ?>">
```

**Brute-force lockout additionally hooks into your auth branch** (failures happen in app code upstream of the middleware, which cannot see them):

```php
// 3. Before authenticating: a locked account skips the credential check entirely,
//    instead of answering "wrong password" to every guess.
if (SecurityGuard::isLockedOut($userId, $ip)) {
    return response('Too Many Requests', 429);
}

// 4. The wrong-password branch: record one failure; a threat comes back once the threshold trips.
$threat = SecurityGuard::recordFailedLogin($userId, $ip);
if ($threat !== null) { /* this attempt locked the account */ }
```

**Known limitations**: (1) the first login becomes the baseline — the first login an account ever makes is silent, so an attacker who logs in before the real owner defines "normal"; (2) same for sessions: an attacker who uses a token/session before its real owner sets the baseline; (3) keep the key in the `SECURITY_SIGNING_KEY` environment variable, never in version control; (4) `session.cookie` and `session.headers` must stay in sync with the values read in `middleware/*/SecurityMiddleware.php`; (5) with `include_ip => false` (the default) the lock is keyed to the **account**, so an attacker can lock any account out by hammering it with wrong passwords — which is why `lock_seconds` defaults low; switch `include_ip` on for a stricter policy, at the cost of an attacker resetting the counter by rotating IPs.

### IP Attack Escalation Blacklist

```php
'ip_blacklist' => [
    'enabled'             => true,
    'max_attempts'        => 5,     // max attacks within window
    'window_seconds'      => 60,    // counting window (seconds), resets after expiry
    'ban_duration_seconds' => 900,  // ban duration (seconds), default 15 minutes
],
```

When an IP triggers `max_attempts` attack detections within `window_seconds`, it is banned for `ban_duration_seconds`. All requests from banned IPs return 403 immediately.

### Storage Configuration

```php
'storage' => [
    'type' => 'file',  // 'file' | 'redis' | 'cache'

    // File storage (default, zero dependencies)
    'file' => ['path' => ''],

    // Redis storage (type=redis, provide pre-connected \Redis instance via redis_instance)
    // Framework users: use your framework's Redis connection (e.g. Laravel's Redis::connection())
    // Non-framework users: use php-redis extension — new \Redis(); $redis->connect('127.0.0.1', 6379);
    'redis' => [
        'prefix' => 'security:',
    ],

    // Cache file storage (one file per key, better for high-concurrency)
    'cache' => [
        'path'   => '',
        'prefix' => 'security_',
    ],
],
```

`file` stores data in a single JSON file with `flock` atomic writes. `redis` uses an externally-provided Redis instance for distributed shared storage. `cache` stores each key as an independent file, avoiding single-file write contention.

---

## Design

### Project Structure

```
security-php/
├── src/                                  # Core library (zero framework coupling)
│   ├── SecurityGuard.php                 # Facade: init / guard / blockDecision / identity forwarding
│   ├── DetectorChain.php                 # Detector chain (strategy pattern), runs by priority
│   ├── DetectorInterface.php             # Detector contract
│   ├── NormalizationScanner.php          # Encoding normalization: rescans decoded variants
│   ├── IpBlacklist.php                   # IP attack escalation blacklist
│   ├── Logger.php                        # Attack log: atomic writes / rotation / dedup / CRLF defence
│   ├── ThreatResult.php                  # Threat value object
│   ├── helpers.php                       # Global security_guard() / security_scan_current_request()
│   ├── Composer/Installer.php            # composer-plugin: publishes config on install
│   ├── Detector/                         # 31 stateless detectors
│   │   ├── AbstractRegexDetector.php     #   Regex base class (25 detectors extend it)
│   │   └── ...                           #   Xss / SqlInjection / Ssrf / Upload / JwtAttack ...
│   ├── Identity/                         # 4 cross-request checks (outside the chain, app-integrated)
│   │   ├── IdentityGuard.php             #   Single facade, threats merged into the main result
│   │   ├── SessionFingerprint.php        #   Session hijack: session id → fingerprint baseline
│   │   ├── LoginBaseline.php             #   Unusual login: account → usual locations
│   │   ├── LoginLockout.php              #   Brute-force lockout: failure count → lock
│   │   ├── FieldSigner.php               #   Data tamper: HMAC over protected fields
│   │   └── IpPrefix.php                  #   IP subnet normalization (IPv4 / IPv6)
│   └── Storage/                          # Pluggable persistence
│       ├── StorageInterface.php          #   Shared contract; IdentityGuard and IpBlacklist share one instance
│       ├── FileStorage.php               #   Single JSON file + flock
│       ├── RedisStorage.php              #   Externally-injected \Redis instance
│       └── CacheStorage.php              #   One file per key
├── middleware/                           # Framework adapters: extract request → call SecurityGuard → inject headers
│   ├── Laravel/                          #   SecurityMiddleware + SecurityServiceProvider (auto-discovery)
│   ├── Webman/SecurityMiddleware.php     #   Same responsibility as the two below
│   ├── Thinkphp/SecurityMiddleware.php
│   └── Hyperf/SecurityMiddleware.php
├── config/security.php                   # Default configuration (every option commented)
├── tests/                                # 402 tests, 978 assertions
│   ├── Core/                             #   Facade / chain / storage / logger / identity / features
│   ├── Detector/                         #   Full detector regression + edge cases
│   └── Middleware/                       #   All four adapters
├── docs/                                 # Design docs, code review reports, test reports
├── scripts/release.sh                    # Release script
├── phpunit.xml
└── composer.json
```

### Architecture

```
HTTP Request
  │
  ▼
┌─────────────────┐
│ Middleware Layer │  Extract GET/POST/COOKIE/FILES from framework Request → flatten to key-value
│ (4 adapters)    │  Invoke SecurityGuard::guard()
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  SecurityGuard   │  Facade: IP whitelist → IP blacklist check → field whitelist → $_SERVER inject →
│                 │  nested flattening → scan. Identity check: IdentityGuard's threats are merged
│                 │  into the same result set. Post-scan: records attacking IPs into IpBlacklist
└────────┬────────┘
         │
    ┌────┴─────┬──────────┐
    ▼          ▼          ▼
┌────────┐ ┌──────────────┐ ┌───────────────┐
│IpBlacklist│ │ DetectorChain │ │ IdentityGuard │  Cross-request state checks (outside the regex chain):
│         │ │               │ │               │  session hijack / unusual login / data tamper / brute-force lockout
│  ┌────┐ │ └──────┬───────┘ └───────┬───────┘
│  │Storage││        │                 │
│  │File/ ││   ← IpBlacklist and IdentityGuard share one Storage instance
│  │Redis/││        │                 │
│  │Cache ││        │                 │
└──┴────┴─┘        ▼                 │
         ┌─────────────────┐          │
         │  31 Detectors    │  25 extend AbstractRegexDetector, define only name() + patterns() + priority()
         │  (strategy)      │  6 override detect(): Upload (file scan), JwtAttack (JWT decode),
         │                 │  HttpMethod/BodySize/ContentType/CsrfOrigin ($data-injected, decoupled from $_SERVER)
         └────────┬────────┘          │
                  │                   │
                  └─────────┬─────────┘
                            ▼
         ┌─────────────────┐
         │     Logger       │  Attack log: fopen+flock atomic writes, size-based rotation, CRLF sanitization, dedup
         └─────────────────┘
```

> The **31 Detectors** box is the regex detectors inside `DetectorChain`. The four identity checks are not counted among them — they need cross-request state, so they run outside the chain in `IdentityGuard` and are merged into the same threat list (sharing logging, dedup, and block/log mode). `ip_blacklist` is likewise outside the chain; `SecurityGuard` calls it directly.

### Design Decisions

**1. Abstract Detector Base Class**

25 of 31 detectors extend `AbstractRegexDetector`. Each is ~15 lines defining only `name()` and `patterns()`. Eliminates ~500 lines of duplicated scan loops. A change to the scanning logic (e.g., adding nested array support) modifies a single file.

The remaining 6 detectors implement `DetectorInterface` directly with custom `detect()`: `UploadDetector` (file extension+content scan), `JwtAttackDetector` (JWT structure decoding), `HttpMethodDetector` / `BodySizeDetector` / `ContentTypeDetector` / `CsrfOriginDetector` ($_SERVER superglobal checks).

```php
class XssDetector extends AbstractRegexDetector
{
    public function name(): string { return 'xss'; }

    protected function patterns(): array
    {
        return [
            '/<script\b/i'    => ['severity' => 'critical', 'detail' => 'Script tag injection'],
            '/\bon[a-z]+\s*=/i' => ['severity' => 'high', 'detail' => 'Event handler injection'],
        ];
    }
}
```

**2. Nested Array Flattening**

`SecurityGuard::flattenData()` recursively processes nested JSON request bodies:

```php
['user' => ['name' => '<script>x</script>']]
→ ['user.name' => '<script>x</script>']
```

Array values are JSON-encoded as strings for detector scanning. Field names use dot-separated paths (e.g. `user.profile.bio`).

**3. Security Hardening**

| Measure | Location | Detail |
|---|---|---|
| PCRE backtrack limit | SecurityGuard::guard() | Sets `pcre.backtrack_limit=1000000` before scan, restores in `finally` |
| Regex error detection | AbstractRegexDetector | Logs to `error_log` on `preg_match === false` (malformed pattern) |
| Log injection prevention | Logger::sanitize() | `\r\n` → `\\r\\n`, `|` → space |
| Atomic log writes | Logger::log() | `fopen`+`flock`+`fwrite` — no TOCTOU race |
| Sensitive data masking | DataLeakDetector | AWS keys appear as `AKIAIOS***XAMPLE` in logs |
| IP whitelist CIDR | SecurityGuard | IPv4 via `ip2long` + bitmask, IPv6 via `inet_pton` + binary comparison |
| IP attack escalation blacklist | IpBlacklist | Per-IP attack counting within window, auto-ban, pluggable storage backends (File/Redis/Cache), `flock` atomic writes (File mode) |
| Credential redaction | IdentityGuard | Session IDs / tokens are persisted as `sha256` hashes only; logs carry `#` + the first 8 hash chars — plaintext never reaches storage or logs |
| Signing key off-repo | config | `signing_key` comes from `getenv('SECURITY_SIGNING_KEY')` so no key enters version control; tamper detection silently disables when unset |
| Encoding normalization | NormalizationScanner | URL / double-encoding, fullwidth and HTML entities each decoded once and rescanned, hits tagged `[decoded:xxx]`; cheap pre-checks keep unencoded requests free |
| Account hashing | LoginLockout | Lock keys and threat payloads carry only `sha256(user_id)` — no plaintext account reaches storage or logs |
| Security headers | SecurityGuard::securityHeaders() | nosniff / X-Frame-Options etc. injected on both normal and blocked responses; empty-valued headers skipped |
| Default log mode | config | High-FP detectors default to record-only |

**4. Pluggable Storage Abstraction**

`IpBlacklist` and `IdentityGuard` are decoupled from I/O via `StorageInterface`. The `SecurityGuard::createStorage()` factory selects the adapter based on `storage.type`:

```php
interface StorageInterface {
    get(string $key): mixed;  set(string $key, mixed $value): void;
    delete(string $key): void; has(string $key): bool;
    all(): array;             clear(): void;
}
```

| Adapter | Backend | Use Case |
|---|---|---|
| `FileStorage` | Single JSON file + `flock` | Default, zero-dependency |
| `RedisStorage` | Redis via externally-injected \Redis instance | Distributed / HA deployments |
| `CacheStorage` | One serialized file per key | High-concurrency, no single-file contention |

**5. Framework Adapter Strategy**

- Middleware layer has a single responsibility: extract data from framework Request → invoke SecurityGuard
- Core detection logic is zero-dependency, framework-agnostic, requires only PHP 8.0 standard library
- Laravel auto-discovered via `extra.laravel.providers`
- Webman/ThinkPHP/Hyperf registered manually in middleware config
- Global function `security_guard()` supports non-framework projects

**6. Adding a New Detector**

```php
// Option A: Regex-based detector (extend AbstractRegexDetector)
// 1. Create src/Detector/MyDetector.php
class MyDetector extends AbstractRegexDetector
{
    public function name(): string { return 'my_detector'; }
    protected function patterns(): array {
        return [
            '/attack_pattern/i' => ['severity' => 'high', 'detail' => 'Description'],
        ];
    }
}

// Option B: Custom logic detector (implement DetectorInterface)
// For checking $_SERVER, filesystem, or other non-input-data sources
class MyCustomDetector implements DetectorInterface
{
    public function name(): string { return 'my_custom'; }
    public function detect(array $data): ?ThreatResult
    {
        return new ThreatResult(
            type: 'my_custom',
            severity: 'high',
            field: '_server.SOME_VAR',
            payload: $_SERVER['SOME_VAR'] ?? '',
            detail: 'Custom attack detected',
            httpStatus: 418, // custom status code
        );
    }
}

// 2. Register in SecurityGuard::$detectorMap
'my_detector' => Detector\MyDetector::class,
'my_custom'   => Detector\MyCustomDetector::class,

// 3. Add config in config/security.php
'my_detector' => ['enabled' => true, 'mode' => 'block'],
'my_custom'   => ['enabled' => true, 'mode' => 'block'],
```

## Open Source — Your Support Is Welcome

| WeChat Pay | Alipay |
|:---:|:---:|
| <img src="./docs/weixinpay.png" alt="WeChat Pay" width="130" height="130" /> | <img src="./docs/alipay.png" alt="Alipay" width="130" height="130" /> |

---

### Dependencies

- PHP >= 8.0
- Zero external dependencies

---

## Testing

```bash
composer install
vendor/bin/phpunit
```

```
OK (402 tests, 978 assertions)
```

## License

MIT License — Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
