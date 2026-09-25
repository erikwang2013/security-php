# Security Plugin Design

> **Note (2026-09-25, v1.4.x):** The block response now depends on the client. As of v1.4.0 `SecurityGuard::blockResponse()` returns an HTML page rendered by `src/BlockPage.php` (mascot + status + the detector names that fired) when the request's `Accept` contains `text/html`, and the original plain-text `block_message` otherwise; `block_page.enabled` (absent key = on) turns the page off, and all four middlewares plus `security_guard()` go through that one method. The same release added a Composer-free install path (`prepend.php` as an `auto_prepend_file` entry point, a PSR-4 fallback loader in `src/helpers.php`, `SECURITY_CONFIG` to point at your own config copy) and a regex prefilter gate in `AbstractRegexDetector` (patterns grouped by flag set, one combined alternation per group, applied below 8KB). v1.4.1 tightened the stateful side: shared-lock reads and write-failure logging in `FileStorage`, blacklist entry reclamation with active bans surviving a window reset, throttled session-fingerprint refresh, IPv4-mapped IPv6 treated as IPv4, rotation-collision suffixes in `Logger`, named HTML entities decoded, one MGET per SCAN batch in `RedisStorage`. The structure and storage tables below are the 2026-05-21 design and stay frozen.

> **Note (2026-09-15):** Design as of 2026-05-21. The project has since gained an `identity` layer — session hijack, unusual login, data tamper and login brute-force lockout detection — which runs *outside* `DetectorChain` because it needs cross-request state. Two cross-cutting additions came with it: `NormalizationScanner` re-scans decoded variants (URL / double-encoding, fullwidth, HTML entities) to close encoding bypasses, and `SecurityGuard::securityHeaders()` injects hardening response headers on both normal and blocked responses. The diagram and detector sections below have been updated to include these; see README「身份维度检测」/ "Identity Detection" for config and integration.

## Overview

`erikwang2013/security-php` — PHP security attack detection plugin. Detects XSS, SQL injection, command injection, path traversal, malicious file uploads, and 26 other attack types. Compatible with webman, Laravel, ThinkPHP, Hyperf via framework-specific middleware adapters. Includes HTTP protocol validation (method/size/content-type), CSRF origin check, IP attack escalation blacklist, and pluggable storage backends (File/Redis/Cache). On top of the 31 stateless detectors, the `identity` layer adds four cross-request checks (session hijack, unusual login, data tamper, login brute-force lockout), and encoding normalization rescans decoded payload variants.

## Architecture

```
Request → Framework Middleware → SecurityGuard → DetectorChain → [31 Detectors] ─┐
                  │                  │                                          │
                  │             ┌────┴────────┐                                 ├→ ThreatResult[]
                  │             ▼              ▼                                │
                  │        IpBlacklist       Logger          IdentityGuard ─────┘
                  │        (attack counting) (file log)  (session/login/tamper/lockout)
                  │             │                              │
                  │        ┌────┴──────────────────────────────┘
                  │        ▼         ▼         ▼
                  │    FileStorage RedisStorage CacheStorage
                  │    (JSON+flock) (php-redis) (per-key files)
```

Three layers plus storage abstraction:
- **Middleware layer** `middleware/` — extracts request data per framework, invokes core, returns block or pass
- **Core layer** `src/` — detection logic, detector chain, logging, IP blacklist, storage adapters
- **Config layer** `config/` — main switch, per-detector mode, log channel, block response, storage backend selection

## Data Flow

1. Middleware extracts `$_GET + $_POST + $_COOKIE + $_FILES + headers` into a flat key→value array
2. `SecurityGuard::guard($data, $meta)` invoked with request metadata (IP, method, URI)
3. IP whitelist check → IP blacklist check (banned IPs return immediate block)
4. Field whitelist removal → nested array flattening → PCRE backtrack limit protection
5. `DetectorChain` runs each enabled detector in order
6. Each detector returns `null` (safe) or `ThreatResult` (threat found, with optional custom HTTP status)
7. Attack IPs recorded to `IpBlacklist` via configured storage backend (File/Redis/Cache)
8. Based on per-detector mode config, either block (with detector-specific or default status code) or log-only

## Components

### DetectorInterface
Each detector implements:
- `name(): string` — unique key matching config, e.g. 'xss', 'sql_injection'
- `detect(array $data): ?ThreatResult`

### ThreatResult (DTO)
Fields: `type`, `severity` (critical/high/medium/low), `field`, `payload`, `detail`, `httpStatus` (default 403, detectors can specify 405/413/415 etc.)

### DetectorChain
- Holds ordered list of enabled detectors
- Runs all detectors on each request (no early exit — one request can trigger multiple threat types)
- Returns `ThreatResult[]` (empty = safe)

### 31 Detectors (27 payload-scanner + 4 HTTP-protocol)

**Payload scanners (27):** Extend `AbstractRegexDetector` (25) or implement `DetectorInterface` directly (2: Upload, JwtAttack). Cover injection attacks (XSS, SQLi, CMDi, NoSQL, LDAP, XPATH, JNDI, SSI, GraphQL, SSTI), protocol/request attacks (SSRF, XXE, header/host injection, request smuggling, open redirect, CORS, WebSocket, DNS rebinding), data/serialization (deserialization, CSV, mail header, JWT, prototype pollution), and file/sensitive data (path traversal, upload, data leak).

**HTTP protocol validators (4):** Implement `DetectorInterface` directly, read `$_SERVER` superglobals:
| Detector | Check | Status Code |
|---|---|---|
| HttpMethodDetector | `$_SERVER['REQUEST_METHOD']` against allowed methods | **405** |
| BodySizeDetector | `$_SERVER['CONTENT_LENGTH']` against max size | **413** |
| ContentTypeDetector | `$_SERVER['CONTENT_TYPE']` against allowed MIME types (strips charset) | **415** |
| CsrfOriginDetector | `$_SERVER['HTTP_ORIGIN']` vs `$_SERVER['HTTP_HOST']`, with configurable cross-origin whitelist | 403 |

### Identity Checks (outside DetectorChain)

Stateless detectors cannot see history, so these four run in `IdentityGuard` (`src/Identity/`) and their threats are merged into the same result list by `SecurityGuard::guard()`, sharing logging, dedup and block/log mode. Default mode is `log` for all four.

| Check | Threat type | State | Status Code |
|---|---|---|---|
| Session hijack | `session_hijack` | `ident:sess:` + `sha256(session id)` → UA + IP-prefix fingerprint | **401** |
| Unusual login | `unusual_login` | `ident:login:` + `sha256(user id)` → set of known login places | **401** |
| Data tamper | `data_tamper` | HMAC-SHA256 signature over the protected field values | 403 |
| Login lockout | `login_lockout` | `ident:login:` + `sha256(user id)` → failure count in a sliding window | **429** |

`IdentityGuard::check()` runs only the two *per-request* checks (`session_hijack`, `data_tamper`). The other two are caller-driven, because only the application knows whether a login attempt succeeded: `recordLogin()` fires from the success branch, `recordFailedLogin()` and `isLockedOut()` from the failure branch. Each check is gated by `detectors.<type>.enabled`, so adding one is a config entry plus a guard read — the block/log mode, logging and IP escalation all work without new code.

Session identity is extracted from either a cookie or a token header (`Authorization: Bearer` / `X-Token` / custom), so cookie-less API and mini-program clients take the same code path. Raw session IDs and tokens are never persisted or logged — only `sha256` hashes, logged as `#` + the first 8 hex chars. The signing key comes from `getenv('SECURITY_SIGNING_KEY')`; unset means the tamper check silently disables.

Lockout keys on the account by default (`include_ip => false`), which is what lets it stop a distributed spray — but it also means an attacker can lock any known account by hammering it. That is why `lock_seconds` defaults low (900s); set `include_ip => true` to split the counter per source IP when that tradeoff is unacceptable.

`SecurityGuard::guard()` passes the **unfiltered** flatten to `IdentityGuard::check()` while the detector chain gets the whitelist-filtered one. A protected field that also appears in `whitelist_fields` would otherwise arrive with its signature stripped and read as tampering.

### Storage Abstraction
Pluggable storage backends via `StorageInterface` (`get/set/delete/has/all/clear`):

| Adapter | Backend | Use Case |
|---|---|---|
| `FileStorage` | Single JSON file + `flock` | Default, zero-dependency |
| `RedisStorage` | Redis via php-redis extension | Distributed / HA deployments |
| `CacheStorage` | One serialized file per key | High-concurrency, no single-file contention |

Configured via `storage.type` in config. `SecurityGuard::createStorage()` factory creates the adapter and injects it into `IpBlacklist`.

### IpBlacklist
IP attack escalation backed by pluggable storage:
- Tracks per-IP attack count within configurable window (default 60s)
- Auto-bans IP after threshold (default 5) with configurable duration (default 15min)
- Pluggable storage: FileStorage (JSON+flock), RedisStorage, CacheStorage
- Whitelisted IPs bypass blacklist entirely
- Checked in `SecurityGuard::guard()` before scan; attack records written after scan

### SecurityGuard
Facade class, single entry point for all callers:
- `guard(array $data, array $meta): ThreatResult[]` — full scan (IP whitelist → blacklist check → flatten → detect → record IP → return)
- `shouldBlock(ThreatResult[] $threats): bool` — checks per-detector mode config
- `blockStatusCode(?array $threats = null): int` — returns per-threat status code (405/413/415) if available, else config default (403)
- `blockMessage(): string` — block response message
- `detectorOption(string $name, string $option, mixed $default): mixed` — access detector config
- `createStorage(array $config): StorageInterface` — factory: returns FileStorage/RedisStorage/CacheStorage based on `storage.type` config

### Logger
File-based attack log:
- Logs timestamp, IP, URI, method, threat type, severity, field, payload
- Log rotation by max file size
- Channel abstraction for future Redis/syslog

### Global Functions (helpers.php)
- `security_scan(array $data): array` — scan arbitrary data
- `security_scan_current_request(): array` — auto-extract from superglobals and pass the same `$meta` the middlewares pass (notably `cookies`, `user_agent` and the `headers` named by `identity.session.headers`, so the identity layer works here too; `Authorization` falls back to `getallheaders()` under Apache+CGI)
- `security_is_safe(array $data): bool` — boolean check
- `security_guard(): void` — emit `security_headers.*`, scan, then die with the threat's own status code on a block (not always 403)

The non-framework path is not a reduced mode: it runs the same pipeline as the middlewares. Only the caller-driven identity hooks (`recordLogin()` / `recordFailedLogin()` / `isLockedOut()`) stay with the application, exactly as in a framework.

### Framework Middlewares
Each middleware:
1. Extracts input from framework-native Request object
2. Calls `SecurityGuard::guard()`
3. Checks `SecurityGuard::shouldBlock()`
4. Returns 403 or passes to next handler

## Configuration

`config/security.php`:
- `enabled` — global on/off switch
- `detectors.<name>.enabled` — per-detector on/off
- `detectors.<name>.mode` — 'block' or 'log'
- `detectors.<name>.<option>` — detector-specific options (e.g. `allowed_methods`, `max_size`, `allowed_types`, `allowed_origins`)
- `block_status_code` — default HTTP status for blocks (403); detectors can override via ThreatResult::$httpStatus
- `block_message` — response message
- `log.enabled/channel/path/max_size/dedup_seconds` — logging config
- `whitelist_ips` — CIDR support (IPv4 + IPv6)
- `whitelist_fields` — skip scanning these field names
- `ip_blacklist.enabled/max_attempts/window_seconds/ban_duration_seconds` — IP escalation config
- `storage.type` — backend: `file` (JSON+flock), `redis` (php-redis), `cache` (per-key files)
- `storage.file.path` / `storage.redis.*` / `storage.cache.*` — per-backend options
- `identity.enabled` — master switch for the identity layer (requires a storage backend)
- `identity.session.*` — session fingerprint options (identity source: cookie name / token header)
- `identity.login.*` — login baseline options; `identity.login.lockout.*` nests here (`max_failures`, `window_seconds`, `lock_seconds`, `include_ip`)
- `identity.tamper.*` — fields to sign and the signature envelope option
- `signing_key` — HMAC key for `data_tamper`, read from `getenv('SECURITY_SIGNING_KEY')`; empty disables signing entirely (fail-safe: `sign()` returns `''`, `verify()` returns `null`, so upgrades never start rejecting requests)
- `normalization.enabled` / `normalization.max_depth` — decode URL / double-encoding, fullwidth and HTML-entity variants before re-scanning; matched variants are tagged `[decoded:xxx]` in the payload
- `security_headers.*` — response headers injected on both normal and blocked responses; empty-string values are skipped

## Package Structure

```
erikwang2013/security-php/
  composer.json
  config/
    security.php
  src/
    DetectorInterface.php
    ThreatResult.php
    DetectorChain.php
    SecurityGuard.php
    Logger.php
    IpBlacklist.php
    NormalizationScanner.php
    Storage/
      StorageInterface.php
      FileStorage.php
      RedisStorage.php
      CacheStorage.php
    Identity/
      IdentityGuard.php
      SessionFingerprint.php
      LoginBaseline.php
      LoginLockout.php
      FieldSigner.php
      IpPrefix.php
    Detector/
      AbstractRegexDetector.php
      XssDetector.php
      SqlInjectionDetector.php
      CommandInjectionDetector.php
      PathTraversalDetector.php
      UploadDetector.php
      SsrfDetector.php
      XxeDetector.php
      HeaderInjectionDetector.php
      DeserializationDetector.php
      LdapInjectionDetector.php
      MailHeaderDetector.php
      SstiDetector.php
      NosqlInjectionDetector.php
      OpenRedirectDetector.php
      JwtAttackDetector.php
      HostHeaderDetector.php
      RequestSmugglingDetector.php
      GraphqlInjectionDetector.php
      XpathInjectionDetector.php
      JndiInjectionDetector.php
      SsiInjectionDetector.php
      CsvInjectionDetector.php
      DataLeakDetector.php
      PrototypePollutionDetector.php
      WebSocketDetector.php
      CorsDetector.php
      DnsRebindingDetector.php
      HttpMethodDetector.php
      BodySizeDetector.php
      ContentTypeDetector.php
      CsrfOriginDetector.php
    helpers.php
    Composer/
      Installer.php
  middleware/
    Laravel/
      SecurityMiddleware.php
      SecurityServiceProvider.php
    Webman/
      SecurityMiddleware.php
    Thinkphp/
      SecurityMiddleware.php
    Hyperf/
      SecurityMiddleware.php
```

## Framework Compatibility

| Framework | Input Extraction | Registration |
|---|---|---|
| Laravel | `$request->all()` + `$request->file()` | Auto via ServiceProvider |
| Webman | `$request->post()` + `$request->get()` | Manual in config/middleware.php |
| ThinkPHP | `$request->param()` + `$request->file()` | Manual in app/middleware.php |
| Hyperf | `$request->getParsedBody()` + `$request->getUploadedFiles()` | Manual in config/middlewares.php |
| None (plain PHP) | `$_GET` / `$_POST` / `$_COOKIE` / `$_FILES` + `$_SERVER` headers | Call `security_guard()` in a bootstrap file |

The "None" row is a first-class adapter, not a fallback: `helpers.php` performs the same header injection and the same identity-layer `$meta` assembly as the four middlewares.

> **Note (2026-09-15):** Step 1 of Data Flow used to read as `$_GET + $_POST + $_COOKIE + $_FILES`, i.e. a plain `array_merge()`. That kept one value per name, and the four adapters disagree on precedence (Laravel body-over-query, Hyperf query-over-body, Webman POST-over-GET) — so a same-named field on two sources was a hole in the entire regex detector family, because whatever the merge dropped never reached a detector while the application could still read it. All five extraction sites now route through `SecurityGuard::mergeRequestSources()`: the last source keeps the bare name exactly as `array_merge()` left it, and whatever it displaces is scanned under `_<source>.<name>`. The change is purely additive. The same release restored `UploadDetector`, whose `$_FILES`-shaped match never fired inside `guard()` because `flattenData()` had already split it into `field.name` / `field.tmp_name`; it now re-pairs them (including `field.name.0` for multi-file input).
