# Security Plugin Design

## Overview

`erikwang2013/security-php` — PHP security attack detection plugin. Detects XSS, SQL injection, command injection, path traversal, malicious file uploads, and 26 other attack types. Compatible with webman, Laravel, ThinkPHP, Hyperf via framework-specific middleware adapters. Includes HTTP protocol validation (method/size/content-type), CSRF origin check, IP attack escalation blacklist, and pluggable storage backends (File/Redis/Cache).

## Architecture

```
Request → Framework Middleware → SecurityGuard → DetectorChain → [31 Detectors] → ThreatResult[]
                  │                  │
                  │             ┌────┴────────┐
                  │             ▼              ▼
                  │        IpBlacklist       Logger
                  │        (attack counting) (file log)
                  │             │
                  │        ┌────┴────┐
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

**Payload scanners (27):** Extend `AbstractRegexDetector` (23) or implement `DetectorInterface` directly (4: Upload, JwtAttack, PrototypePollution, DataLeak). Cover injection attacks (XSS, SQLi, CMDi, NoSQL, LDAP, XPATH, JNDI, SSI, GraphQL, SSTI), protocol/request attacks (SSRF, XXE, header/host injection, request smuggling, open redirect, CORS, WebSocket, DNS rebinding), data/serialization (deserialization, CSV, mail header, JWT, prototype pollution), and file/sensitive data (path traversal, upload, data leak).

**HTTP protocol validators (4):** Implement `DetectorInterface` directly, read `$_SERVER` superglobals:
| Detector | Check | Status Code |
|---|---|---|
| HttpMethodDetector | `$_SERVER['REQUEST_METHOD']` against allowed methods | **405** |
| BodySizeDetector | `$_SERVER['CONTENT_LENGTH']` against max size | **413** |
| ContentTypeDetector | `$_SERVER['CONTENT_TYPE']` against allowed MIME types (strips charset) | **415** |
| CsrfOriginDetector | `$_SERVER['HTTP_ORIGIN']` vs `$_SERVER['HTTP_HOST']`, with configurable cross-origin whitelist | 403 |

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
- `security_scan_current_request(): array` — auto-extract from superglobals
- `security_is_safe(array $data): bool` — boolean check
- `security_guard(): void` — scan + die(403) on block

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
    Storage/
      StorageInterface.php
      FileStorage.php
      RedisStorage.php
      CacheStorage.php
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
