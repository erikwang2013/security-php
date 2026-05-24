# Security PHP

> [English Documentation](README_EN.md)

基于 PHP 的安全攻击检测插件，支持 31 种攻击类型检测，兼容 Laravel、Webman、ThinkPHP、Hyperf 框架。

Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz

---

## 项目说明

Security PHP 是一个轻量级 PHP 安全中间件，通过正则模式匹配和结构分析检测常见的 Web 攻击载荷。每个检测器独立可配置（启用/禁用 + 拦截/日志模式），支持 IP 白名单（含 IPv4/IPv6 CIDR）、IP 攻击升级黑名单（5次/60s → 封禁15分钟）、字段白名单、日志轮转和去重。检测器可返回自定义 HTTP 状态码（405/413/415 等）。持久化数据支持 File/Redis/Cache 三种存储后端，可按需切换。

### 支持的攻击类型

#### 注入类攻击

| 检测器 | 说明 |
|---|---|
| `xss` | XSS 跨站脚本 — `<script>`、事件处理器 `on[a-z]+=`、SVG/CSS 注入、`javascript:` URI |
| `sql_injection` | SQL 注入 — UNION SELECT（含 `/**/`、`(` 绕过）、sleep/benchmark/pg_sleep、布尔盲注、schema 枚举、存储过程执行 |
| `command_injection` | 命令注入 — 反引号、`$()`、管道符、`/dev/tcp`、PHP 代码执行函数、链式执行 |
| `nosql_injection` | NoSQL 注入 — MongoDB `$ne`/`$gt`/`$regex`/`$where` 操作符、认证绕过 |
| `ldap_injection` | LDAP 注入 — 过滤操作符 `(|)`、`(&)`、`(!)`、通配符、属性枚举、hex 编码逃逸 |
| `xpath_injection` | XPATH 注入 — 布尔绕过 `1=1`、`|` 联合操作、`count/string/substring` 盲注函数 |
| `jndi_injection` | JNDI/Log4Shell — `${jndi:ldap://`、`${lower:j}` 混淆、`${env:}` 环境变量查找 |
| `ssi_injection` | SSI 服务端包含 — `<!--#exec cmd=`、`<!--#include file=`、`<!--#echo var=` |
| `graphql_injection` | GraphQL 注入 — 内省 `__schema`/`__type`、深度嵌套 DoS、mutation 检测 |
| `ssti` | SSTI 服务端模板注入 — Jinja2 `{{}}`、FreeMarker `${}`、ERB `<% %>`、Python MRO 遍历 |

#### 协议与请求攻击

| 检测器 | 说明 |
|---|---|
| `ssrf` | SSRF 服务端请求伪造 — 内网 IP、cloud metadata (169.254.169.254)、IPv6 loopback、gopher/dict 危险协议 |
| `xxe` | XXE XML 外部实体注入 — `<!ENTITY` SYSTEM/PUBLIC、参数实体、DOCTYPE 声明 |
| `header_injection` | HTTP 响应头注入 — CRLF (`%0d%0a` / `\r\n`)、Set-Cookie/Location/Content-Length 注入 |
| `host_header` | Host 头攻击 — CRLF Host 注入、`X-Forwarded-Host`/`X-Original-URL` 投毒 |
| `request_smuggling` | HTTP 请求走私 — Transfer-Encoding/Content-Length 不一致、双重 TE 头、折叠头混淆 |
| `open_redirect` | 开放重定向 — `//evil.com` 协议相对 URL、`javascript:`/`data:` 伪协议 |
| `cors` | CORS 绕过 — `Origin: null`、`Access-Control-Allow-*` 头注入、preflight 投毒 |
| `websocket` | WebSocket 劫持 — Upgrade 头注入、null Origin 绕过、ws:// URL 检测 |
| `dns_rebinding` | DNS 重绑定 — Host 头内网 IP、localhost、无 TLD 短主机名 |

#### HTTP 协议层校验

| 检测器 | 说明 |
|---|---|
| `http_method` | HTTP 方法校验 — 仅允许配置的 HTTP 方法（GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH），非法方法返回 **405** |
| `body_size` | 请求体大小限制 — 超过配置上限（默认 10MB）返回 **413** |
| `content_type` | Content-Type 校验 — 仅允许配置的 MIME 类型，非法类型返回 **415** |
| `csrf_origin` | CSRF Origin 检查 — 检测跨域请求 Origin 头是否与 Host 匹配，支持额外跨域白名单 |
| `ip_blacklist` | IP 攻击升级黑名单 — 同一 IP 在窗口时间内触发 N 次攻击后自动封禁（默认 5次/60s → 封禁15分钟），数据通过可插拔存储后端（File/Redis/Cache）持久化 |

#### 数据与序列化攻击

| 检测器 | 说明 |
|---|---|
| `deserialization` | PHP 反序列化 — `O:数字:` / `C:数字:` 序列化对象、`unserialize()` 调用、魔术方法引用 |
| `csv_injection` | CSV 公式注入 — `=cmd|`、`=powershell`、`HYPERLINK()` 等 Excel 公式攻击 |
| `mail_header` | 邮件头注入 — Bcc/Cc/From/To 注入、MIME multipart 注入 |
| `jwt_attack` | JWT 攻击 — **结构解码分析**：`alg: none` 绕过、`kid` 路径遍历注入、空签名检测 |
| `prototype_pollution` | JS 原型污染 — `__proto__`/`constructor` 键检测、`__defineGetter__`/`__defineSetter__` |

#### 文件与敏感数据

| 检测器 | 说明 |
|---|---|
| `path_traversal` | 路径遍历 — `../`/`..\\`、`php://filter`/`php://input`、null 字节、URL 编码绕过 |
| `upload` | 恶意文件上传 — 扩展名白名单 + PHP 标签 (`<?php`, `<?=`) 内容扫描 |
| `data_leak` | 敏感数据泄露 — 信用卡号、AWS Access Key、私钥头 `-----BEGIN`、数据库连接串、API Token、JWT Secret |

---

## 安装

```bash
composer require erikwang2013/security-php
```

要求 PHP >= 8.1。

---

## 使用说明

### 快速开始（全局函数）

```php
<?php
require 'vendor/autoload.php';

// 扫描当前请求（自动提取 GET/POST/COOKIE/FILES）
$threats = security_scan_current_request();

if (!empty($threats)) {
    foreach ($threats as $threat) {
        echo "检测到攻击: {$threat->type} - {$threat->detail}\n";
    }
}

// 或一行：安全检测 + 自动拦截
security_guard();
```

### Laravel

安装后自动发现。手动发布配置：

```bash
php artisan vendor:publish --tag=security-config
```

中间件别名 `security` 已自动注册，在路由中使用：

```php
Route::middleware('security')->group(function () {
    Route::post('/api', [ApiController::class, 'handle']);
});
```

或在 `app/Http/Kernel.php` 中注册全局中间件：

```php
protected $middleware = [
    \Erikwang2013\Security\Middleware\Laravel\SecurityMiddleware::class,
];
```

### Webman

在 `config/middleware.php` 中添加：

```php
return [
    \Erikwang2013\Security\Middleware\Webman\SecurityMiddleware::class,
];
```

### ThinkPHP

在 `app/middleware.php` 中添加：

```php
return [
    \Erikwang2013\Security\Middleware\Thinkphp\SecurityMiddleware::class,
];
```

### Hyperf

在 `config/autoload/middlewares.php` 中添加：

```php
return [
    'http' => [
        \Erikwang2013\Security\Middleware\Hyperf\SecurityMiddleware::class,
    ],
];
```

### 手动调用

```php
use Erikwang2013\Security\SecurityGuard;

// 初始化
$config = require 'config/security.php';
SecurityGuard::init($config);

// 扫描任意数据
$threats = SecurityGuard::guard(['input' => '<script>alert(1)</script>']);

// 检查是否需要拦截
if (!empty($threats) && SecurityGuard::shouldBlock($threats)) {
    http_response_code(SecurityGuard::blockStatusCode());
    die(SecurityGuard::blockMessage());
}
```

---

## 配置说明

配置文件发布后位于 `config/security.php`，所有配置项均有中文注释。

### 总开关

```php
'enabled' => true,  // false 时关闭所有检测
```

### 检测器配置

每个检测器独立控制：

```php
'detectors' => [
    'xss' => [
        'enabled' => true,   // 是否启用
        'mode'    => 'block', // 'block' 拦截 | 'log' 仅记录
    ],
    // ...
],
```

> **注意**：`header_injection`、`ssti`、`nosql_injection` 默认为 `log` 模式，防止对正常文本（多段落文本、前端模板、Shell 变量）误拦截。确认业务场景后可按需改为 `block`。

### 拦截配置

```php
'block_status_code' => 403,   // 默认 HTTP 状态码。当检测器返回自定义状态码时（如 405/413/415），
                              // SecurityGuard::blockStatusCode($threats) 优先使用检测器的状态码
'block_message'     => 'Request blocked by security policy',
```

### 日志配置

```php
'log' => [
    'enabled'       => true,
    'channel'       => 'file',
    'path'          => '',      // 留空使用临时目录
    'max_size'      => 10,      // MB，超过后自动轮转。设为 0 禁用
    'dedup_seconds' => 5,       // 去重窗口，同一请求内相同攻击不重复记录
],
```

日志格式：
```
[2026-05-21 14:22:32] 192.168.1.1 POST /api/login | sql_injection | critical | field=username payload=admin'-- detail=SQL comment termination
```

### IP 白名单

```php
'whitelist_ips' => [
    '127.0.0.1',           // 单个 IP
    '10.0.0.0/8',          // CIDR 网段
    '192.168.1.0/24',      // /24 子网
    '::1',                 // IPv6 单地址
    'fe80::/10',           // IPv6 CIDR
],
```

### 字段白名单

```php
'whitelist_fields' => ['_token', '_method', 'csrf_token'],
```

### IP 攻击升级黑名单

```php
'ip_blacklist' => [
    'enabled'             => true,
    'max_attempts'        => 5,     // 窗口内最大攻击次数
    'window_seconds'      => 60,    // 计数窗口（秒），超过后重置
    'ban_duration_seconds' => 900,  // 封禁时长（秒），默认 15 分钟
],
```

当同一 IP 在 `window_seconds` 秒内触发 `max_attempts` 次任意攻击检测后，该 IP 被封禁 `ban_duration_seconds` 秒。封禁期间所有请求直接返回 403。

### 存储配置

```php
'storage' => [
    'type' => 'file',  // 'file' | 'redis' | 'cache'

    // File 存储（默认，零依赖）
    'file' => ['path' => ''],

    // Redis 存储（需 php-redis 扩展，适合分布式场景）
    'redis' => [
        'host'     => '127.0.0.1',
        'port'     => 6379,
        'timeout'  => 2.0,
        'password' => null,
        'database' => 0,
        'prefix'   => 'security:',
    ],

    // Cache 文件缓存（每个 key 独立文件，适合高并发读写）
    'cache' => [
        'path'   => '',
        'prefix' => 'security_',
    ],
],
```

`file` 模式将数据存储在单个 JSON 文件中（flock 原子写入）。`redis` 使用 Redis 扩展实现分布式共享存储。`cache` 将每个 key 存为独立文件，避免单文件写入竞争。

---

## 设计说明

### 架构

```
HTTP Request
  │
  ▼
┌─────────────────┐
│ Middleware Layer │  从框架 Request 提取 GET/POST/COOKIE/FILES → 扁平化 key-value
│ (4 adapters)    │  调用 SecurityGuard::guard()
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  SecurityGuard   │  入口门面：IP 白名单 → IP 黑名单检查 → 字段白名单 → 嵌套扁平化 → 正则超时保护 → 扫描
│                 │  攻击记录：扫描后若发现威胁，自动记录 IP 到 IpBlacklist
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌────────┐ ┌──────────────┐
│IpBlacklist│ │ DetectorChain │  责任链：按序执行所有已启用的检测器，收集所有 ThreatResult
│         │ └──────┬───────┘
│  ┌────┐ │        │
│  │Storage││        │
│  │File/ ││        │
│  │Redis/││        │
│  │Cache ││        │
└──┴────┴─┘        │
                  ▼
         ┌─────────────────┐
         │  31 Detectors    │  23 个继承 AbstractRegexDetector，仅定义 name() + patterns()
         │  (strategy)      │  8 个自定义 detect()：Upload（文件内容扫描）、
         │                 │  JwtAttack（JWT 头解码）、PrototypePollution（键名检查）、
         │                 │  HttpMethod/BodySize/ContentType/CsrfOrigin（$_SERVER 检查）
         └────────┬────────┘
                  │
                  ▼
         ┌─────────────────┐
         │     Logger       │  攻击日志：fopen+flock 原子写入、按大小轮转、CRLF 注入防护、去重
         └─────────────────┘
```

### 关键设计决策

**1. 抽象检测器基类**

31 个检测器中的 23 个继承 `AbstractRegexDetector`，每个仅需定义 `name()` 和 `patterns()` 方法（约 15 行代码）。消除了 ~500 行重复的扫描循环代码。修改扫描逻辑（如新增嵌套数组支持）只需改动基类一处。

其余 8 个检测器直接实现 `DetectorInterface` 并自定义 `detect()` 方法：`UploadDetector`（文件扩展名+内容扫描）、`JwtAttackDetector`（JWT 结构解码分析）、`PrototypePollutionDetector`（对象键名检查）、`HttpMethodDetector` / `BodySizeDetector` / `ContentTypeDetector` / `CsrfOriginDetector`（$_SERVER 超全局变量检查）。

```php
class XssDetector extends AbstractRegexDetector
{
    public function name(): string { return 'xss'; }

    protected function patterns(): array
    {
        return [
            '/<script\b/i'    => ['severity' => 'critical', 'detail' => 'Script tag injection'],
            '/\bon[a-z]+\s*=/i' => ['severity' => 'high', 'detail' => 'Event handler injection'],
            // ...
        ];
    }
}
```

**2. 嵌套数组扁平化**

`SecurityGuard::flattenData()` 递归处理 JSON 请求体中的嵌套结构：

```php
['user' => ['name' => '<script>x</script>']]
→ ['user.name' => '<script>x</script>']
```

数组值会被 JSON 编码为字符串供检测器扫描。字段名使用点号分隔路径（如 `user.profile.bio`）。

**3. 安全措施**

| 措施 | 位置 | 说明 |
|---|---|---|
| PCRE 回溯限制 | SecurityGuard::guard() | 扫描前设 `pcre.backtrack_limit=1000000`，finally 中恢复 |
| 正则错误检测 | AbstractRegexDetector | `preg_match === false` 时触发 `error_log` |
| 日志注入防护 | Logger::sanitize() | `\r\n` → `\\r\\n`，`|` → 空格 |
| 原子日志写入 | Logger::log() | fopen+flock+fwrite，避免竞态 |
| 敏感数据掩码 | DataLeakDetector | AWS Key 等敏感信息在日志中显示为 `AKIAIOS***XAMPLE` |
| IP 白名单 CIDR | SecurityGuard | 支持 IPv4 ip2long + 位掩码、IPv6 inet_pton + 二进制匹配 |
| IP 攻击升级黑名单 | IpBlacklist | 窗口内攻击计数、自动封禁，可插拔存储后端（File/Redis/Cache），flock 原子写入（File 模式） |
| 默认 log 模式 | config | 高误报检测器默认仅记录不拦截 |

**4. 可插拔存储抽象**

`IpBlacklist` 通过 `StorageInterface` 与持久化层解耦。`SecurityGuard::createStorage()` 工厂根据 `storage.type` 配置创建对应适配器注入：

```php
interface StorageInterface {
    get(string $key): mixed;  set(string $key, mixed $value): void;
    delete(string $key): void; has(string $key): bool;
    all(): array;             clear(): void;
}
```

| 适配器 | 存储方式 | 适用场景 |
|---|---|---|
| `FileStorage` | 单 JSON 文件 + `flock` | 默认，零依赖 |
| `RedisStorage` | Redis（php-redis 扩展） | 分布式 / 高可用 |
| `CacheStorage` | 每 key 独立序列化文件 | 高并发，无单文件写入竞争 |

**5. 框架适配策略**

- 中间件层唯一职责：从框架 Request 提取数据 → 调用 SecurityGuard
- 核心检测逻辑与框架零耦合，仅依赖 PHP 8.1 标准库
- Laravel 通过 `extra.laravel.providers` 自动发现
- Webman/ThinkPHP/Hyperf 手动在中间件配置中注册
- 全局函数 `security_guard()` 支持无框架项目

**6. 扩展新检测器**

```php
// 方式一：正则匹配检测器（继承 AbstractRegexDetector）
// 1. 创建 src/Detector/MyDetector.php
class MyDetector extends AbstractRegexDetector
{
    public function name(): string { return 'my_detector'; }
    protected function patterns(): array {
        return [
            '/attack_pattern/i' => ['severity' => 'high', 'detail' => 'My attack description'],
        ];
    }
}

// 方式二：自定义逻辑检测器（实现 DetectorInterface）
// 适用于检查 $_SERVER、文件系统等非输入数据的场景
class MyCustomDetector implements DetectorInterface
{
    public function name(): string { return 'my_custom'; }
    public function detect(array $data): ?ThreatResult
    {
        // 自定义检测逻辑，可返回自定义 HTTP 状态码
        return new ThreatResult(
            type: 'my_custom',
            severity: 'high',
            field: '_server.SOME_VAR',
            payload: $_SERVER['SOME_VAR'] ?? '',
            detail: 'Custom attack detected',
            httpStatus: 418, // 自定义状态码
        );
    }
}

// 2. 在 SecurityGuard::$detectorMap 中注册
'my_detector' => Detector\MyDetector::class,
'my_custom'   => Detector\MyCustomDetector::class,

// 3. 在 config/security.php 中添加配置
'my_detector' => ['enabled' => true, 'mode' => 'block'],
'my_custom'   => ['enabled' => true, 'mode' => 'block'],
```

## 开源不易，欢迎支持

| 微信 | 支付宝 |
|:---:|:---:|
| ![微信](./docs/weixinpay.png "微信") | ![支付宝](./docs/alipay.png "支付宝") |

---

### 依赖

- PHP >= 8.1
- 零外部依赖

---

## 测试

```bash
composer install
vendor/bin/phpunit
```

```
OK (192 tests, 578 assertions)
```

## License

MIT License — Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
