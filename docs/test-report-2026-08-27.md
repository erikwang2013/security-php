# 单元测试报告 — 2026-08-27

## 结论

| 指标 | 数值 |
|---|---|
| 测试总数 | **338** |
| 通过 | **337** |
| 失败 | **0** |
| 跳过 | **1**（标记 src 缺陷，见缺陷 #1） |
| 断言数 | 833 |
| 运行时间 | ~6.4s（PHP 8.3.7，phpunit 12.5.25） |
| 可重复性 | 连续 3 次运行全绿（无 /tmp 共享状态累积） |

测试方法 194 个（DataProvider 展开后 338 个用例）。

## 新增 / 修改的测试文件

| 文件 | 测试方法数 | 覆盖内容 |
|---|---|---|
| `tests/Core/ThreatResultTest.php`（新增） | 2 | ThreatResult 构造与默认值 |
| `tests/Core/SecurityGuardAdvancedTest.php`（新增） | 23 | 可信代理/XFF 解析（for= 语法、伪造 XFF、无效 XFF）、meta 注入（method/TE/CL/CT/origin+host）、flatten 冲突 # 后缀、JSON 数组值、自定义白名单字段、detectorOption、自定义 allowed_methods/max_size/allowed_types/allowed_origins、storage 三种后端 + instance 注入、block_message、shouldBlock 未知类型默认 log |
| `tests/Core/StorageTest.php`（新增） | 9 | FileStorage（损坏 JSON 恢复、默认路径、自动建目录）、CacheStorage（过期清理、损坏文件、空目录 noop）、RedisStorage（真实 Redis 读写/scan/前缀隔离，无服务器自动跳过） |
| `tests/Core/HelpersTest.php`（新增） | 7 | security_scan / security_is_safe / security_scan_current_request（superglobals）/ security_guard 拦截（子进程验证 die）与放行 |
| `tests/Core/InstallerTest.php`（新增） | 8 | Composer 插件：事件注册、activate 发布配置（Laravel/Webman/ThinkPHP/Hyperf 目标）、不覆盖已有配置、未知项目不发布、onPackageInstall 仅处理自身包、onPackageUpdate 用 targetPackage、4 个 is* 框架探测函数（含 Composer 类 stub，因 composer/composer 非 dev 依赖） |
| `tests/Middleware/MiddlewareTest.php`（新增） | 10 | 4 个框架中间件适配器（Laravel/Webman/ThinkPHP/Hyperf）：拦截 403 + 放行 + 文件上传拦截（框架与 PSR-7 类均用本地 stub，均带 class_exists 守卫） |
| `tests/Detector/DetectorEdgeCasesTest.php`（新增） | 39 | AbstractRegexDetector 64KB 截断（头/尾命中、中缝盲区）、无效正则跳过并继续、优先级默认值；DataLeak Luhn 过滤与长密钥掩码；JWT 非 JSON 头/大写 NONE/kid 管道与路径穿越/空签名；原型污染直接键字符串值/defineSetter/Object.create/toString 覆盖；DNS Rebinding 端口剥离/单标签/伪 TLD；Upload 嵌套多文件/缺 tmp 扩展名检查/大小写/无扩展名/.env；请求走私混淆 TE/折叠头/注入 CL/双 TE；WebSocket 原始 URL/密钥头注入/合法 Origin 不误报；CORS Max-Age 与 preflight |
| `tests/Core/DetectorChainTest.php`（修改） | +2 | 优先级升序排序、同优先级保持插入序 |

## 覆盖矩阵

### 核心类

| 类 | 方法 | 覆盖状态 |
|---|---|---|
| `SecurityGuard` | init / guard / shouldBlock / blockStatusCode / blockMessage / detectorOption / getIpBlacklist / reset | ✅ 全绿 |
| | resolveClientIp（可信代理、XFF 首跳、for= 语法、无效回退） | ✅ |
| | ipMatches（IPv4/IPv6 CIDR、无 CIDR、/0、/33、畸形前缀） | ✅ |
| | matchCidrBinary / filterWhitelistFields / flattenData（嵌套、冲突 # 后缀、JSON 表示） | ✅ |
| | createStorage（file / cache / redis / instance 注入） | ✅ |
| `ThreatResult` | 构造、httpStatus 默认 403 与覆盖 | ✅ |
| `DetectorChain` | add（优先级排序）/ scan / count / 空链 | ✅ |
| `IpBlacklist` | record / isBanned / getBanInfo / reset、窗口过期、封禁过期、阈值 | ✅（既有） |
| `Logger` | log / 轮转 / 去重 / 清洗 CRLF 与管道 / 截断 / disabled | ✅（既有） |
| `helpers.php` | security_scan / security_is_safe / security_scan_current_request / security_guard（子进程） | ✅ |
| `Composer\Installer` | activate / deactivate / uninstall / getSubscribedEvents / onPackageInstall / onPackageUpdate / publishConfig / detectTargets / isLaravel / isWebman / isThinkPHP / isHyperf | ✅ |

### 存储

| 类 | 方法 | 覆盖状态 |
|---|---|---|
| `StorageInterface` | 全接口 | ✅ |
| `FileStorage` | get/set/delete/has/all/clear、损坏 JSON、缺目录、默认路径 | ✅ |
| `CacheStorage` | get/set/delete/has/clear、过期条目、损坏文件 | ✅ |
| | **all()** | ⚠️ 跳过（src 缺陷 #1，无法枚举） |
| `RedisStorage` | get/set/delete/has/all/clear、前缀隔离（真实 Redis，无服务器自动跳过） | ✅ |

### 中间件

| 适配器 | 覆盖状态 |
|---|---|
| `middleware/Laravel/SecurityMiddleware` | ✅ 拦截 403 / 放行 / PHP 上传拦截 |
| `middleware/Webman/SecurityMiddleware` | ✅ 拦截 403 / 放行 / PHP 上传拦截（含插件配置路径回退） |
| `middleware/Thinkphp/SecurityMiddleware` | ✅ 拦截 403 / 放行 |
| `middleware/Hyperf/SecurityMiddleware` | ✅ 拦截 403 / 放行 |
| `middleware/Laravel/SecurityServiceProvider` | 未覆盖（Laravel 服务提供者胶水，非中间件本体；需完整 Laravel 容器） |

### 31 个 Detector

| Detector | 正向用例 | 误报用例 | 专项逻辑 |
|---|---|---|---|
| XssDetector | 6 | 3 | ✅ |
| SqlInjectionDetector | 12 | 5 | ✅ |
| CommandInjectionDetector | 6 | 2 | ✅（反引号中文文本不高危） |
| PathTraversalDetector | 6 | 3 | ✅ |
| UploadDetector | — | — | ✅ 内容 PHP 标签（含 2048 字节处）、扩展名白名单逐段、多文件/嵌套数组、缺 tmp、.env、大小写 |
| SsrfDetector | 12 | 2 | ✅ |
| XxeDetector | 3 | 1 | ✅ |
| HeaderInjectionDetector | 4 | 2 | ✅ |
| DeserializationDetector | 4 | 2 | ✅ |
| LdapInjectionDetector | 3 | 2 | ✅ |
| MailHeaderDetector | 3 | — | ✅ |
| SstiDetector | 5 | 2 | ✅ |
| NosqlInjectionDetector | 4 | 1 | ✅ |
| OpenRedirectDetector | 5 | 2 | ✅ |
| JwtAttackDetector | 3 | 1 | ✅ 非 JSON 头、大写 NONE、kid 管道/穿越、空签名、HMAC 普通 kid 不误报 |
| HostHeaderDetector | 3 | — | ✅ |
| RequestSmugglingDetector | 3 | — | ✅ 混淆 TE、折叠头、注入 CL、双 TE critical |
| GraphqlInjectionDetector | 4 | 2 | ✅ |
| XpathInjectionDetector | 3 | 1 | ✅ |
| JndiInjectionDetector | 4 | 1 | ✅ |
| SsiInjectionDetector | 3 | — | ✅ |
| CsvInjectionDetector | 3 | 1 | ✅ |
| DataLeakDetector | 4 | 3 | ✅ Luhn 过滤（无效卡号剔除、多值只留有效）、长密钥掩码 |
| PrototypePollutionDetector | 3 | 2 | ✅ 直接键（字符串值）、defineSetter、Object.create、toString 覆盖 |
| WebSocketDetector | 2 | — | ✅ 原始 ws:// URL、Sec-WebSocket-Key、合法 Origin 不误报 |
| CorsDetector | 2 | — | ✅ Max-Age low、preflight medium |
| DnsRebindingDetector | 7 | 2 | ✅ 端口剥离、IPv6+端口、单标签 medium、myhost.local 不报、普通字段裸 IP 不报 |
| HttpMethodDetector | — | — | ✅ TRACE 405、白名单方法、自定义 allowed_methods |
| BodySizeDetector | — | — | ✅ 413、正常体、自定义 max_size |
| ContentTypeDetector | — | — | ✅ 415、参数剥离、自定义 allowed_types |
| CsrfOriginDetector | — | — | ✅ 403、同源、端口、allowed_origins |
| AbstractRegexDetector | — | — | ✅ 64KB 头/尾扫描、中缝盲区（文档化）、无效正则跳过、priority 默认 0 |

## 发现的 src 缺陷清单（未修复，交修复组）

1. **`src/Storage/CacheStorage.php:88-94` — `all()` 永远返回空数组（功能性缺陷）**
   文件名只存 `md5($key)`，`all()` 从文件名反推 key 后再调 `get($key)`，`get()` 会对 key 再次 md5 查找 → 永远 miss。`CacheStorage` 无法枚举任何已存条目（`all()` 恒为 `[]`）。
   测试：`tests/Core/StorageTest::testCacheStorageAllSkipsExpiredAndMissing` 被 `markTestSkipped` 标记，修复后应自动恢复断言。

2. **`src/Detector/AbstractRegexDetector.php:40` — 无效正则先抛 E_WARNING 再走 error_log（健壮性缺陷）**
   `preg_match()` 对无效模式在返回 false 之前已发出 `E_WARNING: Compilation failed`。库内虽有 error_log + continue 的优雅处理，但 warning 已逃逸：在 `failOnWarning=true` 的构建（本项目 phpunit.xml）或把 warning 转异常的框架下会直接报错/崩溃。
   测试：`DetectorEdgeCasesTest::testRegexDetectorSkipsInvalidPatternAndContinues` 用临时 error handler 吞掉该 warning 后验证了库自身的处理路径。

3. **`src/Composer/Installer.php:39,50` — `onPackageInstall`/`onPackageUpdate` 依赖未初始化的 `$this->io`（潜在崩溃）**
   `private IOInterface $io` 无默认值，只在 `activate()` 中赋值；事件回调里 `publishConfig()` 使用 `$this->io->write()`。真实 Composer 总是先 activate 再派发事件所以不炸，但任何绕过 activate 的直接调用（测试/其他调度器）会 `Error: Typed property ... must not be accessed before initialization`。建议给 `$io` 默认值或事件回调内做空判断。

4. **`src/Storage/FileStorage.php:107-131` — `write()` 为死代码**
   私有方法 `write()` 全类无调用（实际写入走 `mutate()`）。建议删除或确认是否为预留接口。

## 备注

- 无 xdebug，覆盖率矩阵基于逐文件人工追踪（已通读全部 src/middleware/config）。
- Redis 相关测试（RedisStorage、storage type=redis）连接 127.0.0.1:6379，服务器不可用时自动 skip（3 个用例）。
- `Composer\Installer` 与 4 个中间件在无框架依赖环境下通过本地 stub 测试，所有 stub 均带 `class_exists`/`interface_exists`/`function_exists` 守卫，真实框架安装后不会冲突。
- `security_guard()` 的 die() 路径用子进程验证（`HelpersTest::runSubprocess`）。

## 缺陷修复记录（2026-08-27，修复组）

全部 4 个缺陷已修复，338 测试（834 断言）全绿：

1. **CacheStorage::all() 恒空** — 文件格式改为 `[expiry, key, value]`，`all()` 从文件内容恢复 key；`get()` 兼容旧 `[expiry, value]` 格式并校验 key（md5 碰撞防护）。原 skip 测试已恢复硬断言并通过。
2. **AbstractRegexDetector 无效正则 E_WARNING 逃逸** — PHP 8.0+ 无效正则抛 `ValueError`，已加 try/catch 兜底（与 error_log + continue 路径并存），warning/异常均不再逃逸。
3. **Installer `$this->io` 未初始化** — 属性改 `?IOInterface $io = null`，`publishConfig()` 用 `$this->io?->write()`；绕过 activate() 直接调用不再崩溃（静默不写日志）。不引入 NullIO（vendor 无 Composer IO 类）。
4. **FileStorage::write() 死代码** — 已删除。

PHP 8.0+ 兼容：`composer.json` `php: >=8.0`（原 >=8.1），`ThreatResult` 移除 `readonly`（8.1 特性），lock 已同步。
