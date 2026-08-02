# Security PHP 代码审查报告

**日期**：2026-08-02
**测试结果**：192 tests, 578 assertions — 全部通过
**代码规模**：~3900 行（src + tests）

---

## 一、严重问题（Bug）

### 1.1 FileStorage 读写竞态条件

**文件**：`src/Storage/FileStorage.php:26-31`

```php
public function set(string $key, mixed $value): void
{
    $data = $this->read();   // 读
    $data[$key] = $value;
    $this->write($data);      // 写 — 中间无锁
}
```

`read()` 和 `write()` 之间没有锁保护。两个并发请求可能：
1. 请求 A 读取 `{ip1: {count: 3}}`
2. 请求 B 读取 `{ip1: {count: 3}}`
3. 请求 A 写入 `{ip1: {count: 4}}`
4. 请求 B 写入 `{ip1: {count: 4}}` — A 的递增丢失

虽然 `write()` 内部有 `flock`，但锁仅覆盖写入操作，不覆盖整个 read-modify-write 周期。

**建议**：在 `set()` 方法级别使用 `c+` 模式打开文件并全程持锁。

### 1.2 Logger 去重缓存无上限，长时间运行可能内存泄漏

**文件**：`src/Logger.php:79-93`

去重缓存 `$this->dedupCache` 只在检测重复时惰性清理过期条目。在 Swoole/Workerman 等常驻进程模式下，如果攻击者不断变换 IP，缓存会无限增长。

**建议**：增加最大缓存条目限制（如 1000 条），超过时淘汰最旧的条目。

### 1.3 Logger 日志轮转存在竞态窗口

**文件**：`src/Logger.php:57-65`

```php
flock($fp, LOCK_UN);
fclose($fp);
rename($this->path, ...);     // 释放锁后 rename
$fp = fopen($this->path, 'a'); // 另一个进程可能在此之间创建了文件
```

释放锁→rename→重新打开之间存在窗口，另一个进程可能已经创建了新文件。

**建议**：使用 `'c'` 模式保持文件打开，在持有锁的情况下完成轮转。

---

## 二、中等问题（设计与健壮性）

### 2.1 RedisStorage::all() 使用 KEYS 命令

**文件**：`src/Storage/RedisStorage.php:73`

```php
$keys = $this->redis->keys($this->prefix . '*');
```

`KEYS *` 在生产环境中会阻塞 Redis 服务器所有其他操作。当 key 数量多时，可能导致 Redis 短暂不可用。

**建议**：改用 `SCAN` 迭代器，或在文档中注明此方法仅用于测试/调试。

### 2.2 四个检测器直接依赖 `$_SERVER` 超全局变量

**文件**：`HttpMethodDetector.php`、`BodySizeDetector.php`、`ContentTypeDetector.php`、`CsrfOriginDetector.php`

这四个检测器直接读取 `$_SERVER`，与其他检测器（通过 `$data` 参数接收输入）的设计不一致：
- 单元测试必须修改全局状态
- 无法在 CLI 脚本、队列 Worker 等非 HTTP 上下文中使用

**建议**：通过 `SecurityGuard::guard()` 的 `$meta` 参数传递 server 信息。

### 2.3 无输入值大小限制

**文件**：`src/Detector/AbstractRegexDetector.php:23-51`

检测器对所有输入值不做长度限制。对于包含大量文本的字段，每个检测器都会对整个值做正则匹配，即使 `pcre.backtrack_limit` 已设置，仍可能造成显著的 CPU 消耗。

**建议**：在 `AbstractRegexDetector::detect()` 中增加最大扫描长度限制（如 64KB），超过则截断或跳过。

### 2.4 AbstractRegexDetector 仅返回第一个匹配

**文件**：`src/Detector/AbstractRegexDetector.php:39-47`

```php
if ($result === 1) {
    return new ThreatResult(...);  // 立即返回，跳过其余字段和模式
}
```

如果请求同时触发同一检测器的多个攻击模式，只会报告第一个。对于拦截场景足够，但日志/监控场景会丢失完整的攻击画像。

**建议**：考虑改为返回数组或 yield 模式。短期可在 `DetectorChain::scan()` 中增加选项控制是否早停。

### 2.5 IP 地址无格式校验

**文件**：`src/SecurityGuard.php:101,107`

`$ip` 参数可以是任意字符串，不检查是否为合法 IP 格式。非法值虽不会造成安全问题，但可能在存储中产生垃圾数据。

**建议**：增加 `filter_var($ip, FILTER_VALIDATE_IP)` 校验。

### 2.6 检测器无优先级排序

**文件**：`src/DetectorChain.php`

所有检测器按注册顺序执行，无优先级区分。廉价检测器（如 `body_size`：一次整数比较）和昂贵检测器（如 `data_leak`：多个复杂正则）没有区别对待。

**建议**：为检测器增加优先级/代价属性，让廉价检测器先运行。

### 2.7 上游依赖保持更新可避免潜在漏洞

`composer.json` 中仅依赖 `php: >=8.1` 和 `phpunit: ^12.5`（dev），零第三方运行时依赖是优点。但 PHP 本身的安全更新需要使用者自行关注。

---

## 三、优化建议

### 3.1 正则预检优化

对每个 pattern 先做快速的 `stripos` 预检，匹配特征子串后再执行完整正则，可减少约 30-50% 的 `preg_match` 调用。

### 3.2 检测器实例复用

当前 `SecurityGuard::init()` 中每个检测器 `new` 一次后加入链。对于高频请求场景，可考虑对象池或单例模式（但当前设计已足够好）。

### 3.3 composer.json 描述过时

`composer.json:3` 描述为 "27 threat detectors"，实际已支持 31 种，建议更新。

---

## 四、测试覆盖评估

| 维度 | 评分 | 说明 |
|------|------|------|
| 检测器正向覆盖 | ★★★★★ | 31 个检测器全部有攻击 payload 测试 |
| 检测器反向覆盖 | ★★★★★ | 正常输入不触发误报的测试充分 |
| 边界条件 | ★★★★☆ | 涵盖空数组、非字符串值、null 字节、白名单、IPv4/IPv6 CIDR |
| 存储后端 | ★★★★☆ | FileStorage 和 CacheStorage 有完整测试；RedisStorage 需 Redis 环境跳过 |
| 并发场景 | ★★☆☆☆ | 无并发/竞态测试 |
| 性能基准 | ☆☆☆☆☆ | 无性能基准或大数据量测试 |
| $_SERVER 检测器 | ★★★☆☆ | 有测试但依赖全局状态修改 |

---

## 五、总体评价

### 优点

- **架构清晰**：DetectorInterface → AbstractRegexDetector → 具体检测器的三层抽象优秀，新增检测器成本极低
- **零外部依赖**：核心检测仅需 PHP 8.1 标准库，部署简单
- **框架适配优雅**：中间件层与核心检测逻辑完全解耦，4 个框架适配器职责单一
- **安全措施到位**：PCRE 回溯限制、日志 CRLF 注入防护、敏感数据掩码、原子日志写入、IP CIDR 白名单
- **测试覆盖全面**：192 个测试覆盖所有检测器的正/反向用例和核心组件
- **配置灵活**：每个检测器独立可配置（启用/禁用 + block/log 模式），可自定义 HTTP 状态码
- **可插拔存储**：File/Redis/Cache 三种后端，接口清晰

### 改进优先级汇总

| 优先级 | 问题 | 影响范围 |
|--------|------|----------|
| P0 | FileStorage 读写竞态 (1.1) | 高并发下 IP 黑名单计数可能丢失 |
| P1 | Logger 去重缓存无上限 (1.2) | 常驻进程可能内存泄漏 |
| P1 | RedisStorage KEYS 阻塞 (2.1) | 生产环境 Redis 阻塞风险 |
| P2 | $_SERVER 直接依赖 (2.2) | CLI/队列场景无法使用 |
| P2 | 无输入大小限制 (2.3) | 大 payload 场景 CPU 消耗 |
| P3 | 仅返回第一个匹配 (2.4) | 日志完整性损失 |
| P3 | 检测器无优先级 (2.6) | 性能优化空间 |

---

## 六、修复建议代码

### 6.1 FileStorage 原子化 set()（P0）

```php
public function set(string $key, mixed $value): void
{
    $fp = @fopen($this->path, 'c+');
    if ($fp === false) return;

    if (flock($fp, LOCK_EX)) {
        $raw = stream_get_contents($fp);
        $data = json_decode($raw ?: '{}', true) ?: [];
        $data[$key] = $value;

        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
        fflush($fp);
        flock($fp, LOCK_UN);
    }
    fclose($fp);
}
```

### 6.2 Logger 去重缓存上限（P1）

```php
private function isDuplicate(ThreatResult $threat, array $meta): bool
{
    // ... 现有清理逻辑 ...

    // 防止内存无限增长
    if (count($this->dedupCache) > 1000) {
        $this->dedupCache = array_slice($this->dedupCache, -500, preserve_keys: true);
    }

    $this->dedupCache[$key] = $now + $this->dedupWindow;
    return false;
}
```

### 6.3 输入大小限制（P2）

```php
abstract class AbstractRegexDetector implements DetectorInterface
{
    private const MAX_SCAN_LENGTH = 65536; // 64KB

    public function detect(array $data): ?ThreatResult
    {
        foreach ($data as $field => $value) {
            if (!is_string($value)) {
                continue;
            }
            // 超长值截断扫描
            $scanValue = strlen($value) > self::MAX_SCAN_LENGTH
                ? substr($value, 0, self::MAX_SCAN_LENGTH)
                : $value;
            foreach ($this->patterns() as $pattern => $info) {
                // ...
            }
        }
        return null;
    }
}
```
