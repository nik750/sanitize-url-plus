# sanitize-url-plus

[![npm version](https://img.shields.io/npm/v/sanitize-url-plus.svg)](https://www.npmjs.com/package/sanitize-url-plus)
[![npm downloads](https://img.shields.io/npm/dm/sanitize-url-plus.svg)](https://www.npmjs.com/package/sanitize-url-plus)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)]()

A comprehensive, **zero-dependency** URL sanitization library for Node.js and browsers. Covers every known URL-based attack vector including XSS, SSRF, open redirect, credential injection, path traversal, CRLF injection, null byte injection, IP obfuscation, and IDN homograph attacks.

Built on the **WHATWG URL API** (the same parser browsers use) to eliminate parser-discrepancy vulnerabilities like CVE-2025-56200.

---

## Features

- **Three modes**: `sanitize()` strips danger, `validate()` throws on danger, `check()` returns a detailed result
- **Zero runtime dependencies** — no supply chain risk
- **TypeScript-first** — full type declarations included
- **Dual ESM + CJS** — works with `import` and `require`
- **Configurable** — allowlists, blocklists, scheme control, and more
- **106 tests** covering real-world attack payloads

---

## Installation

```bash
npm install sanitize-url-plus
```

---

## Quick Start

```typescript
import { sanitize, validate, check } from 'sanitize-url-plus';

// sanitize() — strips dangerous parts, returns safe URL or null
sanitize('https://user:pass@example.com/path');
// => 'https://example.com/path'

sanitize('javascript:alert(1)');
// => null

sanitize('http://192.168.1.1/admin');
// => null  (SSRF risk)

// validate() — throws SanitizeError on any issue
validate('https://example.com');           // passes silently
validate('javascript:alert(1)');           // throws SanitizeError
validate('https://192.168.1.1/admin');     // throws SanitizeError

// check() — returns a full result object, never throws
const result = check('https://user:pass@example.com/');
// {
//   safe: false,
//   url: 'https://example.com/',   ← credentials stripped
//   issues: [{ code: 'CREDENTIAL_LEAK', component: 'credentials', message: '...' }]
// }
```

---

## API Reference

### `sanitize(url, options?): string | null`

Strips dangerous components from a URL and returns the sanitized version, or `null` if the URL cannot be made safe.

**Recoverable** (returns cleaned URL):
- Embedded credentials (`user:pass@host`) — stripped automatically

**Unrecoverable** (returns `null`):
- Dangerous scheme (`javascript:`, `vbscript:`, etc.)
- SSRF target (private IP, loopback, cloud metadata)
- IP obfuscation (hex/octal/decimal integer IP)
- Homograph domain (mixed-script or punycode)
- Path traversal (`../`)
- CRLF injection (`%0d%0a`)
- Null byte injection (`%00`)
- Fragment XSS (`#javascript:`)
- URL too long

```typescript
sanitize(url: string, options?: SanitizeOptions): string | null
```

---

### `validate(url, options?): void`

Validates a URL and throws a `SanitizeError` if any security issue is detected. Does **not** modify the URL.

```typescript
validate(url: string, options?: SanitizeOptions): void

// Catching the error
try {
  validate(userInput);
} catch (e) {
  if (e instanceof SanitizeError) {
    console.log(e.code);       // 'SSRF_RISK'
    console.log(e.component);  // 'host'
    console.log(e.issues);     // all issues found
  }
}
```

---

### `check(url, options?): SanitizeResult`

Runs the full pipeline and returns a detailed result object. Never throws.

```typescript
check(url: string, options?: SanitizeOptions): SanitizeResult

interface SanitizeResult {
  safe: boolean;          // true only if zero issues found
  url: string | null;     // sanitized URL, or null if unrecoverable
  issues: SanitizeIssue[];
}

interface SanitizeIssue {
  code: IssueCode;
  message: string;
  component: 'scheme' | 'host' | 'path' | 'query' | 'fragment' | 'url' | 'credentials';
}
```

---

### `SanitizeOptions`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `allowedSchemes` | `string[]` | `['https', 'http']` | URL schemes considered safe |
| `allowPrivateIPs` | `boolean` | `false` | Allow private/loopback IP addresses |
| `allowCredentials` | `boolean` | `false` | Allow `user:pass@` in URLs |
| `allowDataUrls` | `boolean` | `false` | Allow `data:` URLs (still blocks dangerous MIME types) |
| `maxLength` | `number` | `2048` | Maximum URL length in characters |
| `allowHomographDomains` | `boolean` | `false` | Allow mixed-script / punycode domains |
| `allowedHosts` | `string[]` | `[]` | Allowlist of permitted hostnames (prefix with `.` for subdomains) |
| `blockedHosts` | `string[]` | `[]` | Blocklist of forbidden hostnames |

---

### `IssueCode`

| Code | Description |
|------|-------------|
| `DANGEROUS_SCHEME` | `javascript:`, `vbscript:`, or other non-allowed scheme |
| `SSRF_RISK` | Loopback, private IP, cloud metadata, or blocked host |
| `OPEN_REDIRECT` | Protocol-relative or backslash-as-slash redirect trick |
| `CREDENTIAL_LEAK` | `user:pass@` present in URL |
| `NULL_BYTE` | `%00` or `\0` in any URL component |
| `CRLF_INJECTION` | `%0d%0a` or `\r\n` in URL |
| `PATH_TRAVERSAL` | `../` or encoded variants in path |
| `URL_TOO_LONG` | URL exceeds `maxLength` |
| `HOMOGRAPH_DOMAIN` | Mixed-script or suspicious punycode domain |
| `FRAGMENT_XSS` | `javascript:` in URL fragment |
| `DATA_URL_CONTENT` | Dangerous MIME type in `data:` URL |
| `IP_OBFUSCATION` | Hex/octal/decimal integer IP representation |
| `INVALID_URL` | URL cannot be parsed |

---

## Vulnerability Coverage

| Attack Vector | Example Payload | Detected By |
|---------------|----------------|-------------|
| XSS via `javascript:` | `javascript:alert(1)` | Scheme checker |
| XSS via encoded scheme | `%6a%61%76%61%73%63%72%69%70%74:alert(1)` | Protocol normalizer |
| XSS via HTML entity | `&#106;avascript:alert(1)` | Protocol normalizer |
| XSS via uppercase | `JAVASCRIPT:alert(1)` | Scheme checker |
| XSS via whitespace | `\tjavascript:alert(1)` | Protocol normalizer |
| `vbscript:` execution | `vbscript:MsgBox('xss')` | Scheme checker |
| `data:text/html` XSS | `data:text/html,<script>alert(1)</script>` | Scheme + data checker |
| Open redirect (backslash) | `https:\\evil.com` | Protocol normalizer |
| SSRF — loopback | `http://localhost/admin` | Host checker |
| SSRF — private IP | `http://192.168.1.1/` | Host checker |
| SSRF — cloud metadata | `http://169.254.169.254/` | Host checker |
| SSRF — IPv6 loopback | `http://[::1]/` | Host checker |
| IP obfuscation (hex) | `http://0x7f000001/` | Host checker |
| IP obfuscation (octal) | `http://0177.0.0.1/` | Host checker |
| IP obfuscation (decimal) | `http://2130706433/` | Host checker |
| Credential injection | `https://user:pass@evil.com` | Credentials checker |
| Path traversal | `https://example.com/../../../etc/passwd` | Path checker |
| Path traversal (encoded) | `https://example.com/..%2F..%2Fetc` | Path checker |
| Null byte injection | `https://example.com/file%00.txt` | Path/query/fragment checker |
| CRLF injection | `https://example.com/%0d%0aSet-Cookie:evil=1` | Path/query checker |
| Fragment XSS | `https://example.com/#javascript:alert(1)` | Fragment checker |
| IDN homograph | `https://ex\u0430mple.com/` (Cyrillic 'а') | Host checker |
| Punycode obfuscation | `https://xn--e1awd7f.com/` | Host checker |
| URL too long | `https://example.com/` + 2100 chars | Length checker |
| XSS in query param | `?redirect=javascript:alert(1)` | Query checker |

---

## Examples

### Allowlist specific hosts

```typescript
import { sanitize } from 'sanitize-url-plus';

const safeUrl = sanitize(userInput, {
  allowedHosts: ['api.myapp.com', '.cdn.myapp.com'],
});
// Only api.myapp.com and *.cdn.myapp.com are permitted
```

### Internal tooling (allow private IPs)

```typescript
import { validate } from 'sanitize-url-plus';

validate(webhookUrl, {
  allowPrivateIPs: true,
  allowedSchemes: ['https'],
});
```

### Get full issue details

```typescript
import { check } from 'sanitize-url-plus';

const { safe, url, issues } = check(untrustedUrl);

if (!safe) {
  for (const issue of issues) {
    console.warn(`[${issue.code}] ${issue.component}: ${issue.message}`);
  }
}
```

### Allow FTP for file servers

```typescript
import { sanitize } from 'sanitize-url-plus';

const url = sanitize(input, {
  allowedSchemes: ['https', 'http', 'ftp'],
  allowedHosts: ['.files.example.com'],
});
```

---

## How It Works

The sanitizer runs a multi-stage pipeline:

```
Raw URL string
    │
    ▼
[1] Length check          — reject URLs exceeding maxLength
    │
    ▼
[2] Protocol normalizer   — strip control chars, decode HTML entities,
    │                        decode percent-encoded schemes, normalize backslashes
    ▼
[3] WHATWG URL parser     — parse with the same engine browsers use
    │                        (avoids parser-discrepancy CVEs)
    ▼
[4] Scheme checker        — enforce allowedSchemes, block always-dangerous schemes,
    │                        inspect data: URL MIME types
    ▼
[5] Credentials checker   — detect and strip user:pass@ from URL
    │
    ▼
[6] Host checker          — SSRF (loopback, private IP, cloud metadata),
    │                        IP obfuscation (hex/octal/decimal), homograph detection
    ▼
[7] Path checker          — path traversal (../ and encoded variants),
    │                        null byte, CRLF injection
    ▼
[8] Query checker         — null byte, CRLF, dangerous scheme in param values
    │
    ▼
[9] Fragment checker      — javascript: in fragment, null byte, CRLF
    │
    ▼
  Result
```

---

## Security Notes

- **Parser-discrepancy protection**: Uses the WHATWG `URL` constructor (Node.js built-in) as the single source of truth for URL parsing. This prevents the class of vulnerabilities where a validator uses different parsing rules than the downstream consumer (e.g. CVE-2025-56200 in validator.js).

- **Zero dependencies**: No third-party runtime dependencies means no transitive supply-chain risk.

- **Defense in depth**: The normalizer decodes obfuscated schemes *before* parsing, catching attacks that rely on the parser being more lenient than the validator.

- **This library sanitizes URLs, not HTML**. If you are inserting URLs into HTML attributes, you still need to HTML-encode the output.

---

## Requirements

- Node.js 18 or later (for built-in WHATWG `URL` support)
- TypeScript 5.x (for development)

---

## License

[Apache 2.0](LICENSE)
