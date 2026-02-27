# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-27

### Added

- Initial release
- `sanitize(url, options?)` — strips dangerous URL components, returns safe URL or null
- `validate(url, options?)` — throws `SanitizeError` on any security issue
- `check(url, options?)` — returns full `SanitizeResult` with all detected issues
- `SanitizeError` class with `code`, `component`, and `issues` properties
- Full TypeScript types: `SanitizeOptions`, `SanitizeResult`, `SanitizeIssue`, `IssueCode`, `UrlComponent`
- Vulnerability coverage:
  - XSS via `javascript:`, `vbscript:`, encoded/obfuscated schemes
  - SSRF via loopback, private IP ranges (RFC 1918), cloud metadata endpoints
  - IP address obfuscation (hex, octal, decimal integer)
  - Credential injection (`user:pass@host`)
  - Path traversal (`../`, `..%2F`, `%2e%2e%2f`)
  - Null byte injection (`%00`)
  - CRLF injection (`%0d%0a`)
  - Fragment XSS (`#javascript:`)
  - IDN homograph / mixed-script domains
  - Punycode domain obfuscation
  - Dangerous `data:` URL MIME types
  - Overly long URLs
  - Open redirect via backslash normalization
- Dual ESM + CJS build output
- Zero runtime dependencies
