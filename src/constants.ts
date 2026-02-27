/**
 * URL schemes considered safe by default.
 */
export const DEFAULT_ALLOWED_SCHEMES: readonly string[] = ["https", "http"];

/**
 * URL schemes that are always dangerous regardless of options.
 * These cannot be recovered by sanitization — the URL must be rejected.
 */
export const ALWAYS_DANGEROUS_SCHEMES: readonly string[] = [
  "javascript",
  "vbscript",
  "jscript",
  "livescript",
  "mocha",
];

/**
 * Schemes that carry executable or sensitive content and are blocked
 * unless explicitly opted in via allowedSchemes.
 */
export const SENSITIVE_SCHEMES: readonly string[] = [
  "data",
  "blob",
  "file",
  "ftp",
  "ftps",
  "sftp",
  "gopher",
  "dict",
  "phar",
  "smb",
  "ldap",
  "ldaps",
  "telnet",
  "nntp",
  "irc",
  "ircs",
  "ws",
  "wss",
];

/**
 * data: URL MIME types that can execute code or exfiltrate data.
 */
export const DANGEROUS_DATA_MIME_TYPES: readonly string[] = [
  "text/html",
  "text/xml",
  "application/xhtml+xml",
  "application/xml",
  "application/javascript",
  "application/ecmascript",
  "text/javascript",
  "text/ecmascript",
  "application/x-javascript",
  "application/vnd.ms-htmlhelp",
  "application/x-www-form-urlencoded",
  "multipart/form-data",
  "application/octet-stream",
];

/**
 * Default maximum URL length. IE/older proxies cap at 2048; modern browsers
 * support much more, but very long URLs are a DoS/obfuscation signal.
 */
export const DEFAULT_MAX_LENGTH = 2048;

// ---------------------------------------------------------------------------
// IP address patterns
// ---------------------------------------------------------------------------

/**
 * Loopback hostnames that should never be reached from user-supplied URLs.
 */
export const LOOPBACK_HOSTNAMES: readonly string[] = [
  "localhost",
  "localtest.me",
  "lvh.me",
  "vcap.me",
  "lacolhost.com",
  "127.0.0.1",
  "::1",
  "[::1]",
  "0.0.0.0",
  "[::ffff:127.0.0.1]",
  "[::ffff:7f00:1]",
];

/**
 * Cloud provider metadata endpoints that are common SSRF targets.
 */
export const CLOUD_METADATA_HOSTS: readonly string[] = [
  "169.254.169.254",          // AWS / GCP / Azure IMDS
  "metadata.google.internal", // GCP
  "169.254.170.2",            // AWS ECS task metadata
  "fd00:ec2::254",            // AWS IPv6 metadata
  "[fd00:ec2::254]",
  "100.100.100.200",          // Alibaba Cloud metadata
];

// ---------------------------------------------------------------------------
// Regex patterns — all pre-compiled to avoid ReDoS
// ---------------------------------------------------------------------------

/**
 * Matches null bytes in any encoding form.
 */
export const NULL_BYTE_RE = /(?:%00|\x00|\\0)/i;

/**
 * Matches CRLF sequences in any encoding form.
 */
export const CRLF_RE = /(?:%0[dD]|%0[aA]|\r|\n)/;

/**
 * Matches path traversal sequences in decoded or encoded form.
 * Covers: ../ ..\  %2e%2e%2f  %2e%2e/  ..%2f  ..%5c  %2e./  .%2e/
 */
export const PATH_TRAVERSAL_RE =
  /(?:\.\.[\\/]|%2e%2e[\\/]|%2e%2e%2f|%2e%2e%5c|\.\.%2f|\.\.%5c|%2e\.[\\/]|\.%2e[\\/])/i;

/**
 * Matches a javascript: scheme in fragment, accounting for whitespace and
 * common encoding tricks.
 */
export const FRAGMENT_XSS_RE = /^[\s\u0000]*j[\s\u0000]*a[\s\u0000]*v[\s\u0000]*a[\s\u0000]*s[\s\u0000]*c[\s\u0000]*r[\s\u0000]*i[\s\u0000]*p[\s\u0000]*t[\s\u0000]*:/i;

/**
 * Matches hex-encoded IP addresses like 0x7f000001.
 */
export const HEX_IP_RE = /^0x[0-9a-f]{1,8}$/i;

/**
 * Matches octal-encoded IP addresses like 0177.0.0.1.
 */
export const OCTAL_IP_RE = /^0[0-7]+(?:\.0[0-7]+){0,3}$/;

/**
 * Matches a pure decimal integer that could be an IPv4 address (e.g. 2130706433).
 */
export const DECIMAL_IP_RE = /^\d{8,10}$/;

/**
 * Matches backslash characters that some parsers treat as forward slashes.
 */
export const BACKSLASH_RE = /\\/g;

/**
 * Matches leading/trailing whitespace and control characters that are
 * stripped by browsers before parsing (tab, newline, carriage return).
 */
export const URL_WHITESPACE_RE = /[\t\n\r\u0000\u0001-\u001f\u007f]/g;

/**
 * Matches HTML entity encoding of characters used in scheme names.
 * e.g. &#106; = 'j', &#x6A; = 'j'
 */
export const HTML_ENTITY_RE = /&#(?:x[0-9a-f]+|[0-9]+);?/gi;

/**
 * Matches punycode labels in a domain (xn--...).
 */
export const PUNYCODE_LABEL_RE = /(?:^|\.)xn--[a-z0-9-]+/i;

/**
 * Unicode script ranges for homograph detection.
 * We flag domains that mix Latin characters with visually similar
 * characters from Cyrillic, Greek, or other scripts.
 *
 * This regex matches characters that are NOT in the basic Latin/ASCII range
 * but ARE in scripts known to have Latin lookalikes.
 */
export const MIXED_SCRIPT_RE =
  /[\u0400-\u04FF\u0370-\u03FF\u0250-\u02AF\u1D00-\u1DBF\u2C60-\u2C7F\uA720-\uA7FF]/;
