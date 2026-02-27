/**
 * sanitize-url-plus
 *
 * A comprehensive, zero-dependency URL sanitization library covering all known
 * URL-based attack vectors including XSS, SSRF, open redirect, credential
 * injection, homograph attacks, path traversal, CRLF injection, and more.
 *
 * @example
 * import { sanitize, validate, check } from 'sanitize-url-plus';
 *
 * // Sanitize: strip dangerous parts, return safe URL or null
 * const safe = sanitize('https://user:pass@example.com/path');
 * // => 'https://example.com/path'
 *
 * // Validate: throw on any issue
 * validate('https://example.com'); // passes
 * validate('javascript:alert(1)'); // throws SanitizeError
 *
 * // Check: get full result object
 * const result = check('https://192.168.1.1/admin');
 * // => { safe: false, url: null, issues: [{ code: 'SSRF_RISK', ... }] }
 */

export { sanitize } from "./sanitize.js";
export { validate } from "./validate.js";
export { check } from "./check.js";
export { SanitizeError } from "./types.js";
export type {
  SanitizeOptions,
  SanitizeResult,
  SanitizeIssue,
  IssueCode,
  UrlComponent,
} from "./types.js";
