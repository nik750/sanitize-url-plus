import type { SanitizeOptions } from "./types.js";
import { check } from "./check.js";

/**
 * Sanitizes a URL by stripping dangerous components and returning a safe URL.
 *
 * - Strips embedded credentials (user:pass@host)
 * - Normalizes backslash-as-slash tricks
 * - Strips null bytes and CRLF from path/query/fragment
 * - Returns `null` if the URL is fundamentally unsafe and cannot be recovered
 *   (e.g. `javascript:` scheme, SSRF target, homograph domain, too long)
 *
 * @param url - The URL string to sanitize
 * @param options - Optional configuration
 * @returns The sanitized URL string, or `null` if the URL cannot be made safe
 *
 * @example
 * sanitize('https://user:pass@example.com/path')
 * // => 'https://example.com/path'
 *
 * sanitize('javascript:alert(1)')
 * // => null
 *
 * sanitize('https://example.com/../../../etc/passwd')
 * // => null  (path traversal detected)
 */
export function sanitize(url: string, options?: SanitizeOptions): string | null {
  const result = check(url, options);
  return result.url;
}
