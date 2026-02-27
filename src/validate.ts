import type { SanitizeOptions } from "./types.js";
import { SanitizeError } from "./types.js";
import { check } from "./check.js";

/**
 * Validates a URL and throws a `SanitizeError` if any security issue is found.
 *
 * Unlike `sanitize()`, this function does not modify the URL — it either
 * passes the URL through unchanged or throws with a detailed error.
 *
 * @param url - The URL string to validate
 * @param options - Optional configuration
 * @throws {SanitizeError} if the URL fails any security check
 *
 * @example
 * validate('https://example.com') // => void (passes)
 *
 * validate('javascript:alert(1)')
 * // throws SanitizeError { code: 'DANGEROUS_SCHEME', ... }
 *
 * validate('https://192.168.1.1/admin')
 * // throws SanitizeError { code: 'SSRF_RISK', ... }
 */
export function validate(url: string, options?: SanitizeOptions): void {
  const result = check(url, options);

  if (!result.safe) {
    const firstIssue = result.issues[0];
    if (!firstIssue) {
      throw new SanitizeError(
        {
          code: "INVALID_URL",
          message: "URL failed validation for an unknown reason.",
          component: "url",
        },
        result.issues
      );
    }
    throw new SanitizeError(firstIssue, result.issues);
  }
}
