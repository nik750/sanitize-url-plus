import type { SanitizeIssue, SanitizeOptions } from "../types.js";
import { DEFAULT_MAX_LENGTH } from "../constants.js";

/**
 * Checks that the URL does not exceed the maximum allowed length.
 *
 * Overly long URLs are a signal for:
 * - DoS attacks (parser exhaustion)
 * - Obfuscation (hiding malicious content in a sea of noise)
 * - Bypassing security filters that truncate input
 */
export function checkLength(
  url: string,
  options: Required<SanitizeOptions>
): SanitizeIssue[] {
  const maxLength = options.maxLength ?? DEFAULT_MAX_LENGTH;

  if (url.length > maxLength) {
    return [
      {
        code: "URL_TOO_LONG",
        message: `URL length (${url.length}) exceeds the maximum allowed length of ${maxLength} characters.`,
        component: "url",
      },
    ];
  }

  return [];
}
