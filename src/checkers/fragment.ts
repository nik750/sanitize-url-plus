import type { SanitizeIssue } from "../types.js";
import { FRAGMENT_XSS_RE, NULL_BYTE_RE, CRLF_RE } from "../constants.js";

/**
 * Checks the URL fragment (#...) for XSS and injection attacks.
 *
 * Handles:
 * - javascript: in fragment (some frameworks use fragment for routing)
 * - Null byte injection
 * - CRLF injection
 */
export function checkFragment(parsed: URL): SanitizeIssue[] {
  const issues: SanitizeIssue[] = [];
  // parsed.hash includes the leading #
  const fragment = parsed.hash.replace(/^#/, "");

  if (!fragment) return issues;

  if (FRAGMENT_XSS_RE.test(fragment)) {
    issues.push({
      code: "FRAGMENT_XSS",
      message: `URL fragment contains a "javascript:" scheme that could be executed by client-side routers.`,
      component: "fragment",
    });
  }

  if (NULL_BYTE_RE.test(fragment)) {
    issues.push({
      code: "NULL_BYTE",
      message: `URL fragment contains a null byte injection attempt.`,
      component: "fragment",
    });
  }

  if (CRLF_RE.test(fragment)) {
    issues.push({
      code: "CRLF_INJECTION",
      message: `URL fragment contains a CRLF injection attempt.`,
      component: "fragment",
    });
  }

  // Check decoded fragment as well
  try {
    const decoded = decodeURIComponent(fragment);
    if (decoded !== fragment) {
      if (FRAGMENT_XSS_RE.test(decoded) && !issues.some((i) => i.code === "FRAGMENT_XSS")) {
        issues.push({
          code: "FRAGMENT_XSS",
          message: `URL fragment contains an encoded "javascript:" scheme.`,
          component: "fragment",
        });
      }
    }
  } catch {
    // ignore malformed encoding
  }

  return issues;
}
