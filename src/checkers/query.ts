import type { SanitizeIssue } from "../types.js";
import { NULL_BYTE_RE, CRLF_RE } from "../constants.js";

/**
 * Checks the URL query string for injection attacks.
 *
 * Handles:
 * - Null byte injection: %00, \0
 * - CRLF injection: %0d, %0a, \r, \n
 * - XSS payloads embedded in query parameters (javascript: in values)
 */
export function checkQuery(parsed: URL): SanitizeIssue[] {
  const issues: SanitizeIssue[] = [];
  const query = parsed.search; // includes leading ?

  if (!query) return issues;

  if (NULL_BYTE_RE.test(query)) {
    issues.push({
      code: "NULL_BYTE",
      message: `URL query string contains a null byte injection attempt.`,
      component: "query",
    });
  }

  if (CRLF_RE.test(query)) {
    issues.push({
      code: "CRLF_INJECTION",
      message: `URL query string contains a CRLF injection attempt.`,
      component: "query",
    });
  }

  // Check individual parameter values for dangerous scheme injection
  // (e.g. ?redirect=javascript:alert(1))
  for (const [key, value] of parsed.searchParams) {
    if (containsDangerousScheme(value)) {
      issues.push({
        code: "DANGEROUS_SCHEME",
        message: `Query parameter "${key}" contains a dangerous scheme value that could enable XSS.`,
        component: "query",
      });
      break;
    }
  }

  return issues;
}

/**
 * Checks if a string value contains a dangerous scheme after decoding.
 */
function containsDangerousScheme(value: string): boolean {
  const DANGEROUS_SCHEME_RE =
    /(?:javascript|vbscript|jscript|livescript|data\s*:(?:[^,]*,)?(?:text\/html|application\/javascript))/i;

  if (DANGEROUS_SCHEME_RE.test(value)) return true;

  // Try decoded version
  try {
    const decoded = decodeURIComponent(value);
    if (decoded !== value && DANGEROUS_SCHEME_RE.test(decoded)) return true;
  } catch {
    // ignore
  }

  return false;
}
