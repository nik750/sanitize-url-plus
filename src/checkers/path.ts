import type { SanitizeIssue } from "../types.js";
import { NULL_BYTE_RE, CRLF_RE, PATH_TRAVERSAL_RE } from "../constants.js";

/**
 * Checks the URL path for injection and traversal attacks.
 *
 * Handles:
 * - Path traversal: ../, ..%2F, %2e%2e%2f, ..%5c
 * - Null byte injection: %00, \0
 * - CRLF injection: %0d, %0a, \r, \n
 *
 * @param parsed - The parsed URL object
 * @param rawUrl - The original raw URL string before WHATWG normalization,
 *                 used to detect traversal sequences that the parser resolves away
 */
export function checkPath(parsed: URL, rawUrl?: string): SanitizeIssue[] {
  const issues: SanitizeIssue[] = [];
  const path = parsed.pathname;

  // The WHATWG URL parser resolves ../ sequences in the path automatically,
  // so we must check the raw URL string for traversal patterns before parsing.
  const rawPath = extractRawPath(rawUrl ?? parsed.href);

  const pathToCheck = rawPath ?? path;

  // Check raw path (before decoding) for encoded attacks
  if (NULL_BYTE_RE.test(pathToCheck)) {
    issues.push({
      code: "NULL_BYTE",
      message: `URL path contains a null byte injection attempt.`,
      component: "path",
    });
  }

  if (CRLF_RE.test(pathToCheck)) {
    issues.push({
      code: "CRLF_INJECTION",
      message: `URL path contains a CRLF injection attempt that could split HTTP responses.`,
      component: "path",
    });
  }

  if (PATH_TRAVERSAL_RE.test(pathToCheck)) {
    issues.push({
      code: "PATH_TRAVERSAL",
      message: `URL path contains a path traversal sequence ("../") that could access unintended files.`,
      component: "path",
    });
  }

  // Also check the decoded path for traversal (catches double-encoded variants)
  try {
    const decoded = decodeURIComponent(pathToCheck);
    if (decoded !== pathToCheck && PATH_TRAVERSAL_RE.test(decoded)) {
      if (!issues.some((i) => i.code === "PATH_TRAVERSAL")) {
        issues.push({
          code: "PATH_TRAVERSAL",
          message: `URL path contains a double-encoded path traversal sequence.`,
          component: "path",
        });
      }
    }
    if (decoded !== pathToCheck && NULL_BYTE_RE.test(decoded)) {
      if (!issues.some((i) => i.code === "NULL_BYTE")) {
        issues.push({
          code: "NULL_BYTE",
          message: `URL path contains a double-encoded null byte.`,
          component: "path",
        });
      }
    }
  } catch {
    // decodeURIComponent throws on malformed sequences — that itself is suspicious
    issues.push({
      code: "NULL_BYTE",
      message: `URL path contains malformed percent-encoding that could indicate an injection attempt.`,
      component: "path",
    });
  }

  return issues;
}

/**
 * Extracts the raw path portion from a URL string without parsing it,
 * preserving any ../ sequences that the WHATWG URL parser would normalize away.
 */
function extractRawPath(rawUrl: string): string | null {
  // Find the path start: after scheme://host[:port]
  const schemeEnd = rawUrl.indexOf("://");
  if (schemeEnd === -1) return null;

  const afterScheme = rawUrl.indexOf("/", schemeEnd + 3);
  if (afterScheme === -1) return null;

  // Path ends at ? or # or end of string
  const queryStart = rawUrl.indexOf("?", afterScheme);
  const fragmentStart = rawUrl.indexOf("#", afterScheme);

  let pathEnd = rawUrl.length;
  if (queryStart !== -1) pathEnd = Math.min(pathEnd, queryStart);
  if (fragmentStart !== -1) pathEnd = Math.min(pathEnd, fragmentStart);

  return rawUrl.slice(afterScheme, pathEnd);
}

/**
 * Returns a sanitized version of the path with traversal sequences normalized.
 * Uses the URL spec's own path resolution to collapse ../ sequences.
 */
export function sanitizePath(parsed: URL): string {
  // The WHATWG URL parser already resolves ../ sequences in most cases.
  // We additionally strip null bytes and CRLF from the path.
  return parsed.pathname
    .replace(/\x00/g, "")
    .replace(/[\r\n]/g, "");
}
