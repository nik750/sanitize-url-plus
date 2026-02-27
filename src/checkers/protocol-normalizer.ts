import type { SanitizeIssue } from "../types.js";
import {
  BACKSLASH_RE,
  URL_WHITESPACE_RE,
  HTML_ENTITY_RE,
  ALWAYS_DANGEROUS_SCHEMES,
} from "../constants.js";

/**
 * Result of pre-parsing normalization.
 */
export interface NormalizeResult {
  normalized: string;
  issues: SanitizeIssue[];
}

/**
 * Normalizes a raw URL string before it is passed to the WHATWG URL parser.
 *
 * Handles:
 * - Leading/trailing whitespace and control characters (tab, CR, LF, NUL)
 * - Backslash-as-slash tricks (https:\evil.com)
 * - HTML entity encoding in scheme (&#106;avascript:)
 * - Double/triple-encoded schemes (%6a%61%76%61%73%63%72%69%70%74:)
 * - Protocol-relative URLs (//evil.com, ///evil.com)
 *
 * Returns the normalized string and any issues found.
 */
export function normalizeRawUrl(raw: string): NormalizeResult {
  const issues: SanitizeIssue[] = [];
  let url = raw;

  // Strip leading/trailing whitespace and browser-stripped control chars
  const stripped = url.replace(URL_WHITESPACE_RE, "");
  if (stripped !== url) {
    url = stripped;
  }

  // Decode HTML entities in the scheme area (first ~30 chars)
  const schemeArea = url.slice(0, 30);
  if (HTML_ENTITY_RE.test(schemeArea)) {
    const decoded = decodeHtmlEntities(url);
    if (decoded !== url) {
      url = decoded;
    }
  }

  // Decode percent-encoded scheme characters
  // e.g. %6a%61%76%61%73%63%72%69%70%74: -> javascript:
  const percentDecoded = decodePercentEncodedScheme(url);
  if (percentDecoded !== url) {
    url = percentDecoded;
  }

  // Replace backslashes with forward slashes in the authority/path
  // (browsers treat \ as / in some positions, enabling open redirect)
  const withForwardSlashes = url.replace(BACKSLASH_RE, "/");
  if (withForwardSlashes !== url) {
    url = withForwardSlashes;
  }

  // After normalization, check if the scheme is now dangerous
  const schemeMatch = /^([a-z][a-z0-9+\-.]*):/.exec(url.toLowerCase().trim());
  if (schemeMatch) {
    const scheme = schemeMatch[1] ?? "";
    if (ALWAYS_DANGEROUS_SCHEMES.includes(scheme)) {
      issues.push({
        code: "DANGEROUS_SCHEME",
        message: `URL contains an obfuscated dangerous scheme "${scheme}:" that was detected after decoding.`,
        component: "scheme",
      });
    }
  }

  return { normalized: url, issues };
}

/**
 * Decodes HTML entities in the scheme portion of a URL.
 * e.g. &#106;avascript: -> javascript:
 */
function decodeHtmlEntities(url: string): string {
  return url.replace(HTML_ENTITY_RE, (entity) => {
    const hex = /&#x([0-9a-f]+);?/i.exec(entity);
    if (hex) return String.fromCodePoint(parseInt(hex[1] ?? "0", 16));
    const dec = /&#([0-9]+);?/.exec(entity);
    if (dec) return String.fromCodePoint(parseInt(dec[1] ?? "0", 10));
    return entity;
  });
}

/**
 * Decodes percent-encoded characters in the scheme portion only.
 * Browsers do NOT percent-decode scheme characters, but some server-side
 * validators do, creating a discrepancy that attackers exploit.
 *
 * We decode the first segment (before the first colon or slash) to detect
 * obfuscated schemes.
 */
function decodePercentEncodedScheme(url: string): string {
  // Only look at the potential scheme portion (before first : or /)
  const colonIdx = url.indexOf(":");
  const slashIdx = url.indexOf("/");
  const endIdx =
    colonIdx === -1
      ? slashIdx === -1
        ? url.length
        : slashIdx
      : slashIdx === -1
        ? colonIdx
        : Math.min(colonIdx, slashIdx);

  const schemePart = url.slice(0, endIdx);
  if (!/%[0-9a-f]{2}/i.test(schemePart)) return url;

  try {
    const decoded = decodeURIComponent(schemePart);
    return decoded + url.slice(endIdx);
  } catch {
    return url;
  }
}
