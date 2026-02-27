import type { SanitizeIssue, SanitizeOptions } from "../types.js";
import {
  ALWAYS_DANGEROUS_SCHEMES,
  DEFAULT_ALLOWED_SCHEMES,
  DANGEROUS_DATA_MIME_TYPES,
} from "../constants.js";

/**
 * Checks the URL scheme against allowlists and blocklists.
 *
 * Handles:
 * - Always-dangerous schemes (javascript:, vbscript:, etc.)
 * - Schemes not in the allowed list
 * - Dangerous data: URL MIME types
 */
export function checkScheme(
  parsed: URL,
  options: Required<SanitizeOptions>
): SanitizeIssue[] {
  const issues: SanitizeIssue[] = [];
  // URL.protocol includes the trailing colon, e.g. "https:"
  const scheme = parsed.protocol.replace(/:$/, "").toLowerCase();

  if (ALWAYS_DANGEROUS_SCHEMES.includes(scheme)) {
    issues.push({
      code: "DANGEROUS_SCHEME",
      message: `The scheme "${scheme}:" is always dangerous and cannot be sanitized.`,
      component: "scheme",
    });
    return issues;
  }

  const allowedSchemes = options.allowedSchemes.map((s) => s.toLowerCase());

  if (!allowedSchemes.includes(scheme)) {
    issues.push({
      code: "DANGEROUS_SCHEME",
      message: `The scheme "${scheme}:" is not in the list of allowed schemes: [${allowedSchemes.join(", ")}].`,
      component: "scheme",
    });
  }

  if (scheme === "data" && options.allowDataUrls) {
    issues.push(...checkDataUrlContent(parsed.href));
  }

  return issues;
}

/**
 * Inspects the MIME type of a data: URL for dangerous content types.
 */
function checkDataUrlContent(href: string): SanitizeIssue[] {
  const issues: SanitizeIssue[] = [];
  // data:[<mediatype>][;base64],<data>
  const mimeMatch = /^data:([^;,]+)/i.exec(href);
  if (!mimeMatch) return issues;

  const mime = (mimeMatch[1] ?? "").trim().toLowerCase();
  if (DANGEROUS_DATA_MIME_TYPES.some((d) => mime.startsWith(d))) {
    issues.push({
      code: "DATA_URL_CONTENT",
      message: `The data: URL uses a dangerous MIME type "${mime}" that can execute code.`,
      component: "scheme",
    });
  }

  return issues;
}

/**
 * Returns the default allowed schemes merged with user options.
 */
export function resolveAllowedSchemes(options: SanitizeOptions): string[] {
  return options.allowedSchemes ?? [...DEFAULT_ALLOWED_SCHEMES];
}
