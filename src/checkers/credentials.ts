import type { SanitizeIssue, SanitizeOptions } from "../types.js";

/**
 * Checks for and optionally strips userinfo (credentials) from a URL.
 *
 * Handles:
 * - https://user:pass@evil.com — credential leakage / phishing
 * - https://user@evil.com — username-only userinfo
 *
 * Returns issues and a sanitized URL with credentials stripped.
 */
export function checkCredentials(
  parsed: URL,
  options: Required<SanitizeOptions>
): { issues: SanitizeIssue[]; sanitized: URL } {
  const issues: SanitizeIssue[] = [];
  const sanitized = new URL(parsed.href);

  const hasCredentials = parsed.username !== "" || parsed.password !== "";

  if (hasCredentials) {
    if (!options.allowCredentials) {
      issues.push({
        code: "CREDENTIAL_LEAK",
        message: `URL contains embedded credentials (${parsed.username ? "username" : ""}${parsed.password ? ":password" : ""}) which can leak sensitive information.`,
        component: "credentials",
      });
    }
    // Always strip credentials in the sanitized output
    sanitized.username = "";
    sanitized.password = "";
  }

  return { issues, sanitized };
}
