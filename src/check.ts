import type { SanitizeOptions, SanitizeResult, SanitizeIssue } from "./types.js";
import {
  DEFAULT_ALLOWED_SCHEMES,
  DEFAULT_MAX_LENGTH,
  ALWAYS_DANGEROUS_SCHEMES,
} from "./constants.js";
import { normalizeRawUrl } from "./checkers/protocol-normalizer.js";
import { checkScheme } from "./checkers/scheme.js";
import { checkCredentials } from "./checkers/credentials.js";
import { checkHost } from "./checkers/host.js";
import { checkPath } from "./checkers/path.js";
import { checkQuery } from "./checkers/query.js";
import { checkFragment } from "./checkers/fragment.js";
import { checkLength } from "./checkers/length.js";

/**
 * Resolves user-provided options against their defaults.
 */
function resolveOptions(options?: SanitizeOptions): Required<SanitizeOptions> {
  return {
    allowedSchemes: options?.allowedSchemes ?? [...DEFAULT_ALLOWED_SCHEMES],
    allowPrivateIPs: options?.allowPrivateIPs ?? false,
    allowCredentials: options?.allowCredentials ?? false,
    allowDataUrls: options?.allowDataUrls ?? false,
    maxLength: options?.maxLength ?? DEFAULT_MAX_LENGTH,
    allowHomographDomains: options?.allowHomographDomains ?? false,
    allowedHosts: options?.allowedHosts ?? [],
    blockedHosts: options?.blockedHosts ?? [],
  };
}

/**
 * Determines whether a URL with the given issues can be partially sanitized
 * (i.e. the dangerous parts can be stripped) or must be rejected entirely.
 */
function isRecoverable(issues: SanitizeIssue[]): boolean {
  // These issue types mean the URL itself is fundamentally dangerous
  // and cannot be made safe by stripping parts.
  const unrecoverableCodes = new Set([
    "DANGEROUS_SCHEME",
    "INVALID_URL",
    "SSRF_RISK",
    "IP_OBFUSCATION",
    "HOMOGRAPH_DOMAIN",
    "URL_TOO_LONG",
    "PATH_TRAVERSAL",
    "FRAGMENT_XSS",
    "CRLF_INJECTION",
    "NULL_BYTE",
  ]);
  return !issues.some((i) => unrecoverableCodes.has(i.code));
}

/**
 * Runs the full sanitizer pipeline against a URL string.
 *
 * Returns a `SanitizeResult` with:
 * - `safe`: whether the URL passed all checks
 * - `url`: the sanitized URL (with credentials stripped, etc.) or null if unrecoverable
 * - `issues`: all issues detected
 */
export function check(url: string, options?: SanitizeOptions): SanitizeResult {
  const opts = resolveOptions(options);
  const allIssues: SanitizeIssue[] = [];

  // ── Step 1: Length check on raw input ──────────────────────────────────────
  allIssues.push(...checkLength(url, opts));

  // ── Step 2: Normalize raw URL (decode obfuscation, strip control chars) ────
  const { normalized, issues: normIssues } = normalizeRawUrl(url);
  allIssues.push(...normIssues);

  // If normalization already found a dangerous scheme, bail early
  if (normIssues.some((i) => i.code === "DANGEROUS_SCHEME")) {
    return { safe: false, url: null, issues: allIssues };
  }

  // ── Step 3: Parse with WHATWG URL API ──────────────────────────────────────
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    allIssues.push({
      code: "INVALID_URL",
      message: `"${url}" is not a valid URL and cannot be parsed.`,
      component: "url",
    });
    return { safe: false, url: null, issues: allIssues };
  }

  // ── Step 4: Scheme check ───────────────────────────────────────────────────
  const schemeIssues = checkScheme(parsed, opts);
  allIssues.push(...schemeIssues);

  // If scheme is always-dangerous, no point running further checks
  const scheme = parsed.protocol.replace(/:$/, "").toLowerCase();
  if (ALWAYS_DANGEROUS_SCHEMES.includes(scheme)) {
    return { safe: false, url: null, issues: allIssues };
  }

  // ── Step 5: Credential check (also produces sanitized URL) ─────────────────
  const { issues: credIssues, sanitized: credSanitized } = checkCredentials(
    parsed,
    opts
  );
  allIssues.push(...credIssues);

  // Work with the credential-stripped URL from here on
  const working = credSanitized;

  // ── Step 6: Host check (SSRF, IP obfuscation, homograph) ───────────────────
  allIssues.push(...checkHost(working, opts));

  // ── Step 7: Path check ─────────────────────────────────────────────────────
  // Pass the normalized raw URL so the path checker can detect ../ sequences
  // before the WHATWG parser resolves them away.
  allIssues.push(...checkPath(working, normalized));

  // ── Step 8: Query check ────────────────────────────────────────────────────
  allIssues.push(...checkQuery(working));

  // ── Step 9: Fragment check ─────────────────────────────────────────────────
  allIssues.push(...checkFragment(working));

  // ── Determine result ───────────────────────────────────────────────────────
  const safe = allIssues.length === 0;

  if (safe) {
    return { safe: true, url: working.href, issues: [] };
  }

  // Attempt partial recovery (strip credentials, etc.)
  const recoverable = isRecoverable(allIssues);
  const resultUrl = recoverable ? working.href : null;

  return { safe: false, url: resultUrl, issues: allIssues };
}
