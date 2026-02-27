/**
 * All issue codes that can be reported by the sanitizer.
 * Each code maps to a specific URL-based attack vector.
 */
export type IssueCode =
  | "DANGEROUS_SCHEME"       // javascript:, vbscript:, data:text/html, etc.
  | "SSRF_RISK"              // loopback, private IP, cloud metadata endpoint
  | "OPEN_REDIRECT"          // protocol-relative, backslash-as-slash tricks
  | "CREDENTIAL_LEAK"        // userinfo (user:pass@) present in URL
  | "NULL_BYTE"              // %00 or \0 in any component
  | "CRLF_INJECTION"         // %0d/%0a or literal \r\n in URL
  | "PATH_TRAVERSAL"         // ../ or encoded variants in path
  | "URL_TOO_LONG"           // exceeds maxLength
  | "HOMOGRAPH_DOMAIN"       // mixed-script or suspicious punycode domain
  | "FRAGMENT_XSS"           // javascript: in fragment
  | "DATA_URL_CONTENT"       // dangerous MIME type in data: URL
  | "INVALID_URL"            // URL cannot be parsed at all
  | "IP_OBFUSCATION";        // octal/hex/decimal integer IP representation

/**
 * The URL component where an issue was detected.
 */
export type UrlComponent =
  | "scheme"
  | "host"
  | "path"
  | "query"
  | "fragment"
  | "url"
  | "credentials";

/**
 * A single issue found during URL analysis.
 */
export interface SanitizeIssue {
  code: IssueCode;
  message: string;
  component: UrlComponent;
}

/**
 * The result returned by `check()`.
 */
export interface SanitizeResult {
  /** Whether the URL is considered safe with the given options. */
  safe: boolean;
  /**
   * The sanitized URL string, or null if the URL cannot be made safe
   * (e.g. a bare `javascript:` URL with no recoverable content).
   */
  url: string | null;
  /** All issues detected, even those that were automatically fixed. */
  issues: SanitizeIssue[];
}

/**
 * Options to configure the sanitizer behaviour.
 */
export interface SanitizeOptions {
  /**
   * URL schemes that are considered safe.
   * @default ['https', 'http']
   */
  allowedSchemes?: string[];

  /**
   * Allow URLs that resolve to private/loopback IP addresses.
   * Useful for internal tooling; dangerous in user-facing contexts.
   * @default false
   */
  allowPrivateIPs?: boolean;

  /**
   * Allow userinfo (user:password) in URLs.
   * @default false
   */
  allowCredentials?: boolean;

  /**
   * Allow data: URLs. When false, all data: URLs are blocked.
   * @default false
   */
  allowDataUrls?: boolean;

  /**
   * Maximum allowed URL length in characters.
   * @default 2048
   */
  maxLength?: number;

  /**
   * Allow domains that appear to use mixed Unicode scripts (homograph risk).
   * @default false
   */
  allowHomographDomains?: boolean;

  /**
   * An explicit allowlist of hostnames. When provided, only these hosts
   * (and their subdomains if the entry starts with `.`) are permitted.
   */
  allowedHosts?: string[];

  /**
   * An explicit blocklist of hostnames. These hosts are always rejected,
   * even if they appear in `allowedHosts`.
   */
  blockedHosts?: string[];
}

/**
 * Error thrown by `validate()` when a URL fails a security check.
 */
export class SanitizeError extends Error {
  readonly code: IssueCode;
  readonly component: UrlComponent;
  readonly issues: SanitizeIssue[];

  constructor(issue: SanitizeIssue, allIssues: SanitizeIssue[] = []) {
    super(issue.message);
    this.name = "SanitizeError";
    this.code = issue.code;
    this.component = issue.component;
    this.issues = allIssues.length > 0 ? allIssues : [issue];
  }
}
