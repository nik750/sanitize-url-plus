import type { SanitizeIssue, SanitizeOptions } from "../types.js";
import {
  LOOPBACK_HOSTNAMES,
  CLOUD_METADATA_HOSTS,
  HEX_IP_RE,
  OCTAL_IP_RE,
  DECIMAL_IP_RE,
  MIXED_SCRIPT_RE,
  PUNYCODE_LABEL_RE,
} from "../constants.js";

/**
 * Checks the host component for SSRF risks, IP obfuscation, and homograph attacks.
 *
 * Handles:
 * - Loopback addresses (127.x, ::1, localhost)
 * - Private IP ranges (RFC 1918: 10.x, 172.16-31.x, 192.168.x)
 * - Link-local / cloud metadata (169.254.x.x, fd00:ec2::254)
 * - Hex/octal/decimal integer IP obfuscation
 * - Allowlist/blocklist enforcement
 * - IDN homograph / mixed-script domains
 * - Suspicious punycode labels
 */
export function checkHost(
  parsed: URL,
  options: Required<SanitizeOptions>
): SanitizeIssue[] {
  const issues: SanitizeIssue[] = [];
  const hostname = parsed.hostname.toLowerCase();

  if (!hostname) return issues;

  // Blocklist check (takes priority over allowlist)
  if (isHostBlocked(hostname, options.blockedHosts)) {
    issues.push({
      code: "SSRF_RISK",
      message: `Host "${hostname}" is in the blocked hosts list.`,
      component: "host",
    });
    return issues;
  }

  // Allowlist check — if provided, only listed hosts are permitted
  if (
    options.allowedHosts.length > 0 &&
    !isHostAllowed(hostname, options.allowedHosts)
  ) {
    issues.push({
      code: "SSRF_RISK",
      message: `Host "${hostname}" is not in the allowed hosts list.`,
      component: "host",
    });
    return issues;
  }

  if (!options.allowPrivateIPs) {
    // Resolve obfuscated IP representations first
    const resolvedIp = resolveObfuscatedIp(hostname);

    if (resolvedIp !== null && resolvedIp !== hostname) {
      issues.push({
        code: "IP_OBFUSCATION",
        message: `Host "${hostname}" uses an obfuscated IP representation that resolves to "${resolvedIp}".`,
        component: "host",
      });
    }

    const effectiveHost = resolvedIp ?? hostname;

    if (isLoopback(effectiveHost)) {
      issues.push({
        code: "SSRF_RISK",
        message: `Host "${hostname}" resolves to a loopback address, which is an SSRF risk.`,
        component: "host",
      });
    } else if (isPrivateIp(effectiveHost)) {
      issues.push({
        code: "SSRF_RISK",
        message: `Host "${hostname}" resolves to a private/internal IP address, which is an SSRF risk.`,
        component: "host",
      });
    } else if (isCloudMetadata(effectiveHost)) {
      issues.push({
        code: "SSRF_RISK",
        message: `Host "${hostname}" is a cloud provider metadata endpoint, which is a critical SSRF risk.`,
        component: "host",
      });
    } else if (isLinkLocal(effectiveHost)) {
      issues.push({
        code: "SSRF_RISK",
        message: `Host "${hostname}" is a link-local address, which is an SSRF risk.`,
        component: "host",
      });
    }
  }

  // Homograph / IDN checks
  if (!options.allowHomographDomains) {
    const homographIssue = checkHomograph(hostname);
    if (homographIssue) issues.push(homographIssue);
  }

  return issues;
}

// ---------------------------------------------------------------------------
// Allowlist / blocklist helpers
// ---------------------------------------------------------------------------

function isHostAllowed(hostname: string, allowedHosts: string[]): boolean {
  return allowedHosts.some((allowed) => {
    const a = allowed.toLowerCase();
    if (a.startsWith(".")) {
      // Subdomain wildcard: .example.com matches sub.example.com and example.com
      return hostname === a.slice(1) || hostname.endsWith(a);
    }
    return hostname === a;
  });
}

function isHostBlocked(hostname: string, blockedHosts: string[]): boolean {
  return blockedHosts.some((blocked) => {
    const b = blocked.toLowerCase();
    if (b.startsWith(".")) {
      return hostname === b.slice(1) || hostname.endsWith(b);
    }
    return hostname === b;
  });
}

// ---------------------------------------------------------------------------
// SSRF / IP helpers
// ---------------------------------------------------------------------------

function isLoopback(host: string): boolean {
  if (LOOPBACK_HOSTNAMES.includes(host)) return true;
  // 127.0.0.0/8
  if (/^127\.\d+\.\d+\.\d+$/.test(host)) return true;
  // ::1 variants
  if (host === "::1" || host === "[::1]") return true;
  return false;
}

function isPrivateIp(host: string): boolean {
  // 10.0.0.0/8
  if (/^10\.\d+\.\d+\.\d+$/.test(host)) return true;
  // 172.16.0.0/12
  const m172 = /^172\.(\d+)\.\d+\.\d+$/.exec(host);
  if (m172) {
    const octet = parseInt(m172[1] ?? "0", 10);
    if (octet >= 16 && octet <= 31) return true;
  }
  // 192.168.0.0/16
  if (/^192\.168\.\d+\.\d+$/.test(host)) return true;
  // fc00::/7 (unique local IPv6)
  if (/^f[cd][0-9a-f]{2}:/i.test(host)) return true;
  return false;
}

function isLinkLocal(host: string): boolean {
  // 169.254.0.0/16 (AWS/Azure/GCP metadata)
  if (/^169\.254\.\d+\.\d+$/.test(host)) return true;
  // fe80::/10
  if (/^fe[89ab][0-9a-f]:/i.test(host)) return true;
  return false;
}

function isCloudMetadata(host: string): boolean {
  return CLOUD_METADATA_HOSTS.includes(host);
}

/**
 * Attempts to resolve obfuscated IP representations to their dotted-decimal form.
 * Returns the resolved IP string, or null if the host is not an obfuscated IP.
 */
function resolveObfuscatedIp(host: string): string | null {
  // Hex IP: 0x7f000001
  if (HEX_IP_RE.test(host)) {
    const num = parseInt(host, 16);
    return intToIpv4(num);
  }

  // Decimal integer IP: 2130706433
  if (DECIMAL_IP_RE.test(host)) {
    const num = parseInt(host, 10);
    if (num <= 0xffffffff) {
      return intToIpv4(num);
    }
  }

  // Octal IP: 0177.0.0.1
  if (OCTAL_IP_RE.test(host)) {
    const parts = host.split(".");
    const resolved = parts
      .map((p) => parseInt(p, 8))
      .join(".");
    return resolved;
  }

  // Mixed-notation: 0x7f.0.0.1 or 0177.0.0.1 mixed with decimal
  if (/^(?:0x[0-9a-f]+|\d+)(?:\.(?:0x[0-9a-f]+|\d+)){1,3}$/i.test(host)) {
    const parts = host.split(".");
    const resolved = parts
      .map((p) => {
        if (/^0x/i.test(p)) return parseInt(p, 16);
        if (/^0[0-7]+$/.test(p)) return parseInt(p, 8);
        return parseInt(p, 10);
      })
      .join(".");
    return resolved;
  }

  return null;
}

function intToIpv4(num: number): string {
  return [
    (num >>> 24) & 0xff,
    (num >>> 16) & 0xff,
    (num >>> 8) & 0xff,
    num & 0xff,
  ].join(".");
}

// ---------------------------------------------------------------------------
// Homograph / IDN helpers
// ---------------------------------------------------------------------------

function checkHomograph(hostname: string): SanitizeIssue | null {
  // Strip brackets from IPv6
  const host = hostname.replace(/^\[|\]$/g, "");

  // Split into labels and check each
  const labels = host.split(".");

  for (const label of labels) {
    // Check for mixed-script characters (Cyrillic, Greek, etc. mixed with Latin)
    if (MIXED_SCRIPT_RE.test(label) && /[a-z]/i.test(label)) {
      return {
        code: "HOMOGRAPH_DOMAIN",
        message: `Domain label "${label}" mixes Latin characters with visually similar characters from another Unicode script (potential homograph/phishing attack).`,
        component: "host",
      };
    }

    // Flag suspicious punycode labels
    if (PUNYCODE_LABEL_RE.test(label)) {
      return {
        code: "HOMOGRAPH_DOMAIN",
        message: `Domain label "${label}" uses Punycode encoding (xn--), which may be used to disguise a homograph attack.`,
        component: "host",
      };
    }
  }

  return null;
}
