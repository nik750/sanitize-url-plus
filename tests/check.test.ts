import { describe, it, expect } from "vitest";
import { check } from "../src/check.js";

describe("check()", () => {
  it("returns safe:true and the URL for a clean URL", () => {
    const r = check("https://example.com/path?q=hello");
    expect(r.safe).toBe(true);
    expect(r.url).toBe("https://example.com/path?q=hello");
    expect(r.issues).toHaveLength(0);
  });

  it("returns safe:false and issues for dangerous URL", () => {
    const r = check("javascript:alert(1)");
    expect(r.safe).toBe(false);
    expect(r.url).toBeNull();
    expect(r.issues.length).toBeGreaterThan(0);
  });

  it("returns multiple issues when multiple problems exist", () => {
    // URL with credentials AND path traversal
    const r = check("https://user:pass@example.com/../../../etc/passwd");
    expect(r.safe).toBe(false);
    expect(r.issues.length).toBeGreaterThanOrEqual(2);
    expect(r.issues.some((i) => i.code === "CREDENTIAL_LEAK")).toBe(true);
    expect(r.issues.some((i) => i.code === "PATH_TRAVERSAL")).toBe(true);
  });

  it("returns INVALID_URL for unparseable input", () => {
    const r = check(":::not-a-url:::");
    expect(r.safe).toBe(false);
    expect(r.issues.some((i) => i.code === "INVALID_URL")).toBe(true);
  });

  it("returns URL_TOO_LONG for excessively long URLs", () => {
    const longUrl = "https://example.com/" + "x".repeat(2100);
    const r = check(longUrl);
    expect(r.safe).toBe(false);
    expect(r.issues.some((i) => i.code === "URL_TOO_LONG")).toBe(true);
  });

  it("includes issue component information", () => {
    const r = check("https://user:pass@example.com/");
    const credIssue = r.issues.find((i) => i.code === "CREDENTIAL_LEAK");
    expect(credIssue?.component).toBe("credentials");
  });

  it("includes issue message", () => {
    const r = check("javascript:alert(1)");
    expect(r.issues[0]?.message).toBeTruthy();
    expect(typeof r.issues[0]?.message).toBe("string");
  });

  describe("CRLF injection", () => {
    it("detects CRLF in URL", () => {
      const r = check("https://example.com/path%0d%0aSet-Cookie:evil=1");
      expect(r.safe).toBe(false);
      expect(r.issues.some((i) => i.code === "CRLF_INJECTION")).toBe(true);
    });
  });

  describe("null byte injection", () => {
    it("detects null byte in URL", () => {
      const r = check("https://example.com/file%00.txt");
      expect(r.safe).toBe(false);
      expect(r.issues.some((i) => i.code === "NULL_BYTE")).toBe(true);
    });
  });

  describe("open redirect vectors", () => {
    it("normalizes backslash and checks resulting URL", () => {
      // After normalization https:\\evil.com -> https://evil.com
      // which is a valid external URL — should pass
      const r = check("https:\\\\example.com\\path");
      // The backslash is normalized to forward slash, resulting in a valid URL
      expect(r.url).toBeTruthy();
    });
  });

  describe("edge cases", () => {
    it("handles empty string", () => {
      const r = check("");
      expect(r.safe).toBe(false);
      expect(r.issues.some((i) => i.code === "INVALID_URL")).toBe(true);
    });

    it("handles URL with only whitespace", () => {
      const r = check("   ");
      expect(r.safe).toBe(false);
    });

    it("handles very short invalid URL", () => {
      const r = check("x");
      expect(r.safe).toBe(false);
    });

    it("handles URL with port number", () => {
      const r = check("https://example.com:8443/api");
      expect(r.safe).toBe(true);
    });

    it("handles URL with IPv6 host", () => {
      // Public IPv6 address should be fine
      const r = check("https://[2001:db8::1]/path");
      expect(r.issues.some((i) => i.code === "SSRF_RISK")).toBe(false);
    });
  });
});
