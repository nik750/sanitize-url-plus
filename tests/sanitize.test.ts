import { describe, it, expect } from "vitest";
import { sanitize } from "../src/sanitize.js";

describe("sanitize()", () => {
  describe("returns null for unrecoverable URLs", () => {
    it("returns null for javascript: scheme", () => {
      expect(sanitize("javascript:alert(1)")).toBeNull();
    });

    it("returns null for vbscript: scheme", () => {
      expect(sanitize("vbscript:MsgBox('xss')")).toBeNull();
    });

    it("returns null for SSRF target", () => {
      expect(sanitize("http://192.168.1.1/admin")).toBeNull();
    });

    it("returns null for localhost", () => {
      expect(sanitize("http://localhost/")).toBeNull();
    });

    it("returns null for cloud metadata endpoint", () => {
      expect(sanitize("http://169.254.169.254/latest/meta-data/")).toBeNull();
    });

    it("returns null for homograph domain", () => {
      expect(sanitize("https://ex\u0430mple.com/")).toBeNull();
    });

    it("returns null for URL exceeding maxLength", () => {
      const longUrl = "https://example.com/" + "a".repeat(2100);
      expect(sanitize(longUrl)).toBeNull();
    });

    it("returns null for invalid URL", () => {
      expect(sanitize("not a url")).toBeNull();
    });

    it("returns null for path traversal", () => {
      expect(sanitize("https://example.com/../../../etc/passwd")).toBeNull();
    });

    it("returns null for hex obfuscated loopback", () => {
      expect(sanitize("http://0x7f000001/")).toBeNull();
    });
  });

  describe("strips credentials (recoverable)", () => {
    it("strips username and password", () => {
      const result = sanitize("https://user:pass@example.com/path");
      expect(result).toBe("https://example.com/path");
    });

    it("strips username-only credential", () => {
      const result = sanitize("https://user@example.com/path");
      expect(result).toBe("https://example.com/path");
    });
  });

  describe("passes safe URLs through", () => {
    it("returns https URL unchanged", () => {
      expect(sanitize("https://example.com/path?q=1#section")).toBe(
        "https://example.com/path?q=1#section"
      );
    });

    it("returns http URL unchanged", () => {
      expect(sanitize("http://example.com/")).toBe("http://example.com/");
    });
  });

  describe("open redirect normalization", () => {
    it("normalizes backslash-as-slash tricks", () => {
      // https:\evil.com after normalization becomes https://evil.com
      // which is a valid URL — the backslash trick is neutralized by normalization
      const result = sanitize("https:\\\\example.com\\path");
      // After backslash->slash normalization, this becomes https://example.com/path
      expect(result).toBe("https://example.com/path");
    });
  });

  describe("options", () => {
    it("respects custom maxLength", () => {
      const url = "https://example.com/" + "a".repeat(50);
      expect(sanitize(url, { maxLength: 30 })).toBeNull();
      expect(sanitize(url, { maxLength: 200 })).not.toBeNull();
    });

    it("respects allowPrivateIPs", () => {
      expect(sanitize("http://192.168.1.1/", { allowPrivateIPs: true })).not.toBeNull();
      expect(sanitize("http://192.168.1.1/")).toBeNull();
    });

    it("respects allowedHosts", () => {
      expect(
        sanitize("https://trusted.com/", { allowedHosts: ["trusted.com"] })
      ).not.toBeNull();
      expect(
        sanitize("https://evil.com/", { allowedHosts: ["trusted.com"] })
      ).toBeNull();
    });

    it("respects blockedHosts", () => {
      expect(
        sanitize("https://evil.com/", { blockedHosts: ["evil.com"] })
      ).toBeNull();
    });
  });
});
