import { describe, it, expect } from "vitest";
import { validate } from "../src/validate.js";
import { SanitizeError } from "../src/types.js";

describe("validate()", () => {
  it("does not throw for a safe URL", () => {
    expect(() => validate("https://example.com/path?q=1")).not.toThrow();
  });

  it("throws SanitizeError for javascript: scheme", () => {
    expect(() => validate("javascript:alert(1)")).toThrow(SanitizeError);
  });

  it("exposes the correct error code on the thrown error", () => {
    try {
      validate("javascript:alert(1)");
      expect.fail("Should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(SanitizeError);
      const err = e as SanitizeError;
      expect(err.code).toBe("DANGEROUS_SCHEME");
      expect(err.component).toBe("scheme");
    }
  });

  it("throws for SSRF risk", () => {
    expect(() => validate("http://192.168.1.1/admin")).toThrow(SanitizeError);
  });

  it("throws for invalid URL", () => {
    expect(() => validate("not a url at all")).toThrow(SanitizeError);
  });

  it("throws for URL that is too long", () => {
    const longUrl = "https://example.com/" + "a".repeat(2100);
    expect(() => validate(longUrl)).toThrow(SanitizeError);
  });

  it("includes all issues in the error's issues array", () => {
    try {
      validate("https://user:pass@192.168.1.1/path");
      expect.fail("Should have thrown");
    } catch (e) {
      const err = e as SanitizeError;
      expect(err.issues.length).toBeGreaterThan(0);
    }
  });

  it("throws for credential injection", () => {
    try {
      validate("https://user:password@example.com");
      expect.fail("Should have thrown");
    } catch (e) {
      const err = e as SanitizeError;
      expect(err.code).toBe("CREDENTIAL_LEAK");
    }
  });

  it("passes with allowCredentials: true", () => {
    expect(() =>
      validate("https://user:pass@example.com", { allowCredentials: true })
    ).not.toThrow();
  });

  it("throws for path traversal", () => {
    expect(() =>
      validate("https://example.com/../../../etc/passwd")
    ).toThrow(SanitizeError);
  });

  it("throws for homograph domain", () => {
    // 'а' is Cyrillic U+0430
    expect(() => validate("https://ex\u0430mple.com/")).toThrow(SanitizeError);
  });

  it("respects custom allowedSchemes", () => {
    expect(() =>
      validate("ftp://files.example.com/file.txt", {
        allowedSchemes: ["https", "http", "ftp"],
      })
    ).not.toThrow();
  });
});
