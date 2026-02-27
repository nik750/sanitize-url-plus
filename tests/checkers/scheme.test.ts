import { describe, it, expect } from "vitest";
import { check } from "../../src/check.js";

describe("Scheme checker", () => {
  describe("always-dangerous schemes", () => {
    it("blocks javascript: scheme", () => {
      const r = check("javascript:alert(1)");
      expect(r.safe).toBe(false);
      expect(r.url).toBeNull();
      expect(r.issues.some((i) => i.code === "DANGEROUS_SCHEME")).toBe(true);
    });

    it("blocks vbscript: scheme", () => {
      const r = check("vbscript:MsgBox('xss')");
      expect(r.safe).toBe(false);
      expect(r.issues.some((i) => i.code === "DANGEROUS_SCHEME")).toBe(true);
    });

    it("blocks jscript: scheme", () => {
      const r = check("jscript:alert(1)");
      expect(r.safe).toBe(false);
      expect(r.issues.some((i) => i.code === "DANGEROUS_SCHEME")).toBe(true);
    });
  });

  describe("XSS via encoded javascript: scheme", () => {
    it("blocks percent-encoded javascript: scheme (%6a%61%76%61%73%63%72%69%70%74:)", () => {
      const r = check("%6a%61%76%61%73%63%72%69%70%74:alert(1)");
      expect(r.safe).toBe(false);
      expect(r.issues.some((i) => i.code === "DANGEROUS_SCHEME" || i.code === "INVALID_URL")).toBe(true);
    });

    it("blocks HTML entity encoded javascript: (&#106;avascript:)", () => {
      const r = check("&#106;avascript:alert(1)");
      expect(r.safe).toBe(false);
    });

    it("blocks javascript: with leading whitespace", () => {
      const r = check("   javascript:alert(1)");
      expect(r.safe).toBe(false);
      expect(r.url).toBeNull();
    });

    it("blocks javascript: with tab character", () => {
      const r = check("\tjavascript:alert(1)");
      expect(r.safe).toBe(false);
    });

    it("blocks javascript: with newline", () => {
      const r = check("\njavascript:alert(1)");
      expect(r.safe).toBe(false);
    });

    it("blocks JAVA SCRIPT: (uppercase)", () => {
      const r = check("JAVASCRIPT:alert(1)");
      expect(r.safe).toBe(false);
      expect(r.url).toBeNull();
    });
  });

  describe("non-allowed schemes", () => {
    it("blocks ftp: by default", () => {
      const r = check("ftp://example.com/file.txt");
      expect(r.safe).toBe(false);
      expect(r.issues.some((i) => i.code === "DANGEROUS_SCHEME")).toBe(true);
    });

    it("blocks file: by default", () => {
      const r = check("file:///etc/passwd");
      expect(r.safe).toBe(false);
    });

    it("blocks gopher: by default", () => {
      const r = check("gopher://evil.com:70/1");
      expect(r.safe).toBe(false);
    });

    it("blocks data: by default", () => {
      const r = check("data:text/plain,hello");
      expect(r.safe).toBe(false);
    });

    it("allows ftp: when explicitly in allowedSchemes", () => {
      const r = check("ftp://files.example.com/file.txt", {
        allowedSchemes: ["https", "http", "ftp"],
      });
      expect(r.issues.some((i) => i.code === "DANGEROUS_SCHEME")).toBe(false);
    });
  });

  describe("data: URL content", () => {
    it("blocks data:text/html when allowDataUrls is true", () => {
      const r = check("data:text/html,<script>alert(1)</script>", {
        allowedSchemes: ["https", "http", "data"],
        allowDataUrls: true,
      });
      expect(r.safe).toBe(false);
      expect(r.issues.some((i) => i.code === "DATA_URL_CONTENT")).toBe(true);
    });

    it("blocks data:application/javascript when allowDataUrls is true", () => {
      const r = check("data:application/javascript,alert(1)", {
        allowedSchemes: ["https", "http", "data"],
        allowDataUrls: true,
      });
      expect(r.safe).toBe(false);
      expect(r.issues.some((i) => i.code === "DATA_URL_CONTENT")).toBe(true);
    });

    it("allows data:image/png when allowDataUrls is true", () => {
      const r = check("data:image/png;base64,iVBORw0KGgo=", {
        allowedSchemes: ["https", "http", "data"],
        allowDataUrls: true,
      });
      expect(r.issues.some((i) => i.code === "DATA_URL_CONTENT")).toBe(false);
    });
  });

  describe("safe schemes", () => {
    it("allows https:", () => {
      const r = check("https://example.com");
      expect(r.safe).toBe(true);
    });

    it("allows http:", () => {
      const r = check("http://example.com");
      expect(r.safe).toBe(true);
    });
  });
});
