import { describe, it, expect } from "vitest";
import { check } from "../../src/check.js";

describe("Path checker", () => {
  describe("path traversal", () => {
    it("blocks ../ in path", () => {
      const r = check("https://example.com/../../../etc/passwd");
      expect(r.safe).toBe(false);
      expect(r.issues.some((i) => i.code === "PATH_TRAVERSAL")).toBe(true);
    });

    it("blocks ..%2F (encoded slash)", () => {
      const r = check("https://example.com/..%2F..%2Fetc%2Fpasswd");
      expect(r.safe).toBe(false);
      expect(r.issues.some((i) => i.code === "PATH_TRAVERSAL")).toBe(true);
    });

    it("blocks %2e%2e%2f (fully encoded)", () => {
      const r = check("https://example.com/%2e%2e%2fetc%2fpasswd");
      expect(r.safe).toBe(false);
      expect(r.issues.some((i) => i.code === "PATH_TRAVERSAL")).toBe(true);
    });

    it("blocks ..%5c (backslash encoded)", () => {
      const r = check("https://example.com/..%5cetc%5cpasswd");
      expect(r.safe).toBe(false);
      expect(r.issues.some((i) => i.code === "PATH_TRAVERSAL")).toBe(true);
    });
  });

  describe("null byte injection", () => {
    it("blocks %00 in path", () => {
      const r = check("https://example.com/file%00.txt");
      expect(r.safe).toBe(false);
      expect(r.issues.some((i) => i.code === "NULL_BYTE")).toBe(true);
    });
  });

  describe("CRLF injection", () => {
    it("blocks %0d%0a in path", () => {
      const r = check("https://example.com/path%0d%0aSet-Cookie:evil=1");
      expect(r.safe).toBe(false);
      expect(r.issues.some((i) => i.code === "CRLF_INJECTION")).toBe(true);
    });

    it("blocks %0a (LF only) in path", () => {
      const r = check("https://example.com/path%0aX-Injected:yes");
      expect(r.safe).toBe(false);
      expect(r.issues.some((i) => i.code === "CRLF_INJECTION")).toBe(true);
    });
  });

  describe("clean paths", () => {
    it("allows normal path", () => {
      const r = check("https://example.com/users/profile/settings");
      expect(r.issues.some((i) => i.component === "path")).toBe(false);
    });

    it("allows encoded characters in path", () => {
      const r = check("https://example.com/hello%20world");
      expect(r.issues.some((i) => i.component === "path")).toBe(false);
    });
  });
});
