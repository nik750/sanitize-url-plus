import { describe, it, expect } from "vitest";
import { check } from "../../src/check.js";

describe("Query checker", () => {
  it("blocks null byte in query string", () => {
    const r = check("https://example.com/search?q=hello%00world");
    expect(r.safe).toBe(false);
    expect(r.issues.some((i) => i.code === "NULL_BYTE")).toBe(true);
  });

  it("blocks CRLF in query string", () => {
    const r = check("https://example.com/?redirect=%0d%0aSet-Cookie:evil=1");
    expect(r.safe).toBe(false);
    expect(r.issues.some((i) => i.code === "CRLF_INJECTION")).toBe(true);
  });

  it("blocks javascript: in query parameter value", () => {
    const r = check("https://example.com/?redirect=javascript:alert(1)");
    expect(r.safe).toBe(false);
    expect(r.issues.some((i) => i.code === "DANGEROUS_SCHEME")).toBe(true);
  });

  it("blocks data:text/html in query parameter value", () => {
    const r = check(
      "https://example.com/?url=data:text/html,<script>alert(1)</script>"
    );
    expect(r.safe).toBe(false);
  });

  it("allows clean query string", () => {
    const r = check("https://example.com/search?q=hello+world&page=2");
    expect(r.issues.some((i) => i.component === "query")).toBe(false);
  });
});

describe("Fragment checker", () => {
  it("blocks javascript: in fragment", () => {
    const r = check("https://example.com/#javascript:alert(1)");
    expect(r.safe).toBe(false);
    expect(r.issues.some((i) => i.code === "FRAGMENT_XSS")).toBe(true);
  });

  it("blocks encoded javascript: in fragment", () => {
    const r = check("https://example.com/#%6a%61%76%61%73%63%72%69%70%74:alert(1)");
    expect(r.safe).toBe(false);
    expect(r.issues.some((i) => i.code === "FRAGMENT_XSS")).toBe(true);
  });

  it("blocks null byte in fragment", () => {
    const r = check("https://example.com/#section%00evil");
    expect(r.safe).toBe(false);
    expect(r.issues.some((i) => i.code === "NULL_BYTE")).toBe(true);
  });

  it("allows clean fragment", () => {
    const r = check("https://example.com/page#section-2");
    expect(r.issues.some((i) => i.component === "fragment")).toBe(false);
  });
});
