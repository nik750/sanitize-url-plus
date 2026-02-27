import { describe, it, expect } from "vitest";
import { check } from "../../src/check.js";

describe("Host checker — SSRF", () => {
  describe("loopback addresses", () => {
    it("blocks localhost", () => {
      const r = check("http://localhost/admin");
      expect(r.safe).toBe(false);
      expect(r.issues.some((i) => i.code === "SSRF_RISK")).toBe(true);
    });

    it("blocks 127.0.0.1", () => {
      const r = check("http://127.0.0.1/");
      expect(r.safe).toBe(false);
      expect(r.issues.some((i) => i.code === "SSRF_RISK")).toBe(true);
    });

    it("blocks 127.x.x.x range", () => {
      const r = check("http://127.99.99.99/");
      expect(r.safe).toBe(false);
    });

    it("blocks ::1 (IPv6 loopback)", () => {
      const r = check("http://[::1]/");
      expect(r.safe).toBe(false);
    });

    it("blocks 0.0.0.0", () => {
      const r = check("http://0.0.0.0/");
      expect(r.safe).toBe(false);
    });

    it("allows loopback when allowPrivateIPs is true", () => {
      const r = check("http://localhost/", { allowPrivateIPs: true });
      expect(r.issues.some((i) => i.code === "SSRF_RISK")).toBe(false);
    });
  });

  describe("private IP ranges (RFC 1918)", () => {
    it("blocks 10.0.0.1", () => {
      const r = check("http://10.0.0.1/");
      expect(r.safe).toBe(false);
      expect(r.issues.some((i) => i.code === "SSRF_RISK")).toBe(true);
    });

    it("blocks 172.16.0.1", () => {
      const r = check("http://172.16.0.1/");
      expect(r.safe).toBe(false);
    });

    it("blocks 172.31.255.255", () => {
      const r = check("http://172.31.255.255/");
      expect(r.safe).toBe(false);
    });

    it("allows 172.32.0.1 (outside private range)", () => {
      const r = check("http://172.32.0.1/");
      expect(r.issues.some((i) => i.code === "SSRF_RISK")).toBe(false);
    });

    it("blocks 192.168.1.1", () => {
      const r = check("http://192.168.1.1/");
      expect(r.safe).toBe(false);
    });
  });

  describe("cloud metadata endpoints", () => {
    it("blocks AWS metadata endpoint 169.254.169.254", () => {
      const r = check("http://169.254.169.254/latest/meta-data/");
      expect(r.safe).toBe(false);
      expect(r.issues.some((i) => i.code === "SSRF_RISK")).toBe(true);
    });

    it("blocks GCP metadata endpoint", () => {
      const r = check("http://metadata.google.internal/computeMetadata/v1/");
      expect(r.safe).toBe(false);
    });
  });

  describe("IP address obfuscation", () => {
    it("blocks hex IP 0x7f000001 (= 127.0.0.1)", () => {
      const r = check("http://0x7f000001/");
      expect(r.safe).toBe(false);
      expect(
        r.issues.some(
          (i) => i.code === "IP_OBFUSCATION" || i.code === "SSRF_RISK"
        )
      ).toBe(true);
    });

    it("blocks decimal integer IP 2130706433 (= 127.0.0.1)", () => {
      const r = check("http://2130706433/");
      expect(r.safe).toBe(false);
      expect(
        r.issues.some(
          (i) => i.code === "IP_OBFUSCATION" || i.code === "SSRF_RISK"
        )
      ).toBe(true);
    });

    it("blocks octal IP 0177.0.0.1 (= 127.0.0.1)", () => {
      const r = check("http://0177.0.0.1/");
      expect(r.safe).toBe(false);
    });

    it("blocks mixed-notation 0x7f.0.0.1", () => {
      const r = check("http://0x7f.0.0.1/");
      expect(r.safe).toBe(false);
    });
  });

  describe("allowedHosts / blockedHosts", () => {
    it("allows only listed hosts when allowedHosts is set", () => {
      const opts = { allowedHosts: ["example.com"] };
      expect(check("https://example.com/path", opts).safe).toBe(true);
      expect(check("https://evil.com/path", opts).safe).toBe(false);
    });

    it("allows subdomains with leading dot notation", () => {
      const opts = { allowedHosts: [".example.com"] };
      expect(check("https://api.example.com/", opts).safe).toBe(true);
      expect(check("https://example.com/", opts).safe).toBe(true);
      expect(check("https://evil.com/", opts).safe).toBe(false);
    });

    it("blocks hosts in blockedHosts even if in allowedHosts", () => {
      const opts = {
        allowedHosts: ["example.com"],
        blockedHosts: ["example.com"],
      };
      expect(check("https://example.com/", opts).safe).toBe(false);
    });
  });
});

describe("Host checker — Homograph", () => {
  it("blocks mixed-script domain (Cyrillic + Latin)", () => {
    // 'а' is Cyrillic U+0430, looks like Latin 'a'
    const r = check("https://ex\u0430mple.com/");
    expect(r.safe).toBe(false);
    expect(r.issues.some((i) => i.code === "HOMOGRAPH_DOMAIN")).toBe(true);
  });

  it("blocks punycode domain by default", () => {
    const r = check("https://xn--e1awd7f.com/");
    expect(r.safe).toBe(false);
    expect(r.issues.some((i) => i.code === "HOMOGRAPH_DOMAIN")).toBe(true);
  });

  it("allows punycode domain when allowHomographDomains is true", () => {
    const r = check("https://xn--e1awd7f.com/", {
      allowHomographDomains: true,
    });
    expect(r.issues.some((i) => i.code === "HOMOGRAPH_DOMAIN")).toBe(false);
  });
});
