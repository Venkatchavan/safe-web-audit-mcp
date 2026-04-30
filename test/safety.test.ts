import { test } from "node:test";
import assert from "node:assert/strict";

import { isBlockedIp, validateUrlForAudit } from "../src/safety.ts";
import { analyzeHeaders, normalizeHeaders, summarizeRisk } from "../src/checks.ts";
import { auditUrl } from "../src/audit.ts";

test("isBlockedIp: private IPv4 ranges", () => {
  assert.equal(isBlockedIp("127.0.0.1"), true);
  assert.equal(isBlockedIp("10.1.2.3"), true);
  assert.equal(isBlockedIp("192.168.0.5"), true);
  assert.equal(isBlockedIp("172.16.0.1"), true);
  assert.equal(isBlockedIp("172.31.255.255"), true);
  assert.equal(isBlockedIp("169.254.169.254"), true);
  assert.equal(isBlockedIp("0.0.0.0"), true);
  assert.equal(isBlockedIp("8.8.8.8"), false);
  assert.equal(isBlockedIp("1.1.1.1"), false);
});

test("isBlockedIp: IPv6 ranges", () => {
  assert.equal(isBlockedIp("::1"), true);
  assert.equal(isBlockedIp("fe80::1"), true);
  assert.equal(isBlockedIp("fd00::1"), true);
  assert.equal(isBlockedIp("::ffff:127.0.0.1"), true);
  assert.equal(isBlockedIp("2606:4700:4700::1111"), false);
});

test("validateUrlForAudit rejects non-http(s)", async () => {
  const r = await validateUrlForAudit("ftp://example.com");
  assert.equal(r.ok, false);
});

test("validateUrlForAudit rejects localhost", async () => {
  const r = await validateUrlForAudit("http://localhost/");
  assert.equal(r.ok, false);
});

test("validateUrlForAudit rejects internal IP literal", async () => {
  const r = await validateUrlForAudit("http://127.0.0.1/");
  assert.equal(r.ok, false);
});

test("validateUrlForAudit rejects metadata host", async () => {
  const r = await validateUrlForAudit("http://169.254.169.254/latest/");
  assert.equal(r.ok, false);
});

test("auditUrl refuses without confirm_authorized", async () => {
  const r = await auditUrl({ url: "https://example.com", confirm_authorized: false });
  assert.equal(r.status, null);
  assert.ok(r.errors && r.errors[0].includes("confirm_authorized"));
});

test("analyzeHeaders flags missing security headers and insecure cookies", () => {
  const headers = normalizeHeaders({
    "set-cookie": ["sid=abc; Path=/"],
    server: "nginx/1.18.0",
  });
  const { findings } = analyzeHeaders(headers, new URL("https://example.com"));
  const titles = findings.map((f) => f.title);
  assert.ok(titles.some((t) => t.includes("Strict-Transport-Security")));
  assert.ok(titles.some((t) => t.includes("Content-Security-Policy")));
  assert.ok(titles.some((t) => t.includes("Secure flag")));
  assert.ok(titles.some((t) => t.includes("HttpOnly")));
  assert.ok(titles.some((t) => t.includes("SameSite")));
  assert.ok(titles.some((t) => t.includes("Server software disclosed")));
});

test("analyzeHeaders flags non-HTTPS as high", () => {
  const headers = normalizeHeaders({});
  const { findings } = analyzeHeaders(headers, new URL("http://example.com"));
  assert.equal(summarizeRisk(findings), "high");
});

test("analyzeHeaders accepts strong headers", () => {
  const headers = normalizeHeaders({
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=()",
  });
  const { findings, positives } = analyzeHeaders(headers, new URL("https://example.com"));
  assert.equal(findings.length, 0);
  assert.ok(positives.length >= 6);
});
