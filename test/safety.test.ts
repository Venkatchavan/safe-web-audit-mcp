import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import path from "node:path";
import os from "node:os";

// Make storage / consent files isolated per test run.
const tmp = mkdtempSync(path.join(os.tmpdir(), "swa-test-"));
process.env.SAFE_WEB_AUDIT_HOME = tmp;

import { isBlockedIp, validateUrlForAudit } from "../src/safety.ts";
import {
  analyzeHeaders,
  normalizeHeaders,
  summarizeRisk,
  type Finding,
} from "../src/checks.ts";
import { auditUrl } from "../src/audit.ts";
import { redactString, redactValue } from "../src/redaction.ts";
import { adjustSeverity } from "../src/scoring.ts";
import {
  generateAuthToken,
  verifyAuthorization,
  hasConsent,
} from "../src/authorization.ts";
import { generateTemplate, emergencyChecklist } from "../src/templates.ts";
import { saveAudit, listHistory, diff, compareLatest } from "../src/storage.ts";

test("isBlockedIp: private IPv4 ranges", () => {
  assert.equal(isBlockedIp("127.0.0.1"), true);
  assert.equal(isBlockedIp("10.1.2.3"), true);
  assert.equal(isBlockedIp("192.168.0.5"), true);
  assert.equal(isBlockedIp("172.16.0.1"), true);
  assert.equal(isBlockedIp("169.254.169.254"), true);
  assert.equal(isBlockedIp("8.8.8.8"), false);
});

test("isBlockedIp: IPv6 ranges", () => {
  assert.equal(isBlockedIp("::1"), true);
  assert.equal(isBlockedIp("fe80::1"), true);
  assert.equal(isBlockedIp("fd00::1"), true);
  assert.equal(isBlockedIp("::ffff:127.0.0.1"), true);
  assert.equal(isBlockedIp("2606:4700:4700::1111"), false);
});

test("validateUrlForAudit blocks bad inputs", async () => {
  for (const u of [
    "ftp://example.com",
    "http://localhost/",
    "http://127.0.0.1/",
    "http://169.254.169.254/",
  ]) {
    const r = await validateUrlForAudit(u);
    assert.equal(r.ok, false, `expected ${u} to be blocked`);
  }
});

test("auditUrl refuses without confirm_authorized", async () => {
  const r = await auditUrl({ url: "https://example.com", confirm_authorized: false });
  assert.equal(r.status, null);
  assert.ok(r.errors && r.errors[0].includes("confirm_authorized"));
});

test("analyzeHeaders flags missing headers and emits codes", () => {
  const headers = normalizeHeaders({
    "set-cookie": ["sid=abc; Path=/"],
    server: "nginx/1.18.0",
    "x-powered-by": "Express",
  });
  const { findings } = analyzeHeaders(headers, new URL("https://example.com"));
  const codes = findings.map((f: Finding) => f.code);
  assert.ok(codes.includes("MISSING_HSTS"));
  assert.ok(codes.includes("MISSING_CSP"));
  assert.ok(codes.includes("COOKIE_NO_SECURE"));
  assert.ok(codes.includes("COOKIE_NO_HTTPONLY"));
  assert.ok(codes.includes("COOKIE_NO_SAMESITE"));
  assert.ok(codes.includes("SERVER_HEADER_DISCLOSURE"));
  assert.ok(codes.includes("X_POWERED_BY_DISCLOSURE"));
});

test("analyzeHeaders flags non-HTTPS as high", () => {
  const headers = normalizeHeaders({});
  const { findings } = analyzeHeaders(headers, new URL("http://example.com"));
  assert.equal(summarizeRisk(findings), "high");
});

test("redactString redacts emails, IPs, JWTs, bearer tokens", () => {
  const input =
    "user alice@example.com from 10.0.0.5 sent Authorization: Bearer abc123xyz token=eyJhbGciOiJIUzI1NiJ9.payload.signature";
  const out = redactString(input);
  assert.ok(!out.includes("alice@example.com"));
  assert.ok(!out.includes("10.0.0.5"));
  assert.ok(!out.includes("abc123xyz"));
  assert.ok(out.includes("<REDACTED"));
});

test("redactValue scrubs nested objects", () => {
  const obj = { evidence: "Set-Cookie: sid=secretvalue; Path=/", note: "ok" };
  const r = redactValue(obj);
  assert.ok(!JSON.stringify(r).includes("secretvalue"));
});

test("adjustSeverity bumps severity for risk-sensitive site types", () => {
  assert.equal(adjustSeverity("MISSING_CSP", "medium", "ecommerce"), "high");
  assert.equal(adjustSeverity("MISSING_CSP", "medium", "portfolio"), "medium");
  assert.equal(adjustSeverity("SERVER_HEADER_DISCLOSURE", "low", "portfolio"), "info");
});

test("generateAuthToken returns a unique-looking string", () => {
  const a = generateAuthToken();
  const b = generateAuthToken();
  assert.match(a, /^swa-[0-9a-f]{24}$/);
  assert.notEqual(a, b);
});

test("verify_authorization records consent for statement method", async () => {
  const token = generateAuthToken();
  const r = await verifyAuthorization({
    url: "https://example.com",
    method: "statement",
    statement:
      "I am the owner and authorize a non-invasive defensive audit. Token=" + token,
    identity: "Owner <owner@example.com>",
  });
  assert.equal(r.ok, true);
  assert.ok(r.consent_id);
  assert.equal(await hasConsent("example.com"), true);
});

test("verify_authorization rejects short/empty statement", async () => {
  const r = await verifyAuthorization({
    url: "https://example.com",
    method: "statement",
    statement: "short",
    identity: "x",
  });
  assert.equal(r.ok, false);
});

test("generateTemplate produces all template kinds with required content", () => {
  const sec = generateTemplate({
    name: "security_txt",
    contact_email: "sec@example.com",
    domain: "example.com",
  });
  assert.match(sec.content, /Contact: mailto:sec@example.com/);
  assert.match(sec.content, /Expires:/);
  for (const name of [
    "responsible_disclosure",
    "password_policy",
    "backup_checklist",
    "incident_contact_plan",
  ] as const) {
    const out = generateTemplate({ name, org_name: "Acme" });
    assert.ok(out.content.length > 100);
  }
});

test("emergencyChecklist tailors steps to options", () => {
  const c1 = emergencyChecklist({});
  assert.ok(c1.steps.length >= 4);
  const c2 = emergencyChecklist({ has_admin_panel: true, handles_user_data: true });
  const titles = c2.steps.map((s) => s.step);
  assert.ok(titles.some((t) => t.includes("admin panels")));
  assert.ok(titles.some((t) => t.includes("user notification")));
});

test("storage: save + list + diff", async () => {
  const baseReport = {
    target_url: "https://t.example",
    final_url: "https://t.example/",
    status: 200,
    method_used: "HEAD" as const,
    redirect_chain: [],
    risk_summary: "medium" as const,
    findings: [
      {
        code: "MISSING_CSP" as const,
        title: "x",
        severity: "medium" as const,
        evidence: "x",
        recommendation: "x",
      },
      {
        code: "MISSING_HSTS" as const,
        title: "x",
        severity: "medium" as const,
        evidence: "x",
        recommendation: "x",
      },
    ],
    positive_checks: [],
    ethical_notice: "",
    redacted: true,
  };
  await saveAudit(baseReport as any, "saas");
  const later = {
    ...baseReport,
    risk_summary: "low" as const,
    findings: [
      {
        code: "MISSING_PERMISSIONS_POLICY" as const,
        title: "x",
        severity: "low" as const,
        evidence: "x",
        recommendation: "x",
      },
    ],
  };
  await saveAudit(later as any, "saas");
  const entries = await listHistory("https://t.example/");
  assert.ok(entries.length >= 2);
  const cmp = await compareLatest("https://t.example/");
  assert.ok(cmp);
  assert.ok(cmp!.resolved.includes("MISSING_CSP"));
  assert.ok(cmp!.introduced.includes("MISSING_PERMISSIONS_POLICY"));
});

test("auditUrl honors require_recorded_consent", async () => {
  // example.com host does not have consent in the freshly-isolated dir
  const r = await auditUrl({
    url: "https://example.org",
    confirm_authorized: true,
    require_recorded_consent: true,
  });
  assert.equal(r.status, null);
  assert.ok(r.errors?.some((e) => e.includes("No prior consent")));
});
