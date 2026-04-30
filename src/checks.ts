/**
 * Header / cookie analysis for the audit_url tool.
 * Each Finding has a stable `code` so other features (humanize, fixes,
 * compliance, history diff) can correlate.
 */

import type { FindingCode } from "./codes.js";

export type Severity = "info" | "low" | "medium" | "high";

export interface Finding {
  code: FindingCode;
  title: string;
  severity: Severity;
  evidence: string;
  recommendation: string;
}

export interface HeaderAnalysis {
  findings: Finding[];
  positives: string[];
}

interface SecHeaderSpec {
  name: string;
  code: FindingCode;
  severity: Severity;
  recommendation: string;
  validate?: (value: string) => Finding | null;
}

const SECURITY_HEADERS: SecHeaderSpec[] = [
  {
    name: "strict-transport-security",
    code: "MISSING_HSTS",
    severity: "medium",
    recommendation:
      "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` (HTTPS only).",
    validate: (value) => {
      const m = value.match(/max-age\s*=\s*(\d+)/i);
      const age = m ? Number(m[1]) : 0;
      if (age < 15552000) {
        return {
          code: "WEAK_HSTS",
          title: "Weak Strict-Transport-Security max-age",
          severity: "low",
          evidence: `Strict-Transport-Security: ${value}`,
          recommendation:
            "Set max-age to at least 15552000 (180 days); 31536000 (1 year) is preferred.",
        };
      }
      return null;
    },
  },
  {
    name: "content-security-policy",
    code: "MISSING_CSP",
    severity: "medium",
    recommendation:
      "Define a Content-Security-Policy that restricts script, frame, and connect sources.",
  },
  {
    name: "x-frame-options",
    code: "MISSING_X_FRAME_OPTIONS",
    severity: "low",
    recommendation:
      "Set `X-Frame-Options: DENY` (or use CSP `frame-ancestors`) to mitigate clickjacking.",
  },
  {
    name: "x-content-type-options",
    code: "MISSING_X_CONTENT_TYPE_OPTIONS",
    severity: "low",
    recommendation: "Set `X-Content-Type-Options: nosniff`.",
    validate: (value) => {
      if (value.trim().toLowerCase() !== "nosniff") {
        return {
          code: "WEAK_X_CONTENT_TYPE_OPTIONS",
          title: "X-Content-Type-Options is not 'nosniff'",
          severity: "low",
          evidence: `X-Content-Type-Options: ${value}`,
          recommendation: "Set the value to exactly `nosniff`.",
        };
      }
      return null;
    },
  },
  {
    name: "referrer-policy",
    code: "MISSING_REFERRER_POLICY",
    severity: "low",
    recommendation:
      "Set a Referrer-Policy such as `strict-origin-when-cross-origin` or `no-referrer`.",
  },
  {
    name: "permissions-policy",
    code: "MISSING_PERMISSIONS_POLICY",
    severity: "low",
    recommendation:
      "Define a Permissions-Policy to disable powerful features you do not use (e.g. `geolocation=(), camera=()`).",
  },
];

export interface NormalizedHeaders {
  map: Map<string, string[]>;
}

export function normalizeHeaders(
  raw: Record<string, string | string[] | undefined> | Headers,
): NormalizedHeaders {
  const map = new Map<string, string[]>();
  if (raw instanceof Headers) {
    raw.forEach((value, key) => {
      const k = key.toLowerCase();
      const list = map.get(k) ?? [];
      list.push(value);
      map.set(k, list);
    });
    const anyHeaders = raw as unknown as { getSetCookie?: () => string[] };
    if (typeof anyHeaders.getSetCookie === "function") {
      const cookies = anyHeaders.getSetCookie();
      if (cookies.length > 0) map.set("set-cookie", cookies);
    }
  } else {
    for (const [k, v] of Object.entries(raw)) {
      if (v === undefined) continue;
      map.set(k.toLowerCase(), Array.isArray(v) ? v : [v]);
    }
  }
  return { map };
}

export function analyzeHeaders(
  headers: NormalizedHeaders,
  finalUrl: URL,
): HeaderAnalysis {
  const findings: Finding[] = [];
  const positives: string[] = [];
  const isHttps = finalUrl.protocol === "https:";

  for (const spec of SECURITY_HEADERS) {
    const values = headers.map.get(spec.name);
    if (spec.name === "strict-transport-security" && !isHttps) continue;

    if (!values || values.length === 0) {
      findings.push({
        code: spec.code,
        title: `Missing ${prettyHeader(spec.name)} header`,
        severity: spec.severity,
        evidence: `No ${prettyHeader(spec.name)} header in response.`,
        recommendation: spec.recommendation,
      });
      continue;
    }

    const value = values.join(", ");
    positives.push(`${prettyHeader(spec.name)} present: ${truncate(value, 200)}`);
    if (spec.validate) {
      const issue = spec.validate(value);
      if (issue) findings.push(issue);
    }
  }

  // Information disclosure
  const serverVal = headers.map.get("server")?.join(", ");
  if (serverVal) {
    findings.push({
      code: "SERVER_HEADER_DISCLOSURE",
      title: "Server software disclosed via Server header",
      severity: /\d/.test(serverVal) ? "low" : "info",
      evidence: `Server: ${truncate(serverVal, 200)}`,
      recommendation:
        "Remove or genericize this header to avoid disclosing software/version details.",
    });
  }
  const poweredVal = headers.map.get("x-powered-by")?.join(", ");
  if (poweredVal) {
    findings.push({
      code: "X_POWERED_BY_DISCLOSURE",
      title: "Server framework disclosed via X-Powered-By",
      severity: "low",
      evidence: `X-Powered-By: ${truncate(poweredVal, 200)}`,
      recommendation:
        "Remove this header (it serves no purpose for visitors and helps attackers).",
    });
  }

  // Cookie flags
  const setCookies = headers.map.get("set-cookie") ?? [];
  for (const cookie of setCookies) {
    const cookieName = cookie.split("=")[0]?.trim() || "(unnamed)";
    const lower = cookie.toLowerCase();
    const hasSecure = /;\s*secure(\s*;|\s*$)/.test(lower) || lower.includes("; secure");
    const hasHttpOnly = lower.includes("httponly");
    const sameSiteMatch = lower.match(/samesite\s*=\s*(strict|lax|none)/);

    if (isHttps && !hasSecure) {
      findings.push({
        code: "COOKIE_NO_SECURE",
        title: `Cookie '${cookieName}' missing Secure flag`,
        severity: "medium",
        evidence: truncate(cookie, 200),
        recommendation: "Add the `Secure` attribute so the cookie is only sent over HTTPS.",
      });
    }
    if (!hasHttpOnly) {
      findings.push({
        code: "COOKIE_NO_HTTPONLY",
        title: `Cookie '${cookieName}' missing HttpOnly flag`,
        severity: "low",
        evidence: truncate(cookie, 200),
        recommendation:
          "Add `HttpOnly` if the cookie is not read by client-side JavaScript.",
      });
    }
    if (!sameSiteMatch) {
      findings.push({
        code: "COOKIE_NO_SAMESITE",
        title: `Cookie '${cookieName}' missing SameSite attribute`,
        severity: "low",
        evidence: truncate(cookie, 200),
        recommendation: "Set `SameSite=Lax` or `SameSite=Strict` (or `None; Secure`).",
      });
    } else if (sameSiteMatch[1] === "none" && !hasSecure) {
      findings.push({
        code: "COOKIE_SAMESITE_NONE_NO_SECURE",
        title: `Cookie '${cookieName}' uses SameSite=None without Secure`,
        severity: "medium",
        evidence: truncate(cookie, 200),
        recommendation: "`SameSite=None` cookies must also have `Secure`.",
      });
    }
  }

  if (!isHttps) {
    findings.push({
      code: "NO_HTTPS",
      title: "Site is not served over HTTPS",
      severity: "high",
      evidence: `Final URL uses ${finalUrl.protocol}`,
      recommendation: "Serve the site over HTTPS and redirect HTTP to HTTPS.",
    });
  } else {
    positives.push("Final response is served over HTTPS.");
  }

  return { findings, positives };
}

export function summarizeRisk(findings: Finding[]): "low" | "medium" | "high" {
  if (findings.some((f) => f.severity === "high")) return "high";
  if (findings.some((f) => f.severity === "medium")) return "medium";
  return "low";
}

function prettyHeader(name: string): string {
  return name
    .split("-")
    .map((p) => (p.length === 0 ? p : p[0].toUpperCase() + p.slice(1)))
    .join("-");
}

function truncate(s: string, max: number): string {
  return s.length <= max ? s : s.slice(0, max - 1) + "…";
}
