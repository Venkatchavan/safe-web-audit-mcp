/**
 * Header / cookie analysis for the audit_url tool.
 */

export type Severity = "info" | "low" | "medium" | "high";

export interface Finding {
  title: string;
  severity: Severity;
  evidence: string;
  recommendation: string;
}

export interface HeaderAnalysis {
  findings: Finding[];
  positives: string[];
}

const SECURITY_HEADERS: Array<{
  name: string;
  severity: Severity;
  recommendation: string;
  validate?: (value: string) => Finding | null;
}> = [
  {
    name: "strict-transport-security",
    severity: "medium",
    recommendation:
      "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` (HTTPS only).",
    validate: (value) => {
      const m = value.match(/max-age\s*=\s*(\d+)/i);
      const age = m ? Number(m[1]) : 0;
      if (age < 15552000) {
        return {
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
    severity: "medium",
    recommendation:
      "Define a Content-Security-Policy that restricts script, frame, and connect sources.",
  },
  {
    name: "x-frame-options",
    severity: "low",
    recommendation:
      "Set `X-Frame-Options: DENY` (or use CSP `frame-ancestors`) to mitigate clickjacking.",
  },
  {
    name: "x-content-type-options",
    severity: "low",
    recommendation: "Set `X-Content-Type-Options: nosniff`.",
    validate: (value) => {
      if (value.trim().toLowerCase() !== "nosniff") {
        return {
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
    severity: "low",
    recommendation:
      "Set a Referrer-Policy such as `strict-origin-when-cross-origin` or `no-referrer`.",
  },
  {
    name: "permissions-policy",
    severity: "low",
    recommendation:
      "Define a Permissions-Policy to disable powerful features you do not use (e.g. `geolocation=(), camera=()`).",
  },
];

const INFO_DISCLOSURE_HEADERS = ["server", "x-powered-by", "x-aspnet-version"];

export interface NormalizedHeaders {
  // lowercase header name -> array of values
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
    // getSetCookie if available (Node 20+)
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
    // HSTS is only meaningful over HTTPS.
    if (spec.name === "strict-transport-security" && !isHttps) continue;

    if (!values || values.length === 0) {
      findings.push({
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
  for (const name of INFO_DISCLOSURE_HEADERS) {
    const values = headers.map.get(name);
    if (values && values.length > 0) {
      const value = values.join(", ");
      // Only flag if it looks like it leaks version info (contains a digit)
      // or is x-powered-by (usually not needed at all).
      const looksVersioned = /\d/.test(value);
      const severity: Severity =
        name === "x-powered-by" || looksVersioned ? "low" : "info";
      findings.push({
        title: `Server software disclosed via ${prettyHeader(name)}`,
        severity,
        evidence: `${prettyHeader(name)}: ${truncate(value, 200)}`,
        recommendation:
          "Remove or genericize this header to avoid disclosing software/version details.",
      });
    }
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
        title: `Cookie '${cookieName}' missing Secure flag`,
        severity: "medium",
        evidence: truncate(cookie, 200),
        recommendation: "Add the `Secure` attribute so the cookie is only sent over HTTPS.",
      });
    }
    if (!hasHttpOnly) {
      findings.push({
        title: `Cookie '${cookieName}' missing HttpOnly flag`,
        severity: "low",
        evidence: truncate(cookie, 200),
        recommendation:
          "Add `HttpOnly` if the cookie is not read by client-side JavaScript.",
      });
    }
    if (!sameSiteMatch) {
      findings.push({
        title: `Cookie '${cookieName}' missing SameSite attribute`,
        severity: "low",
        evidence: truncate(cookie, 200),
        recommendation: "Set `SameSite=Lax` or `SameSite=Strict` (or `None; Secure`).",
      });
    } else if (sameSiteMatch[1] === "none" && !hasSecure) {
      findings.push({
        title: `Cookie '${cookieName}' uses SameSite=None without Secure`,
        severity: "medium",
        evidence: truncate(cookie, 200),
        recommendation: "`SameSite=None` cookies must also have `Secure`.",
      });
    }
  }

  if (!isHttps) {
    findings.push({
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
