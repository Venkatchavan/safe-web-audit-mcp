/**
 * Impact-based scoring: adjusts finding severity based on the type of site.
 * E.g., missing CSP on a clinic or ecommerce site is worse than on a static
 * portfolio.
 */

import type { Severity } from "./checks.js";
import type { FindingCode } from "./codes.js";

export type SiteType =
  | "school"
  | "clinic"
  | "ngo"
  | "ecommerce"
  | "portfolio"
  | "saas"
  | "blog"
  | "other";

const SEVERITY_ORDER: Severity[] = ["info", "low", "medium", "high"];

function bump(sev: Severity, by: number): Severity {
  const idx = SEVERITY_ORDER.indexOf(sev);
  const next = Math.min(SEVERITY_ORDER.length - 1, Math.max(0, idx + by));
  return SEVERITY_ORDER[next];
}

/**
 * Per (site_type, code) severity adjustment. Positive => raise, negative => lower.
 * Missing entries mean "no change".
 */
const ADJUSTMENTS: Partial<
  Record<SiteType, Partial<Record<FindingCode, number>>>
> = {
  clinic: {
    NO_HTTPS: +1,
    MISSING_HSTS: +1,
    COOKIE_NO_SECURE: +1,
    COOKIE_NO_HTTPONLY: +1,
    MISSING_CSP: +1,
  },
  ecommerce: {
    NO_HTTPS: +1,
    MISSING_HSTS: +1,
    COOKIE_NO_SECURE: +1,
    COOKIE_NO_SAMESITE: +1,
    MISSING_CSP: +1,
    COOKIE_NO_HTTPONLY: +1,
  },
  saas: {
    MISSING_CSP: +1,
    COOKIE_NO_SECURE: +1,
    COOKIE_NO_HTTPONLY: +1,
    COOKIE_NO_SAMESITE: +1,
  },
  school: {
    MISSING_CSP: +1,
    COOKIE_NO_SECURE: +1,
  },
  ngo: {
    NO_HTTPS: +1,
    COOKIE_NO_SECURE: +1,
  },
  portfolio: {
    SERVER_HEADER_DISCLOSURE: -1,
    X_POWERED_BY_DISCLOSURE: -1,
  },
  blog: {
    SERVER_HEADER_DISCLOSURE: -1,
  },
};

export function adjustSeverity(
  code: FindingCode,
  current: Severity,
  siteType: SiteType,
): Severity {
  const delta = ADJUSTMENTS[siteType]?.[code] ?? 0;
  if (delta === 0) return current;
  return bump(current, delta);
}

export const SITE_TYPE_NOTES: Record<SiteType, string> = {
  school:
    "Schools typically host minors' data and parent communication; even simple sites need basic transport security.",
  clinic:
    "Clinics handle health information; transport security and cookie hygiene are non-negotiable.",
  ngo:
    "NGOs often handle donations and sensitive contact info; HTTPS and secure cookies are critical.",
  ecommerce:
    "Ecommerce sites handle payments and accounts; CSP, HSTS, and secure session cookies are critical.",
  portfolio:
    "Portfolios are mostly static; the highest-impact issues are HTTPS and basic clickjacking protection.",
  saas:
    "SaaS handles tenant data; CSP, secure cookies, and CSRF defenses are essential.",
  blog:
    "Blogs often integrate third-party scripts; CSP and clickjacking protection matter most.",
  other: "General defensive baseline applied.",
};
