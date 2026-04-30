/**
 * audit_url implementation. Performs a single, non-invasive request
 * (HEAD, falling back to GET) and analyzes response headers.
 *
 * Manually walks redirects so that every hop is re-validated for SSRF.
 *
 * Optional enrichment (all default-on, opt-out):
 *   - humanize  -> attaches plain-language explanations per finding
 *   - redact    -> Safe Evidence Mode (default true)
 *   - site_type -> impact-based severity adjustment
 *   - save_history -> append snapshot to local timeline
 */

import http from "node:http";
import https from "node:https";

import { validateUrlForAudit } from "./safety.js";
import {
  analyzeHeaders,
  Finding,
  normalizeHeaders,
  Severity,
  summarizeRisk,
} from "./checks.js";
import {
  COMPLIANCE,
  ComplianceMapping,
  HUMANIZE,
  Humanization,
} from "./codes.js";
import { redactValue } from "./redaction.js";
import { adjustSeverity, SiteType, SITE_TYPE_NOTES } from "./scoring.js";
import { hasConsent } from "./authorization.js";
import { saveAudit } from "./storage.js";

const REQUEST_TIMEOUT_MS = 8_000;
const MAX_REDIRECTS = 5;
const USER_AGENT = "safe-web-audit/0.1 (+defensive non-invasive audit)";

export interface AuditInput {
  url: string;
  confirm_authorized: boolean;
  follow_redirects?: boolean;
  site_type?: SiteType;
  redact?: boolean;
  humanize?: boolean;
  include_compliance?: boolean;
  save_history?: boolean;
  require_recorded_consent?: boolean;
}

export interface RedirectHop {
  from: string;
  to: string;
  status: number;
}

export interface EnrichedFinding extends Finding {
  what_this_means?: string;
  why_it_matters?: string;
  who_can_fix?: string;
  message_to_developer?: string;
  compliance?: ComplianceMapping;
}

export interface AuditReport {
  target_url: string;
  final_url: string | null;
  status: number | null;
  method_used: "HEAD" | "GET" | null;
  redirect_chain: RedirectHop[];
  risk_summary: "low" | "medium" | "high";
  findings: EnrichedFinding[];
  positive_checks: string[];
  ethical_notice: string;
  site_type?: SiteType;
  site_type_note?: string;
  redacted: boolean;
  consent_recorded?: boolean;
  errors?: string[];
}

const ETHICAL_NOTICE =
  "This is a non-invasive defensive audit. Only run it on sites you own or are explicitly authorized to test.";

export async function auditUrl(input: AuditInput): Promise<AuditReport> {
  const redact = input.redact !== false; // default true
  const humanize = input.humanize !== false; // default true
  const includeCompliance = input.include_compliance !== false; // default true
  const siteType: SiteType = input.site_type ?? "other";

  const baseReport: AuditReport = {
    target_url: input.url,
    final_url: null,
    status: null,
    method_used: null,
    redirect_chain: [],
    risk_summary: "low",
    findings: [],
    positive_checks: [],
    ethical_notice: ETHICAL_NOTICE,
    site_type: siteType,
    site_type_note: SITE_TYPE_NOTES[siteType],
    redacted: redact,
  };

  if (input.confirm_authorized !== true) {
    return {
      ...baseReport,
      errors: [
        "Refusing to run: `confirm_authorized` must be true. Only audit sites you own or are authorized to test.",
      ],
    };
  }

  const initialCheck = await validateUrlForAudit(input.url);
  if (!initialCheck.ok) {
    return { ...baseReport, errors: [`Blocked: ${initialCheck.reason}`] };
  }

  if (input.require_recorded_consent) {
    const ok = await hasConsent(initialCheck.hostname ?? "");
    if (!ok) {
      return {
        ...baseReport,
        errors: [
          `No prior consent record for ${initialCheck.hostname}. Use the verify_authorization tool first.`,
        ],
      };
    }
  }

  const followRedirects = input.follow_redirects ?? true;
  let currentUrl = input.url;
  // Pin the resolved IP after validation to prevent DNS rebinding on the actual fetch.
  let pinnedIp: string | undefined = initialCheck.resolvedAddresses?.[0];
  const redirectChain: RedirectHop[] = [];
  const errors: string[] = [];

  let finalResponse: Response | null = null;
  let methodUsed: "HEAD" | "GET" | null = null;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    let response: Response;
    try {
      const result = await requestWithHeadFallback(currentUrl, pinnedIp);
      response = result.response;
      methodUsed = result.method;
    } catch (err) {
      errors.push(
        `Request failed for ${currentUrl}: ${err instanceof Error ? err.message : String(err)}`,
      );
      break;
    }

    const status = response.status;
    const isRedirect = status >= 300 && status < 400 && response.headers.has("location");

    if (!isRedirect || !followRedirects) {
      finalResponse = response;
      if (isRedirect && !followRedirects) {
        const loc = response.headers.get("location");
        if (loc) {
          try {
            const next = new URL(loc, currentUrl).toString();
            redirectChain.push({ from: currentUrl, to: next, status });
          } catch {
            /* ignore */
          }
        }
      }
      break;
    }

    const location = response.headers.get("location");
    if (!location) {
      finalResponse = response;
      break;
    }
    let nextUrl: string;
    try {
      nextUrl = new URL(location, currentUrl).toString();
    } catch {
      errors.push(`Malformed redirect Location: ${location}`);
      finalResponse = response;
      break;
    }
    redirectChain.push({ from: currentUrl, to: nextUrl, status });

    const check = await validateUrlForAudit(nextUrl);
    if (!check.ok) {
      errors.push(`Blocked redirect to ${nextUrl}: ${check.reason}`);
      finalResponse = response;
      break;
    }
    currentUrl = nextUrl;
    pinnedIp = check.resolvedAddresses?.[0]; // re-pin IP for next hop

    if (hop === MAX_REDIRECTS) {
      errors.push(`Stopped after ${MAX_REDIRECTS} redirects.`);
      finalResponse = response;
      break;
    }
  }

  if (!finalResponse) {
    return {
      ...baseReport,
      redirect_chain: redirectChain,
      errors: errors.length > 0 ? errors : ["No response received."],
    };
  }

  const finalUrl = new URL(currentUrl);
  const headers = normalizeHeaders(finalResponse.headers);
  const { findings, positives } = analyzeHeaders(headers, finalUrl);

  // Impact-based scoring
  const adjusted: Finding[] = findings.map((f) => ({
    ...f,
    severity: adjustSeverity(f.code, f.severity, siteType) as Severity,
  }));

  // Humanize / compliance enrichment
  const enriched: EnrichedFinding[] = adjusted.map((f) => {
    const out: EnrichedFinding = { ...f };
    if (humanize) {
      const h: Humanization | undefined = HUMANIZE[f.code];
      if (h) {
        out.what_this_means = h.what_this_means;
        out.why_it_matters = h.why_it_matters;
        out.who_can_fix = h.who_can_fix;
        out.message_to_developer = h.message_to_developer;
      }
    }
    if (includeCompliance) {
      const c = COMPLIANCE[f.code];
      if (c) out.compliance = c;
    }
    return out;
  });

  if (redirectChain.length > 0) {
    positives.push(`Followed ${redirectChain.length} redirect(s) safely.`);
  }
  if (finalUrl.protocol === "https:" && input.url.startsWith("http://")) {
    positives.push("HTTP request was upgraded to HTTPS via redirect.");
  }

  try {
    if (finalResponse.body && typeof finalResponse.body.cancel === "function") {
      await finalResponse.body.cancel();
    }
  } catch {
    /* ignore */
  }

  let report: AuditReport = {
    target_url: input.url,
    final_url: finalUrl.toString(),
    status: finalResponse.status,
    method_used: methodUsed,
    redirect_chain: redirectChain,
    risk_summary: summarizeRisk(enriched),
    findings: enriched,
    positive_checks: positives,
    ethical_notice: ETHICAL_NOTICE,
    site_type: siteType,
    site_type_note: SITE_TYPE_NOTES[siteType],
    redacted: redact,
  };
  if (errors.length > 0) report.errors = errors;

  // Redaction is applied to the final report so all enrichment fields are
  // also scrubbed. The `redacted` boolean reflects the requested mode.
  if (redact) {
    report = redactValue(report);
    report.redacted = true;
  }

  if (input.save_history) {
    try {
      await saveAudit(report, siteType);
    } catch (err) {
      report.errors = [
        ...(report.errors ?? []),
        `Could not save history: ${err instanceof Error ? err.message : String(err)}`,
      ];
    }
  }

  return report;
}

async function requestWithHeadFallback(
  url: string,
  pinnedIp?: string,
): Promise<{ response: Response; method: "HEAD" | "GET" }> {
  try {
    const response = await safeFetch(url, "HEAD", pinnedIp);
    if (response.status === 405 || response.status === 501 || response.status === 400) {
      try {
        await response.body?.cancel();
      } catch {
        /* ignore */
      }
      const getResp = await safeFetch(url, "GET", pinnedIp);
      return { response: getResp, method: "GET" };
    }
    return { response, method: "HEAD" };
  } catch {
    const getResp = await safeFetch(url, "GET", pinnedIp);
    return { response: getResp, method: "GET" };
  }
}

async function safeFetch(
  url: string,
  method: "HEAD" | "GET",
  pinnedIp?: string,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    if (pinnedIp) {
      return await safeFetchPinned(url, method, pinnedIp, controller.signal);
    }
    return await fetch(url, {
      method,
      redirect: "manual",
      signal: controller.signal,
      headers: { "user-agent": USER_AGENT, accept: "*/*" },
    });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Fetch using a pre-validated pinned IP to prevent DNS rebinding.
 * Connects directly to the resolved IP; passes the original hostname
 * as the Host header (and as TLS SNI for HTTPS).
 */
function safeFetchPinned(
  url: string,
  method: "HEAD" | "GET",
  pinnedIp: string,
  signal: AbortSignal,
): Promise<Response> {
  return new Promise<Response>((resolve, reject) => {
    if (signal.aborted) {
      reject(new Error("Request aborted"));
      return;
    }
    const u = new URL(url);
    const isHttps = u.protocol === "https:";
    const port = u.port ? Number(u.port) : (isHttps ? 443 : 80);
    const path = (u.pathname + u.search) || "/";

    const onAbort = () => req.destroy(new Error("Request aborted"));
    signal.addEventListener("abort", onAbort, { once: true });

    const requestOptions: https.RequestOptions = {
      hostname: pinnedIp,
      port,
      path,
      method,
      headers: {
        "user-agent": USER_AGENT,
        accept: "*/*",
        host: u.host, // preserve original hostname for virtual hosting
      },
    };

    if (isHttps) {
      requestOptions.servername = u.hostname; // TLS SNI
      requestOptions.rejectUnauthorized = true;
    }

    const mod: typeof https = isHttps ? https : (http as unknown as typeof https);
    const req = mod.request(requestOptions, (res) => {
      signal.removeEventListener("abort", onAbort);

      // Build a Headers object, preserving multi-value headers (e.g. Set-Cookie).
      const headerEntries: [string, string][] = [];
      for (const [k, v] of Object.entries(res.headers)) {
        if (v === undefined) continue;
        if (Array.isArray(v)) {
          for (const item of v) headerEntries.push([k, item]);
        } else {
          headerEntries.push([k, v as string]);
        }
      }

      // Drain the body immediately — we only need headers.
      res.resume();

      resolve(new Response(null, {
        status: res.statusCode ?? 0,
        headers: new Headers(headerEntries),
      }));
    });

    req.on("error", (err: Error) => {
      signal.removeEventListener("abort", onAbort);
      reject(err);
    });

    req.end();
  });
}
