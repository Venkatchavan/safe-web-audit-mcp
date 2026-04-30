/**
 * audit_url implementation. Performs a single, non-invasive request
 * (HEAD, falling back to GET) and analyzes response headers.
 *
 * Manually walks redirects so that every hop is re-validated for SSRF.
 */

import { validateUrlForAudit } from "./safety.js";
import {
  analyzeHeaders,
  Finding,
  normalizeHeaders,
  summarizeRisk,
} from "./checks.js";

const REQUEST_TIMEOUT_MS = 8_000;
const MAX_REDIRECTS = 5;
const USER_AGENT = "safe-web-audit/0.1 (+defensive non-invasive audit)";

export interface AuditInput {
  url: string;
  confirm_authorized: boolean;
  follow_redirects?: boolean;
}

export interface RedirectHop {
  from: string;
  to: string;
  status: number;
}

export interface AuditReport {
  target_url: string;
  final_url: string | null;
  status: number | null;
  method_used: "HEAD" | "GET" | null;
  redirect_chain: RedirectHop[];
  risk_summary: "low" | "medium" | "high";
  findings: Finding[];
  positive_checks: string[];
  ethical_notice: string;
  errors?: string[];
}

const ETHICAL_NOTICE =
  "This is a non-invasive defensive audit. Only run it on sites you own or are explicitly authorized to test.";

export async function auditUrl(input: AuditInput): Promise<AuditReport> {
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
  };

  if (input.confirm_authorized !== true) {
    return {
      ...baseReport,
      risk_summary: "low",
      errors: [
        "Refusing to run: `confirm_authorized` must be true. Only audit sites you own or are authorized to test.",
      ],
    };
  }

  const followRedirects = input.follow_redirects ?? true;

  // Validate the initial URL.
  const initialCheck = await validateUrlForAudit(input.url);
  if (!initialCheck.ok) {
    return { ...baseReport, errors: [`Blocked: ${initialCheck.reason}`] };
  }

  let currentUrl = input.url;
  const redirectChain: RedirectHop[] = [];
  const errors: string[] = [];

  let finalResponse: Response | null = null;
  let methodUsed: "HEAD" | "GET" | null = null;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    let response: Response;
    try {
      const result = await requestWithHeadFallback(currentUrl);
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
      // If we are not following redirects but got one, still capture the hop.
      if (isRedirect && !followRedirects) {
        const loc = response.headers.get("location");
        if (loc) {
          try {
            const next = new URL(loc, currentUrl).toString();
            redirectChain.push({ from: currentUrl, to: next, status });
          } catch {
            // ignore malformed Location
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

    // Re-validate the redirect target against the same safety rules.
    const check = await validateUrlForAudit(nextUrl);
    if (!check.ok) {
      errors.push(`Blocked redirect to ${nextUrl}: ${check.reason}`);
      finalResponse = response;
      break;
    }

    currentUrl = nextUrl;

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

  if (redirectChain.length > 0) {
    positives.push(`Followed ${redirectChain.length} redirect(s) safely.`);
  }
  if (finalUrl.protocol === "https:" && input.url.startsWith("http://")) {
    positives.push("HTTP request was upgraded to HTTPS via redirect.");
  }

  // Drain body to free the connection (we never use it).
  try {
    if (finalResponse.body && typeof finalResponse.body.cancel === "function") {
      await finalResponse.body.cancel();
    }
  } catch {
    /* ignore */
  }

  const report: AuditReport = {
    target_url: input.url,
    final_url: finalUrl.toString(),
    status: finalResponse.status,
    method_used: methodUsed,
    redirect_chain: redirectChain,
    risk_summary: summarizeRisk(findings),
    findings,
    positive_checks: positives,
    ethical_notice: ETHICAL_NOTICE,
  };
  if (errors.length > 0) report.errors = errors;
  return report;
}

async function requestWithHeadFallback(
  url: string,
): Promise<{ response: Response; method: "HEAD" | "GET" }> {
  // HEAD first.
  try {
    const response = await safeFetch(url, "HEAD");
    // Some servers return 405/501 for HEAD; fall back to GET.
    if (response.status === 405 || response.status === 501 || response.status === 400) {
      try {
        await response.body?.cancel();
      } catch {
        /* ignore */
      }
      const getResp = await safeFetch(url, "GET");
      return { response: getResp, method: "GET" };
    }
    return { response, method: "HEAD" };
  } catch {
    const getResp = await safeFetch(url, "GET");
    return { response: getResp, method: "GET" };
  }
}

async function safeFetch(url: string, method: "HEAD" | "GET"): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    return await fetch(url, {
      method,
      // We handle redirects manually so each hop is re-validated.
      redirect: "manual",
      signal: controller.signal,
      headers: {
        "user-agent": USER_AGENT,
        accept: "*/*",
      },
    });
  } finally {
    clearTimeout(timer);
  }
}
