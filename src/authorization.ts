/**
 * Authorization-proof verification for consent-based auditing.
 *
 * Three accepted methods:
 *   1. dns       — TXT record at  _safe-web-audit.<host>  containing the token
 *   2. html      — file at        https://<host>/.well-known/safe-web-audit.txt
 *                  containing the token
 *   3. statement — caller-provided signed statement (free-form text incl. the
 *                  token + the caller's identity). No server-side trust here;
 *                  it's a recorded affidavit.
 *
 * Verified consent is appended to the local consent ledger
 *   $SAFE_WEB_AUDIT_HOME/consent.json
 * which never leaves the host.
 */

import { promises as dns } from "node:dns";
import { promises as fs } from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import path from "node:path";
import os from "node:os";

import { validateUrlForAudit } from "./safety.js";

export type AuthMethod = "dns" | "html" | "statement";

export interface AuthorizationInput {
  url: string;
  method: AuthMethod;
  token?: string; // required for dns / html
  statement?: string; // required for "statement"
  identity?: string; // free-form: name/email/role attesting authorization
}

export interface AuthorizationResult {
  ok: boolean;
  method: AuthMethod;
  hostname: string;
  token_used?: string;
  evidence?: string;
  consent_id?: string;
  reason?: string;
}

export interface ConsentRecord {
  id: string;
  timestamp: string;
  hostname: string;
  url: string;
  method: AuthMethod;
  token_hash?: string;
  identity?: string;
  scope: string;
}

const SCOPE_TEXT =
  "Non-invasive defensive audit only: HEAD/GET request, headers and cookie-flag inspection, redirect-chain validation. No crawling, fuzzing, brute-forcing, login, or form submission.";

function homeDir(): string {
  return process.env.SAFE_WEB_AUDIT_HOME || path.join(os.homedir(), ".safe-web-audit");
}
function consentFile(): string {
  return path.join(homeDir(), "consent.json");
}

export function generateAuthToken(): string {
  return `swa-${randomBytes(12).toString("hex")}`;
}

export async function verifyAuthorization(
  input: AuthorizationInput,
): Promise<AuthorizationResult> {
  const safety = await validateUrlForAudit(input.url);
  if (!safety.ok) {
    return { ok: false, method: input.method, hostname: "", reason: `Blocked: ${safety.reason}` };
  }
  const u = new URL(input.url);
  const hostname = u.hostname;

  if (input.method === "dns") {
    if (!input.token) {
      return { ok: false, method: "dns", hostname, reason: "token is required for dns method" };
    }
    const recordHost = `_safe-web-audit.${hostname}`;
    let records: string[][];
    try {
      records = await dns.resolveTxt(recordHost);
    } catch (err) {
      return {
        ok: false,
        method: "dns",
        hostname,
        reason: `DNS TXT lookup failed for ${recordHost}: ${
          err instanceof Error ? err.message : String(err)
        }`,
      };
    }
    const flat = records.map((parts) => parts.join("")).map((s) => s.trim());
    if (!flat.some((v) => v === input.token || v === `safe-web-audit=${input.token}`)) {
      return {
        ok: false,
        method: "dns",
        hostname,
        reason: `Token not found in TXT record at ${recordHost}.`,
      };
    }
    const consent_id = await recordConsent({
      hostname,
      url: input.url,
      method: "dns",
      token_hash: hashToken(input.token),
      identity: input.identity,
    });
    return {
      ok: true,
      method: "dns",
      hostname,
      token_used: input.token,
      evidence: `TXT ${recordHost} contains token`,
      consent_id,
    };
  }

  if (input.method === "html") {
    if (!input.token) {
      return { ok: false, method: "html", hostname, reason: "token is required for html method" };
    }
    const wkUrl = `${u.protocol}//${u.host}/.well-known/safe-web-audit.txt`;
    const wkSafety = await validateUrlForAudit(wkUrl);
    if (!wkSafety.ok) {
      return { ok: false, method: "html", hostname, reason: `Blocked: ${wkSafety.reason}` };
    }
    let body: string;
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 8000);
      const resp = await fetch(wkUrl, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: { "user-agent": "safe-web-audit/0.1 (auth-proof)" },
      });
      clearTimeout(timer);
      if (!resp.ok) {
        return {
          ok: false,
          method: "html",
          hostname,
          reason: `Fetched ${wkUrl} -> HTTP ${resp.status}`,
        };
      }
      // Cap body size at 16KB.
      const reader = resp.body?.getReader();
      let total = 0;
      const chunks: Uint8Array[] = [];
      if (reader) {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          if (value) {
            total += value.length;
            if (total > 16_384) break;
            chunks.push(value);
          }
        }
      }
      body = Buffer.concat(chunks.map((c) => Buffer.from(c))).toString("utf8");
    } catch (err) {
      return {
        ok: false,
        method: "html",
        hostname,
        reason: `Fetch failed: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
    if (!body.includes(input.token)) {
      return {
        ok: false,
        method: "html",
        hostname,
        reason: `Token not found in ${wkUrl}.`,
      };
    }
    const consent_id = await recordConsent({
      hostname,
      url: input.url,
      method: "html",
      token_hash: hashToken(input.token),
      identity: input.identity,
    });
    return {
      ok: true,
      method: "html",
      hostname,
      token_used: input.token,
      evidence: `${wkUrl} contains token`,
      consent_id,
    };
  }

  // method === "statement"
  if (!input.statement || input.statement.trim().length < 20) {
    return {
      ok: false,
      method: "statement",
      hostname,
      reason: "A signed statement of at least 20 characters is required.",
    };
  }
  if (!input.identity || input.identity.trim().length < 2) {
    return {
      ok: false,
      method: "statement",
      hostname,
      reason: "An identity (name/email/role) is required for statement-based authorization.",
    };
  }
  const consent_id = await recordConsent({
    hostname,
    url: input.url,
    method: "statement",
    identity: input.identity,
  });
  return {
    ok: true,
    method: "statement",
    hostname,
    evidence: `Recorded signed statement (${input.statement.length} chars) by ${input.identity}`,
    consent_id,
  };
}

async function recordConsent(args: {
  hostname: string;
  url: string;
  method: AuthMethod;
  token_hash?: string;
  identity?: string;
}): Promise<string> {
  const records = await readConsent();
  const id = `consent-${randomBytes(8).toString("hex")}`;
  const rec: ConsentRecord = {
    id,
    timestamp: new Date().toISOString(),
    hostname: args.hostname,
    url: args.url,
    method: args.method,
    token_hash: args.token_hash,
    identity: args.identity,
    scope: SCOPE_TEXT,
  };
  records.push(rec);
  await fs.mkdir(homeDir(), { recursive: true });
  await fs.writeFile(consentFile(), JSON.stringify(records.slice(-500), null, 2), "utf8");
  return id;
}

async function readConsent(): Promise<ConsentRecord[]> {
  try {
    const raw = await fs.readFile(consentFile(), "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as ConsentRecord[]) : [];
  } catch (err) {
    if ((err as NodeJS.ErrnoException)?.code === "ENOENT") return [];
    return [];
  }
}

export async function listConsent(hostname?: string): Promise<ConsentRecord[]> {
  const all = await readConsent();
  if (!hostname) return all;
  return all.filter((r) => r.hostname === hostname);
}

export async function hasConsent(hostname: string): Promise<boolean> {
  const all = await readConsent();
  return all.some((r) => r.hostname === hostname);
}

function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}
