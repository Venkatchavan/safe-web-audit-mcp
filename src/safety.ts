/**
 * Safety helpers: URL validation and SSRF protection.
 *
 * Blocks private/internal/loopback/link-local ranges and known cloud
 * metadata endpoints. Only http/https are allowed.
 */

import { promises as dns } from "node:dns";
import net from "node:net";

export const ALLOWED_PROTOCOLS = new Set(["http:", "https:"]);

const METADATA_HOSTS = new Set([
  "169.254.169.254", // AWS / GCP / Azure IMDS
  "metadata.google.internal",
  "metadata.goog",
]);

export interface UrlSafetyResult {
  ok: boolean;
  reason?: string;
  hostname?: string;
  resolvedAddresses?: string[];
}

export function parseUrlStrict(raw: string): URL | null {
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

/**
 * Returns true if the given IP literal is in a private/blocked range.
 */
export function isBlockedIp(ip: string): boolean {
  if (!net.isIP(ip)) return false;

  if (net.isIPv4(ip)) {
    const parts = ip.split(".").map((n) => Number(n));
    const [a, b] = parts;
    if (a === 0) return true; // 0.0.0.0/8
    if (a === 10) return true; // 10.0.0.0/8
    if (a === 127) return true; // loopback
    if (a === 169 && b === 254) return true; // link-local + metadata
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 192 && b === 0 && parts[2] === 0) return true; // 192.0.0.0/24
    if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
    if (a >= 224) return true; // multicast / reserved / broadcast
    return false;
  }

  // IPv6
  const lower = ip.toLowerCase();
  if (lower === "::" || lower === "::1") return true; // unspecified / loopback
  if (lower.startsWith("fe80:") || lower.startsWith("fe80::")) return true; // link-local
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // unique local fc00::/7
  if (lower.startsWith("ff")) return true; // multicast
  // IPv4-mapped IPv6: ::ffff:a.b.c.d
  const mapped = lower.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (mapped && isBlockedIp(mapped[1])) return true;
  return false;
}

/**
 * Validate a URL for non-invasive auditing.
 * - Must be http/https
 * - Hostname must not be an internal IP literal
 * - DNS resolution must not return any blocked address
 */
export async function validateUrlForAudit(raw: string): Promise<UrlSafetyResult> {
  const u = parseUrlStrict(raw);
  if (!u) return { ok: false, reason: "Invalid URL." };
  if (!ALLOWED_PROTOCOLS.has(u.protocol)) {
    return { ok: false, reason: `Protocol ${u.protocol} is not allowed. Use http or https.` };
  }

  const hostname = u.hostname;
  if (!hostname) return { ok: false, reason: "URL is missing a hostname." };

  const lowered = hostname.toLowerCase();
  if (lowered === "localhost" || lowered.endsWith(".localhost")) {
    return { ok: false, reason: "Localhost targets are blocked.", hostname };
  }
  if (METADATA_HOSTS.has(lowered)) {
    return { ok: false, reason: "Cloud metadata endpoints are blocked.", hostname };
  }

  // If it's already an IP literal, check directly.
  // URL hostnames may wrap IPv6 in brackets; strip them.
  const ipCandidate = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;

  if (net.isIP(ipCandidate)) {
    if (isBlockedIp(ipCandidate)) {
      return { ok: false, reason: `IP ${ipCandidate} is in a blocked range.`, hostname };
    }
    return { ok: true, hostname, resolvedAddresses: [ipCandidate] };
  }

  // Resolve via DNS and ensure no address falls in blocked ranges.
  let addresses: string[] = [];
  try {
    const records = await dns.lookup(hostname, { all: true, verbatim: true });
    addresses = records.map((r) => r.address);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, reason: `DNS lookup failed: ${msg}`, hostname };
  }

  if (addresses.length === 0) {
    return { ok: false, reason: "DNS lookup returned no addresses.", hostname };
  }

  for (const addr of addresses) {
    if (isBlockedIp(addr)) {
      return {
        ok: false,
        reason: `Hostname resolves to blocked address ${addr}.`,
        hostname,
        resolvedAddresses: addresses,
      };
    }
  }

  return { ok: true, hostname, resolvedAddresses: addresses };
}
