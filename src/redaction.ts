/**
 * Safe Evidence Mode: redact sensitive data from finding evidence and other
 * fields before the report leaves the server.
 *
 * Targets cookie values, bearer tokens, API keys, email addresses, IPv4 and
 * IPv6 addresses (other than well-known publics), and a handful of common
 * leakable headers.
 */

const PATTERNS: Array<[RegExp, string]> = [
  // Bearer tokens / Authorization
  [/\b(Authorization\s*[:=]\s*Bearer\s+)\S+/gi, "$1<REDACTED>"],
  [/\bBearer\s+[A-Za-z0-9._\-]+/gi, "Bearer <REDACTED>"],
  // API keys / tokens (long alnum)
  [/\b(api[_-]?key|token|secret|password)\s*[:=]\s*["']?[A-Za-z0-9._\-]{12,}["']?/gi, "$1=<REDACTED>"],
  // JWT-ish
  [/\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b/g, "<REDACTED_JWT>"],
  // Emails
  [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, "<REDACTED_EMAIL>"],
  // IPv4
  [/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, "<REDACTED_IP>"],
  // IPv6 (loose)
  [/\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b/gi, "<REDACTED_IP6>"],
];

export function redactString(input: string): string {
  let out = input;
  // Redact cookie values: anything between "=" and ";" or end inside Set-Cookie-like text
  out = out.replace(/(set-cookie:?\s*[^=;\s]+\s*=\s*)([^;\s]+)/gi, "$1<REDACTED>");
  for (const [re, rep] of PATTERNS) {
    out = out.replace(re, rep);
  }
  return out;
}

export function redactValue<T>(value: T): T {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return redactString(value) as unknown as T;
  if (Array.isArray(value)) {
    return value.map((v) => redactValue(v)) as unknown as T;
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) {
      out[k] = redactValue(v);
    }
    return out as unknown as T;
  }
  return value;
}
