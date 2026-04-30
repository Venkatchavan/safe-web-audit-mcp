#!/usr/bin/env node
/**
 * safe-web-audit MCP server entrypoint.
 *
 * Tools:
 *   - audit_url              Run a non-invasive defensive audit
 *   - verify_authorization   Prove ownership/consent (DNS / HTML / statement)
 *   - generate_fixes         Platform-specific fix recipes for findings
 *   - audit_history          Local timeline + before/after diff
 *   - generate_template      security.txt, disclosure page, password policy, …
 *   - emergency_checklist    Calm incident-response checklist
 *
 * Transports: stdio (default) and streamable HTTP (--http).
 */

import http from "node:http";
import { randomUUID } from "node:crypto";

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

import { auditUrl } from "./audit.js";
import {
  generateAuthToken,
  listConsent,
  verifyAuthorization,
} from "./authorization.js";
import { FIXES, FindingCode, Platform } from "./codes.js";
import { compareLatest, listHistory } from "./storage.js";
import { emergencyChecklist, generateTemplate, TemplateName } from "./templates.js";

// ------------------------------ Schemas --------------------------------------

const SiteTypeEnum = z.enum([
  "school",
  "clinic",
  "ngo",
  "ecommerce",
  "portfolio",
  "saas",
  "blog",
  "other",
]);

const AuditInputSchema = z.object({
  url: z.string().min(1),
  confirm_authorized: z.boolean(),
  follow_redirects: z.boolean().optional(),
  site_type: SiteTypeEnum.optional(),
  redact: z.boolean().optional(),
  humanize: z.boolean().optional(),
  include_compliance: z.boolean().optional(),
  save_history: z.boolean().optional(),
  require_recorded_consent: z.boolean().optional(),
});

const VerifyAuthSchema = z.object({
  url: z.string().min(1),
  method: z.enum(["dns", "html", "statement"]),
  token: z.string().optional(),
  statement: z.string().optional(),
  identity: z.string().optional(),
  generate_token: z.boolean().optional(),
});

const PlatformEnum = z.enum([
  "nginx",
  "apache",
  "caddy",
  "cloudflare",
  "vercel",
  "netlify",
  "express",
  "django",
  "rails",
  "wordpress",
]);

const GenerateFixesSchema = z.object({
  finding_codes: z.array(z.string()).min(1),
  platform: PlatformEnum,
});

const AuditHistorySchema = z.object({
  action: z.enum(["list", "compare"]).default("list"),
  url: z.string().optional(),
});

const TemplateSchema = z.object({
  name: z.enum([
    "security_txt",
    "responsible_disclosure",
    "password_policy",
    "backup_checklist",
    "incident_contact_plan",
  ]),
  contact_email: z.string().optional(),
  org_name: z.string().optional(),
  domain: z.string().optional(),
});

const EmergencySchema = z.object({
  scenario: z.string().optional(),
  has_admin_panel: z.boolean().optional(),
  handles_user_data: z.boolean().optional(),
});

// ------------------------------ Tool descriptors -----------------------------

const TOOLS = [
  {
    name: "audit_url",
    description:
      "Run a non-invasive, consent-based safety audit on a URL you own or are authorized to test. " +
      "Inspects security headers, cookie flags, and redirect chain. Optional human-friendly explanations, " +
      "compliance mapping, impact-based scoring (site_type), Safe Evidence Mode (redact), and local history.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["url", "confirm_authorized"],
      properties: {
        url: { type: "string", description: "Target URL (http/https). Public hosts only." },
        confirm_authorized: {
          type: "boolean",
          description:
            "Must be true. Caller confirms they own or are authorized to audit the target.",
        },
        follow_redirects: { type: "boolean", default: true },
        site_type: {
          type: "string",
          enum: ["school", "clinic", "ngo", "ecommerce", "portfolio", "saas", "blog", "other"],
          description: "Used for impact-based scoring.",
        },
        redact: {
          type: "boolean",
          default: true,
          description: "Safe Evidence Mode: redact cookies, tokens, emails, IPs.",
        },
        humanize: { type: "boolean", default: true },
        include_compliance: { type: "boolean", default: true },
        save_history: {
          type: "boolean",
          default: false,
          description: "Save a snapshot to local timeline (~/.safe-web-audit/history.json).",
        },
        require_recorded_consent: {
          type: "boolean",
          default: false,
          description:
            "If true, refuse unless verify_authorization has previously recorded consent for this hostname.",
        },
      },
    },
  },
  {
    name: "verify_authorization",
    description:
      "Prove ownership/authorization for a URL via DNS TXT, HTML well-known file, or a signed statement. " +
      "Verified consent is appended to the local consent ledger.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["url", "method"],
      properties: {
        url: { type: "string" },
        method: { type: "string", enum: ["dns", "html", "statement"] },
        token: {
          type: "string",
          description:
            "Required for dns/html. The token to look for at _safe-web-audit.<host> (TXT) " +
            "or /.well-known/safe-web-audit.txt (HTML).",
        },
        statement: { type: "string", description: "Required for method=statement." },
        identity: { type: "string", description: "Name/email/role of the person attesting." },
        generate_token: {
          type: "boolean",
          description: "If true and no token is given, return a fresh token to publish.",
        },
      },
    },
  },
  {
    name: "generate_fixes",
    description:
      "Return platform-specific configuration snippets for one or more finding codes (e.g. MISSING_HSTS).",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["finding_codes", "platform"],
      properties: {
        finding_codes: { type: "array", items: { type: "string" }, minItems: 1 },
        platform: {
          type: "string",
          enum: [
            "nginx",
            "apache",
            "caddy",
            "cloudflare",
            "vercel",
            "netlify",
            "express",
            "django",
            "rails",
            "wordpress",
          ],
        },
      },
    },
  },
  {
    name: "audit_history",
    description:
      "List previously-saved audits (local only) or compare the most recent two audits for a target " +
      "to show what improved and what remains.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        action: { type: "string", enum: ["list", "compare"], default: "list" },
        url: { type: "string", description: "Filter/compare by URL or hostname." },
      },
    },
  },
  {
    name: "generate_template",
    description:
      "Generate a public-good template: security.txt, responsible disclosure page, password policy, " +
      "backup checklist, or incident contact plan.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["name"],
      properties: {
        name: {
          type: "string",
          enum: [
            "security_txt",
            "responsible_disclosure",
            "password_policy",
            "backup_checklist",
            "incident_contact_plan",
          ],
        },
        contact_email: { type: "string" },
        org_name: { type: "string" },
        domain: { type: "string" },
      },
    },
  },
  {
    name: "emergency_checklist",
    description:
      "Return a calm, defensive checklist for suspected compromise: preserve logs, rotate keys, " +
      "disable exposed admin panels, contact hosting, notify users.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        scenario: { type: "string" },
        has_admin_panel: { type: "boolean" },
        handles_user_data: { type: "boolean" },
      },
    },
  },
] as const;

// ------------------------------ Server build ---------------------------------

function jsonContent(obj: unknown) {
  return [{ type: "text", text: JSON.stringify(obj, null, 2) }];
}

function textContent(text: string) {
  return [{ type: "text", text }];
}

function buildServer(): Server {
  const server = new Server(
    { name: "safe-web-audit", version: "0.2.1" },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS as unknown as never[] }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const name = req.params.name;
    const args = req.params.arguments ?? {};
    try {
      switch (name) {
        case "audit_url": {
          const parsed = AuditInputSchema.safeParse(args);
          if (!parsed.success) return invalidArgs(parsed.error.issues.map((i) => i.message));
          const report = await auditUrl(parsed.data);
          const isError =
            Array.isArray(report.errors) && report.errors.length > 0 && report.status === null;
          return { isError, content: jsonContent(report) };
        }
        case "verify_authorization": {
          const parsed = VerifyAuthSchema.safeParse(args);
          if (!parsed.success) return invalidArgs(parsed.error.issues.map((i) => i.message));
          const v = parsed.data;
          if (v.generate_token && !v.token) {
            const token = generateAuthToken();
            return {
              content: jsonContent({
                generated_token: token,
                next_steps: nextStepsForToken(v.url, v.method, token),
              }),
            };
          }
          const result = await verifyAuthorization({
            url: v.url,
            method: v.method,
            token: v.token,
            statement: v.statement,
            identity: v.identity,
          });
          return { isError: !result.ok, content: jsonContent(result) };
        }
        case "generate_fixes": {
          const parsed = GenerateFixesSchema.safeParse(args);
          if (!parsed.success) return invalidArgs(parsed.error.issues.map((i) => i.message));
          const platform = parsed.data.platform as Platform;
          const fixes = parsed.data.finding_codes.map((codeRaw) => {
            const code = codeRaw as FindingCode;
            const recipe = FIXES[code]?.[platform];
            if (!recipe) {
              return {
                code,
                platform,
                available: false,
                note: `No ${platform} recipe for ${code}. See the recommendation field of the finding.`,
              };
            }
            return { code, platform, available: true, ...recipe };
          });
          return { content: jsonContent({ platform, fixes }) };
        }
        case "audit_history": {
          const parsed = AuditHistorySchema.safeParse(args);
          if (!parsed.success) return invalidArgs(parsed.error.issues.map((i) => i.message));
          if (parsed.data.action === "compare") {
            if (!parsed.data.url) return invalidArgs(["url is required for compare"]);
            const cmp = await compareLatest(parsed.data.url);
            if (!cmp) {
              return {
                content: jsonContent({
                  message:
                    "Need at least two saved audits for this target. Run audit_url with save_history: true twice.",
                }),
              };
            }
            return { content: jsonContent(cmp) };
          }
          const entries = await listHistory(parsed.data.url);
          return { content: jsonContent({ count: entries.length, entries }) };
        }
        case "generate_template": {
          const parsed = TemplateSchema.safeParse(args);
          if (!parsed.success) return invalidArgs(parsed.error.issues.map((i) => i.message));
          const out = generateTemplate({
            name: parsed.data.name as TemplateName,
            contact_email: parsed.data.contact_email,
            org_name: parsed.data.org_name,
            domain: parsed.data.domain,
          });
          return { content: jsonContent(out) };
        }
        case "emergency_checklist": {
          const parsed = EmergencySchema.safeParse(args);
          if (!parsed.success) return invalidArgs(parsed.error.issues.map((i) => i.message));
          return { content: jsonContent(emergencyChecklist(parsed.data)) };
        }
        case "list_consent": {
          // Internal/utility tool not advertised; kept simple.
          const records = await listConsent();
          return { content: jsonContent({ records }) };
        }
        default:
          return { isError: true, content: textContent(`Unknown tool: ${name}`) };
      }
    } catch (err) {
      return {
        isError: true,
        content: textContent(
          `Tool ${name} failed: ${err instanceof Error ? err.message : String(err)}`,
        ),
      };
    }
  });

  return server;
}

function invalidArgs(msgs: string[]) {
  return { isError: true, content: textContent(`Invalid arguments: ${msgs.join("; ")}`) };
}

function nextStepsForToken(
  url: string,
  method: "dns" | "html" | "statement",
  token: string,
): string[] {
  let host = "";
  try {
    host = new URL(url).host;
  } catch {
    /* ignore */
  }
  if (method === "dns") {
    return [
      `Add a TXT record at _safe-web-audit.${host} with value: ${token}`,
      "Wait for DNS propagation (usually a minute or two).",
      `Then call verify_authorization again with method='dns' and token='${token}'.`,
    ];
  }
  if (method === "html") {
    return [
      `Create a file at https://${host}/.well-known/safe-web-audit.txt containing: ${token}`,
      `Then call verify_authorization again with method='html' and token='${token}'.`,
    ];
  }
  return [
    "For statement-based authorization, call verify_authorization with method='statement', identity, and a signed statement.",
    `Reference token (optional): ${token}`,
  ];
}

// ------------------------------ Transports -----------------------------------

interface CliOptions {
  http: boolean;
  port: number;
  host: string;
  authToken?: string;
  noAuth: boolean;
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    http: false,
    port: Number(process.env.PORT ?? 8787),
    host: process.env.HOST ?? "0.0.0.0",
    authToken: process.env.MCP_AUTH_TOKEN || undefined,
    noAuth: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--http") opts.http = true;
    else if (a === "--stdio") opts.http = false;
    else if (a === "--port") opts.port = Number(argv[++i]);
    else if (a === "--host") opts.host = argv[++i];
    else if (a === "--auth-token") opts.authToken = argv[++i];
    else if (a === "--no-auth") opts.noAuth = true;
    else if (a === "--help" || a === "-h") printHelpAndExit(0);
  }
  if (!Number.isFinite(opts.port) || opts.port <= 0) {
    console.error(`Invalid port: ${opts.port}`);
    process.exit(2);
  }
  return opts;
}

function printHelpAndExit(code: number): never {
  console.log(`safe-web-audit — defensive MCP server

Usage:
  safe-web-audit                 Run on stdio (default; for local MCP clients)
  safe-web-audit --http          Run streamable HTTP server
  safe-web-audit --http --port 3000

Options:
  --http                Use streamable HTTP transport
  --stdio               Use stdio transport (default)
  --port <n>            HTTP port (default: $PORT or 8787)
  --host <h>            HTTP bind host (default: 0.0.0.0)
  --auth-token <tok>    Require Bearer <tok> on HTTP (or set $MCP_AUTH_TOKEN)
  --no-auth             Skip auth enforcement (local/dev only; NOT for public endpoints)
  -h, --help            Show this help
`);
  process.exit(code);
}

async function runStdio() {
  const server = buildServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "localhost"]);

async function runHttp(opts: CliOptions) {
  if (!LOOPBACK_HOSTS.has(opts.host) && !opts.authToken && !opts.noAuth) {
    console.error(
      "[safe-web-audit] FATAL: HTTP mode is binding to a non-loopback host (" + opts.host + ") without authentication.\n" +
      "Set --auth-token <token> or the MCP_AUTH_TOKEN environment variable to protect this endpoint.\n" +
      "For local-only development, use --host 127.0.0.1 instead.\n" +
      "To explicitly opt out of this check (not recommended): pass --no-auth."
    );
    process.exit(1);
  }
  const sessions = new Map<
    string,
    { server: Server; transport: StreamableHTTPServerTransport }
  >();
  const httpServer = http.createServer(async (req, res) => {
    try {
      if (req.method === "GET" && (req.url === "/health" || req.url === "/healthz")) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ status: "ok", name: "safe-web-audit" }));
        return;
      }
      if (opts.authToken) {
        const auth = req.headers["authorization"];
        if (auth !== `Bearer ${opts.authToken}`) {
          res.writeHead(401, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: "unauthorized" }));
          return;
        }
      }
      const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
      if (url.pathname !== "/mcp") {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "not found", hint: "POST to /mcp" }));
        return;
      }
      const sessionHeader = req.headers["mcp-session-id"];
      const sid = Array.isArray(sessionHeader) ? sessionHeader[0] : sessionHeader;
      let entry = sid ? sessions.get(sid) : undefined;
      if (!entry) {
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
        });
        const server = buildServer();
        await server.connect(transport);
        transport.onclose = () => {
          const id = transport.sessionId;
          if (id) sessions.delete(id);
        };
        const body = await readJsonBody(req);
        await transport.handleRequest(req, res, body);
        const newId = transport.sessionId;
        if (newId) sessions.set(newId, { server, transport });
        return;
      }
      const body = await readJsonBody(req);
      await entry.transport.handleRequest(req, res, body);
    } catch (err) {
      console.error("[safe-web-audit] HTTP error:", err);
      if (!res.headersSent) {
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: "internal error" }));
      } else {
        try {
          res.end();
        } catch {
          /* ignore */
        }
      }
    }
  });
  await new Promise<void>((resolve) =>
    httpServer.listen(opts.port, opts.host, () => resolve()),
  );
  console.error(
    `[safe-web-audit] streamable HTTP listening on http://${opts.host}:${opts.port}/mcp` +
      (opts.authToken ? " (auth required)" : ""),
  );
  const shutdown = async () => {
    console.error("[safe-web-audit] shutting down");
    await new Promise<void>((r) => httpServer.close(() => r()));
    for (const { transport } of sessions.values()) {
      try {
        await transport.close();
      } catch {
        /* ignore */
      }
    }
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

async function readJsonBody(req: http.IncomingMessage): Promise<unknown> {
  if (req.method !== "POST") return undefined;
  const chunks: Buffer[] = [];
  let total = 0;
  const MAX = 1_000_000;
  for await (const chunk of req) {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += buf.length;
    if (total > MAX) throw new Error("request body too large");
    chunks.push(buf);
  }
  if (chunks.length === 0) return undefined;
  const raw = Buffer.concat(chunks).toString("utf8");
  if (!raw.trim()) return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error("invalid JSON body");
  }
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.http) await runHttp(opts);
  else await runStdio();
}

main().catch((err) => {
  console.error("safe-web-audit fatal error:", err);
  process.exit(1);
});
