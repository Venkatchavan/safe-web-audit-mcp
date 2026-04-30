#!/usr/bin/env node
/**
 * safe-web-audit MCP server entrypoint.
 *
 * Supports two transports:
 *   - stdio (default): for local MCP clients (Claude Desktop, Cursor, VS Code,
 *     Continue, Cline, Windsurf, Zed, etc.)
 *   - http: streamable HTTP transport on a port, for hosted/remote use.
 *
 * Usage:
 *   safe-web-audit                  # stdio
 *   safe-web-audit --http           # HTTP on PORT (default 8787)
 *   PORT=3000 safe-web-audit --http # HTTP on port 3000
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

const AuditInputSchema = z.object({
  url: z.string().min(1, "url is required"),
  confirm_authorized: z.boolean(),
  follow_redirects: z.boolean().optional(),
});

const TOOL_DEFINITION = {
  name: "audit_url",
  description:
    "Run a non-invasive, consent-based safety audit on a URL you own or are authorized to test. " +
    "Performs a single HEAD (or GET fallback) request, inspects security headers, cookie flags, " +
    "and redirect chain. Does NOT crawl, fuzz, brute-force, log in, or submit forms.",
  inputSchema: {
    type: "object",
    additionalProperties: false,
    required: ["url", "confirm_authorized"],
    properties: {
      url: {
        type: "string",
        description:
          "Target URL (http or https). Public hosts only; private/internal IPs are blocked.",
      },
      confirm_authorized: {
        type: "boolean",
        description:
          "Must be true. Confirms the caller owns or has explicit authorization to audit the target.",
      },
      follow_redirects: {
        type: "boolean",
        description:
          "Whether to follow redirects (each hop is re-validated). Default: true.",
        default: true,
      },
    },
  },
} as const;

function buildServer(): Server {
  const server = new Server(
    { name: "safe-web-audit", version: "0.1.0" },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [TOOL_DEFINITION],
  }));

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    if (req.params.name !== "audit_url") {
      return {
        isError: true,
        content: [{ type: "text", text: `Unknown tool: ${req.params.name}` }],
      };
    }

    const parsed = AuditInputSchema.safeParse(req.params.arguments ?? {});
    if (!parsed.success) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `Invalid arguments: ${parsed.error.issues.map((i) => i.message).join("; ")}`,
          },
        ],
      };
    }

    const report = await auditUrl(parsed.data);
    const isError =
      Array.isArray(report.errors) && report.errors.length > 0 && report.status === null;
    return {
      isError,
      content: [{ type: "text", text: JSON.stringify(report, null, 2) }],
    };
  });

  return server;
}

interface CliOptions {
  http: boolean;
  port: number;
  host: string;
  authToken?: string;
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = {
    http: false,
    port: Number(process.env.PORT ?? 8787),
    host: process.env.HOST ?? "0.0.0.0",
    authToken: process.env.MCP_AUTH_TOKEN || undefined,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--http") opts.http = true;
    else if (a === "--stdio") opts.http = false;
    else if (a === "--port") opts.port = Number(argv[++i]);
    else if (a === "--host") opts.host = argv[++i];
    else if (a === "--auth-token") opts.authToken = argv[++i];
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
  -h, --help            Show this help
`);
  process.exit(code);
}

async function runStdio() {
  const server = buildServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

async function runHttp(opts: CliOptions) {
  // Stateful streamable HTTP. Each MCP session gets its own Server instance
  // and transport, keyed by the Mcp-Session-Id header.
  const sessions = new Map<
    string,
    { server: Server; transport: StreamableHTTPServerTransport }
  >();

  const httpServer = http.createServer(async (req, res) => {
    try {
      // Health endpoint for load balancers / uptime checks.
      if (req.method === "GET" && (req.url === "/health" || req.url === "/healthz")) {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ status: "ok", name: "safe-web-audit" }));
        return;
      }

      // Optional bearer-token auth.
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
  const MAX = 1_000_000; // 1 MB
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
