# safe-web-audit

A small, **defensive** Model Context Protocol (MCP) server that performs **non-invasive, consent-based** safety checks on a single URL.

It is designed for site owners and authorized testers who want a quick read on their own site's security headers, cookie flags, redirect chain, and TLS posture — without scanning, crawling, fuzzing, or any kind of active testing.

[![CI](https://github.com/Venkatchavan/safe-web-audit-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Venkatchavan/safe-web-audit-mcp/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/safe-web-audit.svg)](https://www.npmjs.com/package/safe-web-audit)

---

## Tools

| Tool | What it does |
|------|--------------|
| `audit_url` | Non-invasive defensive audit. Adds **human-friendly explanations**, **compliance mapping** (OWASP / CIS / ISO / privacy), **impact-based scoring** by `site_type`, **Safe Evidence Mode** (redacts cookies, tokens, emails, IPs), and optional **local timeline** snapshot. |
| `verify_authorization` | Prove ownership via DNS TXT (`_safe-web-audit.<host>`), an HTML well-known file (`/.well-known/safe-web-audit.txt`), or a signed statement. Verified consent is recorded locally. |
| `generate_fixes` | Returns ready-to-paste config snippets for **Nginx, Apache, Caddy, Cloudflare, Vercel, Netlify, Express, Django, Rails, WordPress** keyed off finding codes (e.g. `MISSING_HSTS`). |
| `audit_history` | Lists locally-saved audits or **diffs the last two** for a target — what improved, what remains. Data never leaves your machine. |
| `generate_template` | Produces public-good docs: `security.txt`, responsible-disclosure page, password policy, backup checklist, incident-contact plan. |
| `emergency_checklist` | Calm, defensive incident-response checklist: preserve logs, rotate keys, take exposed admin panels offline, contact hosting, plan user notification. |

### Defensive by construction

- ❌ No crawling, link-following, fuzzing, brute-forcing, login, or form submission
- ❌ No `POST` / `PUT` / `DELETE` / `PATCH`
- ❌ No requests to private/internal IPs (SSRF guarded)
- ✅ Safe Evidence Mode is **on by default** — sensitive data is redacted
- ✅ Every redirect hop is re-validated
- ✅ All history and consent stay local at `~/.safe-web-audit/` (override with `SAFE_WEB_AUDIT_HOME`)

## What `audit_url` reports

A single HEAD (with GET fallback) request and a structured report including:

- Whether HTTPS is used
- Final status code, method used, and full redirect chain
- Presence and quality of security headers:
  - `Strict-Transport-Security`
  - `Content-Security-Policy`
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Referrer-Policy`
  - `Permissions-Policy`
- Cookie flags on every `Set-Cookie`: `Secure`, `HttpOnly`, `SameSite`
- Server fingerprinting headers: `Server`, `X-Powered-By`
- An overall `risk_summary` of `low` / `medium` / `high`
- A list of `findings` with severity, evidence, and recommendation
- A list of `positive_checks`
- An `ethical_notice`

## What it explicitly does **not** do

- ❌ No crawling, link-following, or sitemap walking
- ❌ No form submission, login attempts, or auth bypass
- ❌ No fuzzing, brute-forcing, or path enumeration
- ❌ No `POST` / `PUT` / `DELETE` / `PATCH` requests
- ❌ No requests to private/internal IPs (SSRF-protected)
- ❌ No exploitation of any kind

If `confirm_authorized` is not `true`, the tool refuses to run.

## Safety guarantees

- Only `http://` and `https://` URLs are accepted.
- DNS is resolved up-front and **every** address is checked against blocked ranges (loopback, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, IPv6 ULA / link-local, IPv4-mapped IPv6, cloud metadata IPs, etc.).
- Redirects are followed manually; **each hop is re-validated** against the same rules.
- Short request timeouts (8 s) and a hard cap of 5 redirects.
- Only `HEAD` is sent first; `GET` is used only as a fallback if `HEAD` fails or returns 405/501.
- Response bodies are discarded — only headers and status are inspected.

---

## Install

### Via `npx` (recommended for local clients)

No install required — your MCP client can launch it on demand:

```bash
npx -y safe-web-audit
```

### Globally

```bash
npm install -g safe-web-audit
safe-web-audit            # stdio
safe-web-audit --http     # streamable HTTP on :8787
```

### From source

Requires Node.js 18+ (Node 20+ recommended).

```bash
git clone https://github.com/Venkatchavan/safe-web-audit-mcp
cd safe-web-audit
npm install
npm run build
npm start
```

### Docker

Pre-built multi-arch images are published to GHCR:

```bash
docker run --rm -p 8787:8787 ghcr.io/Venkatchavan/safe-web-audit-mcp:latest
# Health: http://localhost:8787/health
# MCP:    http://localhost:8787/mcp
```

With auth:

```bash
docker run --rm -p 8787:8787 \
  -e MCP_AUTH_TOKEN=$(openssl rand -hex 24) \
  ghcr.io/Venkatchavan/safe-web-audit-mcp:latest
```

---

## Transports

| Transport | When to use | Command |
|-----------|-------------|---------|
| **stdio** (default) | Local AI tools / IDE extensions | `safe-web-audit` |
| **streamable HTTP** | Hosted/remote, shared deployments | `safe-web-audit --http` |

HTTP options:

```
--port <n>            HTTP port (default: $PORT or 8787)
--host <h>            Bind host (default: 0.0.0.0)
--auth-token <tok>    Require Bearer <tok> (or set $MCP_AUTH_TOKEN)
```

The HTTP transport speaks the standard MCP **Streamable HTTP** spec, so any MCP-compatible client that supports remote servers can connect at `https://your.host/mcp`.

---

## Use it from any AI tool

`safe-web-audit` works with every MCP-aware client. The exact config UI differs, but the underlying entry is always the same:

- **Command:** `npx`
- **Args:** `["-y", "safe-web-audit"]`
- (or `command: "node"`, `args: ["/abs/path/to/dist/index.js"]` if installed from source)

### Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "safe-web-audit": {
      "command": "npx",
      "args": ["-y", "safe-web-audit"]
    }
  }
}
```

### Claude Code (CLI)

```bash
claude mcp add safe-web-audit -- npx -y safe-web-audit
```

### Cursor

Settings → MCP → **Add new MCP server**, or `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "safe-web-audit": {
      "command": "npx",
      "args": ["-y", "safe-web-audit"]
    }
  }
}
```

### VS Code — one-click Agent Plugin (recommended)

The repo ships a `plugin.json` + `.mcp.json`, so VS Code can install it directly from the URL:

1. Open the Command Palette (`⇧⌘P`) → **Chat: Install Plugin From Source**
2. Paste `https://github.com/Venkatchavan/safe-web-audit-mcp.git`
3. VS Code clones the plugin and registers `safe-web-audit` in your MCP server list automatically.

You can also browse it in the Extensions view by typing `@agentPlugins` in the search field.

### VS Code — manual config

Add to your user `settings.json` (or `.vscode/mcp.json` for workspace-level):

```jsonc
// .vscode/mcp.json  — already included in this repo
{
  "servers": {
    "safe-web-audit": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "safe-web-audit@latest"]
    }
  }
}
```

### Continue (`continue.dev`)

`~/.continue/config.json`:

```json
{
  "experimental": {
    "modelContextProtocolServers": [
      {
        "name": "safe-web-audit",
        "transport": {
          "type": "stdio",
          "command": "npx",
          "args": ["-y", "safe-web-audit"]
        }
      }
    ]
  }
}
```

### Cline / Roo Code

```json
{
  "mcpServers": {
    "safe-web-audit": {
      "command": "npx",
      "args": ["-y", "safe-web-audit"],
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

### Windsurf

`~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "safe-web-audit": {
      "command": "npx",
      "args": ["-y", "safe-web-audit"]
    }
  }
}
```

### Zed

`~/.config/zed/settings.json`:

```json
{
  "context_servers": {
    "safe-web-audit": {
      "command": {
        "path": "npx",
        "args": ["-y", "safe-web-audit"]
      }
    }
  }
}
```

### Remote / hosted (any client that supports HTTP MCP)

Once you've deployed the HTTP transport (Docker, Fly, Render, Cloud Run, etc.), point any **remote-capable** MCP client at it:

```json
{
  "mcpServers": {
    "safe-web-audit": {
      "url": "https://safe-web-audit.example.com/mcp",
      "headers": { "Authorization": "Bearer YOUR_TOKEN" }
    }
  }
}
```

For clients that don't speak remote MCP yet, bridge with [`mcp-remote`](https://www.npmjs.com/package/mcp-remote):

```json
{
  "mcpServers": {
    "safe-web-audit": {
      "command": "npx",
      "args": [
        "-y", "mcp-remote",
        "https://safe-web-audit.example.com/mcp",
        "--header", "Authorization: Bearer YOUR_TOKEN"
      ]
    }
  }
}
```

---

## Example `audit_url` calls

Minimal call (consent required):

```json
{
  "name": "audit_url",
  "arguments": {
    "url": "https://example.com",
    "confirm_authorized": true
  }
}
```

Without following redirects:

```json
{
  "name": "audit_url",
  "arguments": {
    "url": "https://example.com",
    "confirm_authorized": true,
    "follow_redirects": false
  }
}
```

Refusal example (no consent) — the tool returns an error report instructing the caller to set `confirm_authorized: true`.

### Authorization Proof flow

For stronger consent, use `verify_authorization` first:

```jsonc
// 1) Get a token
{ "name": "verify_authorization",
  "arguments": { "url": "https://example.com", "method": "dns", "generate_token": true } }

// 2) Publish the TXT record at _safe-web-audit.example.com  (or the well-known file)

// 3) Verify
{ "name": "verify_authorization",
  "arguments": { "url": "https://example.com", "method": "dns",
                 "token": "swa-…", "identity": "owner@example.com" } }

// 4) Audit, requiring recorded consent
{ "name": "audit_url",
  "arguments": { "url": "https://example.com", "confirm_authorized": true,
                 "site_type": "ecommerce", "save_history": true,
                 "require_recorded_consent": true } }

// 5) After applying fixes, run audit again then diff:
{ "name": "audit_history",
  "arguments": { "action": "compare", "url": "https://example.com" } }
```

### Fix Generator

```jsonc
{ "name": "generate_fixes",
  "arguments": { "platform": "nginx",
                 "finding_codes": ["MISSING_HSTS", "MISSING_CSP", "MISSING_X_FRAME_OPTIONS"] } }
```

### Example output (abridged)

```json
{
  "target_url": "https://example.com",
  "final_url": "https://example.com/",
  "status": 200,
  "method_used": "HEAD",
  "redirect_chain": [],
  "risk_summary": "medium",
  "findings": [
    {
      "title": "Missing Content-Security-Policy header",
      "severity": "medium",
      "evidence": "No Content-Security-Policy header in response.",
      "recommendation": "Define a Content-Security-Policy that restricts script, frame, and connect sources."
    }
  ],
  "positive_checks": [
    "Strict-Transport-Security present: max-age=63072000",
    "Final response is served over HTTPS."
  ],
  "ethical_notice": "This is a non-invasive defensive audit. Only run it on sites you own or are explicitly authorized to test."
}
```

---

## Deploying a public endpoint

The HTTP transport is a single Node process that listens on `$PORT`. Any platform that runs Docker or Node will work.

### Render / Railway / Fly.io / Cloud Run / Azure Container Apps

1. Point the platform at this repo (or the GHCR image `ghcr.io/Venkatchavan/safe-web-audit-mcp:latest`).
2. Expose port `8787` (or set `PORT` to whatever the platform requires).
3. Set `MCP_AUTH_TOKEN` to a strong random value.
4. The MCP endpoint is `POST /mcp`. Health check: `GET /health`.

### docker-compose

```yaml
services:
  safe-web-audit:
    image: ghcr.io/Venkatchavan/safe-web-audit-mcp:latest
    restart: unless-stopped
    ports:
      - "8787:8787"
    environment:
      MCP_AUTH_TOKEN: ${MCP_AUTH_TOKEN}
```

> ⚠️ Always run a public deployment behind HTTPS (a reverse proxy or platform-provided TLS) and set `MCP_AUTH_TOKEN`. The server only emits non-invasive checks, but the auth token prevents abuse of your bandwidth.

---

## CI/CD

This repository ships with two GitHub Actions workflows:

### `.github/workflows/ci.yml`

Runs on every push and pull request:

- Tests on Node 18 / 20 / 22
- TypeScript build
- Docker image build (no push)

### `.github/workflows/release.yml`

Triggered when you push a tag like `v0.1.0`:

1. Builds and tests on Node 20.
2. Publishes to **npm** with [npm provenance](https://docs.npmjs.com/generating-provenance-statements) (`--provenance`).
3. Builds a multi-arch (amd64 + arm64) Docker image and pushes it to **GHCR** as:
   - `ghcr.io/Venkatchavan/safe-web-audit-mcp:<version>`
   - `ghcr.io/Venkatchavan/safe-web-audit-mcp:<major>.<minor>`
   - `ghcr.io/Venkatchavan/safe-web-audit-mcp:latest`
4. Creates a GitHub Release with auto-generated notes.

#### Required secrets

| Secret | Where | Used by |
|--------|-------|---------|
| `NPM_TOKEN` | npm Automation token with publish access | `release.yml` (npm publish) |
| `GITHUB_TOKEN` | Provided automatically | `release.yml` (GHCR push, release) |

#### Cutting a release

```bash
npm version patch   # or minor / major
git push --follow-tags
```

The tag push triggers `release.yml`, which publishes to npm + GHCR and creates a GitHub release.



---

## Development

```bash
npm install
npm run build       # compile to dist/
npm test            # run the test suite (Node test runner + tsx)
npm run dev         # tsc --watch
```

Run the HTTP server locally:

```bash
node dist/index.js --http --port 8787
curl http://localhost:8787/health
```

## License

MIT — see [LICENSE](LICENSE).
