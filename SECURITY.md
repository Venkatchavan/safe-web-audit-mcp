# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x (latest) | ✅ |

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report security issues by emailing the maintainer directly or by opening a [GitHub Security Advisory](https://github.com/Venkatchavan/safe-web-audit-mcp/security/advisories/new) (private disclosure).

Include:
- A description of the vulnerability and its impact
- Steps to reproduce
- Any suggested remediation

You should receive an acknowledgement within 48 hours and a resolution timeline within 7 days.

## Security Design

`safe-web-audit` is defensive by construction:

- **No offensive capabilities** — no crawling, fuzzing, brute-forcing, login, form submission, or exploitation.
- **SSRF protection** — all hostnames are resolved via DNS before any request. Every resolved address is checked against private/loopback/link-local/metadata ranges. Each redirect hop is re-validated. The resolved IP is pinned for the actual connection to prevent DNS rebinding.
- **Consent gate** — the `confirm_authorized` flag must be `true`; tools refuse to operate otherwise. An optional `verify_authorization` workflow provides cryptographic proof of ownership.
- **Safe Evidence Mode** — cookies, tokens, emails, and IPs are redacted from all output by default.
- **Local-only persistence** — audit history and consent records are stored at `~/.safe-web-audit/` and never transmitted.
- **HTTP auth enforcement** — when `--http` is used with a non-loopback bind address, an auth token is required unless `--no-auth` is explicitly set.

## Scope

The following are **in scope** for responsible disclosure:

- SSRF bypass (private IP reachable via audit_url)
- Auth bypass on the HTTP transport
- Consent gate bypass
- Sensitive data leaked in output despite redaction being enabled
- Supply chain issues (malicious dependency, compromised build)

The following are **out of scope**:

- Findings against third-party sites (this tool audits your own sites)
- DNS resolution behaviour of the underlying OS
- Issues requiring physical access to the machine
