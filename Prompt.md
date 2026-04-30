Create a defensive Model Context Protocol server named `safe-web-audit`.

Goal:
Build a local MCP server for ethical, consent-based website safety checks. It should only inspect URLs that the user says they own or are authorized to test. It must not exploit, brute-force, crawl, fuzz, bypass auth, or attack anything.

Tech:
Use TypeScript and the official MCP SDK if available. Create a clean project with package.json, src files, README, and basic tests if practical.

MCP tool:
Add one tool named `audit_url`.

Input schema:
- url: string, required
- confirm_authorized: boolean, required
- follow_redirects: boolean, optional, default true

Safety rules:
- If `confirm_authorized` is not true, refuse to run.
- Only allow http:// and https:// URLs.
- Do not send POST/PUT/DELETE/PATCH requests.
- Use HEAD first, fall back to GET only if HEAD fails.
- Use short timeouts.
- Do not crawl links.
- Do not test forms.
- Do not attempt login.
- Block private/internal IP ranges by default to prevent SSRF, including localhost, 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, link-local, and metadata IPs.
- If redirects are followed, re-check every redirect target against the same safety rules.

Checks:
- Whether HTTPS is used
- Final status code
- Redirect chain
- Presence and quality of these headers:
  - Strict-Transport-Security
  - Content-Security-Policy
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
- Cookie flags if Set-Cookie is present:
  - Secure
  - HttpOnly
  - SameSite
- Basic server information exposure:
  - Server header
  - X-Powered-By header

Output:
Return a structured JSON-like report with:
- target_url
- final_url
- status
- risk_summary: low/medium/high
- findings: array of objects with title, severity, evidence, recommendation
- positive_checks: array
- ethical_notice: short reminder that this is a non-invasive defensive audit

README:
Include setup instructions, how to run the MCP server, example MCP config, and example `audit_url` calls.

Keep the implementation simple, readable, and defensive. Do not include offensive scanning features.
