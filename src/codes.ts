/**
 * Central registry of finding codes plus enrichment data:
 *   - Human-friendly explanations (for non-technical owners)
 *   - Compliance mappings (OWASP / CIS / ISO-style / privacy hygiene)
 *   - Platform-specific fix recipes (for Fix Generator / PR Assistant)
 *
 * Findings produced by checks.ts use these codes; humanize/fixes/compliance
 * features all key off the same code so they stay in sync.
 */

export type FindingCode =
  | "NO_HTTPS"
  | "MISSING_HSTS"
  | "WEAK_HSTS"
  | "MISSING_CSP"
  | "MISSING_X_FRAME_OPTIONS"
  | "MISSING_X_CONTENT_TYPE_OPTIONS"
  | "WEAK_X_CONTENT_TYPE_OPTIONS"
  | "MISSING_REFERRER_POLICY"
  | "MISSING_PERMISSIONS_POLICY"
  | "COOKIE_NO_SECURE"
  | "COOKIE_NO_HTTPONLY"
  | "COOKIE_NO_SAMESITE"
  | "COOKIE_SAMESITE_NONE_NO_SECURE"
  | "SERVER_HEADER_DISCLOSURE"
  | "X_POWERED_BY_DISCLOSURE";

export interface Humanization {
  what_this_means: string;
  why_it_matters: string;
  who_can_fix: string;
  message_to_developer: string;
}

export interface ComplianceMapping {
  owasp?: string[];
  cis?: string[];
  iso?: string[];
  privacy?: string[];
}

export const HUMANIZE: Record<FindingCode, Humanization> = {
  NO_HTTPS: {
    what_this_means:
      "Your site is being served without encryption.",
    why_it_matters:
      "Anything visitors type — passwords, addresses, payment info — can be read or modified by anyone on the same network.",
    who_can_fix: "Your hosting provider, web developer, or CDN administrator.",
    message_to_developer:
      "Please enable HTTPS for the site (free certificates from Let's Encrypt or via the hosting/CDN dashboard) and redirect all HTTP traffic to HTTPS.",
  },
  MISSING_HSTS: {
    what_this_means:
      "Browsers aren't told to always use the HTTPS version of your site.",
    why_it_matters:
      "Attackers on public Wi-Fi can downgrade visitors to an unencrypted connection on the first visit.",
    who_can_fix: "Whoever manages your web server or CDN config.",
    message_to_developer:
      "Please add the response header `Strict-Transport-Security: max-age=31536000; includeSubDomains` (HTTPS responses only).",
  },
  WEAK_HSTS: {
    what_this_means: "HSTS is enabled, but its lifetime is too short.",
    why_it_matters:
      "A short max-age means the protection lapses quickly between visits.",
    who_can_fix: "Whoever manages your web server or CDN config.",
    message_to_developer:
      "Please raise the HSTS max-age to at least 31536000 (1 year) and include `includeSubDomains`.",
  },
  MISSING_CSP: {
    what_this_means:
      "There is no Content Security Policy telling browsers which scripts are allowed to run.",
    why_it_matters:
      "If anyone manages to inject a script (e.g. via a comment, ad, or compromised plugin), the browser will run it.",
    who_can_fix: "Your web developer or framework/template maintainer.",
    message_to_developer:
      "Please add a Content-Security-Policy header. Start with a report-only policy, e.g. `default-src 'self'; img-src 'self' data:; script-src 'self'`. Tighten until clean.",
  },
  MISSING_X_FRAME_OPTIONS: {
    what_this_means:
      "Your site can be embedded inside another site's frame.",
    why_it_matters:
      "An attacker can hide your site behind a fake page and trick visitors into clicking buttons (clickjacking).",
    who_can_fix: "Your web developer or hosting administrator.",
    message_to_developer:
      "Please set `X-Frame-Options: DENY` (or use CSP `frame-ancestors 'none'`).",
  },
  MISSING_X_CONTENT_TYPE_OPTIONS: {
    what_this_means:
      "Browsers are allowed to guess what type your files are.",
    why_it_matters:
      "An uploaded file can be reinterpreted as something dangerous (e.g. an image treated as JavaScript).",
    who_can_fix: "Your web developer or hosting administrator.",
    message_to_developer: "Please set `X-Content-Type-Options: nosniff`.",
  },
  WEAK_X_CONTENT_TYPE_OPTIONS: {
    what_this_means: "The X-Content-Type-Options header is set but not to 'nosniff'.",
    why_it_matters:
      "Without exactly 'nosniff', browsers may still guess content types unsafely.",
    who_can_fix: "Your web developer or hosting administrator.",
    message_to_developer: "Please set the header value to exactly `nosniff`.",
  },
  MISSING_REFERRER_POLICY: {
    what_this_means:
      "Your site doesn't control how much information browsers leak when visitors click outbound links.",
    why_it_matters:
      "Other sites can see exact pages your visitors came from, including private URLs.",
    who_can_fix: "Your web developer.",
    message_to_developer:
      "Please set `Referrer-Policy: strict-origin-when-cross-origin` (or `no-referrer`).",
  },
  MISSING_PERMISSIONS_POLICY: {
    what_this_means:
      "Your site has not declared which browser features (camera, microphone, geolocation, etc.) it needs.",
    why_it_matters:
      "If something untrusted runs on your site, it could request these features without your knowledge.",
    who_can_fix: "Your web developer.",
    message_to_developer:
      "Please add a Permissions-Policy header that disables features you don't use, e.g. `geolocation=(), camera=(), microphone=()`.",
  },
  COOKIE_NO_SECURE: {
    what_this_means: "A cookie is sent without requiring HTTPS.",
    why_it_matters:
      "On insecure networks, attackers can steal the cookie and impersonate the user.",
    who_can_fix: "The developer who sets the cookie (often the auth/session code).",
    message_to_developer: "Please add the `Secure` attribute to this cookie.",
  },
  COOKIE_NO_HTTPONLY: {
    what_this_means: "A cookie can be read by any JavaScript running on the page.",
    why_it_matters:
      "If any third-party script is compromised, it can steal session cookies.",
    who_can_fix: "The developer who sets the cookie.",
    message_to_developer:
      "If this cookie isn't read by client-side JavaScript, please add the `HttpOnly` attribute.",
  },
  COOKIE_NO_SAMESITE: {
    what_this_means: "A cookie has no SameSite attribute.",
    why_it_matters:
      "It may be sent in cross-site requests, enabling CSRF attacks.",
    who_can_fix: "The developer who sets the cookie.",
    message_to_developer: "Please set `SameSite=Lax` (or `Strict`) on this cookie.",
  },
  COOKIE_SAMESITE_NONE_NO_SECURE: {
    what_this_means: "A cookie uses SameSite=None but is missing Secure.",
    why_it_matters:
      "Modern browsers reject this combination; the cookie will fail to set.",
    who_can_fix: "The developer who sets the cookie.",
    message_to_developer:
      "Cookies with `SameSite=None` must also be marked `Secure`.",
  },
  SERVER_HEADER_DISCLOSURE: {
    what_this_means:
      "Your server reveals the exact software (and sometimes version) it runs.",
    why_it_matters:
      "Attackers use this to look up known exploits for that exact version.",
    who_can_fix: "Whoever manages your web server or CDN.",
    message_to_developer:
      "Please remove or genericize the `Server` header (e.g. nginx `server_tokens off;`).",
  },
  X_POWERED_BY_DISCLOSURE: {
    what_this_means:
      "Your site advertises which framework/platform powers it.",
    why_it_matters:
      "This isn't needed and helps attackers narrow their targets.",
    who_can_fix: "Your web developer or hosting administrator.",
    message_to_developer:
      "Please remove the `X-Powered-By` header (e.g. Express: `app.disable('x-powered-by')`).",
  },
};

export const COMPLIANCE: Record<FindingCode, ComplianceMapping> = {
  NO_HTTPS: {
    owasp: ["A02:2021 Cryptographic Failures"],
    cis: ["CIS Control 3: Data Protection"],
    iso: ["ISO 27001 A.8.24 Use of cryptography"],
    privacy: ["GDPR Art. 32 (security of processing)"],
  },
  MISSING_HSTS: {
    owasp: ["A02:2021 Cryptographic Failures"],
    cis: ["CIS Control 3: Data Protection"],
  },
  WEAK_HSTS: { owasp: ["A02:2021 Cryptographic Failures"] },
  MISSING_CSP: {
    owasp: ["A03:2021 Injection", "A05:2021 Security Misconfiguration"],
    cis: ["CIS Control 16: Application Software Security"],
  },
  MISSING_X_FRAME_OPTIONS: {
    owasp: ["A05:2021 Security Misconfiguration"],
  },
  MISSING_X_CONTENT_TYPE_OPTIONS: {
    owasp: ["A05:2021 Security Misconfiguration"],
  },
  WEAK_X_CONTENT_TYPE_OPTIONS: {
    owasp: ["A05:2021 Security Misconfiguration"],
  },
  MISSING_REFERRER_POLICY: {
    privacy: ["GDPR data minimization (Art. 5(1)(c))"],
  },
  MISSING_PERMISSIONS_POLICY: {
    owasp: ["A05:2021 Security Misconfiguration"],
  },
  COOKIE_NO_SECURE: {
    owasp: ["A02:2021 Cryptographic Failures", "A07:2021 Identification and Authentication Failures"],
  },
  COOKIE_NO_HTTPONLY: {
    owasp: ["A07:2021 Identification and Authentication Failures"],
  },
  COOKIE_NO_SAMESITE: {
    owasp: ["A01:2021 Broken Access Control (CSRF)"],
  },
  COOKIE_SAMESITE_NONE_NO_SECURE: {
    owasp: ["A05:2021 Security Misconfiguration"],
  },
  SERVER_HEADER_DISCLOSURE: { owasp: ["A05:2021 Security Misconfiguration"] },
  X_POWERED_BY_DISCLOSURE: { owasp: ["A05:2021 Security Misconfiguration"] },
};

export type Platform =
  | "nginx"
  | "apache"
  | "caddy"
  | "cloudflare"
  | "vercel"
  | "netlify"
  | "express"
  | "django"
  | "rails"
  | "wordpress";

export interface FixRecipe {
  description: string;
  /** A snippet (config line, code change, or doc instructions). */
  snippet: string;
  /** Where this snippet typically goes. */
  location?: string;
}

/**
 * FIXES[code][platform] -> recipe.
 * Only common, well-supported snippets are included; everything else falls
 * back to a generic recommendation.
 */
export const FIXES: Partial<Record<FindingCode, Partial<Record<Platform, FixRecipe>>>> = {
  MISSING_HSTS: {
    nginx: {
      description: "Add HSTS in the HTTPS server block.",
      location: "nginx server { ... } block (HTTPS)",
      snippet: `add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;`,
    },
    apache: {
      description: "Add HSTS via mod_headers.",
      location: ".htaccess or VirtualHost",
      snippet: `Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"`,
    },
    caddy: {
      description: "Add HSTS in your Caddyfile.",
      location: "Caddyfile site block",
      snippet: `header Strict-Transport-Security "max-age=31536000; includeSubDomains"`,
    },
    cloudflare: {
      description: "Enable HSTS in the Cloudflare dashboard.",
      location: "SSL/TLS → Edge Certificates → HSTS",
      snippet:
        "Enable HSTS, max-age 12 months, Include subdomains. Verify your HTTPS works for all subdomains first.",
    },
    vercel: {
      description: "Add a header rule in vercel.json.",
      location: "vercel.json",
      snippet: `{
  "headers": [
    { "source": "/(.*)", "headers": [
      { "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains" }
    ] }
  ]
}`,
    },
    netlify: {
      description: "Add a header rule in netlify.toml.",
      location: "netlify.toml",
      snippet: `[[headers]]
  for = "/*"
  [headers.values]
    Strict-Transport-Security = "max-age=31536000; includeSubDomains"`,
    },
    express: {
      description: "Use the helmet middleware (default-on for HSTS).",
      location: "your Express app",
      snippet: `import helmet from "helmet";
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));`,
    },
    django: {
      description: "Set HSTS settings.",
      location: "settings.py",
      snippet: `SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_SSL_REDIRECT = True`,
    },
    rails: {
      description: "Force SSL.",
      location: "config/environments/production.rb",
      snippet: `config.force_ssl = true
config.ssl_options = { hsts: { expires: 1.year, subdomains: true } }`,
    },
    wordpress: {
      description: "Add HSTS via your hosting/CDN, or via a plugin like Really Simple SSL.",
      snippet:
        "If using Cloudflare, enable HSTS there. Otherwise add the header in your hosting panel or .htaccess (Apache).",
    },
  },
  MISSING_CSP: {
    nginx: {
      description: "Start with a report-only CSP and tighten over time.",
      location: "nginx server block",
      snippet: `add_header Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; report-uri /csp-report" always;`,
    },
    apache: {
      location: ".htaccess",
      description: "Apache CSP via mod_headers (report-only first).",
      snippet: `Header always set Content-Security-Policy-Report-Only "default-src 'self'; img-src 'self' data:; script-src 'self'"`,
    },
    vercel: {
      location: "vercel.json",
      description: "CSP via headers config.",
      snippet: `{
  "headers": [
    { "source": "/(.*)", "headers": [
      { "key": "Content-Security-Policy", "value": "default-src 'self'; img-src 'self' data:; script-src 'self'" }
    ] }
  ]
}`,
    },
    netlify: {
      location: "netlify.toml",
      description: "CSP via headers config.",
      snippet: `[[headers]]
  for = "/*"
  [headers.values]
    Content-Security-Policy = "default-src 'self'; img-src 'self' data:; script-src 'self'"`,
    },
    express: {
      location: "your Express app",
      description: "Use helmet.contentSecurityPolicy.",
      snippet: `app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    imgSrc: ["'self'", "data:"],
    scriptSrc: ["'self'"]
  }
}));`,
    },
    django: {
      location: "settings.py (with django-csp installed)",
      description: "django-csp configuration.",
      snippet: `MIDDLEWARE += ["csp.middleware.CSPMiddleware"]
CSP_DEFAULT_SRC = ("'self'",)
CSP_IMG_SRC = ("'self'", "data:")
CSP_SCRIPT_SRC = ("'self'",)`,
    },
    rails: {
      location: "config/initializers/content_security_policy.rb",
      description: "Rails CSP DSL.",
      snippet: `Rails.application.config.content_security_policy do |p|
  p.default_src :self
  p.img_src     :self, :data
  p.script_src  :self
end`,
    },
  },
  MISSING_X_FRAME_OPTIONS: {
    nginx: {
      location: "nginx server block",
      description: "Deny framing.",
      snippet: `add_header X-Frame-Options "DENY" always;`,
    },
    apache: {
      location: ".htaccess",
      description: "Deny framing.",
      snippet: `Header always set X-Frame-Options "DENY"`,
    },
    express: {
      location: "your Express app",
      description: "Helmet sets this by default.",
      snippet: `app.use(helmet.frameguard({ action: "deny" }));`,
    },
  },
  MISSING_X_CONTENT_TYPE_OPTIONS: {
    nginx: {
      location: "nginx server block",
      description: "Disable MIME sniffing.",
      snippet: `add_header X-Content-Type-Options "nosniff" always;`,
    },
    apache: {
      location: ".htaccess",
      description: "Disable MIME sniffing.",
      snippet: `Header always set X-Content-Type-Options "nosniff"`,
    },
    express: {
      location: "your Express app",
      description: "Helmet sets this by default.",
      snippet: `app.use(helmet.noSniff());`,
    },
  },
  MISSING_REFERRER_POLICY: {
    nginx: {
      location: "nginx server block",
      description: "Limit referrer leakage.",
      snippet: `add_header Referrer-Policy "strict-origin-when-cross-origin" always;`,
    },
    apache: {
      location: ".htaccess",
      description: "Limit referrer leakage.",
      snippet: `Header always set Referrer-Policy "strict-origin-when-cross-origin"`,
    },
    express: {
      location: "your Express app",
      description: "Helmet referrer policy.",
      snippet: `app.use(helmet.referrerPolicy({ policy: "strict-origin-when-cross-origin" }));`,
    },
  },
  MISSING_PERMISSIONS_POLICY: {
    nginx: {
      location: "nginx server block",
      description: "Disable powerful APIs you don't use.",
      snippet: `add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;`,
    },
    apache: {
      location: ".htaccess",
      description: "Disable powerful APIs you don't use.",
      snippet: `Header always set Permissions-Policy "geolocation=(), camera=(), microphone=()"`,
    },
  },
  X_POWERED_BY_DISCLOSURE: {
    express: {
      location: "your Express app",
      description: "Disable the header.",
      snippet: `app.disable("x-powered-by");`,
    },
    apache: {
      location: ".htaccess",
      description: "Strip the header.",
      snippet: `Header unset X-Powered-By`,
    },
  },
  SERVER_HEADER_DISCLOSURE: {
    nginx: {
      location: "nginx http { } block",
      description: "Hide server version.",
      snippet: `server_tokens off;`,
    },
    apache: {
      location: "main config",
      description: "Hide server version.",
      snippet: `ServerTokens Prod
ServerSignature Off`,
    },
  },
  COOKIE_NO_SECURE: {
    express: {
      location: "session/cookie config",
      description: "Mark cookies Secure.",
      snippet: `app.use(session({
  cookie: { secure: true, httpOnly: true, sameSite: "lax" }
}));`,
    },
    django: {
      location: "settings.py",
      description: "Force secure cookies.",
      snippet: `SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"`,
    },
    rails: {
      location: "config/environments/production.rb",
      description: "Force secure cookies.",
      snippet: `config.force_ssl = true # implies secure cookies
# Or explicitly:
Rails.application.config.session_store :cookie_store, secure: true, httponly: true, same_site: :lax`,
    },
  },
  COOKIE_NO_HTTPONLY: {
    express: {
      location: "session/cookie config",
      description: "Mark cookies HttpOnly.",
      snippet: `res.cookie("name", "value", { httpOnly: true, secure: true, sameSite: "lax" });`,
    },
  },
  COOKIE_NO_SAMESITE: {
    express: {
      location: "session/cookie config",
      description: "Set SameSite.",
      snippet: `res.cookie("name", "value", { sameSite: "lax", secure: true, httpOnly: true });`,
    },
  },
};
