# Contributing

Thank you for your interest in contributing to `safe-web-audit`.

## Guiding principle

This project is **defensive by construction**. Every contribution must preserve that property. Pull requests that add offensive capabilities (crawling, fuzzing, login testing, exploitation, etc.) will be declined.

## Getting started

```bash
git clone https://github.com/Venkatchavan/safe-web-audit-mcp
cd safe-web-audit-mcp
npm install
npm run build
npm test
```

Node.js 18 or higher is required; Node 20+ is recommended.

## Making changes

1. Fork the repo and create a branch: `git checkout -b feat/my-change`
2. Make your changes in `src/`
3. Add or update tests in `test/`
4. Run `npm run build && npm test` — all tests must pass
5. Open a pull request against `main`

## What we welcome

- Bug fixes and security hardening
- New finding codes and their humanization / compliance / fix mappings (`src/codes.ts`)
- Additional platform fix recipes (nginx, Apache, Cloudflare, etc.)
- New defensive public-good templates (`src/templates.ts`)
- Improved redaction patterns (`src/redaction.ts`)
- Documentation improvements

## What we will decline

- Any feature that performs active scanning, fuzzing, brute-forcing, login, or form submission
- Any feature that sends `POST` / `PUT` / `DELETE` / `PATCH` to target URLs
- Any feature that disables or weakens SSRF protections
- Any feature that sends audit data to a remote server

## Reporting security issues

See [SECURITY.md](./SECURITY.md).

## Code style

- TypeScript strict mode (`tsconfig.json`)
- ES modules, Node 18+ built-ins
- No unnecessary dependencies — check before adding one
