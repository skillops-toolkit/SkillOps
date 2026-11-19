---
name: "nextjs-security-headers-auditor"
description: "Use when building or auditing Next.js App Router applications, next.config files, Server Actions, or Route Handlers to catch missing security response headers like X-Content-Type-Options and X-Frame-Options, exposed NEXT_PUBLIC_ secret environment variables, unsanitized dangerouslySetInnerHTML sinks, and unauthenticated Server Actions. Do not trigger for Python backends or CSS styling."
version: "1.0.0"
track: "arch-quality"
tags:
  - "nextjs"
  - "security-headers"
  - "server-actions"
  - "app-router"
  - "typescript"
routing_signals:
  languages: ["typescript", "javascript"]
  files_any: ["next.config.js", "next.config.mjs", "next.config.ts", "proxy.ts", "middleware.ts"]
  dependencies_any: ["next"]
  active_file_globs: ["next.config.*", "**/middleware.*", "**/proxy.*", "**/app/**/route.*", "**/app/**/*.tsx"]
  negative_triggers:
    - "Do not trigger for Python/FastAPI applications or CSS layout bugs."
entrypoints:
  scripts:
    - path: "scripts/audit_nextjs_security.py"
      description: "Deterministic Next.js App Router auditor verifying next.config security headers, NEXT_PUBLIC_ secret leaks, dangerouslyAllowSVG CSP, and raw HTML sinks."
---

# Next.js Security & Headers Auditor (`nextjs-security-headers-auditor`)

## When to Use This Skill
Invoke when configuring `next.config.*`, adding environment variables, writing React Server Actions (`"use server"`), or shipping Next.js App Router pages to production.

## Mandatory Execution Workflow

1. **Audit the Next.js Workspace Deterministically:**
   ```bash
   python catalog/arch-quality/nextjs-security-headers-auditor/scripts/audit_nextjs_security.py --path . --json
   ```
   Inspect all `findings[]` sorted by severity.

2. **Harden HTTP Headers & Client Boundaries:**
   - Configure `async headers()` in `next.config.*` with `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` (or CSP `frame-ancestors`), and `Referrer-Policy` (`missing-security-headers-config`).
   - Never suffix secrets (`SECRET`, `TOKEN`, `PRIVATE_KEY`, `SERVICE_ROLE`, `PASSWORD`, `DATABASE_URL`) with `NEXT_PUBLIC_` (`exposed-next-public-secret`).
   - When setting `dangerouslyAllowSVG: true` in `images`, always pair it with a strict `contentSecurityPolicy` and `contentDispositionType: "attachment"`.
   - Authenticate callers inside every `"use server"` export and avoid raw unsanitized `dangerouslySetInnerHTML`.

3. **Re-Verify:**
   Re-run `audit_nextjs_security.py --path . --json` until `"status": "ok"`.

## Findings Reference

| Rule ID | Severity | Meaning & Fix |
| :--- | :---: | :--- |
| `exposed-next-public-secret` | `error` | `NEXT_PUBLIC_` exposes server secrets into the browser bundle; move to server-only env var. |
| `missing-security-headers-config` | `warning` | `next.config.*` omits `X-Content-Type-Options` / `X-Frame-Options` headers configuration. |
| `svg-images-missing-csp` | `error` | `dangerouslyAllowSVG: true` set without `contentSecurityPolicy` sandbox rules. |
| `unsanitized-dangerous-inner-html` | `warning` | `dangerouslySetInnerHTML` used without explicit DOMPurify sanitization nearby. |
