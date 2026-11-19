# AGENTS.md — SkillOps Engineering Guide

> **SkillOps (`skillops-cli`, `v1.6.0`):** Node.js 20+ / TypeScript 28-IDE Transpiler Engine (`src/`) + Hybrid Executable Skills & Context-Isolated Subagents (`catalog/`).

## 1. Progressive-Disclosure Map (Read Only What Your Task Touches)

- **Contracts & Schemas:** [src/models.ts](src/models.ts) (Zod v4 schemas, `ExitCode` `0`–`5`, `RUNTIME_HARNESS_SPECS`), [SKILL_CONTRACT.md](SKILL_CONTRACT.md)
- **Catalog Auditor & Security:** [src/auditor/parser.ts](src/auditor/parser.ts), [src/auditor/security.ts](src/auditor/security.ts), [src/auditor/collision.ts](src/auditor/collision.ts)
- **Multi-Runtime Sync & Telemetry:** [src/sync/adapters.ts](src/sync/adapters.ts), [src/sync/telemetry.ts](src/sync/telemetry.ts), [src/sync/renderers/](src/sync/renderers/)
- **CLI & Terminal UI:** [src/cli.ts](src/cli.ts), [src/ui/](src/ui/)
- **Catalog:** `catalog/{ai-engineering,python-backend,arch-quality,token-economy}/` and `catalog/subagents/*/SUBAGENT.md`
- **Tests & Docs:** [tests/](tests/), [docs/architecture/](docs/architecture/), [.skillops.yml](.skillops.yml)
- **CI & Governance (only when editing workflows/PRs):** [.github/workflows/](.github/workflows/), [.github/actions/skillops-audit/action.yml](.github/actions/skillops-audit/action.yml)

## 2. Verification Gates

```bash
npm run lint && npm run typecheck && npm test && npm run build
node ./dist/cli.js audit --strict
```

## 3. Git & Sanitization Rules

- **Branching & Commits:** Never push directly to `main`. Use `<type>/<short-kebab-slug>` and conventional commits (`en-US`).
- **Tracked Files:** English (`en-US`) only; never commit `DOCS-DEV/`, `.env`, local machine paths, OS usernames, or API keys.
