---
name: "skill-token-budget-lint"
description: "Use when authoring, reviewing, or refactoring SKILL.md and SUBAGENT.md agent manifests in AI coding repositories to verify line limits, enforce Level 1 routing description word and token budgets, catch missing 'Use when' triggers, and detect wildcard tool permissions or unisolated subagents. Do not trigger for general application TypeScript or Python business logic."
version: "1.0.0"
track: "token-economy"
tags:
  - "token-economy"
  - "skillops"
  - "progressive-disclosure"
  - "subagents"
  - "context-budget"
routing_signals:
  languages: ["markdown", "yaml"]
  files_any: ["SKILL.md", "SUBAGENT.md", ".claude/skills", ".agents/skills"]
  dependencies_any: []
  active_file_globs: ["**/SKILL.md", "**/SUBAGENT.md", "**/.claude/**/*.md", "**/.agents/skills/**/*.md"]
  negative_triggers:
    - "Do not trigger for application TypeScript/Python backend logic or React frontend styling."
entrypoints:
  scripts:
    - path: "scripts/lint_skill_budgets.py"
      description: "Deterministic pure-stdlib linter enforcing line caps, L1 description token/word limits, and subagent isolation budgets on SKILL.md and SUBAGENT.md files."
---

# Skill & Subagent Token Budget Lint (`skill-token-budget-lint`)

## When to Use This Skill
Invoke whenever adding or editing `SKILL.md` skills or `SUBAGENT.md` / `.claude/agents/*.md` subagents to guarantee progressive-disclosure compliance before merging.

## Mandatory Execution Workflow

1. **Run the Deterministic Budget Linter:**
   ```bash
   python catalog/token-economy/skill-token-budget-lint/scripts/lint_skill_budgets.py --path . --json
   ```
   Review `findings[]` and `metrics.files_scanned`.

2. **Enforce Progressive-Disclosure Budgets:**
   - Keep `SKILL.md` at `<= 250` lines (`skill-over-250-lines`) and `SUBAGENT.md` at `<= 180` lines (`subagent-over-180-lines`), offloading bulky checklists into `references/*.md`.
   - Start every L1 `description` with `"Use when..."`, keep `SKILL.md` descriptions between `40` and `110` words (`<= 160` est. tokens), and `SUBAGENT.md` descriptions between `10` and `110` words.
   - Require `context_isolation: true`, `max_output_tokens <= 400`, and explicit canonical tools (never `*`, `all`, or `any`) on subagents.

3. **Re-Verify:**
   Re-run `lint_skill_budgets.py --path . --json` until `"status": "ok"`.

## Findings Reference

| Rule ID | Severity | Meaning & Fix |
| :--- | :---: | :--- |
| `skill-over-250-lines` | `error` | `SKILL.md` exceeds 250 lines; split examples/tables into `references/`. |
| `subagent-over-180-lines` | `error` | `SUBAGENT.md` exceeds 180 lines; condense system prompt rules. |
| `l1-description-out-of-budget` | `warning` | `description` misses `"Use when"`, word range, or `<= 160` token budget. |
| `subagent-isolation-or-tool-violation` | `error` | Subagent uses wildcard tools (`*`/`all`) or omits isolation / `<= 400` output cap. |
