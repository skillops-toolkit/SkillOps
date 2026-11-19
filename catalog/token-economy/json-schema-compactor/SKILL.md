---
name: "json-schema-compactor"
description: "Use when designing or optimizing MCP tool inputSchema payloads, OpenAI/Anthropic function schemas, or API JSON Schemas to reduce prompt token overhead by detecting verbose parameter descriptions exceeding 40 words, redundant inline example arrays, deeply nested object trees, and bloated single-schema payloads injected into every LLM turn. Do not trigger for runtime JSON serialization benchmarks or compression algorithms."
version: "1.0.0"
track: "token-economy"
tags:
  - "token-economy"
  - "json-schema"
  - "mcp-tools"
  - "prompt-tokens"
  - "optimization"
routing_signals:
  languages: ["json", "typescript", "python"]
  files_any: ["package.json", "pyproject.toml"]
  dependencies_any: ["@modelcontextprotocol/sdk", "zod", "openai", "anthropic", "mcp"]
  active_file_globs: ["**/*.schema.json", "**/*schema*.json", "**/*tool*.json"]
  negative_triggers:
    - "Do not trigger for gzip/brotli wire compression or runtime JSON parser tuning."
entrypoints:
  scripts:
    - path: "scripts/audit_schema_footprint.py"
      description: "Deterministic JSON Schema token-footprint profiler detecting verbose descriptions, oversized inline examples, and deep schema nesting."
---

# JSON Schema Compactor (`json-schema-compactor`)

## When to Use This Skill
Invoke whenever LLM function-calling tool definitions or MCP `inputSchema` JSON documents bloat per-turn input tokens and crowd out working context.

## Mandatory Execution Workflow

1. **Measure Schema Token Footprint Deterministically:**
   ```bash
   python catalog/token-economy/json-schema-compactor/scripts/audit_schema_footprint.py --path . --json
   ```
   Inspect `metrics.estimated_schema_tokens` and `findings[]`.

2. **Compact Schema Descriptions & Examples:**
   - Trim parameter `description` strings to `<= 40` crisp imperative words (`verbose-schema-description`). Move multi-sentence tutorials into on-demand `SKILL.md` references.
   - Keep `examples` arrays to at most `2` concise entries or strip redundant examples once property names and `enum` values are self-explanatory (`oversized-schema-examples`).
   - Flatten unnecessarily nested wrapper objects (`> 5` levels deep) to simplify both schema token cost and model argument accuracy (`deep-schema-nesting`).

3. **Re-Verify Footprint:**
   Re-run `audit_schema_footprint.py --path . --json` until `"status": "ok"`.

## Findings Reference

| Rule ID | Severity | Meaning & Fix |
| :--- | :---: | :--- |
| `verbose-schema-description` | `warning` | Property/node `description` exceeds 40 words; tighten copy or relocate prose to docs. |
| `oversized-schema-examples` | `warning` | Inline `examples` array has > 2 items or large serialized footprint. |
| `deep-schema-nesting` | `warning` | JSON Schema tree exceeds depth 5; flatten wrapper keys. |
| `schema-token-bloat` | `error` | Single schema document exceeds 800 estimated prompt tokens. |
