---
name: "structured-output-schema-guard"
description: "Use when defining or auditing JSON Schemas, OpenAI/Anthropic strict structured output contracts, MCP tool inputSchema payloads, or Pydantic/Zod schemas to catch missing additionalProperties false guards, mismatched required property keys, and unbounded strings or arrays that cause runtime validation failures or silent schema rejection. Do not trigger for SQL DDL migrations or CSS stylesheets."
version: "1.0.0"
track: "ai-engineering"
tags:
  - "ai-engineering"
  - "json-schema"
  - "structured-outputs"
  - "mcp-tools"
  - "validation"
routing_signals:
  languages: ["json", "python", "typescript"]
  files_any: ["package.json", "pyproject.toml"]
  dependencies_any: ["pydantic", "zod", "openai", "anthropic", "@modelcontextprotocol/sdk", "ai"]
  active_file_globs: ["**/*.schema.json", "**/*schema*.json", "**/*tool*.ts", "**/*tool*.py"]
  negative_triggers:
    - "Do not trigger for SQL DDL table schemas or CSS stylesheets."
entrypoints:
  scripts:
    - path: "scripts/audit_tool_schemas.py"
      description: "Deterministic JSON Schema auditor verifying additionalProperties:false, required property key parity, and explicit string/array bounds."
---

# Structured Output Schema Guard (`structured-output-schema-guard`)

## When to Use This Skill
Invoke before shipping LLM structured output `response_format` contracts, Anthropic/OpenAI tool definitions, or MCP tool `inputSchema` JSON documents.

## Mandatory Execution Workflow

1. **Audit JSON Schemas Before Wiring Model Calls:**
   ```bash
   python catalog/ai-engineering/structured-output-schema-guard/scripts/audit_tool_schemas.py --path . --json
   ```
   Review `findings[]` and `summary` for structural strict-mode incompatibilities.

2. **Enforce Strict-Mode JSON Schema Guarantees:**
   - Every object node (`"type": "object"`) with `"properties"` should set `"additionalProperties": false` so strict structured-output APIs reject hallucinated keys.
   - Ensure every key listed in `"required"` exists inside `"properties"` (`required-property-mismatch`).
   - Bound top-level/tool arrays with `"maxItems"` and free-form string inputs with `"maxLength"` (or `"enum"`) to prevent unbounded payload generation.

3. **Re-Verify:**
   Re-run `audit_tool_schemas.py --path . --json` and ensure `"status": "ok"` before committing schema changes.

## Findings Reference

| Rule ID | Severity | Meaning & Fix |
| :--- | :---: | :--- |
| `missing-additional-properties-false` | `error` | Object schema lacks `"additionalProperties": false`; strict structured output APIs reject or allow arbitrary keys. |
| `required-property-mismatch` | `error` | Entry in `"required"` is absent from `"properties"`. Fix property spelling or remove stale requirement. |
| `unbounded-tool-array-or-string` | `warning` | Array lacks `maxItems` or unconstrained string lacks `maxLength`/`enum`. |
| `malformed-json-schema` | `error` | Schema file failed strict UTF-8 JSON parsing. |
