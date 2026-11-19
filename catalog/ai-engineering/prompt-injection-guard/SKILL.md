---
name: "prompt-injection-guard"
description: "Use when building or reviewing LLM integrations, system prompts, agent loops, or RAG pipelines in Python, TypeScript, or JavaScript to detect untrusted user input interpolated directly into system prompts, unescaped prompt delimiters, and LLM outputs wired into eval, exec, shell, or SQL execution sinks. Do not trigger for generic XSS escaping in browser templates or unrelated auth middleware."
version: "1.0.0"
track: "ai-engineering"
tags:
  - "ai-engineering"
  - "prompt-injection"
  - "llm-security"
  - "guardrails"
  - "rag"
routing_signals:
  languages: ["python", "typescript", "javascript"]
  files_any: ["pyproject.toml", "package.json"]
  dependencies_any: ["openai", "anthropic", "@anthropic-ai/sdk", "langchain", "llama-index", "ai"]
  active_file_globs: ["**/*.py", "**/*.ts", "**/*.tsx", "**/*.js", "**/*.mjs"]
  negative_triggers:
    - "Do not trigger for DOM XSS sanitization or classic HTTP CSRF protections."
entrypoints:
  scripts:
    - path: "scripts/audit_prompt_boundaries.py"
      description: "Deterministic stdlib AST & pattern auditor detecting system-prompt interpolation, unescaped delimiters, and unsanitized LLM execution sinks."
---

# Prompt Injection Guard (`prompt-injection-guard`)

## When to Use This Skill
Invoke whenever application code constructs LLM prompts (`system`, `developer`, `instructions`), embeds retrieved RAG chunks into prompts, or passes LLM completion text toward downstream tools or interpreters.

## Mandatory Execution Workflow

1. **Audit Prompt & Sink Boundaries First:**
   ```bash
   python catalog/ai-engineering/prompt-injection-guard/scripts/audit_prompt_boundaries.py --path . --json
   ```
   Inspect `status`, `summary`, and every finding in `findings[]` (`severity`, `rule_id`, `file`, `line`, `symbol`, `impact`, `remediation`).

2. **Enforce Role Separation (Never Concatenate Untrusted Text into System Instructions):**
   - Pass untrusted text (`user_input`, `query`, `retrieved_docs`, `ticket_body`) exclusively in a structured `user` message or isolated data block rather than `role: "system"`, `system=`, or `instructions=`.
   - When wrapping untrusted data in XML-like tags (`<context>...</context>`), strip or escape closing tag sequences inside the untrusted payload before embedding.

3. **Gate LLM Output Before Tool or Execution Sinks:**
   - Never pass raw completion text (`response.content`, `completion`, `choices[0]`, `llm_output`) into `eval`, `exec`, shell commands, or raw SQL strings.
   - Validate model outputs against an allowlisted schema or enum before invoking side-effecting tools.

4. **Re-Verify:**
   Re-run `audit_prompt_boundaries.py --path . --json` and confirm `"status": "ok"` (exit code `0`).

## Findings Reference

| Rule ID | Severity | Meaning & Fix |
| :--- | :---: | :--- |
| `untrusted-input-in-system-prompt` | `error` | Interpolates untrusted/user variables into system instructions; move untrusted content to a `user` turn. |
| `llm-output-execution-sink` | `error` | Feeds model output directly into code/shell/SQL execution; validate against strict allowlists instead. |
| `unescaped-prompt-delimiter` | `warning` | Embeds dynamic payload inside XML/triple-quote delimiters without escaping closing markers. |
