---
name: "pydantic-v2-boundary-guard"
description: "Use when writing, reviewing, or migrating Python data models, FastAPI DTOs, or configuration classes using Pydantic v2 to catch removed Pydantic v1 patterns like class Config, @validator, @root_validator, .dict(), and .parse_obj(), plus missing extra='forbid' strict boundary validation. Do not trigger for TypeScript Zod schemas or SQLAlchemy ORM column models."
version: "1.0.0"
track: "python-backend"
tags:
  - "python"
  - "pydantic-v2"
  - "fastapi"
  - "validation"
  - "migration"
routing_signals:
  languages: ["python"]
  files_any: ["pyproject.toml", "requirements.txt"]
  dependencies_any: ["pydantic", "fastapi", "pydantic-settings"]
  active_file_globs: ["**/*.py"]
  negative_triggers:
    - "Do not trigger for TypeScript Zod schemas or raw SQLAlchemy declarative models."
entrypoints:
  scripts:
    - path: "scripts/audit_pydantic_models.py"
      description: "Deterministic Python AST auditor catching legacy Pydantic v1 patterns and BaseModel boundaries lacking ConfigDict strictness."
---

# Pydantic v2 Boundary Guard (`pydantic-v2-boundary-guard`)

## When to Use This Skill
Invoke whenever creating or upgrading Pydantic `BaseModel` / `BaseSettings` schemas, API request/response contracts, or FastAPI boundary models.

## Mandatory Execution Workflow

1. **Audit Python Modules for v1 Holdovers & Permissive Boundaries:**
   ```bash
   python catalog/python-backend/pydantic-v2-boundary-guard/scripts/audit_pydantic_models.py --path . --json
   ```
   Review every finding in `findings[]`.

2. **Migrate v1 Patterns to Idiomatic Pydantic v2:**
   - Replace nested `class Config:` with `model_config = ConfigDict(...)`.
   - Replace `@validator` / `@root_validator` with `@field_validator` (decorated with `@classmethod`) and `@model_validator`.
   - Replace `.dict()`, `.json()`, `.parse_obj()`, and `.parse_raw()` calls with `.model_dump()`, `.model_dump_json()`, `.model_validate()`, and `.model_validate_json()`.

3. **Harden External Input Models:**
   - Set `model_config = ConfigDict(extra="forbid")` on request/config `BaseModel` subclasses unless unknown fields are intentionally preserved or ignored.

4. **Re-Verify:**
   Re-run `audit_pydantic_models.py --path . --json` until `"status": "ok"`.

## Findings Reference

| Rule ID | Severity | Meaning & Fix |
| :--- | :---: | :--- |
| `pydantic-v1-inner-config` | `error` | Legacy `class Config:` inside `BaseModel`; replace with `model_config = ConfigDict(...)`. |
| `pydantic-v1-validator-decorator` | `error` | Deprecated `@validator` / `@root_validator`; upgrade to `@field_validator` / `@model_validator`. |
| `pydantic-v1-method-call` | `warning` | Legacy `.dict()`, `.json()`, `.parse_obj()`, or `.parse_raw()`; migrate to `model_dump*` / `model_validate*`. |
| `missing-model-config-dict` | `warning` | `BaseModel` omits explicit `model_config = ConfigDict(...)` boundary policy. |
