---
name: "pytest-fixture-auditor"
description: "Use when writing, debugging, or reviewing pytest test suites, conftest.py fixtures, or CI test reliability in Python repositories to catch session-to-function ScopeMismatch bugs, yield teardown code missing try/finally blocks, flaky time.sleep calls, and overly broad pytest.raises(Exception) assertions. Do not trigger for TypeScript Vitest suites or production runtime async code."
version: "1.0.0"
track: "python-backend"
tags:
  - "python"
  - "pytest"
  - "testing"
  - "fixtures"
  - "ci-reliability"
routing_signals:
  languages: ["python"]
  files_any: ["pyproject.toml", "pytest.ini", "conftest.py"]
  dependencies_any: ["pytest", "pytest-asyncio"]
  active_file_globs: ["**/test_*.py", "**/*_test.py", "**/conftest.py"]
  negative_triggers:
    - "Do not trigger for TypeScript Vitest/Jest suites or runtime FastAPI handlers."
entrypoints:
  scripts:
    - path: "scripts/audit_pytest_fixtures.py"
      description: "Deterministic Python AST auditor catching pytest ScopeMismatch hazards, yield teardown bugs, wall-clock sleep calls, and broad Exception assertions."
---

# Pytest Fixture Auditor (`pytest-fixture-auditor`)

## When to Use This Skill
Invoke when modifying `conftest.py` or `tests/**/*.py`, diagnosing `ScopeMismatch` errors, or eliminating flaky sleeps and leaked test state.

## Mandatory Execution Workflow

1. **Run the Deterministic Pytest AST Auditor:**
   ```bash
   python catalog/python-backend/pytest-fixture-auditor/scripts/audit_pytest_fixtures.py --path . --json
   ```
   Review every finding in `findings[]` prioritized by `error` over `warning`.

2. **Fix Fixture Scope & Teardown Bugs:**
   - Never depend on function-scoped built-ins (`monkeypatch`, `tmp_path`, `caplog`, `capsys`, `request`) inside `@pytest.fixture(scope="session" | "module" | "package" | "class")` (`fixture-scope-mismatch`).
   - Wrap fixture `yield` cleanup steps in `try: yield ... finally:` so temporary resources are still released when assertions fail mid-test (`yield-teardown-without-finally`).

3. **Replace Flaky Sleeps & Broad Exception Checks:**
   - Replace `time.sleep(...)` / `asyncio.sleep(...)` in test bodies with explicit readiness polling or fake clocks (`flaky-sleep-in-test`).
   - Narrow `pytest.raises(Exception)` to concrete exception classes with `match=` patterns.

4. **Re-Verify:**
   Re-run `audit_pytest_fixtures.py --path . --json` until `"status": "ok"`.

## Findings Reference

| Rule ID | Severity | Meaning & Fix |
| :--- | :---: | :--- |
| `fixture-scope-mismatch` | `error` | Session/module/class fixture requests function-scoped fixture (`monkeypatch`, `tmp_path`). Align scopes. |
| `yield-teardown-without-finally` | `warning` | Cleanup after `yield` runs only on passing tests; wrap `yield` and teardown in `try/finally`. |
| `flaky-sleep-in-test` | `warning` | Wall-clock sleep inside test slows CI and flakes under load; mock clocks or poll condition. |
| `broad-pytest-raises-exception` | `warning` | `pytest.raises(Exception)` masks unintended bugs; assert specific exception subclass. |
