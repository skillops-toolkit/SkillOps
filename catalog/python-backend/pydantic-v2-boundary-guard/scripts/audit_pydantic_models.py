"""Deterministic Pydantic v2 idiom & boundary strictness AST auditor (pure stdlib)."""

from __future__ import annotations

import argparse
import ast
import json
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

SKILL = "pydantic-v2-boundary-guard"
SCRIPT = "audit_pydantic_models.py"

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "__pycache__",
    ".next",
    "coverage",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}
MAX_FILE_BYTES = 2 * 1024 * 1024
V1_DECORATORS = {"validator", "root_validator"}
V1_METHODS = {"parse_obj", "parse_raw", "parse_file", "from_orm"}

_NTFS_REPARSE_LINKS = (0xA0000003, 0xA000000C)
_WINDOWS_DEVICE_STEMS = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "CONIN$",
        "CONOUT$",
        *(f"COM{idx}" for idx in range(1, 10)),
        *(f"LPT{idx}" for idx in range(1, 10)),
    }
)


def _sanitize_label(raw: str) -> str:
    return raw.replace("\x00", "\\x00").strip() or "<empty>"


def _has_unsafe_path_syntax(path: Path) -> bool:
    if "\x00" in str(path):
        return True
    parts = path.parts[1:] if (path.drive or path.root) else path.parts
    for part in parts:
        if ":" in part:
            return True
        if part.split(".", 1)[0].strip().upper() in _WINDOWS_DEVICE_STEMS:
            return True
    return False


def _is_symlink_or_junction(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
    except (OSError, ValueError):
        return True
    try:
        if path.is_junction():
            return True
    except (AttributeError, OSError, ValueError):
        pass
    try:
        st = path.lstat()
    except (OSError, ValueError):
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    try:
        return st.st_reparse_tag in _NTFS_REPARSE_LINKS
    except AttributeError:
        return False


def _has_symlink_ancestor(target: Path) -> bool:
    if _is_symlink_or_junction(target):
        return True
    if not target.is_absolute():
        cur = Path(".")
        for part in target.parts:
            if part in ("", "."):
                continue
            cur = cur / part
            if _is_symlink_or_junction(cur):
                return True
        return False
    exempt: set[Path] = set()
    for base_dir in (Path.cwd(), Path(tempfile.gettempdir())):
        exempt.add(base_dir)
        exempt.update(base_dir.parents)
    for parent in target.parents:
        if parent in exempt:
            break
        if _is_symlink_or_junction(parent):
            return True
    return False


def _is_safe_regular_file_within(path: Path, root_real: Path) -> bool:
    if _has_unsafe_path_syntax(path) or _is_symlink_or_junction(path):
        return False
    try:
        st = path.lstat()
    except OSError:
        return False
    if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_BYTES:
        return False
    try:
        return path.resolve().is_relative_to(root_real)
    except OSError:
        return False


def _iter_python_files(root: Path, root_real: Path) -> list[Path]:
    collected: list[Path] = []
    stack: list[Path] = [root]
    while stack:
        cur = stack.pop()
        try:
            entries = sorted(cur.iterdir(), key=lambda p: p.name)
        except OSError:
            continue
        for entry in entries:
            if entry.name in SKIP_DIRS or _is_symlink_or_junction(entry):
                continue
            try:
                st = entry.lstat()
            except OSError:
                continue
            if stat.S_ISDIR(st.st_mode):
                stack.append(entry)
            elif entry.suffix.lower() == ".py" and _is_safe_regular_file_within(entry, root_real):
                collected.append(entry)
    return collected


def _finding(
    rule_id: str,
    severity: str,
    rel_file: str,
    line: int,
    symbol: str,
    impact: str,
    remediation: str,
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "file": rel_file,
        "line": line,
        "symbol": symbol,
        "impact": impact,
        "remediation": remediation,
    }


def _is_base_model(cls: ast.ClassDef) -> bool:
    for base in cls.bases:
        base_name = ast.unparse(base).split(".")[-1]
        if base_name in {"BaseModel", "BaseSettings"}:
            return True
    return False


def _audit_file(rel_file: str, text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        tree = ast.parse(text, filename=rel_file)
    except SyntaxError:
        return findings

    has_pydantic_import = any(
        (isinstance(node, ast.ImportFrom) and node.module and "pydantic" in node.module)
        or (isinstance(node, ast.Import) and any("pydantic" in alias.name for alias in node.names))
        for node in ast.walk(tree)
    )
    if not has_pydantic_import:
        return findings

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and _is_base_model(node):
            has_model_config = False
            has_inner_config = False
            for stmt in node.body:
                if isinstance(stmt, ast.ClassDef) and stmt.name == "Config":
                    has_inner_config = True
                    findings.append(
                        _finding(
                            "pydantic-v1-inner-config",
                            "error",
                            rel_file,
                            stmt.lineno,
                            f"{node.name}.Config",
                            "Nested 'class Config' is removed/deprecated in Pydantic v2.",
                            "Replace with `model_config = ConfigDict(...)` on the model class.",
                        )
                    )
                elif isinstance(stmt, ast.Assign):
                    for target in stmt.targets:
                        if isinstance(target, ast.Name) and target.id == "model_config":
                            has_model_config = True
                elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.target.id == "model_config":
                    has_model_config = True
                elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for dec in stmt.decorator_list:
                        dec_name = ast.unparse(dec.func if isinstance(dec, ast.Call) else dec).split(".")[-1]
                        if dec_name in V1_DECORATORS:
                            findings.append(
                                _finding(
                                    "pydantic-v1-validator-decorator",
                                    "error",
                                    rel_file,
                                    stmt.lineno,
                                    f"{node.name}.{stmt.name}",
                                    f"Legacy Pydantic v1 '@{dec_name}' decorator detected.",
                                    "Migrate to '@field_validator' or '@model_validator'.",
                                )
                            )
            if not has_model_config and not has_inner_config:
                findings.append(
                    _finding(
                        "missing-model-config-dict",
                        "warning",
                        rel_file,
                        node.lineno,
                        node.name,
                        "Pydantic BaseModel lacks explicit 'model_config = ConfigDict(...)' boundary configuration.",
                        "Add `model_config = ConfigDict(extra='forbid')` or explicit policy.",
                    )
                )
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in V1_METHODS:
                findings.append(
                    _finding(
                        "pydantic-v1-method-call",
                        "warning",
                        rel_file,
                        node.lineno,
                        f".{node.func.attr}()",
                        f"Legacy Pydantic v1 method '.{node.func.attr}()' called.",
                        "Replace with model_validate / model_validate_json / model_dump.",
                    )
                )
    return findings


def scan_repo(root: Path, root_real: Path) -> tuple[list[dict[str, Any]], int]:
    files = _iter_python_files(root, root_real)
    findings: list[dict[str, Any]] = []
    scanned = 0
    for file_path in files:
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned += 1
        rel_file = file_path.relative_to(root).as_posix()
        findings.extend(_audit_file(rel_file, text))
    return findings, scanned


def _emit_invalid_root(target_label: str, as_json: bool) -> int:
    payload = {
        "skill": SKILL,
        "script": SCRIPT,
        "status": "error",
        "target": target_label,
        "summary": {"files_scanned": 0, "findings_count": 0},
        "findings": [],
        "data": {"files_scanned": 0, "findings": []},
        "metrics": {"files_scanned": 0, "findings_count": 0, "errors": 0, "warnings": 0},
    }
    if as_json:
        print(json.dumps(payload, indent=2))
    else:
        sys.stderr.write(f"error: invalid or unsafe directory: {target_label}\n")
    return 2


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint: exit 0 clean, 1 findings, 2 invalid path."""
    parser = argparse.ArgumentParser(description="Audit Python files for Pydantic v2 boundary compliance.")
    parser.add_argument("--path", required=True, help="Directory to scan.")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON output.")
    args = parser.parse_args(argv)

    raw_arg = args.path
    if not raw_arg or not raw_arg.strip() or "\x00" in raw_arg:
        return _emit_invalid_root(_sanitize_label(raw_arg), args.as_json)

    root = Path(raw_arg)
    target_label = root.as_posix() or "."
    if _has_unsafe_path_syntax(root) or _has_symlink_ancestor(root):
        return _emit_invalid_root(target_label, args.as_json)

    try:
        root_st = root.lstat()
    except OSError:
        return _emit_invalid_root(target_label, args.as_json)
    if not stat.S_ISDIR(root_st.st_mode):
        return _emit_invalid_root(target_label, args.as_json)

    try:
        root_real = root.resolve()
    except OSError:
        return _emit_invalid_root(target_label, args.as_json)

    findings, scanned = scan_repo(root, root_real)
    errors = sum(1 for item in findings if item["severity"] == "error")
    warnings = sum(1 for item in findings if item["severity"] == "warning")
    status = "ok" if not findings else "findings_detected"
    if args.as_json:
        print(
            json.dumps(
                {
                    "skill": SKILL,
                    "script": SCRIPT,
                    "status": status,
                    "target": target_label,
                    "summary": {
                        "files_scanned": scanned,
                        "findings_count": len(findings),
                        "errors": errors,
                        "warnings": warnings,
                    },
                    "findings": findings,
                    "data": {"files_scanned": scanned, "findings": findings},
                    "metrics": {
                        "files_scanned": scanned,
                        "findings_count": len(findings),
                        "errors": errors,
                        "warnings": warnings,
                    },
                },
                indent=2,
            )
        )
    else:
        for f in findings:
            print(f"{f['file']}:{f['line']}: {f['severity']}: {f['rule_id']}: {f['impact']}")
        print(f"status={status} files_scanned={scanned} findings={len(findings)}")
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
