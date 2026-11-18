"""Deterministic zero-downtime SQL & migration safety auditor (pure stdlib)."""

from __future__ import annotations

import argparse
import json
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

SKILL = "sql-migration-safety-guard"
SCRIPT = "audit_sql_migrations.py"

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
MAX_LINE_LENGTH = 4096

CREATE_INDEX_RE = re.compile(
    r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+(?!CONCURRENTLY\b)(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][A-Za-z0-9_]*)",
    re.IGNORECASE,
)
ADD_NOT_NULL_RE = re.compile(
    r"\bALTER\s+TABLE\s+[A-Za-z_][A-Za-z0-9_.\"]*\s+ADD\s+(?:COLUMN\s+)?([A-Za-z_][A-Za-z0-9_]*)\s+[^\n;]{1,120}\bNOT\s+NULL\b(?![^\n;]*\bDEFAULT\b)",
    re.IGNORECASE,
)
DROP_UNSAFE_RE = re.compile(
    r"\bDROP\s+(?:TABLE|COLUMN)\s+(?!IF\s+EXISTS\b)([A-Za-z_][A-Za-z0-9_.\"]*)",
    re.IGNORECASE,
)
TRUNCATE_RE = re.compile(r"\bTRUNCATE\s+(?:TABLE\s+)?([A-Za-z_][A-Za-z0-9_.\"]*)", re.IGNORECASE)
DELETE_NO_WHERE_RE = re.compile(r"\bDELETE\s+FROM\s+([A-Za-z_][A-Za-z0-9_.\"]*)\s*;", re.IGNORECASE)

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


def _is_migration_file(path: Path) -> bool:
    lower_posix = path.as_posix().lower()
    if path.suffix.lower() == ".sql":
        return True
    return path.suffix.lower() in {".py", ".ts", ".js"} and ("migration" in lower_posix or "alembic" in lower_posix)


def _iter_migration_files(root: Path, root_real: Path) -> list[Path]:
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
            elif _is_migration_file(entry) and _is_safe_regular_file_within(entry, root_real):
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


def _audit_lines(rel_file: str, lines: list[str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for idx, line in enumerate(lines, start=1):
        if len(line) > MAX_LINE_LENGTH:
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("--") or "skillops-allow-destructive" in stripped:
            continue

        m = CREATE_INDEX_RE.search(line)
        if m:
            findings.append(
                _finding(
                    "non-concurrent-index-creation",
                    "warning",
                    rel_file,
                    idx,
                    m.group(1),
                    "CREATE INDEX without CONCURRENTLY acquires a write lock on live tables.",
                    "Use CREATE INDEX CONCURRENTLY outside a transaction block.",
                )
            )
        m = ADD_NOT_NULL_RE.search(line)
        if m:
            findings.append(
                _finding(
                    "not-null-column-without-default",
                    "error",
                    rel_file,
                    idx,
                    m.group(1),
                    "Adding a NOT NULL column without DEFAULT blocks writes or fails on populated tables.",
                    "Add nullable column first, backfill rows, then apply NOT NULL.",
                )
            )
        m = DROP_UNSAFE_RE.search(line) or TRUNCATE_RE.search(line) or DELETE_NO_WHERE_RE.search(line)
        if m:
            findings.append(
                _finding(
                    "destructive-ddl-or-delete",
                    "error",
                    rel_file,
                    idx,
                    m.group(1),
                    "Destructive DDL or un-scoped DELETE executed without WHERE / IF EXISTS guard.",
                    "Guard deletions with WHERE predicates and verify two-phase column/table drops.",
                )
            )
    return findings


def scan_repo(root: Path, root_real: Path) -> tuple[list[dict[str, Any]], int]:
    files = _iter_migration_files(root, root_real)
    findings: list[dict[str, Any]] = []
    scanned = 0
    for file_path in files:
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned += 1
        rel_file = file_path.relative_to(root).as_posix()
        findings.extend(_audit_lines(rel_file, text.splitlines()))
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
    parser = argparse.ArgumentParser(description="Audit SQL and migration files for unsafe locks or destructive DDL.")
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
