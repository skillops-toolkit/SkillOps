"""Deterministic SKILL.md and SUBAGENT.md progressive-disclosure budget linter (pure stdlib)."""

from __future__ import annotations

import argparse
import json
import math
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

SKILL = "skill-token-budget-lint"
SCRIPT = "lint_skill_budgets.py"

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
WILDCARD_TOOLS = {"*", "all", "any", "**"}

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


def _iter_manifest_files(root: Path, root_real: Path) -> list[Path]:
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
            elif entry.name in {"SKILL.md", "SUBAGENT.md"} and _is_safe_regular_file_within(entry, root_real):
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


def _extract_frontmatter_fields(text: str) -> tuple[dict[str, str], str]:
    match = re.match(r"^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$", text)
    if not match:
        return {}, text
    fm_block, body = match.group(1), match.group(2)
    fields: dict[str, str] = {}
    cur_key: str | None = None
    for raw_line in fm_block.splitlines():
        kv = re.match(r"^([A-Za-z0-9_-]+)\s*:\s*(.*)$", raw_line)
        if kv:
            cur_key = kv.group(1)
            fields[cur_key] = kv.group(2).strip()
        elif cur_key and raw_line.startswith((" ", "\t")) and raw_line.strip().startswith("-"):
            fields[cur_key] = (fields.get(cur_key, "") + " " + raw_line.strip()[1:].strip()).strip()
    return fields, body


def _unquote(val: str) -> str:
    cleaned = val.strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in {'"', "'"}:
        return cleaned[1:-1].strip()
    return cleaned


def _audit_manifest(rel_file: str, kind: str, text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    line_count = len(text.splitlines())
    if kind == "SKILL.md" and line_count > 250:
        findings.append(
            _finding(
                "skill-over-250-lines",
                "error",
                rel_file,
                line_count,
                f"lines={line_count}",
                f"SKILL.md has {line_count} lines, exceeding progressive-disclosure max of 250 lines.",
                "Extract reference tables or verbose examples into references/*.md.",
            )
        )
    elif kind == "SUBAGENT.md" and line_count > 180:
        findings.append(
            _finding(
                "subagent-over-180-lines",
                "error",
                rel_file,
                line_count,
                f"lines={line_count}",
                f"SUBAGENT.md has {line_count} lines, exceeding strict subagent prompt max of 180 lines.",
                "Condense subagent instructions to concise operational rules.",
            )
        )

    fields, _body = _extract_frontmatter_fields(text)
    desc = _unquote(fields.get("description", ""))
    words = [w for w in desc.split() if w]
    est_tokens = math.ceil(len(desc) / 3.8) if desc else 0
    min_words = 40 if kind == "SKILL.md" else 10
    if not desc.startswith("Use when") or len(words) < min_words or len(words) > 110 or est_tokens > 160:
        findings.append(
            _finding(
                "l1-description-out-of-budget",
                "warning",
                rel_file,
                1,
                "frontmatter.description",
                f"L1 description has {len(words)} words (~{est_tokens} tokens); expected 'Use when...', {min_words}-110 words, <= 160 tokens.",
                "Rewrite frontmatter description starting with 'Use when' within budget bounds.",
            )
        )

    if kind == "SUBAGENT.md":
        raw_tools = fields.get("tools", "")
        tool_items = [t.strip(" []\"'") for t in raw_tools.replace(",", " ").split() if t.strip(" []\"'")]
        if any(t.lower() in WILDCARD_TOOLS for t in tool_items):
            findings.append(
                _finding(
                    "subagent-isolation-or-tool-violation",
                    "error",
                    rel_file,
                    1,
                    "frontmatter.tools",
                    "Subagent uses wildcard tool grant ('*', 'all', 'any').",
                    "Declare an explicit minimal canonical allowlist such as [read, search].",
                )
            )
        if fields.get("context_isolation", "").lower() != "true":
            findings.append(
                _finding(
                    "subagent-isolation-or-tool-violation",
                    "error",
                    rel_file,
                    1,
                    "frontmatter.context_isolation",
                    "Subagent does not declare context_isolation: true.",
                    "Set `context_isolation: true` in SUBAGENT.md frontmatter.",
                )
            )
        max_tok_raw = fields.get("max_output_tokens", "")
        try:
            max_tok = int(max_tok_raw)
        except ValueError:
            max_tok = 0
        if max_tok <= 0 or max_tok > 400:
            findings.append(
                _finding(
                    "subagent-isolation-or-tool-violation",
                    "error",
                    rel_file,
                    1,
                    "frontmatter.max_output_tokens",
                    f"Subagent max_output_tokens ({max_tok_raw or 'unset'}) must be between 1 and 400.",
                    "Set `max_output_tokens` <= 400 so briefings remain compact.",
                )
            )
    return findings


def scan_repo(root: Path, root_real: Path) -> tuple[list[dict[str, Any]], int]:
    files = _iter_manifest_files(root, root_real)
    findings: list[dict[str, Any]] = []
    scanned = 0
    for file_path in files:
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned += 1
        rel_file = file_path.relative_to(root).as_posix()
        findings.extend(_audit_manifest(rel_file, file_path.name, text))
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
    parser = argparse.ArgumentParser(description="Lint SKILL.md and SUBAGENT.md token and line budgets.")
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
