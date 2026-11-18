"""Deterministic AST auditor for FastMCP / Model Context Protocol Python servers."""

from __future__ import annotations

import argparse
import ast
import json
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

SKILL = "mcp-architect"
SCRIPT = "validate_mcp_server.py"
MAX_FILE_BYTES = 2 * 1024 * 1024

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
}

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
    cleaned = raw.replace("\x00", "\\x00").strip()
    return cleaned or "<empty>"


def _has_unsafe_path_syntax(path: Path) -> bool:
    raw = str(path)
    if "\x00" in raw:
        return True
    parts = path.parts[1:] if (path.drive or path.root) else path.parts
    for part in parts:
        if ":" in part:
            return True
        stem = part.split(".", 1)[0].strip().upper()
        if stem in _WINDOWS_DEVICE_STEMS:
            return True
    return False


def _is_symlink_or_junction(path: Path) -> bool:
    """Return True when path is a symlink or NTFS junction without following it."""
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


def _walk_python_files(root: Path, root_real: Path) -> list[Path]:
    py_files: list[Path] = []
    stack: list[Path] = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda item: item.name)
        except OSError:
            continue
        subdirs: list[Path] = []
        for entry in entries:
            if _has_unsafe_path_syntax(entry) or entry.is_symlink() or _is_symlink_or_junction(entry):
                continue
            try:
                st = entry.lstat()
            except OSError:
                continue
            if stat.S_ISLNK(st.st_mode):
                continue
            try:
                resolved = entry.resolve()
            except OSError:
                continue
            if not resolved.is_relative_to(root_real):
                continue
            if stat.S_ISDIR(st.st_mode):
                if entry.name in SKIP_DIRS:
                    continue
                subdirs.append(entry)
            elif stat.S_ISREG(st.st_mode) and entry.suffix == ".py":
                py_files.append(entry)
        for subdir in reversed(subdirs):
            stack.append(subdir)
    py_files.sort(key=lambda item: item.relative_to(root).as_posix())
    return py_files


def _is_mcp_tool_decorator(node: ast.expr) -> bool:
    """Return True if decorator is @mcp.tool or @mcp.tool()."""
    target = node.func if isinstance(node, ast.Call) else node
    if isinstance(target, ast.Attribute) and target.attr == "tool":
        return True
    return isinstance(target, ast.Name) and target.id == "tool"


def _display_file(path: Path, base_dir: Path | None) -> str:
    if base_dir is not None and path != base_dir:
        try:
            return path.relative_to(base_dir).as_posix()
        except ValueError:
            pass
    return path.name or path.as_posix()


def audit_mcp_file(path: Path, base_dir: Path | None = None) -> list[dict[str, Any]]:
    """Analyze a Python file for MCP stdio pollution, untyped tools, and unsafe host bindings."""
    rel_file = _display_file(path, base_dir)
    if _has_unsafe_path_syntax(path) or path.is_symlink() or _is_symlink_or_junction(path):
        return []

    try:
        st = path.lstat()
    except OSError as exc:
        msg = str(exc).replace("\x00", "\\x00")
        return [
            {
                "file": rel_file,
                "line": 1,
                "rule": "parse-error",
                "symbol": path.name,
                "impact": f"Unable to stat Python file ({type(exc).__name__}): {msg}",
                "severity": "warning",
            }
        ]

    if not stat.S_ISREG(st.st_mode):
        return []

    if st.st_size > MAX_FILE_BYTES:
        return [
            {
                "file": rel_file,
                "line": 1,
                "rule": "skipped-oversized-file",
                "symbol": path.name,
                "impact": (
                    f"File '{rel_file}' ({st.st_size} bytes) exceeds the "
                    f"{MAX_FILE_BYTES}-byte safety limit and was skipped."
                ),
                "severity": "warning",
            }
        ]

    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=rel_file)
        findings: list[dict[str, Any]] = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id == "print":
                    writes_to_stderr = any(
                        kw.arg == "file"
                        and isinstance(kw.value, ast.Attribute)
                        and kw.value.attr == "stderr"
                        for kw in node.keywords
                    )
                    if not writes_to_stderr:
                        findings.append(
                            {
                                "file": rel_file,
                                "line": node.lineno,
                                "rule": "mcp-stdio-print",
                                "symbol": "print()",
                                "impact": (
                                    "Bare print() to stdout corrupts MCP JSON-RPC stdio framing; "
                                    "use sys.stderr or logging."
                                ),
                                "severity": "error",
                            }
                        )
                for kw in node.keywords:
                    if (
                        kw.arg == "host"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value == "0.0.0.0"
                    ):
                        findings.append(
                            {
                                "file": rel_file,
                                "line": node.lineno,
                                "rule": "mcp-unsafe-host-binding",
                                "symbol": "host='0.0.0.0'",
                                "impact": (
                                    "MCP server binds to 0.0.0.0; bind exclusively to "
                                    "127.0.0.1 or localhost."
                                ),
                                "severity": "error",
                            }
                        )

            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                is_tool = any(_is_mcp_tool_decorator(dec) for dec in node.decorator_list)
                if not is_tool:
                    continue
                if not ast.get_docstring(node):
                    findings.append(
                        {
                            "file": rel_file,
                            "line": node.lineno,
                            "rule": "mcp-missing-tool-docstring",
                            "symbol": node.name,
                            "impact": (
                                f"MCP tool '{node.name}' is missing a docstring required for "
                                "LLM tool schema generation."
                            ),
                            "severity": "warning",
                        }
                    )
                missing_args = [
                    arg.arg
                    for arg in node.args.args
                    if arg.arg not in {"self", "cls"} and arg.annotation is None
                ]
                if missing_args or node.returns is None:
                    findings.append(
                        {
                            "file": rel_file,
                            "line": node.lineno,
                            "rule": "mcp-missing-tool-annotations",
                            "symbol": node.name,
                            "impact": (
                                f"MCP tool '{node.name}' is missing explicit parameter or return "
                                "type annotations."
                            ),
                            "severity": "error",
                        }
                    )
        return findings
    except (SyntaxError, ValueError, RecursionError, UnicodeDecodeError, OSError) as exc:
        lineno = exc.lineno if isinstance(exc, SyntaxError) and exc.lineno else 1
        raw_msg = exc.msg if isinstance(exc, SyntaxError) and exc.msg else str(exc)
        safe_msg = raw_msg.replace("\x00", "\\x00")
        return [
            {
                "file": rel_file,
                "line": lineno,
                "rule": "parse-error",
                "symbol": path.name,
                "impact": f"Could not parse Python file ({type(exc).__name__}): {safe_msg}",
                "severity": "warning",
            }
        ]


def _emit_invalid_target(target_label: str, as_json: bool) -> int:
    if as_json:
        print(
            json.dumps(
                {
                    "skill": SKILL,
                    "script": SCRIPT,
                    "status": "error",
                    "target": target_label,
                    "summary": {"files_scanned": 0, "findings_count": 0},
                    "findings": [],
                    "data": {"files_scanned": 0, "findings": []},
                    "metrics": {
                        "files_scanned": 0,
                        "findings_count": 0,
                        "errors": 0,
                        "warnings": 0,
                    },
                },
                indent=2,
            )
        )
    else:
        sys.stderr.write(f"error: invalid or unsafe target path: {target_label}\n")
    return 2


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for validate_mcp_server.py."""
    parser = argparse.ArgumentParser(description="Audit MCP server Python files.")
    parser.add_argument("--path", required=True, help="Target Python file or directory.")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON output.")
    args = parser.parse_args(argv)

    raw_arg = args.path
    if not raw_arg or not raw_arg.strip() or "\x00" in raw_arg:
        return _emit_invalid_target(_sanitize_label(raw_arg), args.as_json)

    target_path = Path(raw_arg)
    target_label = target_path.as_posix() or "."
    if _has_unsafe_path_syntax(target_path) or _has_symlink_ancestor(target_path):
        return _emit_invalid_target(target_label, args.as_json)

    try:
        target_st = target_path.lstat()
    except OSError:
        return _emit_invalid_target(target_label, args.as_json)

    if stat.S_ISREG(target_st.st_mode):
        try:
            parent_real = target_path.parent.resolve()
            if not target_path.resolve().is_relative_to(parent_real):
                return _emit_invalid_target(target_label, args.as_json)
        except OSError:
            return _emit_invalid_target(target_label, args.as_json)
        base_dir = target_path.parent
        py_files = [target_path]
    elif stat.S_ISDIR(target_st.st_mode):
        try:
            root_real = target_path.resolve()
        except OSError:
            return _emit_invalid_target(target_label, args.as_json)
        base_dir = target_path
        py_files = _walk_python_files(target_path, root_real)
    else:
        return _emit_invalid_target(target_label, args.as_json)

    all_findings: list[dict[str, Any]] = []
    for py_file in py_files:
        all_findings.extend(audit_mcp_file(py_file, base_dir))

    errors = sum(1 for item in all_findings if item["severity"] == "error")
    warnings = sum(1 for item in all_findings if item["severity"] == "warning")
    status = "ok" if not all_findings else "findings_detected"
    payload = {
        "skill": SKILL,
        "script": SCRIPT,
        "status": status,
        "target": target_label,
        "summary": {
            "files_scanned": len(py_files),
            "findings_count": len(all_findings),
            "errors": errors,
            "warnings": warnings,
        },
        "findings": all_findings,
        "data": {
            "files_scanned": len(py_files),
            "findings": all_findings,
        },
        "metrics": {
            "files_scanned": len(py_files),
            "findings_count": len(all_findings),
            "errors": errors,
            "warnings": warnings,
        },
    }
    if args.as_json:
        print(json.dumps(payload, indent=2))
    else:
        sys.stdout.write(f"[{status.upper()}] {len(all_findings)} finding(s) in {target_label}\n")
    return 0 if not all_findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
