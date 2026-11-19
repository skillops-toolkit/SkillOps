"""Deterministic LLM prompt-injection & execution-sink boundary auditor (pure stdlib)."""

from __future__ import annotations

import argparse
import ast
import json
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

SKILL = "prompt-injection-guard"
SCRIPT = "audit_prompt_boundaries.py"

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
SCAN_EXTS = {".py", ".ts", ".tsx", ".js", ".mjs", ".cjs"}
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_LINE_LENGTH = 4096

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

UNTRUSTED_NAMES_RE = re.compile(
    r"\b(?:user_?input|user_?prompt|user_?query|query|prompt_?input|request_?body|req_?body|comment|ticket|retrieved_?doc|context_?chunk|raw_?message)\b",
    re.IGNORECASE,
)
LLM_OUTPUT_RE = re.compile(
    r"\b(?:llm_?output|model_?output|completion|assistant_?reply|choices\[0\]|response\.content|reply_text)\b",
    re.IGNORECASE,
)
SYSTEM_JS_RE = re.compile(
    r"""\b(?:system(?:Prompt|_prompt)?|instructions)\s*[:=]\s*`[^`]*\$\{([^}]+)\}[^`]*`""",
    re.IGNORECASE,
)
ROLE_SYSTEM_JS_RE = re.compile(
    r"""role\s*:\s*['"]system['"][^\n]{0,160}content\s*:\s*`[^`]*\$\{([^}]+)\}[^`]*`""",
    re.IGNORECASE,
)
SINK_JS_RE = re.compile(
    r"""\b(?:eval|execSync|exec|Function)\s*\([^\n)]*""",
    re.IGNORECASE,
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
        resolved = path.resolve()
    except OSError:
        return False
    return resolved.is_relative_to(root_real)


def _iter_source_files(root: Path, root_real: Path) -> list[Path]:
    collected: list[Path] = []
    stack: list[Path] = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda p: p.name)
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
            elif entry.suffix.lower() in SCAN_EXTS and _is_safe_regular_file_within(entry, root_real):
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


def _expr_has_dynamic_untrusted(node: ast.AST) -> str | None:
    if isinstance(node, ast.JoinedStr):
        for val in node.values:
            if isinstance(val, ast.FormattedValue):
                seg = ast.unparse(val.value)
                m = UNTRUSTED_NAMES_RE.search(seg)
                if m:
                    return m.group(0)
    elif isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        seg = ast.unparse(node)
        m = UNTRUSTED_NAMES_RE.search(seg)
        if m:
            return m.group(0)
    elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        seg = " ".join(ast.unparse(arg) for arg in node.args) + " " + " ".join(
            ast.unparse(kw.value) for kw in node.keywords
        )
        m = UNTRUSTED_NAMES_RE.search(seg)
        if m:
            return m.group(0)
    return None


def _audit_python_ast(rel_file: str, content: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        tree = ast.parse(content, filename=rel_file)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg in {
            "system",
            "system_prompt",
            "instructions",
            "developer_instructions",
        }:
            hit = _expr_has_dynamic_untrusted(node.value)
            if hit:
                findings.append(
                    _finding(
                        "untrusted-input-in-system-prompt",
                        "error",
                        rel_file,
                        node.value.lineno if isinstance(node.value, ast.expr) else 1,
                        f"{node.arg}<-{hit}",
                        "Untrusted input is interpolated directly into system instructions, enabling instruction hijacking.",
                        "Keep system instructions static and pass untrusted text strictly inside a structured user message.",
                    )
                )
        elif isinstance(node, ast.Dict):
            keys_vals = list(zip(node.keys, node.values))
            is_system_role = any(
                isinstance(k, ast.Constant)
                and k.value == "role"
                and isinstance(v, ast.Constant)
                and v.value in {"system", "developer"}
                for k, v in keys_vals
            )
            if is_system_role:
                for k, v in keys_vals:
                    if isinstance(k, ast.Constant) and k.value == "content":
                        hit = _expr_has_dynamic_untrusted(v)
                        if hit:
                            findings.append(
                                _finding(
                                    "untrusted-input-in-system-prompt",
                                    "error",
                                    rel_file,
                                    v.lineno if isinstance(v, ast.expr) else 1,
                                    f"system.content<-{hit}",
                                    "Untrusted input is interpolated into a system/developer message dict.",
                                    "Move dynamic user/RAG content into a user-role message instead.",
                                )
                            )
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.lower() in {
                    "system_prompt",
                    "system_message",
                    "instructions",
                }:
                    hit = _expr_has_dynamic_untrusted(node.value)
                    if hit:
                        findings.append(
                            _finding(
                                "untrusted-input-in-system-prompt",
                                "error",
                                rel_file,
                                node.lineno,
                                f"{target.id}<-{hit}",
                                "Dynamic untrusted variable interpolated into system prompt assignment.",
                                "Separate static policy text from untrusted inputs sent as user content.",
                            )
                        )
        elif isinstance(node, ast.Call):
            callee = ast.unparse(node.func)
            is_exec_sink = callee in {"eval", "exec", "os.system"} or callee.startswith(
                ("subprocess.", "cursor.execute", "conn.execute")
            )
            if is_exec_sink:
                args_text = " ".join(ast.unparse(a) for a in node.args)
                m = LLM_OUTPUT_RE.search(args_text)
                if m:
                    findings.append(
                        _finding(
                            "llm-output-execution-sink",
                            "error",
                            rel_file,
                            node.lineno,
                            f"{callee}({m.group(0)})",
                            "Unvalidated LLM output flows into a code, shell, or SQL execution sink.",
                            "Parse and validate LLM responses against strict allowlisted schemas before dispatching actions.",
                        )
                    )
    return findings


def _audit_js_or_ts(rel_file: str, lines: list[str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for idx, line in enumerate(lines, start=1):
        if len(line) > MAX_LINE_LENGTH:
            continue
        sys_match = SYSTEM_JS_RE.search(line) or ROLE_SYSTEM_JS_RE.search(line)
        if sys_match:
            expr = sys_match.group(1)
            untrusted = UNTRUSTED_NAMES_RE.search(expr)
            if untrusted:
                findings.append(
                    _finding(
                        "untrusted-input-in-system-prompt",
                        "error",
                        rel_file,
                        idx,
                        untrusted.group(0),
                        "Template literal interpolates untrusted variable into system prompt/instructions.",
                        "Keep system instructions static and send user payloads in a user message.",
                    )
                )
        sink_match = SINK_JS_RE.search(line)
        if sink_match and LLM_OUTPUT_RE.search(line):
            findings.append(
                _finding(
                    "llm-output-execution-sink",
                    "error",
                    rel_file,
                    idx,
                    sink_match.group(0).strip()[:64],
                    "LLM output is passed toward dynamic JS/shell execution.",
                    "Replace dynamic execution with schema-validated tool dispatch.",
                )
            )
    return findings


def scan_repo(root: Path, root_real: Path) -> tuple[list[dict[str, Any]], int]:
    files = _iter_source_files(root, root_real)
    findings: list[dict[str, Any]] = []
    scanned = 0
    for file_path in files:
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned += 1
        rel_file = file_path.relative_to(root).as_posix()
        if file_path.suffix.lower() == ".py":
            findings.extend(_audit_python_ast(rel_file, text))
        else:
            findings.extend(_audit_js_or_ts(rel_file, text.splitlines()))
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
    parser = argparse.ArgumentParser(description="Audit LLM prompt & output execution boundaries.")
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
