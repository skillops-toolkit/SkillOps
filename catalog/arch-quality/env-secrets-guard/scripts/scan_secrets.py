"""Deterministic secrets and .env hygiene scanner using pure Python stdlib."""

from __future__ import annotations

import argparse
import json
import re
import stat
import struct
import sys
import tempfile
from pathlib import Path
from typing import Any

SKILL = "env-secrets-guard"
SCRIPT = "scan_secrets.py"

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
EXAMPLE_SUFFIXES = (".example", ".sample", ".template", ".dist")

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

AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
GITHUB_TOKEN_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")
ANTHROPIC_KEY_RE = re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")
OPENAI_KEY_RE = re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{32,}")
GOOGLE_API_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")
HUGGINGFACE_TOKEN_RE = re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")
SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")
PRIVATE_KEY_BLOCK_RE = re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")
ASSIGNMENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{0,80})[\"']?\s*[:=]\s*[\"']?([^\s\x00\"'#;,{}]{8,160})[\"']?")

PROVIDER_TOKEN_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws-access-key-id", AWS_ACCESS_KEY_RE),
    ("github-token", GITHUB_TOKEN_RE),
    ("anthropic-api-key", ANTHROPIC_KEY_RE),
    ("openai-api-key", OPENAI_KEY_RE),
    ("google-api-key", GOOGLE_API_KEY_RE),
    ("huggingface-token", HUGGINGFACE_TOKEN_RE),
    ("slack-token", SLACK_TOKEN_RE),
    ("private-key-block", PRIVATE_KEY_BLOCK_RE),
)

SENSITIVE_KEYWORDS = (
    "API_KEY",
    "SECRET",
    "ACCESS_KEY",
    "AUTH_TOKEN",
    "ACCESS_TOKEN",
    "REFRESH_TOKEN",
    "PRIVATE_KEY",
    "PASSWORD",
    "PASSWD",
    "DB_PASS",
    "DATABASE_URL",
)

PLACEHOLDER_SUBSTRINGS = (
    "example",
    "changeme",
    "change_me",
    "your_",
    "your-",
    "xxx",
    "dummy",
    "placeholder",
    "sample",
    "${",
    "%(",
    "***",
    "todo",
    "none",
    "null",
    "true",
    "false",
)

CODE_LOOKUP_PREFIXES = (
    "os.environ",
    "os.getenv",
    "process.env",
    "import.meta.env",
    "deno.env",
    "bun.env",
    "settings.",
    "config.",
    "env.",
    "self.",
    "cls.",
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


def _is_safe_regular_file_within(path: Path, root_real: Path) -> bool:
    if _has_unsafe_path_syntax(path) or path.is_symlink() or _is_symlink_or_junction(path):
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


def _redact(value: str) -> str:
    return f"{value[:4]}***" if len(value) > 4 else "***"


def _is_env_file(name: str) -> bool:
    return name == ".env" or name.startswith(".env.")


def _is_example_env(name: str) -> bool:
    return name.endswith(EXAMPLE_SUFFIXES)


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    if any(marker in lowered for marker in PLACEHOLDER_SUBSTRINGS):
        return True
    open_angle = value.find("<")
    return open_angle != -1 and value.find(">", open_angle + 1) != -1


def _is_dynamic_code_expr(matched_text: str, key_name: str, value: str) -> bool:
    after_key = matched_text[len(key_name) :].lstrip("\"' \t")
    rhs_stripped = after_key[1:].strip() if after_key and after_key[0] in (":", "=") else ""
    is_quoted = (
        len(rhs_stripped) >= 2
        and rhs_stripped[0] in ("'", '"')
        and rhs_stripped[-1] == rhs_stripped[0]
    )
    if is_quoted:
        return False
    lowered = value.lower()
    if lowered.startswith(CODE_LOOKUP_PREFIXES):
        return True
    if any(ch in value for ch in ("(", ")", "[", "]")):
        return True
    return False


def _wildcard_match(text: str, pattern: str) -> bool:
    """Linear-space two-pointer glob matcher supporting '*' and '?' without regex compilation."""
    t_idx = 0
    p_idx = 0
    star_idx = -1
    match_idx = 0
    t_len = len(text)
    p_len = len(pattern)

    while t_idx < t_len:
        if p_idx < p_len and (pattern[p_idx] == "?" or pattern[p_idx] == text[t_idx]):
            t_idx += 1
            p_idx += 1
        elif p_idx < p_len and pattern[p_idx] == "*":
            star_idx = p_idx
            match_idx = t_idx
            p_idx += 1
        elif star_idx != -1:
            p_idx = star_idx + 1
            match_idx += 1
            t_idx = match_idx
        else:
            return False

    while p_idx < p_len and pattern[p_idx] == "*":
        p_idx += 1

    return p_idx == p_len


def _resolve_git_dir(root: Path, root_real: Path) -> Path | None:
    dot_git = root / ".git"
    if _has_unsafe_path_syntax(dot_git) or dot_git.is_symlink() or _is_symlink_or_junction(dot_git):
        return None
    try:
        st = dot_git.lstat()
    except OSError:
        return None

    if stat.S_ISDIR(st.st_mode):
        try:
            resolved_dir = dot_git.resolve()
        except OSError:
            return None
        return dot_git if resolved_dir.is_relative_to(root_real) else None

    if stat.S_ISREG(st.st_mode):
        if st.st_size > MAX_FILE_BYTES:
            return None
        try:
            lines = dot_git.read_text(encoding="utf-8", errors="replace").splitlines()
            first_line = lines[0] if lines else ""
        except OSError:
            return None
        if len(first_line) > MAX_LINE_LENGTH or not first_line.startswith("gitdir:"):
            return None
        raw_target = first_line.partition(":")[2].strip()
        if not raw_target or "\x00" in raw_target:
            return None
        candidate = root / raw_target
        if (
            _has_unsafe_path_syntax(candidate)
            or candidate.is_symlink()
            or _is_symlink_or_junction(candidate)
        ):
            return None
        try:
            resolved = candidate.resolve()
        except OSError:
            return None
        if not resolved.is_relative_to(root_real):
            return None
        # Verify no intermediate segment between root_real and resolved is a symlink/junction
        try:
            rel_parts = resolved.relative_to(root_real).parts
        except ValueError:
            return None
        cur = root_real
        for part in rel_parts:
            cur = cur / part
            if cur.is_symlink() or _is_symlink_or_junction(cur):
                return None
        try:
            target_st = resolved.lstat()
        except OSError:
            return None
        if stat.S_ISDIR(target_st.st_mode):
            return resolved
    return None


def _read_git_index_paths(git_dir: Path | None, root_real: Path) -> set[str]:
    """Parse standard Git DIRC v2/v3 index binary using stdlib struct to detect tracked files."""
    if git_dir is None:
        return set()
    index_path = git_dir / "index"
    if not _is_safe_regular_file_within(index_path, root_real):
        return set()
    try:
        data = index_path.read_bytes()
        if len(data) < 12:
            return set()
        magic, version, entry_count = struct.unpack(">4sII", data[:12])
        if magic != b"DIRC" or version not in (2, 3):
            return set()
        tracked: set[str] = set()
        offset = 12
        data_len = len(data)
        for _ in range(entry_count):
            if offset + 62 > data_len:
                break
            flags = struct.unpack(">H", data[offset + 60 : offset + 62])[0]
            header_size = 62 + (2 if (version >= 3 and (flags & 0x4000)) else 0)
            name_start = offset + header_size
            nul_pos = data.find(b"\x00", name_start)
            if nul_pos == -1:
                break
            rel_path = data[name_start:nul_pos].decode("utf-8", errors="replace")
            if rel_path:
                tracked.add(rel_path)
            entry_len = ((nul_pos - offset) + 8) & ~7
            if entry_len <= 0:
                break
            offset += entry_len
        return tracked
    except OSError:
        return set()


def _matches_gitignore_rule(rel: str, name: str, raw_pattern: str) -> bool:
    dir_only = raw_pattern.endswith("/")
    pattern = raw_pattern.rstrip("/")
    if not pattern:
        return False

    anchored = pattern.startswith("/")
    clean = pattern.lstrip("/")
    if clean.startswith("**/"):
        clean = clean[3:]
        anchored = False

    if dir_only:
        parent_parts = Path(rel).parts[:-1]
        if anchored:
            return bool(parent_parts) and _wildcard_match("/".join(parent_parts), clean)
        return any(_wildcard_match(part, clean) for part in parent_parts)

    if "/" in clean or anchored:
        return _wildcard_match(rel, clean)
    return _wildcard_match(name, clean) or _wildcard_match(rel, clean)


def _collect_ignore_files(
    root: Path,
    root_real: Path,
    rel: str,
    git_dir: Path | None,
) -> list[tuple[Path, str]]:
    """Return [(ignore_file, rel_to_ignore_dir)] ordered from repo exclude down to deepest subdir."""
    candidates: list[tuple[Path, str]] = []
    if git_dir is not None:
        info_dir = git_dir / "info"
        exclude = info_dir / "exclude"
        if (
            not info_dir.is_symlink()
            and not _is_symlink_or_junction(info_dir)
            and _is_safe_regular_file_within(exclude, root_real)
        ):
            candidates.append((exclude, rel))

    parts = Path(rel).parts
    current_dir = root
    for depth in range(len(parts)):
        if current_dir != root:
            if current_dir.is_symlink() or _is_symlink_or_junction(current_dir):
                break
            try:
                if not current_dir.resolve().is_relative_to(root_real):
                    break
            except OSError:
                break
        gitignore = current_dir / ".gitignore"
        sub_rel = "/".join(parts[depth:])
        if _is_safe_regular_file_within(gitignore, root_real):
            candidates.append((gitignore, sub_rel))
        if depth < len(parts) - 1:
            current_dir = current_dir / parts[depth]
    return candidates


def _is_ignored(root: Path, root_real: Path, rel: str, git_dir: Path | None) -> bool:
    ignored = False
    name = Path(rel).name
    for ignore_file, scoped_rel in _collect_ignore_files(root, root_real, rel, git_dir):
        try:
            lines = ignore_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for raw_line in lines:
            if len(raw_line) > MAX_LINE_LENGTH:
                continue
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            negated = stripped.startswith("!")
            rule = stripped[1:].strip() if negated else stripped
            if _matches_gitignore_rule(scoped_rel, name, rule):
                ignored = not negated
    return ignored


def _walk(root: Path, root_real: Path) -> list[Path]:
    files: list[Path] = []
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
            elif stat.S_ISREG(st.st_mode):
                files.append(entry)
        for subdir in reversed(subdirs):
            stack.append(subdir)
    files.sort(key=lambda item: item.relative_to(root).as_posix())
    return files


def _finding(rel: str, line: int, rule: str, severity: str, impact: str) -> dict[str, Any]:
    return {
        "file": rel,
        "line": line,
        "rule": rule,
        "symbol": rule,
        "impact": impact,
        "severity": severity,
    }


def _scan_provider_tokens(rel: str, lineno: int, line: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for rule, pattern in PROVIDER_TOKEN_RULES:
        for match in pattern.finditer(line):
            token = match.group(0)
            if not _is_placeholder(token):
                results.append(
                    _finding(
                        rel,
                        lineno,
                        rule,
                        "error",
                        f"Hardcoded credential detected ({_redact(token)}); "
                        "move it to an environment variable and rotate it.",
                    )
                )
    return results


def _has_sensitive_key_name(raw_key: str) -> bool:
    upper_key = raw_key.upper()
    return any(keyword in upper_key for keyword in SENSITIVE_KEYWORDS)


def scan_repo(root: Path, root_real: Path | None = None) -> tuple[list[dict[str, Any]], int]:
    """Return (findings, files_scanned) for the directory tree under root."""
    resolved_root = root_real if root_real is not None else root.resolve()
    findings: list[dict[str, Any]] = []
    scanned = 0
    git_dir = _resolve_git_dir(root, resolved_root)
    tracked_paths = _read_git_index_paths(git_dir, resolved_root)

    for path in _walk(root, resolved_root):
        rel = path.relative_to(root).as_posix()
        name = path.name

        if _is_env_file(name) and not _is_example_env(name):
            if rel in tracked_paths:
                findings.append(
                    _finding(
                        rel,
                        0,
                        "env-file-tracked",
                        "error",
                        "Environment file is tracked by git; remove it from the index and rotate its secrets.",
                    )
                )
            elif not _is_ignored(root, resolved_root, rel, git_dir):
                findings.append(
                    _finding(
                        rel,
                        0,
                        "env-file-not-ignored",
                        "error",
                        "Environment file is not covered by .gitignore; add '.env' and '.env.*'.",
                    )
                )
            continue  # real .env files hold secrets by design; never scan or print their content

        try:
            st = path.lstat()
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        if st.st_size > MAX_FILE_BYTES:
            findings.append(
                _finding(
                    rel,
                    1,
                    "skipped-oversized-file",
                    "warning",
                    f"File '{rel}' ({st.st_size} bytes) exceeds the {MAX_FILE_BYTES}-byte limit "
                    "and was skipped.",
                )
            )
            continue

        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        scanned += 1

        long_line_warned = False
        for lineno, line in enumerate(text.splitlines(), start=1):
            if len(line) > MAX_LINE_LENGTH:
                if not long_line_warned:
                    findings.append(
                        _finding(
                            rel,
                            lineno,
                            "skipped-long-line",
                            "warning",
                            f"Line {lineno} exceeds {MAX_LINE_LENGTH} characters ({len(line)} chars) "
                            "and was skipped to prevent ReDoS; inspect minified lines manually.",
                        )
                    )
                    long_line_warned = True
                continue

            token_hits = _scan_provider_tokens(rel, lineno, line)
            findings.extend(token_hits)

            for assign_match in ASSIGNMENT_RE.finditer(line):
                key_name = assign_match.group(1)
                secret_val = assign_match.group(2)
                if (
                    _has_sensitive_key_name(key_name)
                    and not _is_placeholder(secret_val)
                    and not _is_dynamic_code_expr(assign_match.group(0), key_name, secret_val)
                ):
                    findings.append(
                        _finding(
                            rel,
                            lineno,
                            "hardcoded-secret-assignment",
                            "warning",
                            f"Literal value assigned to a secret-like name ({_redact(secret_val)}); "
                            "read it from the environment instead.",
                        )
                    )

    return findings, scanned


def _emit_invalid_root(target_label: str, as_json: bool) -> int:
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
        sys.stderr.write(f"error: invalid or unsafe directory: {target_label}\n")
    return 2


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint: exit 0 clean, 1 findings, 2 invalid path."""
    parser = argparse.ArgumentParser(
        description="Scan a repository for secrets and .env hygiene issues."
    )
    parser.add_argument("--path", required=True, help="Repository root directory to scan.")
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
                    "data": {
                        "files_scanned": scanned,
                        "findings": findings,
                    },
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
            print(f"{f['file']}:{f['line']}: {f['severity']}: {f['symbol']}: {f['impact']}")
        print(f"status={status} files_scanned={scanned} findings={len(findings)}")
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
