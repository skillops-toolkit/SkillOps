#!/usr/bin/env python3
"""Deterministic context-window token budget profiler for AI coding agent repositories.

Scans always-on instruction files (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursor/rules/*`,
`.github/instructions/*`) and progressive-disclosure skills (`.claude/skills/*/SKILL.md`,
`.agent/skills/*/SKILL.md`, `catalog/**/SKILL.md`) to estimate startup vs on-demand token load,
flag bloated files (`> 500` lines or `> 2,500` words), and recommend `references/` splits.
"""

from __future__ import annotations

import argparse
import json
import math
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

SKILL = "context-budget-profiler"
SCRIPT = "profile_context_budget.py"

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_LINES_THRESHOLD = 500
MAX_WORDS_THRESHOLD = 2500
SKILL_RECOMMENDED_LINES = 250
SKILL_L1_TOKEN_CAP = 160
DEFAULT_STARTUP_BUDGET = 2500

PUNCT_CODE_CHARS = frozenset("{}[]()<>:;,.=`~@#$%^&*|\\/")

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

ALWAYS_ON_REL_PATHS = (
    "CLAUDE.md",
    ".claude/CLAUDE.md",
    "AGENTS.md",
    "GEMINI.md",
    ".gemini/GEMINI.md",
    ".gemini/STYLEGUIDE.md",
    ".github/copilot-instructions.md",
    ".cursorrules",
    ".windsurfrules",
    ".roorules",
    ".kilocoderules",
    ".continuerules",
    "CONVENTIONS.md",
    "WARP.md",
    "QWEN.md",
    "CRUSH.md",
    "AGENT.md",
)

RULE_DIRS: tuple[tuple[str, ...], ...] = (
    (".cursor", "rules"),
    (".github", "instructions"),
    (".windsurf", "rules"),
    (".roo", "rules"),
    (".kiro", "steering"),
)

SKILL_PARENT_DIRS: tuple[tuple[str, ...], ...] = (
    (".claude", "skills"),
    (".agent", "skills"),
    (".codex", "skills"),
    (".gemini", "skills"),
)

SUBAGENT_FLAT_DIRS: tuple[tuple[tuple[str, ...], str], ...] = (
    ((".claude", "agents"), ".md"),
    ((".agent", "agents"), ".md"),
    ((".github", "agents"), ".agent.md"),
)

SKIP_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".worktrees",
}


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


def _resolve_safe_subdir(repo: Path, repo_real: Path, segments: tuple[str, ...]) -> Path | None:
    current = repo
    for seg in segments:
        if seg in SKIP_DIRS:
            return None
        current = current / seg
        if _has_unsafe_path_syntax(current) or current.is_symlink() or _is_symlink_or_junction(current):
            return None
        try:
            st = current.lstat()
        except OSError:
            return None
        if not stat.S_ISDIR(st.st_mode):
            return None
        try:
            resolved = current.resolve()
        except OSError:
            return None
        if not resolved.is_relative_to(repo_real):
            return None
    return current


def _has_safe_rel_chain(repo: Path, repo_real: Path, candidate: Path) -> bool:
    try:
        rel_parts = candidate.relative_to(repo).parts
    except ValueError:
        return False
    if not rel_parts:
        return False
    if any(part in SKIP_DIRS for part in rel_parts[:-1]):
        return False
    cur = repo
    last_idx = len(rel_parts) - 1
    for idx, part in enumerate(rel_parts):
        cur = cur / part
        if _has_unsafe_path_syntax(cur) or cur.is_symlink() or _is_symlink_or_junction(cur):
            return False
        try:
            st = cur.lstat()
        except OSError:
            return False
        if stat.S_ISLNK(st.st_mode):
            return False
        if idx == last_idx:
            if not stat.S_ISREG(st.st_mode):
                return False
        elif not stat.S_ISDIR(st.st_mode):
            return False
        try:
            resolved = cur.resolve()
        except OSError:
            return False
        if not resolved.is_relative_to(repo_real):
            return False
    return True


def _walk_named_files(root_dir: Path, repo_real: Path, filename: str) -> list[Path]:
    found: list[Path] = []
    stack: list[Path] = [root_dir]
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
            if not resolved.is_relative_to(repo_real):
                continue
            if stat.S_ISDIR(st.st_mode):
                if entry.name in SKIP_DIRS:
                    continue
                subdirs.append(entry)
            elif stat.S_ISREG(st.st_mode) and entry.name == filename:
                found.append(entry)
        for subdir in reversed(subdirs):
            stack.append(subdir)
    found.sort(key=lambda item: item.as_posix())
    return found


def estimate_tokens(text: str) -> int:
    """Deterministic zero-API token estimator matching SkillOps SKILL_CONTRACT.md."""
    stripped = text.strip()
    if not stripped:
        return 0
    words = len(stripped.split())
    punct_bonus = sum(1 for ch in stripped if ch in PUNCT_CODE_CHARS) // 4
    return max(1, math.ceil(words * 1.33) + punct_bonus)


def _slugify_heading(heading: str) -> str:
    chars: list[str] = []
    prev_dash = False
    for ch in heading.lower():
        if ch.isalnum():
            chars.append(ch)
            prev_dash = False
        elif not prev_dash and chars:
            chars.append("-")
            prev_dash = True
    slug = "".join(chars).strip("-")
    return slug[:48] or "details"


def _parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    if not text.startswith("---\n") and not text.startswith("---\r\n"):
        return {}, text
    lines = text.splitlines()
    end_idx = -1
    for idx in range(1, len(lines)):
        if lines[idx].strip() == "---":
            end_idx = idx
            break
    if end_idx == -1:
        return {}, text

    fm: dict[str, str] = {}
    current_key: str | None = None
    for raw in lines[1:end_idx]:
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not raw.startswith((" ", "\t")) and ":" in raw:
            key, val = raw.split(":", 1)
            current_key = key.strip()
            fm[current_key] = val.strip().strip("\"'")
        elif current_key is not None and not stripped.startswith("-"):
            fm[current_key] = f"{fm[current_key]} {stripped}".strip()
    body = "\n".join(lines[end_idx + 1 :])
    return fm, body


def _extract_heavy_sections(body: str, limit: int = 3) -> list[dict[str, Any]]:
    sections: list[tuple[str, list[str]]] = []
    current_title = "introduction"
    current_lines: list[str] = []

    for line in body.splitlines():
        if line.startswith("## ") or line.startswith("### "):
            if current_lines:
                sections.append((current_title, current_lines))
            current_title = line.lstrip("#").strip()
            current_lines = [line]
        else:
            current_lines.append(line)

    if current_lines:
        sections.append((current_title, current_lines))

    scored: list[dict[str, Any]] = []
    for title, sec_lines in sections:
        sec_text = "\n".join(sec_lines)
        words = len(sec_text.split())
        tokens = estimate_tokens(sec_text)
        if words >= 80 and title != "introduction":
            scored.append(
                {
                    "heading": title,
                    "lines": len(sec_lines),
                    "words": words,
                    "estimated_tokens": tokens,
                    "suggested_reference": f"references/{_slugify_heading(title)}.md",
                }
            )

    scored.sort(key=lambda item: item["estimated_tokens"], reverse=True)
    return scored[:limit]


def _discover_context_files(repo: Path, repo_real: Path) -> list[tuple[Path, str]]:
    seen: set[Path] = set()
    discovered: list[tuple[Path, str]] = []

    def _add(candidate: Path, default_tier: str) -> None:
        if not _has_safe_rel_chain(repo, repo_real, candidate):
            return
        try:
            resolved = candidate.resolve()
        except OSError:
            return
        if not resolved.is_relative_to(repo_real) or resolved in seen:
            return
        seen.add(resolved)
        discovered.append((candidate, default_tier))

    for rel_path in ALWAYS_ON_REL_PATHS:
        _add(repo / rel_path, "always-on")

    clinerules = repo / ".clinerules"
    if not _has_unsafe_path_syntax(clinerules) and not clinerules.is_symlink() and not _is_symlink_or_junction(clinerules):
        try:
            cline_st = clinerules.lstat()
        except OSError:
            cline_st = None
        if cline_st is not None:
            if stat.S_ISREG(cline_st.st_mode):
                _add(clinerules, "always-on")
            elif stat.S_ISDIR(cline_st.st_mode):
                safe_cline_dir = _resolve_safe_subdir(repo, repo_real, (".clinerules",))
                if safe_cline_dir is not None:
                    try:
                        children = sorted(safe_cline_dir.iterdir(), key=lambda item: item.name)
                    except OSError:
                        children = []
                    for child in children:
                        if child.suffix in {".md", ".mdc", ".txt"}:
                            _add(child, "scoped-rule")

    for dir_segments in RULE_DIRS:
        rule_dir = _resolve_safe_subdir(repo, repo_real, dir_segments)
        if rule_dir is None:
            continue
        try:
            entries = sorted(rule_dir.iterdir(), key=lambda item: item.name)
        except OSError:
            continue
        for match in entries:
            if match.suffix in {".md", ".mdc", ".txt"}:
                _add(match, "scoped-rule")

    for skill_parent_segments in SKILL_PARENT_DIRS:
        skills_parent = _resolve_safe_subdir(repo, repo_real, skill_parent_segments)
        if skills_parent is None:
            continue
        try:
            skill_dirs = sorted(skills_parent.iterdir(), key=lambda item: item.name)
        except OSError:
            continue
        for skill_dir in skill_dirs:
            if skill_dir.is_symlink() or _is_symlink_or_junction(skill_dir):
                continue
            _add(skill_dir / "SKILL.md", "on-demand-skill")

    catalog_dir = _resolve_safe_subdir(repo, repo_real, ("catalog",))
    if catalog_dir is not None:
        for match in _walk_named_files(catalog_dir, repo_real, "SKILL.md"):
            _add(match, "on-demand-skill")

    subagents_catalog = _resolve_safe_subdir(repo, repo_real, ("catalog", "subagents"))
    if subagents_catalog is not None:
        try:
            sub_dirs = sorted(subagents_catalog.iterdir(), key=lambda item: item.name)
        except OSError:
            sub_dirs = []
        for sub_dir in sub_dirs:
            if sub_dir.is_symlink() or _is_symlink_or_junction(sub_dir):
                continue
            _add(sub_dir / "SUBAGENT.md", "isolated-subagent")

    for dir_segments, required_suffix in SUBAGENT_FLAT_DIRS:
        agents_dir = _resolve_safe_subdir(repo, repo_real, dir_segments)
        if agents_dir is None:
            continue
        try:
            agent_files = sorted(agents_dir.iterdir(), key=lambda item: item.name)
        except OSError:
            continue
        for agent_file in agent_files:
            if agent_file.name.endswith(required_suffix):
                _add(agent_file, "isolated-subagent")

    return discovered


def _classify_effective_tier(default_tier: str, fm: dict[str, str]) -> str:
    if default_tier == "scoped-rule":
        always_apply = fm.get("alwaysApply", "").lower()
        apply_to = fm.get("applyTo", "").strip()
        inclusion = fm.get("inclusion", "").lower()
        if always_apply == "true" or apply_to in {"**", "**/*"} or inclusion == "always":
            return "always-on"
    return default_tier


def profile_repository(
    repo: Path,
    startup_budget: int = DEFAULT_STARTUP_BUDGET,
    repo_real: Path | None = None,
) -> dict[str, Any]:
    resolved_repo = repo_real if repo_real is not None else repo.resolve()
    repo_label = repo.as_posix() or "."
    files_report: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    split_suggestions: list[dict[str, Any]] = []

    for file_path, raw_tier in _discover_context_files(repo, resolved_repo):
        rel = file_path.relative_to(repo).as_posix()
        try:
            st = file_path.lstat()
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        if st.st_size > MAX_FILE_BYTES:
            findings.append(
                {
                    "file": rel,
                    "line": 1,
                    "rule": "skipped-oversized-file",
                    "symbol": file_path.name,
                    "severity": "warning",
                    "impact": (
                        f"Context file '{rel}' ({st.st_size} bytes) exceeds the "
                        f"{MAX_FILE_BYTES}-byte safety limit and was skipped."
                    ),
                }
            )
            continue

        try:
            text = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        raw_lines = text.splitlines()
        line_count = len(raw_lines)
        word_count = len(text.split())
        total_tokens = estimate_tokens(text)
        fm, body = _parse_frontmatter(text)
        tier = _classify_effective_tier(raw_tier, fm)

        desc_tokens = estimate_tokens(fm.get("description", ""))
        if tier == "always-on":
            startup_tokens = total_tokens
        else:
            startup_tokens = desc_tokens if desc_tokens > 0 else min(total_tokens, 120)

        is_bloated = line_count > MAX_LINES_THRESHOLD or word_count > MAX_WORDS_THRESHOLD

        files_report.append(
            {
                "file": rel,
                "tier": tier,
                "lines": line_count,
                "words": word_count,
                "estimated_tokens": total_tokens,
                "startup_tokens": startup_tokens,
                "bloated": is_bloated,
            }
        )

        if is_bloated:
            severity = "error" if tier == "always-on" else "warning"
            findings.append(
                {
                    "file": rel,
                    "line": 1,
                    "rule": "bloated-context-file",
                    "symbol": file_path.name,
                    "severity": severity,
                    "impact": (
                        f"Context file '{rel}' ({line_count} lines, {word_count} words, "
                        f"~{total_tokens} tokens) exceeds the progressive-disclosure threshold "
                        f"({MAX_LINES_THRESHOLD} lines / {MAX_WORDS_THRESHOLD} words)."
                    ),
                }
            )

        if tier == "on-demand-skill":
            if line_count > SKILL_RECOMMENDED_LINES and not is_bloated:
                findings.append(
                    {
                        "file": rel,
                        "line": 1,
                        "rule": "skill-body-over-250-lines",
                        "symbol": file_path.name,
                        "severity": "warning",
                        "impact": (
                            f"Skill '{rel}' has {line_count} lines (recommended <= {SKILL_RECOMMENDED_LINES}); "
                            "extract deep lookup tables or templates into 'references/'."
                        ),
                    }
                )
            if desc_tokens > SKILL_L1_TOKEN_CAP:
                findings.append(
                    {
                        "file": rel,
                        "line": 1,
                        "rule": "skill-l1-description-over-budget",
                        "symbol": file_path.name,
                        "severity": "warning",
                        "impact": (
                            f"Skill '{rel}' frontmatter description consumes ~{desc_tokens} L1 tokens "
                            f"(cap <= {SKILL_L1_TOKEN_CAP} tokens)."
                        ),
                    }
                )

        needs_split_plan = is_bloated or (tier == "always-on" and line_count > 300)
        if needs_split_plan:
            heavy_sections = _extract_heavy_sections(body)
            base_parent = Path(rel).parent.as_posix()
            target_dir = "references" if base_parent == "." else f"{base_parent}/references"
            split_suggestions.append(
                {
                    "source_file": rel,
                    "tier": tier,
                    "current_tokens": total_tokens,
                    "recommended_target_dir": target_dir,
                    "strategy": (
                        "Keep core invariants and workflow commands in the entrypoint file; "
                        f"move detailed examples and lookup tables into '{target_dir}/' loaded on demand."
                    ),
                    "candidate_sections": heavy_sections,
                }
            )

    always_on_tokens = sum(
        item["startup_tokens"] for item in files_report if item["tier"] == "always-on"
    )
    routing_l1_tokens = sum(
        item["startup_tokens"] for item in files_report if item["tier"] != "always-on"
    )
    total_startup_tokens = always_on_tokens + routing_l1_tokens
    total_context_tokens = sum(item["estimated_tokens"] for item in files_report)

    if total_startup_tokens > startup_budget:
        findings.append(
            {
                "file": ".",
                "line": 1,
                "rule": "startup-token-budget-exceeded",
                "symbol": "startup_budget",
                "severity": "warning",
                "impact": (
                    f"Estimated startup context load (~{total_startup_tokens} tokens across always-on files "
                    f"and L1 skill descriptions) exceeds budget of {startup_budget} tokens."
                ),
            }
        )

    errors = sum(1 for f in findings if f["severity"] == "error")
    warnings = sum(1 for f in findings if f["severity"] == "warning")
    bloated_count = sum(1 for f in files_report if f["bloated"])
    status = "error" if errors > 0 else ("warn" if warnings > 0 else "ok")
    summary_text = (
        f"Profiled {len(files_report)} context file(s): ~{total_startup_tokens} startup tokens "
        f"(budget {startup_budget}), {bloated_count} bloated file(s), {errors} error(s), {warnings} warning(s)."
    )

    return {
        "skill": SKILL,
        "script": SCRIPT,
        "status": status,
        "target": repo_label,
        "summary": summary_text,
        "findings": findings,
        "data": {
            "repo": repo_label,
            "files": files_report,
            "findings": findings,
            "split_suggestions": split_suggestions,
        },
        "metrics": {
            "files_scanned": len(files_report),
            "bloated_files": bloated_count,
            "always_on_tokens": always_on_tokens,
            "skill_l1_routing_tokens": routing_l1_tokens,
            "total_startup_tokens": total_startup_tokens,
            "total_on_disk_context_tokens": total_context_tokens,
            "startup_budget": startup_budget,
            "errors": errors,
            "warnings": warnings,
        },
    }


def _emit_invalid_repo(repo_label: str, as_json: bool) -> int:
    msg = f"Repository directory is missing, invalid, or unsafe: {repo_label}"
    if as_json:
        print(
            json.dumps(
                {
                    "skill": SKILL,
                    "script": SCRIPT,
                    "status": "error",
                    "target": repo_label,
                    "summary": msg,
                    "findings": [],
                    "data": {
                        "repo": repo_label,
                        "files": [],
                        "findings": [],
                        "split_suggestions": [],
                    },
                    "metrics": {
                        "files_scanned": 0,
                        "errors": 1,
                        "warnings": 0,
                    },
                },
                indent=2,
            )
        )
    else:
        sys.stderr.write(f"error: {msg}\n")
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Profile AI agent instruction and skill token budgets across a repository."
    )
    parser.add_argument(
        "--repo",
        "--path",
        dest="repo",
        default=".",
        help="Repository root directory to profile.",
    )
    parser.add_argument(
        "--startup-budget",
        type=int,
        default=DEFAULT_STARTUP_BUDGET,
        help=f"Maximum recommended always-on + L1 startup token tax (default: {DEFAULT_STARTUP_BUDGET}).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit structured JSON report.",
    )
    args = parser.parse_args(argv)

    raw_arg = args.repo
    if not raw_arg or not raw_arg.strip() or "\x00" in raw_arg:
        return _emit_invalid_repo(_sanitize_label(raw_arg), args.as_json)

    repo = Path(raw_arg)
    repo_label = repo.as_posix() or "."
    if _has_unsafe_path_syntax(repo) or _has_symlink_ancestor(repo):
        return _emit_invalid_repo(repo_label, args.as_json)

    try:
        repo_st = repo.lstat()
    except OSError:
        return _emit_invalid_repo(repo_label, args.as_json)
    if not stat.S_ISDIR(repo_st.st_mode):
        return _emit_invalid_repo(repo_label, args.as_json)

    try:
        repo_real = repo.resolve()
    except OSError:
        return _emit_invalid_repo(repo_label, args.as_json)

    payload = profile_repository(repo, startup_budget=args.startup_budget, repo_real=repo_real)
    if args.as_json:
        print(json.dumps(payload, indent=2))
    else:
        sys.stdout.write(f"[{payload['status'].upper()}] {payload['summary']}\n")
        for item in payload["findings"]:
            sys.stdout.write(
                f"  - {item['file']}:{item['line']} [{item['severity']}] "
                f"{item['rule']}: {item['impact']}\n"
            )
    return 1 if payload["metrics"]["errors"] > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
