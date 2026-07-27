"""Component parsers for inspection. Each function parses a specific component type."""

from __future__ import annotations

import json as json_mod
import re
from pathlib import Path

from harness_eval.inspection.types import (
    ParsedAgent,
    ParsedClaudeMd,
    ParsedCommand,
    ParsedHooks,
    ParsedSkill,
)
from harness_eval.utils.parsing import parse_frontmatter_rich
from harness_eval.utils.tokens import count_tokens


def list_files(directory: Path) -> list[str]:
    if not directory.is_dir():
        return []
    return sorted(
        str(p.relative_to(directory))
        for p in directory.rglob("*")
        if p.is_file() and ".git" not in p.parts
    )


def _read_and_parse(path: Path) -> tuple[str, object, list[str]]:
    """Read a file and parse its frontmatter. Returns (raw_content, frontmatter_result, errors)."""
    raw_content = path.read_text()
    fm = parse_frontmatter_rich(raw_content)
    return raw_content, fm, fm.errors


def _not_found(path: Path, expected: str) -> tuple[str, None, list[str]]:
    """Return a parse failure for a missing file."""
    return "", None, [f"{expected} not found" if expected else f"Path does not exist: {path}"]


_MAX_SUB_FILES = 50
_MAX_SUB_FILE_BYTES = 100_000


def _read_md_sub_files(skill_dir: Path, skill_md: Path) -> dict[str, str]:
    """Read .md files in *skill_dir* except the primary SKILL.md."""
    result: dict[str, str] = {}
    skill_md_resolved = skill_md.resolve()
    for p in sorted(skill_dir.rglob("*.md")):
        if p.resolve() == skill_md_resolved:
            continue
        if ".git" in p.parts or "__pycache__" in p.parts:
            continue
        if len(result) >= _MAX_SUB_FILES:
            break
        try:
            if p.stat().st_size > _MAX_SUB_FILE_BYTES:
                continue
            content = p.read_text(encoding="utf-8", errors="replace")
            result[str(p.relative_to(skill_dir))] = content
        except OSError:
            continue
    return result


def _resolve_skill_path(skill_path: str) -> tuple[Path, Path | None, list[str]]:
    """Resolve a skill path to (skill_dir, skill_md, errors)."""
    path = Path(skill_path)
    if path.is_file() and path.name.lower() == "skill.md":
        return path.parent, path, []
    if path.is_dir():
        candidates = [p for p in path.iterdir() if p.name.lower() == "skill.md"]
        if candidates:
            return path, candidates[0], []
        return path, None, ["SKILL.md not found"]
    return path, None, [f"Path does not exist: {path}"]


def _resolve_command_path(command_path: str) -> tuple[Path, Path | None, list[str]]:
    """Resolve a command path to (cmd_dir, cmd_md, errors)."""
    path = Path(command_path)
    if path.is_file() and path.suffix == ".md":
        return path.parent, path, []
    if path.is_dir():
        cmd_md = path / "command.md"
        if cmd_md.exists():
            return path, cmd_md, []
        return path, None, ["command.md not found"]
    return path, None, [f"Path does not exist: {path}"]


def parse_skill(skill_path: str) -> ParsedSkill:
    """Parse a skill directory or SKILL.md file into a ParsedSkill."""
    skill_dir, skill_md, errors = _resolve_skill_path(skill_path)

    if skill_md is None:
        return ParsedSkill(
            dir_path=str(skill_dir),
            dir_name=skill_dir.name,
            skill_md_path=str(skill_dir / "SKILL.md"),
            raw_content="",
            frontmatter={},
            raw_frontmatter="",
            frontmatter_start_line=0,
            body="",
            body_start_line=0,
            files=list_files(skill_dir),
            sub_file_contents=_read_md_sub_files(skill_dir, skill_dir / "SKILL.md"),
            parse_errors=errors,
        )

    raw_content, fm, parse_errors = _read_and_parse(skill_md)

    return ParsedSkill(
        dir_path=str(skill_dir),
        dir_name=skill_dir.name,
        skill_md_path=str(skill_md),
        raw_content=raw_content,
        frontmatter=fm.frontmatter,
        raw_frontmatter=fm.raw_frontmatter,
        frontmatter_start_line=fm.frontmatter_start_line,
        body=fm.body,
        body_start_line=fm.body_start_line,
        files=list_files(skill_dir),
        sub_file_contents=_read_md_sub_files(skill_dir, skill_md),
        parse_errors=parse_errors,
        tokens=count_tokens(raw_content),
    )


def _extract_script_refs_outside_code_blocks(body: str) -> list[str]:
    """Extract .py references only from lines outside fenced code blocks."""
    refs: list[str] = []
    in_fence = False
    for line in body.split("\n"):
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            refs.extend(re.findall(r"[\w./-]+\.py\b", line))
    return refs


def parse_command(command_path: str) -> ParsedCommand:
    """Parse a command directory or command.md file."""
    cmd_dir, cmd_md, errors = _resolve_command_path(command_path)

    if cmd_md is None:
        return ParsedCommand(
            dir_path=str(cmd_dir),
            dir_name=cmd_dir.name,
            command_md_path=str(cmd_dir / "command.md"),
            raw_content="",
            frontmatter={},
            body="",
            body_start_line=0,
            script_references=[],
            files=list_files(cmd_dir),
            parse_errors=errors,
        )

    raw_content, fm, parse_errors = _read_and_parse(cmd_md)
    script_refs = _extract_script_refs_outside_code_blocks(fm.body)

    return ParsedCommand(
        dir_path=str(cmd_dir),
        dir_name=cmd_dir.name,
        command_md_path=str(cmd_md),
        raw_content=raw_content,
        frontmatter=fm.frontmatter,
        body=fm.body,
        body_start_line=fm.body_start_line,
        script_references=script_refs,
        files=list_files(cmd_dir),
        parse_errors=parse_errors,
        tokens=count_tokens(raw_content),
    )


def parse_claude_md(file_path: str) -> ParsedClaudeMd:
    """Parse a CLAUDE.md file."""
    path = Path(file_path)
    if not path.exists():
        return ParsedClaudeMd(
            file_path=file_path,
            raw_content="",
            line_count=0,
            sections=[],
            parse_errors=[f"File not found: {file_path}"],
        )

    raw_content = path.read_text()
    lines = raw_content.split("\n")

    sections: list[dict[str, str]] = []
    current_header = "(top)"
    current_lines: list[str] = []

    for line in lines:
        if line.startswith("#"):
            if current_lines:
                sections.append(
                    {
                        "header": current_header,
                        "content": "\n".join(current_lines),
                    }
                )
            current_header = line.lstrip("#").strip()
            current_lines = []
        else:
            current_lines.append(line)

    if current_lines:
        sections.append(
            {
                "header": current_header,
                "content": "\n".join(current_lines),
            }
        )

    return ParsedClaudeMd(
        file_path=file_path,
        raw_content=raw_content,
        line_count=len(lines),
        sections=sections,
        tokens=count_tokens(raw_content),
    )


def parse_hooks(settings_path: str) -> ParsedHooks:
    """Parse hooks from a .claude/settings.json file."""
    path = Path(settings_path)
    if not path.exists():
        return ParsedHooks(
            file_path=settings_path,
            hooks=[],
            raw_content="",
            parse_errors=[f"File not found: {settings_path}"],
        )

    raw_content = path.read_text()
    try:
        data = json_mod.loads(raw_content)
    except json_mod.JSONDecodeError as e:
        return ParsedHooks(
            file_path=settings_path,
            hooks=[],
            raw_content=raw_content,
            parse_errors=[f"JSON parse error: {e}"],
        )

    hooks: list[dict] = []
    hooks_data = data.get("hooks", {})
    if isinstance(hooks_data, dict):
        for event, hook_list in hooks_data.items():
            if not isinstance(hook_list, list):
                continue
            for hook_entry in hook_list:
                if not isinstance(hook_entry, dict):
                    hooks.append({"event": event, "command": str(hook_entry)})
                    continue
                nested = hook_entry.get("hooks", [])
                if isinstance(nested, list) and nested:
                    for sub_hook in nested:
                        extra = {k: v for k, v in hook_entry.items() if k != "hooks"}
                        if isinstance(sub_hook, str):
                            hooks.append(
                                {
                                    "event": event,
                                    "command": sub_hook,
                                    **extra,
                                }
                            )
                        elif isinstance(sub_hook, dict) and "command" in sub_hook:
                            hooks.append(
                                {
                                    "event": event,
                                    "command": sub_hook["command"],
                                    **extra,
                                }
                            )
                elif "command" in hook_entry:
                    hooks.append({"event": event, **hook_entry})
                else:
                    hooks.append({"event": event, **hook_entry})

    return ParsedHooks(
        file_path=settings_path,
        hooks=hooks,
        raw_content=raw_content,
    )


def parse_agent(agent_path: str) -> ParsedAgent:
    """Parse an agent .md file into a ParsedAgent."""
    path = Path(agent_path)

    if not path.exists() or not path.is_file():
        return ParsedAgent(
            dir_path=str(path.parent),
            file_name=path.name,
            agent_md_path=str(path),
            raw_content="",
            frontmatter={},
            raw_frontmatter="",
            frontmatter_start_line=0,
            body="",
            body_start_line=0,
            referenced_skills=[],
            disallowed_tools=[],
            allowed_tools=[],
            model=None,
            sibling_files={},
            files=[],
            parse_errors=[f"File not found: {path}"],
        )

    raw_content, fm, parse_errors = _read_and_parse(path)

    referenced_skills = fm.frontmatter.get("skills", []) or []
    if isinstance(referenced_skills, str):
        referenced_skills = [s.strip() for s in referenced_skills.split(",")]

    disallowed_raw = fm.frontmatter.get("disallowedTools", "") or ""
    if isinstance(disallowed_raw, list):
        disallowed_tools = [str(t).strip() for t in disallowed_raw if str(t).strip()]
    else:
        disallowed_tools = [t.strip() for t in disallowed_raw.split(",") if t.strip()]

    allowed_raw = fm.frontmatter.get("tools", "") or ""
    if isinstance(allowed_raw, list):
        allowed_tools = [str(t).strip() for t in allowed_raw if str(t).strip()]
    else:
        allowed_tools = [t.strip() for t in allowed_raw.split(",") if t.strip()]

    model = fm.frontmatter.get("model")

    agent_dir = path.parent
    scaffold_root = agent_dir.parent
    sibling_files: dict[str, list[str]] = {}
    for sibling_name in ("harness", "policies", "scripts", "schemas", "env"):
        sibling_dir = scaffold_root / sibling_name
        if sibling_dir.is_dir():
            sibling_files[sibling_name] = sorted(
                str(p.relative_to(scaffold_root)) for p in sibling_dir.rglob("*") if p.is_file()
            )

    return ParsedAgent(
        dir_path=str(agent_dir),
        file_name=path.name,
        agent_md_path=str(path),
        raw_content=raw_content,
        frontmatter=fm.frontmatter,
        raw_frontmatter=fm.raw_frontmatter,
        frontmatter_start_line=fm.frontmatter_start_line,
        body=fm.body,
        body_start_line=fm.body_start_line,
        referenced_skills=referenced_skills,
        disallowed_tools=disallowed_tools,
        allowed_tools=allowed_tools,
        model=model,
        sibling_files=sibling_files,
        files=list_files(agent_dir),
        parse_errors=parse_errors,
        tokens=count_tokens(raw_content),
    )
