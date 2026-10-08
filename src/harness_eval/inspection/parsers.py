"""Component parsers for inspection. Each function parses a specific component type."""

from __future__ import annotations

import json as json_mod
import re
import tomllib
from pathlib import Path
from typing import Any

from harness_eval.inspection.types import (
    ParsedAgent,
    ParsedClaudeMd,
    ParsedCommand,
    ParsedConfig,
    ParsedHarness,
    ParsedHooks,
    ParsedMcpConfig,
    ParsedSkill,
)
from harness_eval.utils.parsing import parse_frontmatter_rich
from harness_eval.utils.tokens import count_tokens


def list_files(
    directory: Path,
    *,
    excludes: tuple[str, ...] = (),
    project_root: Path | str | None = None,
) -> list[str]:
    from harness_eval.inspection._fswalk import iter_files

    if not directory.is_dir():
        return []
    return sorted(
        str(p.relative_to(directory))
        for p in iter_files(directory, excludes=excludes, project_root=project_root)
        if p.is_file()
    )


def _read_and_parse(path: Path) -> tuple[str, object, list[str]]:
    """Read a file and parse its frontmatter. Returns (raw_content, frontmatter_result, errors)."""
    raw_content = path.read_text(encoding="utf-8", errors="replace")
    fm = parse_frontmatter_rich(raw_content)
    return raw_content, fm, fm.errors


def _not_found(path: Path, expected: str) -> tuple[str, None, list[str]]:
    """Return a parse failure for a missing file."""
    return "", None, [f"{expected} not found" if expected else f"Path does not exist: {path}"]


_MAX_SUB_FILES = 50
_MAX_SUB_FILE_BYTES = 100_000


def _read_md_sub_files(
    skill_dir: Path,
    skill_md: Path,
    *,
    excludes: tuple[str, ...] = (),
    project_root: Path | str | None = None,
) -> dict[str, str]:
    """Read .md files in *skill_dir* except the primary SKILL.md."""
    from harness_eval.inspection._fswalk import iter_files

    result: dict[str, str] = {}
    skill_md_resolved = skill_md.resolve()
    for p in iter_files(skill_dir, "*.md", excludes=excludes, project_root=project_root):
        if p.resolve() == skill_md_resolved:
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


_SUPPORTED_COMMAND_EXTS = {".md", ".toml"}


def _resolve_command_path(command_path: str) -> tuple[Path, Path | None, list[str]]:
    """Resolve a command path to (cmd_dir, cmd_md, errors)."""
    path = Path(command_path)
    if path.is_file() and path.suffix in _SUPPORTED_COMMAND_EXTS:
        return path.parent, path, []
    if path.is_dir():
        cmd_md = path / "command.md"
        if cmd_md.exists():
            return path, cmd_md, []
        return path, None, ["command.md not found"]
    return path, None, [f"Path does not exist: {path}"]


def parse_skill(
    skill_path: str,
    *,
    excludes: tuple[str, ...] = (),
    project_root: Path | str | None = None,
) -> ParsedSkill:
    """Parse a skill directory or SKILL.md file into a ParsedSkill.

    *excludes* and *project_root* scope the sub-file walk to what the scan
    may read; a bare call (single-file lint) reads the whole directory."""
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
            files=list_files(skill_dir, excludes=excludes, project_root=project_root),
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
        files=list_files(skill_dir, excludes=excludes, project_root=project_root),
        sub_file_contents=_read_md_sub_files(
            skill_dir, skill_md, excludes=excludes, project_root=project_root
        ),
        parse_errors=parse_errors,
        tokens=count_tokens(raw_content),
    )


_SCRIPT_FILE_RE = re.compile(r"[\w./-]+\.(?:py|sh|bash|js)\b")
_SCRIPTS_DIR_RE = re.compile(r"\./scripts/[\w./-]+")


def _is_remote_script_ref(ref: str) -> bool:
    """True if *ref* looks like a URL path, not a local script."""
    if "://" in ref or ref.startswith("//"):
        return True
    head, sep, _ = ref.lstrip("./").partition("/")
    return bool(sep) and "." in head


def _extract_script_refs_outside_code_blocks(body: str) -> list[str]:
    """Extract script path references from lines outside fenced code blocks."""
    refs: list[str] = []
    in_fence = False
    for line in body.split("\n"):
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            for ref in _SCRIPT_FILE_RE.findall(line):
                if not _is_remote_script_ref(ref):
                    refs.append(ref)
            refs.extend(_SCRIPTS_DIR_RE.findall(line))
    return refs


def parse_command(command_path: str) -> ParsedCommand:
    """Parse a command directory or command.md file."""
    cmd_dir, cmd_md, errors = _resolve_command_path(command_path)

    is_single_file = cmd_md is not None and cmd_md.name.lower() != "command.md"
    resolved_name = cmd_md.stem if is_single_file else cmd_dir.name

    if cmd_md is None:
        return ParsedCommand(
            dir_path=str(cmd_dir),
            dir_name=resolved_name,
            command_md_path=str(cmd_dir / "command.md"),
            raw_content="",
            frontmatter={},
            body="",
            body_start_line=0,
            script_references=[],
            files=list_files(cmd_dir),
            parse_errors=errors,
        )

    if cmd_md.suffix == ".toml":
        return _parse_toml_command(cmd_md, cmd_dir, resolved_name, errors)

    raw_content, fm, parse_errors = _read_and_parse(cmd_md)
    script_refs = _extract_script_refs_outside_code_blocks(fm.body)

    return ParsedCommand(
        dir_path=str(cmd_dir),
        dir_name=resolved_name,
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


def _parse_toml_command(
    path: Path, cmd_dir: Path, resolved_name: str, errors: list[str]
) -> ParsedCommand:
    """Parse a Gemini/Codex-style TOML command (description + prompt/template)."""
    raw_content = path.read_text(encoding="utf-8", errors="replace")
    parse_errors = list(errors)
    fields: dict = {}
    try:
        data = tomllib.loads(raw_content)
    except tomllib.TOMLDecodeError as e:
        parse_errors.append(str(e))
        data = {}
    if isinstance(data, dict):
        fields = dict(data)
        nested = data.get("command")
        if isinstance(nested, dict):
            fields.update(nested)
    desc = fields.get("description")
    frontmatter = {"description": desc} if isinstance(desc, str) else {}
    body = ""
    for key in ("prompt", "template"):
        val = fields.get(key)
        if isinstance(val, str) and val.strip():
            body = val
            break
    return ParsedCommand(
        dir_path=str(cmd_dir),
        dir_name=resolved_name,
        command_md_path=str(path),
        raw_content=raw_content,
        frontmatter=frontmatter,
        body=body,
        body_start_line=0,
        script_references=_extract_script_refs_outside_code_blocks(body),
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

    raw_content = path.read_text(encoding="utf-8", errors="replace")
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
    """Parse hooks from supported assistants into a common event/command view."""
    path = Path(settings_path)
    if not path.exists():
        return ParsedHooks(
            file_path=settings_path,
            hooks=[],
            raw_content="",
            parse_errors=[f"File not found: {settings_path}"],
        )

    raw_content = path.read_text(encoding="utf-8", errors="replace")
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
                        elif isinstance(sub_hook, dict):
                            hooks.append(
                                {"event": event, **extra, **_normalise_hook_entry(sub_hook)}
                            )
                else:
                    hooks.append({"event": event, **_normalise_hook_entry(hook_entry)})

    return ParsedHooks(
        file_path=settings_path,
        hooks=hooks,
        raw_content=raw_content,
    )


def _normalise_hook_entry(entry: dict) -> dict:
    """Keep source fields and expose a shell/exec handler as ``command``."""
    normalised = dict(entry)
    if isinstance(normalised.get("command"), str):
        return normalised
    for key in ("bash", "powershell"):
        value = normalised.get(key)
        if isinstance(value, str) and value.strip():
            normalised["command"] = value
            return normalised
    executable = normalised.get("exec")
    args = normalised.get("args", [])
    if isinstance(executable, str):
        argv = [executable]
        if isinstance(args, list):
            argv.extend(str(arg) for arg in args)
        normalised["command"] = " ".join(argv)
    elif isinstance(executable, list):
        normalised["command"] = " ".join(str(arg) for arg in executable)
    return normalised


def _tool_list(raw: object) -> list[str]:
    """Normalise a frontmatter tool declaration: a comma-separated string, a
    YAML list, a map (keys), a bare scalar, or nothing."""
    if raw is None or raw is False:
        return []
    if isinstance(raw, dict):
        return [str(k).strip() for k in raw if str(k).strip()]
    if isinstance(raw, (list, tuple)):
        return [str(t).strip() for t in raw if str(t).strip()]
    return [t.strip() for t in str(raw).split(",") if t.strip()]


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

    disallowed_tools = _tool_list(fm.frontmatter.get("disallowedTools"))
    allowed_raw = fm.frontmatter.get("tools")
    if isinstance(allowed_raw, dict):
        # OpenCode-style map: ``tools: {write: true, bash: false}``. Keys set
        # to a truthy value are allowed; keys set to false are disallowed.
        allowed_tools = [str(k).strip() for k, v in allowed_raw.items() if v and str(k).strip()]
        disallowed_tools += [
            str(k).strip() for k, v in allowed_raw.items() if not v and str(k).strip()
        ]
    else:
        allowed_tools = _tool_list(allowed_raw)

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


def parse_mcp_config_file(file_path: str) -> ParsedMcpConfig:
    """Read an MCP config file into a ParsedMcpConfig. Does not validate JSON."""
    path = Path(file_path)
    if not path.exists():
        return ParsedMcpConfig(
            file_path=file_path,
            raw_content="",
            parse_errors=[f"File not found: {file_path}"],
        )
    raw_content = path.read_text(encoding="utf-8", errors="replace")
    return ParsedMcpConfig(
        file_path=file_path,
        raw_content=raw_content,
        tokens=count_tokens(raw_content),
    )


def parse_config_file(file_path: str) -> ParsedConfig:
    """Read a general assistant configuration without imposing one schema."""
    path = Path(file_path)
    if not path.exists():
        return ParsedConfig(
            file_path=file_path,
            raw_content="",
            parse_errors=[f"File not found: {file_path}"],
        )
    raw_content = path.read_text(encoding="utf-8", errors="replace")
    return ParsedConfig(
        file_path=file_path,
        raw_content=raw_content,
        tokens=count_tokens(raw_content),
    )


def parse_harness(file_path: str, source_tool: str | None = None) -> ParsedHarness:
    """Parse a pipeline agent harness definition into a ParsedHarness.

    The YAML is loaded once; the format mapper for *source_tool* turns the
    mapping into the normalized ``HarnessFields`` that rules consume.
    """
    import yaml

    from harness_eval.inspection.harness_formats import mapper_for

    path = Path(file_path)
    name = path.stem
    if not path.exists() or not path.is_file():
        return ParsedHarness(
            file_path=str(path),
            name=name,
            raw_content="",
            data={},
            source_tool=source_tool,
            fields=None,
            parse_errors=[f"File not found: {path}"],
        )

    raw_content = path.read_text(encoding="utf-8", errors="replace")
    parse_errors: list[str] = []
    data: dict[str, Any] = {}
    try:
        loaded = yaml.safe_load(raw_content)
    except yaml.YAMLError as exc:
        parse_errors.append(f"Invalid YAML: {exc}")
        loaded = None
    if isinstance(loaded, dict):
        data = loaded
    elif loaded is not None:
        parse_errors.append("Harness file is not a YAML mapping")

    fields = None
    mapper = mapper_for(source_tool)
    if data and mapper is not None:
        fields = mapper(data, path)

    return ParsedHarness(
        file_path=str(path),
        name=name,
        raw_content=raw_content,
        data=data,
        source_tool=source_tool,
        fields=fields,
        parse_errors=parse_errors,
        tokens=count_tokens(raw_content),
    )
