"""Names of skills, commands, and agents present anywhere in the project.

Discovery is conservative on purpose (it decides what gets linted), but a
rule that asks "does the referenced skill exist?" must answer against every
`SKILL.md` in the tree, including layouts discovery does not lint (root-level
skill directories, plugin bundles). The index is built once per scan and kept
in ``scan_state``.
"""

from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path

from harness_eval.inspection.types import RuleContext

_SKIP_PARTS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
_AGENT_DIRS = ("agents", "subagents")
_COMMAND_DIRS = ("commands", "command", "prompts")

# Claude Code built-in slash commands; `/clear` in a command body is not a
# reference to a project skill.
BUILTIN_SLASH = frozenset(
    {
        "help",
        "clear",
        "compact",
        "init",
        "review",
        "model",
        "config",
        "cost",
        "doctor",
        "login",
        "logout",
        "memory",
        "permissions",
        "pr_comments",
        "pr-comments",
        "status",
        "terminal-setup",
        "vim",
        "bug",
        "release-notes",
        "mcp",
        "agents",
        "hooks",
        "plan",
        "resume",
        "add-dir",
        "ide",
        "export",
        "exit",
        "quit",
        "rewind",
        "context",
        "todos",
        "usage",
        "output-style",
        "statusline",
        "plugin",
        "plugins",
        "skills",
        "effort",
        "fast",
        "loop",
        "security-review",
        "simplify",
        "continue",
        "commit",
    }
)


def _root(context: RuleContext) -> Path | None:
    root = context.scan_state.get("project_root")
    return Path(root) if root else None


def _frontmatter_name(skill_md: Path) -> str | None:
    """The ``name:`` field of a SKILL.md, read cheaply from its head."""
    try:
        with skill_md.open(encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
    except OSError:
        return None
    if not head.lstrip("\ufeff").startswith("---"):
        return None
    for line in head.lstrip("\ufeff").splitlines()[1:]:
        if line.strip() == "---":
            break
        m = re.match(r"name\s*:\s*[\"']?([^\"'#]+?)[\"']?\s*$", line)
        if m:
            return m.group(1).strip()
    return None


def component_index(context: RuleContext) -> dict[str, set[str]]:
    """{"skills", "commands", "agents", "plugins"}: names present in the tree."""
    cached: dict[str, set[str]] | None = context.scan_state.get("component_index")
    if cached is not None:
        return cached
    idx: dict[str, set[str]] = {
        "skills": set(),
        "skill_paths": set(),  # skill directories relative to the root, for glob references
        "commands": set(),
        "agents": set(),
        "plugins": set(),
    }
    idx["skills"] |= {s.dir_name for s in context.all_skills}
    root0 = _root(context)
    if root0 is not None and (root0 / ".gitmodules").is_file():
        try:
            gm = (root0 / ".gitmodules").read_text(encoding="utf-8", errors="replace")
        except OSError:
            gm = ""
        if re.search(r"^\s*path\s*=\s*.*skills\s*$", gm, re.M):
            idx["skills_in_submodule"] = {"yes"}
    # A skill is referenced by its frontmatter name, which need not equal the
    # directory (Claude Code defaults the name to the directory only when the
    # field is absent).
    idx["skills"] |= {
        s.frontmatter["name"].strip()
        for s in context.all_skills
        if isinstance(s.frontmatter.get("name"), str) and s.frontmatter["name"].strip()
    }
    idx["commands"] |= {c.dir_name for c in context.all_commands}
    root = _root(context)
    if root is not None and root.is_dir():
        for p in root.rglob("*"):
            if any(part in _SKIP_PARTS for part in p.parts):
                continue
            if p.name == "SKILL.md":
                idx["skills"].add(p.parent.name)
                declared = _frontmatter_name(p)
                if declared:
                    idx["skills"].add(declared)
                rel = p.parent.relative_to(root).as_posix()
                idx["skill_paths"].add(rel)
                # also the path below any `skills/` segment, which is how references are written
                parts = rel.split("/")
                if "skills" in parts:
                    idx["skill_paths"].add("/".join(parts[parts.index("skills") + 1 :]))
            elif p.suffix in (".md", ".toml") and p.is_file():
                parent = p.parent.name
                if parent in _COMMAND_DIRS or any(part in _COMMAND_DIRS for part in p.parts[:-1]):
                    idx["commands"].add(p.stem)
                if parent in _AGENT_DIRS:
                    idx["agents"].add(p.stem.removesuffix(".agent"))
            elif p.name == "plugin.json" and p.parent.name == ".claude-plugin":
                try:
                    name = json.loads(p.read_text(encoding="utf-8", errors="replace")).get("name")
                    if isinstance(name, str):
                        idx["plugins"].add(name)
                except (OSError, ValueError):
                    pass
            elif p.name == "marketplace.json" and p.parent.name == ".claude-plugin":
                try:
                    data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
                    for entry in data.get("plugins", []) or []:
                        if isinstance(entry, dict) and isinstance(entry.get("name"), str):
                            idx["plugins"].add(entry["name"])
                except (OSError, ValueError, AttributeError):
                    pass
    context.scan_state["component_index"] = idx
    return idx


def resolve_skill_reference(name: str, idx: dict[str, set[str]]) -> str | None:
    """Return "missing" when a skill reference cannot be satisfied by this
    repository, or None when it can or when it points outside it.

    `plugin:skill` references name a skill of an installed plugin. When the
    plugin is this repository, the bare skill must exist here; when it is
    another plugin, the repository cannot be expected to carry it.
    """
    bare = name
    if ":" in name:
        plugin, bare = name.split(":", 1)
        if plugin not in idx["plugins"]:
            return None
    if bare in idx["skills"] or bare.rstrip("/").split("/")[-1] in idx["skills"]:
        return None
    if re.fullmatch(r"\d+", bare):
        return None
    if any(ch in bare for ch in "*?["):
        # A glob such as ``business-growth/*`` is satisfied by any skill whose
        # path matches it (or whose name matches, for a glob without a slash);
        # only a glob that matches nothing dangles.
        pat = bare.rstrip("/")
        if "/" in pat:
            if any(fnmatch.fnmatch(pth, pat) for pth in idx.get("skill_paths", ())):
                return None
        elif any(fnmatch.fnmatch(sk, pat) for sk in idx["skills"]):
            return None
    return "missing"
