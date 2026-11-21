"""Every path a discoverer can return must match the pre-commit hook pattern.

If this test fails, a discoverer was taught to read a new path that the
hook ``files`` regex in ``.pre-commit-hooks.yaml`` does not cover.  Update
the regex so commits touching that path trigger the hooks.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from harness_eval.core.discoverers.registry import get_all_discoverers

REPO_ROOT = Path(__file__).resolve().parent.parent
HOOKS_FILE = REPO_ROOT / ".pre-commit-hooks.yaml"


def _hook_pattern() -> re.Pattern[str]:
    """Load the ``files`` regex from the first hook definition."""
    hooks = yaml.safe_load(HOOKS_FILE.read_text())
    return re.compile(hooks[0]["files"])


def _create_fixture_tree(root: Path) -> None:
    """Seed *root* with minimal files every discoverer can discover.

    Each file is just enough for the discoverer to include it in
    ``collect_paths``: the right name in the right directory, with
    content that passes the discoverer's gate (e.g. frontmatter for
    agents, ``mcpServers`` key for MCP configs).
    """
    md = "# placeholder\n"
    agent_md = "---\nmodel: test\n---\n# Agent\n"
    mcp_json = json.dumps({"mcpServers": {"s": {"command": "echo"}}})
    skill_md = "---\nname: s\ndescription: d\n---\nDo something.\n"
    toml_mcp = '[mcp_servers.s]\nurl = "https://example.com"\n'

    def _w(rel: str, content: str = md) -> None:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)

    # Claude Code
    _w("CLAUDE.md")
    _w("skills/review/SKILL.md", skill_md)
    _w(".claude/skills/deploy/SKILL.md", skill_md)
    _w("commands/test.md")
    _w(".claude/commands/check.md")
    _w("commands/deploy/command.md")
    _w(".claude/settings.json", json.dumps({"hooks": {}}))
    _w("agents/code.md", agent_md)
    _w(".claude/agents/plan.md", agent_md)
    _w(".mcp.json", mcp_json)
    _w(".claude/rules/safety.md")
    _w(".claude/output-styles/plain.md")

    # Copilot
    _w(".github/copilot-instructions.md")
    _w(".github/instructions/python.instructions.md")
    _w(".github/skills/review/SKILL.md", skill_md)
    _w(".github/prompts/review.md")
    _w(".github/agents/code.md", agent_md)
    _w(".vscode/mcp.json", mcp_json)
    _w(".github/hooks/checks.json", json.dumps({"version": 1}))
    _w(".github/copilot/settings.json", "{}")

    # Cursor
    _w(".cursorrules")
    _w(".cursor/rules/test.mdc")
    _w(".cursor/commands/cmd.md")
    _w(".cursor/skills/review/SKILL.md", skill_md)
    _w(".cursor/hooks.json", json.dumps({"hooks": {}}))
    _w(".cursor/mcp.json", mcp_json)

    # Windsurf
    _w(".windsurfrules")
    _w(".windsurf/rules/python.md")
    _w(".devin/rules/safety.md")
    _w(".windsurf/skills/review/SKILL.md", skill_md)
    _w(".devin/skills/deploy/SKILL.md", skill_md)
    _w(".windsurf/workflows/deploy.md")
    _w(".devin/workflows/check.md")
    _w(".windsurf/hooks.json", json.dumps({"hooks": {}}))
    _w(".windsurf/mcp_config.json", mcp_json)
    _w("AGENTS.md")

    # Cline
    _w(".clinerules")
    _w(".cline/rules/security.md")
    _w(".cline/skills/secure/SKILL.md", skill_md)

    # Gemini
    _w("GEMINI.md")
    _w(".gemini/commands/cmd.md")
    _w(".gemini/settings.json", mcp_json)
    _w(".gemini/skills/review/SKILL.md", skill_md)

    # OpenCode
    _w(".opencode/commands/cmd.md")
    _w(".opencode/agents/code.md", agent_md)
    _w("opencode.json", json.dumps({"mcp": {}}))
    _w("opencode.jsonc", '{"mcp": {}}')
    _w(".opencode/skills/review/SKILL.md", skill_md)

    # Codex
    _w(".codex/config.toml", toml_mcp)
    _w(".codex/instructions.md")
    _w("codex.json", "{}")
    _w(".codex/skills/docs/SKILL.md", skill_md)

    # Portable .agents/ directory
    _w(".agents/skills/shared/SKILL.md", skill_md)

    # Fullsend harness
    _w("harness/code.yaml", "agent: run tests\n")

    # Third-party (.lola)
    _w(".lola/modules/review/skills/check/SKILL.md", skill_md)
    _w(".lola/modules/review/commands/run.md")
    _w(".lola/modules/review/agents/review.md", agent_md)


def test_hook_pattern_covers_all_discoverer_paths(tmp_path: Path) -> None:
    """Every path a discoverer can return must match the hook files regex."""
    _create_fixture_tree(tmp_path)
    pattern = _hook_pattern()

    uncovered: list[str] = []
    for disc in get_all_discoverers():
        paths = disc.collect_paths(tmp_path, recursive=False)
        for p in paths:
            try:
                rel = str(p.relative_to(tmp_path))
            except ValueError:
                # user_config_dir paths live outside the repo; hooks never see them
                continue
            if not pattern.search(rel):
                uncovered.append(f"  {disc.tool_name}: {rel}")

    assert not uncovered, (
        "Discoverer paths not matched by the hook files regex in "
        ".pre-commit-hooks.yaml:\n" + "\n".join(uncovered)
    )


def test_all_hooks_share_the_same_pattern() -> None:
    """Every hook in .pre-commit-hooks.yaml must use the same files pattern."""
    hooks = yaml.safe_load(HOOKS_FILE.read_text())
    patterns = [h["files"] for h in hooks]
    assert len(set(patterns)) == 1, (
        "Hook file patterns have diverged — all hooks must share one pattern:\n"
        + "\n".join(f"  {h['id']}: {h['files']!r}" for h in hooks)
    )
