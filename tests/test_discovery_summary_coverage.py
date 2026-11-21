"""Test that discovery_summary patterns match what collect_paths() returns.

Each discoverer declares a ``discovery_summary`` property listing the path
patterns it checks.  This test builds a fixture tree containing one file for
every location each discoverer reads, calls ``collect_paths()``, and asserts:

1. Every returned path is covered by a pattern in ``discovery_summary``.
2. Every pattern in ``discovery_summary`` matches at least one returned path.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

import pytest

from harness_eval.core.discoverers.base import ToolDiscoverer
from harness_eval.core.discoverers.registry import DISCOVERERS

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_patterns(summary: str) -> list[str]:
    """Extract backtick-quoted path patterns from a discovery_summary string."""
    return re.findall(r"`([^`]+)`", summary)


def _path_matches_pattern(rel_path: str, pattern: str) -> bool:
    """Check if a relative path is covered by a discovery_summary pattern.

    Rules:
    - Pattern ending with ``/``: directory prefix match.
    - Pattern containing ``*`` or ``?``: fnmatch glob.
    - Pattern containing ``/`` (no glob, no trailing slash): exact path match.
    - Pattern without ``/``: basename match, exact match, or directory prefix.
    """
    if pattern.endswith("/"):
        return rel_path.startswith(pattern)
    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatch(rel_path, pattern)
    if "/" in pattern:
        return rel_path == pattern
    # Simple name (no slash): file match, basename match, or directory prefix.
    return (
        rel_path == pattern or Path(rel_path).name == pattern or rel_path.startswith(pattern + "/")
    )


# ---------------------------------------------------------------------------
# Minimal file contents by extension
# ---------------------------------------------------------------------------

_CONTENT: dict[str, str] = {
    ".md": "# test\n",
    ".mdc": "---\ntitle: test\n---\nTest\n",
    ".json": "{}\n",
    ".jsonc": "{}\n",
    ".yaml": "agent: test\n",
    ".yml": "agent: test\n",
    ".toml": '[test]\nkey = "val"\n',
    ".sh": "#!/bin/sh\n",
}

# ---------------------------------------------------------------------------
# Fixture files per source_tool.
#
# Each entry is a relative path to create under the discoverer's root.
# The test builds the tree, calls collect_paths(), and checks bidirectional
# coverage against the patterns extracted from discovery_summary.
# ---------------------------------------------------------------------------

_FIXTURES: dict[str, list[str]] = {
    "claude": [
        "CLAUDE.md",
        "skills/my-skill/SKILL.md",
        ".claude/skills/cs/SKILL.md",
        "commands/cmd.md",
        ".claude/commands/cc.md",
        ".claude/settings.json",
        ".claude/agents/agent.md",
        "agents/agent.md",
        ".mcp.json",
        ".claude/rules/rule.md",
        ".claude/output-styles/style.md",
    ],
    "cursor": [
        ".cursor/rules/rule.mdc",
        "AGENTS.md",
        ".cursorrules",
        ".cursor/commands/cmd.md",
        ".cursor/skills/skill/SKILL.md",
        ".cursor/hooks.json",
        ".cursor/mcp.json",
    ],
    "windsurf": [
        ".windsurf/rules/rule.md",
        ".devin/rules/rule.md",
        ".windsurfrules",
        ".windsurf/skills/skill/SKILL.md",
        ".devin/skills/skill/SKILL.md",
        ".agents/skills/skill/SKILL.md",
        ".windsurf/workflows/wf.md",
        ".devin/workflows/wf.md",
        ".windsurf/hooks.json",
        ".windsurf/mcp_config.json",
        "AGENTS.md",
    ],
    "cline": [
        # .clinerules as a directory with .md files
        ".clinerules/rule.md",
        ".cline/rules/rule.md",
        ".cline/skills/skill/SKILL.md",
        ".clinerules/skills/skill/SKILL.md",
        ".claude/skills/skill/SKILL.md",
        "AGENTS.md",
    ],
    "copilot": [
        ".github/copilot-instructions.md",
        ".github/instructions/py.instructions.md",
        ".github/skills/skill/SKILL.md",
        ".agents/skills/skill/SKILL.md",
        ".claude/skills/skill/SKILL.md",
        ".github/prompts/prompt.md",
        ".github/agents/agent.md",
        ".vscode/mcp.json",
        ".github/hooks/hook.json",
        ".github/copilot/settings.json",
        ".github/copilot/settings.local.json",
    ],
    "gemini": [
        "GEMINI.md",
        ".gemini/commands/cmd.md",
        ".gemini/commands/cmd.toml",
        ".gemini/settings.json",
        ".gemini/skills/skill/SKILL.md",
        ".agents/skills/skill/SKILL.md",
    ],
    "opencode": [
        "AGENTS.md",
        ".opencode/commands/cmd.md",
        ".opencode/agents/agent.md",
        "opencode.json",
        "opencode.jsonc",
        ".opencode/skills/skill/SKILL.md",
        ".agents/skills/skill/SKILL.md",
        ".claude/skills/skill/SKILL.md",
    ],
    "codex": [
        "AGENTS.md",
        ".codex/instructions.md",
        ".codex/setup.sh",
        ".codex/config.toml",
        ".codex/skills/skill/SKILL.md",
        ".agents/skills/skill/SKILL.md",
        "codex.json",
    ],
    "fullsend": [
        "harness/review.yaml",
    ],
    "third-party": [
        ".lola/modules/pkg/skills/lint-check/SKILL.md",
        ".lola/modules/pkg/commands/cmd.md",
        ".lola/modules/pkg/agents/agent.md",
    ],
}


def _build_fixture_tree(root: Path, source_tool: str) -> None:
    """Create all fixture files for a given discoverer."""
    for rel_path in _FIXTURES[source_tool]:
        path = root / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        suffix = Path(rel_path).suffix
        content = _CONTENT.get(suffix, "content\n")
        path.write_text(content)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestDiscoverySummaryCoverage:
    """Every collect_paths() result must be covered by discovery_summary,
    and every summary pattern must match at least one collected path."""

    @pytest.mark.parametrize(
        "disc",
        DISCOVERERS,
        ids=[d.source_tool for d in DISCOVERERS],
    )
    def test_summary_covers_collected_paths(self, disc: ToolDiscoverer, tmp_path: Path) -> None:
        if not disc.discovery_summary:
            pytest.skip(f"{disc.tool_name} has no discovery_summary")

        source = disc.source_tool
        if source not in _FIXTURES:
            pytest.skip(f"No fixture defined for {source}")

        root = tmp_path / source
        root.mkdir()
        _build_fixture_tree(root, source)

        collected = disc.collect_paths(root)
        patterns = _extract_patterns(disc.discovery_summary)

        assert patterns, f"{disc.tool_name}.discovery_summary has no backtick-quoted patterns"
        assert collected, f"{disc.tool_name}.collect_paths() returned no paths from fixture tree"

        # Direction 1: every collected path must be covered by some pattern
        uncovered = []
        for path in collected:
            rel = str(path.relative_to(root))
            if not any(_path_matches_pattern(rel, p) for p in patterns):
                uncovered.append(rel)
        # fmt: off
        assert not uncovered, (
            f"{disc.tool_name}: collect_paths() returned paths not covered "
            f"by discovery_summary:\n  {uncovered}\n"
            f"Summary patterns: {patterns}"
        )
        # fmt: on

        # Direction 2: every summary pattern must match at least one path
        rel_paths = [str(p.relative_to(root)) for p in collected]
        unmatched = []
        for pattern in patterns:
            if not any(_path_matches_pattern(r, pattern) for r in rel_paths):
                unmatched.append(pattern)
        # fmt: off
        assert not unmatched, (
            f"{disc.tool_name}: discovery_summary patterns with no matching "
            f"collected path:\n  {unmatched}\n"
            f"Collected paths: {rel_paths}"
        )
        # fmt: on


class TestDiscoverySummaryDefault:
    """The base class provides a non-abstract default for discovery_summary."""

    def test_third_party_subclass_without_discovery_summary(self) -> None:
        """A ToolDiscoverer subclass that omits discovery_summary must
        still instantiate (backward compat for third-party subclasses)."""

        class MinimalDiscoverer(ToolDiscoverer):
            @property
            def tool_name(self) -> str:
                return "Minimal"

            @property
            def source_tool(self) -> str:
                return "minimal"

            def detect(self, root: Path) -> bool:
                return False

            def discover(
                self,
                root: Path,
                user_config_dir: Path | None = None,
                *,
                recursive: bool = False,
            ) -> list:
                return []

            def collect_paths(
                self,
                root: Path,
                user_config_dir: Path | None = None,
                *,
                recursive: bool = False,
            ) -> list:
                return []

        disc = MinimalDiscoverer()
        assert disc.discovery_summary == ""

    def test_discovery_summary_is_not_abstract(self) -> None:
        """discovery_summary must not be marked @abstractmethod."""
        fget = ToolDiscoverer.discovery_summary.fget  # type: ignore[attr-defined]
        assert not getattr(fget, "__isabstractmethod__", False)
