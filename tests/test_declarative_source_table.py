"""Tests for declarative source-table discoverers (#158).

For each migrated discoverer (codex, windsurf, cursor), verify that the set
of files behind ``discover()`` equals ``collect_paths()`` on their sample
fixtures.  This is the structural guarantee the declarative table provides:
both methods are derived from the same entries, so they cannot drift.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from harness_eval.core.discoverers.codex import CodexDiscoverer
from harness_eval.core.discoverers.cursor import CursorDiscoverer
from harness_eval.core.discoverers.windsurf import WindsurfDiscoverer

# ---------------------------------------------------------------------------
# Fixtures: minimal trees exercising every entry in each discoverer's table
# ---------------------------------------------------------------------------

_CURSOR_FILES = [
    ".cursor/rules/coding-standards.mdc",
    ".cursorrules",
    "AGENTS.md",
    ".cursor/commands/deploy.md",
    ".cursor/skills/code-review/SKILL.md",
    ".cursor/hooks.json",
    ".cursor/mcp.json",
]

_WINDSURF_FILES = [
    ".windsurf/rules/coding-standards.md",
    ".devin/rules/security.md",
    ".windsurfrules",
    ".windsurf/skills/review/SKILL.md",
    ".devin/skills/deploy/SKILL.md",
    ".agents/skills/shared/SKILL.md",
    ".windsurf/workflows/build.md",
    ".devin/workflows/test.md",
    ".windsurf/hooks.json",
    ".windsurf/mcp_config.json",
    "AGENTS.md",
]

_CODEX_FILES = [
    "AGENTS.md",
    ".codex/instructions.md",
    ".agents/skills/docs/SKILL.md",
    ".codex/skills/lint/SKILL.md",
    "codex.json",
    ".codex/setup.sh",
    ".codex/config.toml",
]

_CONTENT: dict[str, str] = {
    ".md": "# test\n",
    ".mdc": "---\ntitle: test\n---\nTest\n",
    ".json": "{}\n",
    ".toml": '[mcp_servers.docs]\nurl = "https://example.com/mcp"\n',
    ".sh": "#!/bin/sh\n",
}


def _build_tree(root: Path, files: list[str]) -> None:
    for rel in files:
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        suffix = Path(rel).suffix
        path.write_text(_CONTENT.get(suffix, "content\n"))


def _resolved(paths: list[Path]) -> set[str]:
    return {str(p.resolve()) for p in paths}


def _component_paths(components: list) -> set[str]:
    return {str(Path(c.path).resolve()) for c in components}


# ---------------------------------------------------------------------------
# Tests: discover() paths == collect_paths()
# ---------------------------------------------------------------------------


class TestDiscoverEqualsCollectPaths:
    """For migrated discoverers, discover() and collect_paths() read the same
    files.  This is the structural invariant the declarative table enforces."""

    @pytest.mark.parametrize("recursive", [False, True])
    def test_cursor(self, tmp_path: Path, recursive: bool) -> None:
        _build_tree(tmp_path, _CURSOR_FILES)
        disc = CursorDiscoverer()
        collected = _resolved(disc.collect_paths(tmp_path, recursive=recursive))
        discovered = _component_paths(disc.discover(tmp_path, recursive=recursive))
        assert discovered == collected, (
            f"cursor (recursive={recursive}):\n"
            f"  in discover only: {discovered - collected}\n"
            f"  in collect only:  {collected - discovered}"
        )

    @pytest.mark.parametrize("recursive", [False, True])
    def test_windsurf(self, tmp_path: Path, recursive: bool) -> None:
        _build_tree(tmp_path, _WINDSURF_FILES)
        disc = WindsurfDiscoverer()
        collected = _resolved(disc.collect_paths(tmp_path, recursive=recursive))
        discovered = _component_paths(disc.discover(tmp_path, recursive=recursive))
        assert discovered == collected, (
            f"windsurf (recursive={recursive}):\n"
            f"  in discover only: {discovered - collected}\n"
            f"  in collect only:  {collected - discovered}"
        )

    @pytest.mark.parametrize("recursive", [False, True])
    def test_codex(self, tmp_path: Path, recursive: bool) -> None:
        _build_tree(tmp_path, _CODEX_FILES)
        disc = CodexDiscoverer()
        collected = _resolved(disc.collect_paths(tmp_path, recursive=recursive))
        discovered = _component_paths(disc.discover(tmp_path, recursive=recursive))
        assert discovered == collected, (
            f"codex (recursive={recursive}):\n"
            f"  in discover only: {discovered - collected}\n"
            f"  in collect only:  {collected - discovered}"
        )

    def test_codex_with_user_config_dir(self, tmp_path: Path) -> None:
        """user_config_dir paths are covered by both methods."""
        _build_tree(tmp_path, _CODEX_FILES)
        user = tmp_path / "user"
        (user / "config.toml").parent.mkdir(parents=True)
        (user / "config.toml").write_text('[mcp_servers.test]\nurl = "https://example.com"\n')
        disc = CodexDiscoverer()
        collected = _resolved(disc.collect_paths(tmp_path, user))
        discovered = _component_paths(disc.discover(tmp_path, user))
        assert discovered == collected
