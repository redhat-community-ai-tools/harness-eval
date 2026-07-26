"""Tests for Windsurf and Cline file discovery."""

from __future__ import annotations

from pathlib import Path

from harness_eval.core.setup import discover_setup
from harness_eval.core.types import ComponentType
from harness_eval.inspection.engine import inspect_setup

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestWindsurfDiscovery:
    def test_discover_windsurfrules(self) -> None:
        setup = discover_setup(name="windsurf", path=str(FIXTURES_DIR / "sample-windsurf-setup"))
        names = {c.name for c in setup.by_type(ComponentType.CLAUDE_MD)}
        assert ".windsurfrules" in names

    def test_discover_rules_dir(self) -> None:
        setup = discover_setup(name="windsurf", path=str(FIXTURES_DIR / "sample-windsurf-setup"))
        names = {c.name for c in setup.by_type(ComponentType.CLAUDE_MD)}
        assert "coding-standards" in names
        assert "security" in names

    def test_detect_windsurf(self) -> None:
        setup = discover_setup(name="windsurf", path=str(FIXTURES_DIR / "sample-windsurf-setup"))
        assert "Windsurf" in setup.detected_tools
        assert "Claude Code" not in setup.detected_tools

    def test_source_tool_attribution(self) -> None:
        setup = discover_setup(name="windsurf", path=str(FIXTURES_DIR / "sample-windsurf-setup"))
        windsurf = [c for c in setup.components if ".windsurf" in c.path]
        assert windsurf
        for comp in windsurf:
            assert comp.source_tool == "windsurf"

    def test_content_and_frontmatter_parsed(self) -> None:
        setup = discover_setup(name="windsurf", path=str(FIXTURES_DIR / "sample-windsurf-setup"))
        claude_md = setup.by_type(ComponentType.CLAUDE_MD)
        rules = next(c for c in claude_md if c.name == ".windsurfrules")
        assert rules.frontmatter is not None
        assert rules.frontmatter.get("name") == "project-rules"
        coding = next(c for c in claude_md if c.name == "coding-standards")
        assert "PEP 8" in coding.content
        assert coding.token_count > 0

    def test_no_detection_when_absent(self, tmp_path: Path) -> None:
        setup = discover_setup(name="empty", path=str(tmp_path))
        assert "Windsurf" not in setup.detected_tools

    def test_inspect_runs(self) -> None:
        setup = discover_setup(name="windsurf", path=str(FIXTURES_DIR / "sample-windsurf-setup"))
        results = inspect_setup(setup)
        assert len(results) > 0
        assert "claude_md" in {r.target_type for r in results}


class TestClineDirectoryForm:
    def test_discover_rules_dir(self) -> None:
        setup = discover_setup(name="cline", path=str(FIXTURES_DIR / "sample-cline-setup"))
        names = {c.name for c in setup.by_type(ComponentType.CLAUDE_MD)}
        assert "coding" in names
        assert "security" in names

    def test_detect_cline(self) -> None:
        setup = discover_setup(name="cline", path=str(FIXTURES_DIR / "sample-cline-setup"))
        assert "Cline" in setup.detected_tools

    def test_source_tool_attribution(self) -> None:
        setup = discover_setup(name="cline", path=str(FIXTURES_DIR / "sample-cline-setup"))
        cline = [c for c in setup.components if ".clinerules" in c.path]
        assert cline
        for comp in cline:
            assert comp.source_tool == "cline"


class TestClineSingleFileForm:
    def test_discover_single_file(self, tmp_path: Path) -> None:
        (tmp_path / ".clinerules").write_text(
            "# Rules\n\nUse PEP 8. Never hardcode credentials.\n", encoding="utf-8"
        )
        setup = discover_setup(name="cline-file", path=str(tmp_path))
        claude_md = setup.by_type(ComponentType.CLAUDE_MD)
        names = {c.name for c in claude_md}
        assert ".clinerules" in names
        assert "Cline" in setup.detected_tools
        assert all(c.source_tool == "cline" for c in claude_md)


class TestDeduplication:
    def test_no_duplicate_components(self) -> None:
        for fixture in ("sample-windsurf-setup", "sample-cline-setup"):
            setup = discover_setup(name=fixture, path=str(FIXTURES_DIR / fixture))
            resolved = [str(Path(c.path).resolve()) for c in setup.components]
            assert len(resolved) == len(set(resolved))
