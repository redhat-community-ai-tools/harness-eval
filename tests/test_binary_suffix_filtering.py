"""Tests for binary suffix filtering in uncategorized component discovery."""

from __future__ import annotations

from pathlib import Path

from harness_eval.core.setup import discover_setup
from harness_eval.core.types import ComponentType


class TestBinarySuffixFiltering:
    """Verify that _BINARY_SUFFIXES correctly skips binary files but not text formats."""

    def test_svg_is_discovered_not_skipped(self, tmp_path: Path) -> None:
        """SVG is XML-based text and should be discovered, not skipped as binary."""
        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir()
        svg_file = cursor_dir / "icon.svg"
        svg_file.write_text('<svg xmlns="http://www.w3.org/2000/svg"><text>test</text></svg>')

        setup = discover_setup(name="test", path=str(tmp_path))
        uncategorized = setup.by_type(ComponentType.UNCATEGORIZED)
        paths = {c.path for c in uncategorized}
        assert str(svg_file) in paths

    def test_png_is_skipped_as_binary(self, tmp_path: Path) -> None:
        """Genuinely binary formats like PNG should be skipped."""
        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir()
        png_file = cursor_dir / "icon.png"
        png_file.write_bytes(b"\x89PNG\r\n\x1a\n")

        setup = discover_setup(name="test", path=str(tmp_path))
        uncategorized = setup.by_type(ComponentType.UNCATEGORIZED)
        paths = {c.path for c in uncategorized}
        assert str(png_file) not in paths
