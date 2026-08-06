"""Tests for the shared ContextTracker utility."""

from __future__ import annotations

from harness_eval.inspection.rules._context import ContextTracker


class TestIsFenced:
    def test_outside_fence(self) -> None:
        tracker = ContextTracker()
        tracker.update("normal line")
        assert not tracker.is_fenced()

    def test_inside_fence(self) -> None:
        tracker = ContextTracker()
        tracker.update("```python")
        assert tracker.is_fenced()

    def test_exits_fence(self) -> None:
        tracker = ContextTracker()
        tracker.update("```")
        assert tracker.is_fenced()
        tracker.update("some code")
        assert tracker.is_fenced()
        tracker.update("```")
        assert not tracker.is_fenced()

    def test_multiple_fences(self) -> None:
        tracker = ContextTracker()
        tracker.update("```")
        tracker.update("```")
        assert not tracker.is_fenced()
        tracker.update("```bash")
        assert tracker.is_fenced()

    def test_indented_fence(self) -> None:
        tracker = ContextTracker()
        tracker.update("  ```")
        assert tracker.is_fenced()
