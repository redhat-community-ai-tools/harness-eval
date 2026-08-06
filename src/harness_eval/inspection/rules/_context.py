"""Shared context-aware line tracking for rule implementations.

Provides consistent code-fence detection across all rules that need
to adjust severity or skip lines based on surrounding context.
"""

from __future__ import annotations


class ContextTracker:
    """Tracks whether the current line is inside a code fence."""

    def __init__(self) -> None:
        self.in_code_fence: bool = False

    def update(self, line: str) -> None:
        """Update state based on the current line. Call before checking."""
        if line.strip().startswith("```"):
            self.in_code_fence = not self.in_code_fence

    def is_fenced(self) -> bool:
        """Return True if currently inside a code fence."""
        return self.in_code_fence
