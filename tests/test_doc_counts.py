"""Test that documented rule counts match the actual rule registry."""

from __future__ import annotations

import re
from pathlib import Path

import harness_eval.inspection  # noqa: F401 — triggers register_all_rules
from harness_eval.inspection.registry import get_all_rules

ROOT = Path(__file__).resolve().parent.parent

TOTAL_RULES_PATTERN = re.compile(r"(\d+)\s+(?:deterministic\s+)?rules")
SECURITY_RULES_PATTERN = re.compile(r"(\d+)\s+security\s+rules")

FILES_WITH_TOTAL_COUNT = [
    "README.md",
    "CLAUDE.md",
    "commands/lint.md",
    ".cursor/commands/lint.md",
    "skills/lint/SKILL.md",
    "skills/review/report-format.md",
    "docs/INSTALL.md",
    "docs/rules-reference.md",
    ".github/actions/harness-eval/action.yml",
]

FILES_WITH_SECURITY_COUNT = [
    ".github/actions/harness-eval/action.yml",
    "docs/INSTALL.md",
]


def _get_rule_counts() -> tuple[int, int]:
    all_rules = get_all_rules()
    total = len(all_rules)
    security = sum(1 for r in all_rules if r.meta.id.startswith("security/"))
    return total, security


class TestRuleCountDrift:
    def test_total_rule_counts_match_registry(self) -> None:
        total, _ = _get_rule_counts()
        for rel_path in FILES_WITH_TOTAL_COUNT:
            path = ROOT / rel_path
            if not path.exists():
                continue
            for lineno, line in enumerate(path.read_text().splitlines(), 1):
                if SECURITY_RULES_PATTERN.search(line) or "security" in line.lower():
                    continue
                for match in TOTAL_RULES_PATTERN.finditer(line):
                    documented = int(match.group(1))
                    assert documented == total, (
                        f"{rel_path}:{lineno} says {documented} rules but registry has {total}. "
                        f"Update the documented count to match."
                    )

    def test_security_rule_counts_match_registry(self) -> None:
        _, security = _get_rule_counts()
        for rel_path in FILES_WITH_SECURITY_COUNT:
            path = ROOT / rel_path
            if not path.exists():
                continue
            text = path.read_text()
            for match in SECURITY_RULES_PATTERN.finditer(text):
                documented = int(match.group(1))
                assert documented == security, (
                    f"{rel_path} says {documented} security rules but registry has {security}. "
                    f"Update the documented count to match."
                )


class TestCommandSurfaceSync:
    def test_claude_and_cursor_commands_have_same_names(self) -> None:
        claude_dir = ROOT / "commands"
        cursor_dir = ROOT / ".cursor" / "commands"
        if not claude_dir.exists() or not cursor_dir.exists():
            return
        claude_names = {p.stem for p in claude_dir.glob("*.md")}
        cursor_names = {p.stem for p in cursor_dir.glob("*.md")}
        assert claude_names == cursor_names, (
            f"Command surfaces have drifted. "
            f"Only in commands/: {claude_names - cursor_names}. "
            f"Only in .cursor/commands/: {cursor_names - claude_names}."
        )
