"""Tests for CI readiness fixes: tiktoken fallback and orphan detection scope."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from harness_eval.analysis.dependencies import analyze_dependencies
from harness_eval.core.types import ComponentType, ParsedComponent, Setup
from harness_eval.utils import tokens


class TestTiktokenFallback:
    """Token counting must work when tiktoken is unavailable."""

    def setup_method(self):
        tokens._reset()

    def teardown_method(self):
        tokens._reset()

    def test_fallback_returns_chars_div_4(self):
        with patch.object(tokens, "_init_encoder", side_effect=self._force_fallback):
            result = tokens.count_tokens("hello world! this is a test.")
            assert result == len("hello world! this is a test.") // 4

    def test_fallback_warns_once(self):
        with patch.object(tokens, "_init_encoder", side_effect=self._force_fallback):
            with pytest.warns(UserWarning, match="chars/4 approximation"):
                tokens.count_tokens("first call")
            tokens.count_tokens("second call")

    def test_normal_path_uses_tiktoken(self):
        # Reset to ensure fresh init
        tokens._reset()
        result = tokens.count_tokens("hello world")
        assert isinstance(result, int)
        assert result > 0

    def test_empty_string(self):
        assert tokens.count_tokens("") == 0

    @staticmethod
    def _force_fallback():
        tokens._FALLBACK = True


class TestOrphanDetectionScope:
    """Orphan detection must not flag unreferenced skills."""

    @staticmethod
    def _make_setup(components: list[ParsedComponent]) -> Setup:
        return Setup(
            name="test",
            path="/tmp/test",
            fingerprint="test-fingerprint",
            components=components,
        )

    @staticmethod
    def _make_component(name: str, ctype: ComponentType, content: str = "") -> ParsedComponent:
        return ParsedComponent(
            name=name,
            component_type=ctype,
            path=f"/tmp/test/{name}",
            content=content,
        )

    def test_unreferenced_skill_not_orphaned(self):
        components = [
            self._make_component("my-skill", ComponentType.SKILL, "does things"),
            self._make_component("other-skill", ComponentType.SKILL, "does other things"),
            self._make_component("a-command", ComponentType.COMMAND, "runs stuff"),
            self._make_component("main", ComponentType.CLAUDE_MD, "instructions"),
        ]
        setup = self._make_setup(components)
        deps = analyze_dependencies(setup)
        orphan_names = [o.split("/")[-1] for o in deps.orphan_components]
        assert "my-skill" not in orphan_names
        assert "other-skill" not in orphan_names

    def test_referencing_command_still_orphaned_if_not_referenced(self):
        """A command that references a skill but is itself never referenced is orphaned."""
        components = [
            self._make_component("referencing-cmd", ComponentType.COMMAND, "uses skill 'my-skill'"),
            self._make_component("my-skill", ComponentType.SKILL, "does things"),
            self._make_component("other-skill", ComponentType.SKILL, "more stuff"),
            self._make_component("main", ComponentType.CLAUDE_MD, "instructions"),
        ]
        setup = self._make_setup(components)
        deps = analyze_dependencies(setup)
        orphan_names = [o.split("/")[-1] for o in deps.orphan_components]
        assert "referencing-cmd" in orphan_names

    def test_unreferenced_command_is_orphaned(self):
        components = [
            self._make_component("my-skill", ComponentType.SKILL, "does things"),
            self._make_component("other-skill", ComponentType.SKILL, "does other things"),
            self._make_component("lonely-command", ComponentType.COMMAND, "nobody calls me"),
            self._make_component("main", ComponentType.CLAUDE_MD, "instructions"),
        ]
        setup = self._make_setup(components)
        deps = analyze_dependencies(setup)
        orphan_names = [o.split("/")[-1] for o in deps.orphan_components]
        assert "lonely-command" in orphan_names

    def test_referenced_command_not_orphaned(self):
        components = [
            self._make_component("my-skill", ComponentType.SKILL, "uses skill 'used-command'"),
            self._make_component("used-command", ComponentType.COMMAND, "i am used"),
            self._make_component("other-skill", ComponentType.SKILL, "more stuff"),
            self._make_component("main", ComponentType.CLAUDE_MD, "instructions"),
        ]
        setup = self._make_setup(components)
        deps = analyze_dependencies(setup)
        orphan_names = [o.split("/")[-1] for o in deps.orphan_components]
        assert "used-command" not in orphan_names

    def test_small_setup_skips_orphan_check(self):
        components = [
            self._make_component("lonely-command", ComponentType.COMMAND, "nobody calls me"),
            self._make_component("main", ComponentType.CLAUDE_MD, "instructions"),
        ]
        setup = self._make_setup(components)
        deps = analyze_dependencies(setup)
        assert len(deps.orphan_components) == 0
