"""Tests for quality/ lint rules."""

from __future__ import annotations

from pathlib import Path

from harness_eval.inspection.engine import lint

IMPRECISE = "quality/imprecise-instruction"
REDUNDANT = "quality/redundant-guidance"
UNFINISHED = "quality/unfinished-content"
EXAMPLE_GAP = "quality/example-gap"
STALE = "quality/stale-references"


def _make_skill(tmp_path: Path, name: str, body: str) -> str:
    skill_dir = tmp_path / name
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: Test skill\n---\n\n{body}"
    )
    return str(skill_dir)


def _rule_ids(path: str) -> set[str]:
    return {d.rule_id for d in lint(path).diagnostics}


def _findings_for(path: str, rule_id: str) -> list:
    return [d for d in lint(path).diagnostics if d.rule_id == rule_id]


# --- ImpreciseInstruction ---


class TestImpreciseInstruction:
    def test_hedging_try_to(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "s1", "Try to use TypeScript for all new files.")
        assert IMPRECISE in _rule_ids(path)

    def test_hedging_if_possible(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "s2", "Use Python 3.12 if possible.")
        assert IMPRECISE in _rule_ids(path)

    def test_hedging_consider_using(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "s3", "Consider using dataclasses for DTOs.")
        assert IMPRECISE in _rule_ids(path)

    def test_passive_not_flagged(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "s4", "Tests should be run before merging.")
        assert IMPRECISE not in _rule_ids(path)

    def test_passive_needs_not_flagged(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "s5", "Input needs to be validated first.")
        assert IMPRECISE not in _rule_ids(path)

    def test_conditional_if_appropriate(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "s6", "Refactor the module if appropriate.")
        msgs = [d.message for d in _findings_for(path, IMPRECISE)]
        assert any("vague condition" in m for m in msgs)

    def test_no_flag_in_code_block(self, tmp_path: Path) -> None:
        body = "```python\n# Try to connect to the database\ndb.connect()\n```"
        path = _make_skill(tmp_path, "s7", body)
        assert len(_findings_for(path, IMPRECISE)) == 0

    def test_no_flag_blockquote(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "s8", "> Try to keep this in mind.")
        assert len(_findings_for(path, IMPRECISE)) == 0

    def test_no_flag_direct_instruction(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "s9", "Use TypeScript for all new files.")
        assert len(_findings_for(path, IMPRECISE)) == 0

    def test_no_flag_descriptive_passive(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "s10", "The database is hosted on AWS.")
        assert len(_findings_for(path, IMPRECISE)) == 0

    def test_passive_must_not_flagged(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "s11", "All endpoints must be tested before release.")
        assert IMPRECISE not in _rule_ids(path)


# --- RedundantGuidance ---


class TestRedundantGuidance:
    def test_follow_best_practices(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "r1", "Always follow best practices when coding.")
        assert REDUNDANT in _rule_ids(path)

    def test_write_clean_code(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "r2", "Write clean, readable code.")
        assert REDUNDANT in _rule_ids(path)

    def test_handle_errors_properly(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "r3", "Handle errors properly in all functions.")
        assert REDUNDANT in _rule_ids(path)

    def test_write_unit_tests(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "r4", "Always write unit tests for new features.")
        assert REDUNDANT in _rule_ids(path)

    def test_avoid_magic_numbers(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "r5", "Avoid magic numbers in your code.")
        assert REDUNDANT in _rule_ids(path)

    def test_no_flag_specific_instruction(self, tmp_path: Path) -> None:
        path = _make_skill(
            tmp_path,
            "r6",
            "Use `pytest` with fixtures in `tests/conftest.py`.",
        )
        assert len(_findings_for(path, REDUNDANT)) == 0

    def test_no_flag_with_file_path(self, tmp_path: Path) -> None:
        path = _make_skill(
            tmp_path,
            "r7",
            "Write unit tests using patterns in ./tests/helpers.py",
        )
        assert len(_findings_for(path, REDUNDANT)) == 0

    def test_no_flag_in_code_block(self, tmp_path: Path) -> None:
        body = "```\nFollow best practices for error handling.\n```"
        path = _make_skill(tmp_path, "r8", body)
        assert len(_findings_for(path, REDUNDANT)) == 0

    def test_no_flag_specific_with_extension(self, tmp_path: Path) -> None:
        path = _make_skill(
            tmp_path,
            "r9",
            "Validate user input in all .py files using pydantic.",
        )
        assert len(_findings_for(path, REDUNDANT)) == 0

    def test_keep_functions_small(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "r10", "Keep functions small and focused.")
        assert REDUNDANT in _rule_ids(path)

    def test_document_your_code(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "r11", "Document your code thoroughly.")
        assert REDUNDANT in _rule_ids(path)

    def test_tooling_redundant_with_editorconfig(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        (tmp_path / ".editorconfig").write_text("[*]\nindent_style = space\n")
        skill_dir = tmp_path / "skills" / "my-skill"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            "---\nname: my-skill\ndescription: test\n---\n\nUse 2-space indentation for all files."
        )
        result = lint(str(skill_dir))
        msgs = [d.message for d in result.diagnostics if d.rule_id == REDUNDANT]
        assert any(".editorconfig" in m for m in msgs)

    def test_no_tooling_flag_without_config(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        skill_dir = tmp_path / "skills" / "my-skill"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            "---\nname: my-skill\ndescription: test\n---\n\nUse 2-space indentation for all files."
        )
        result = lint(str(skill_dir))
        msgs = [d.message for d in result.diagnostics if d.rule_id == REDUNDANT]
        assert not any(".editorconfig" in m for m in msgs)


# --- UnfinishedContent ---


class TestUnfinishedContent:
    def test_insert_placeholder(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "u1", "Project: [INSERT YOUR PROJECT NAME]")
        assert UNFINISHED in _rule_ids(path)

    def test_your_placeholder(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "u2", "API key: [YOUR API KEY]")
        assert UNFINISHED in _rule_ids(path)

    def test_angle_bracket_placeholder(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "u3", "Replace <your-name-here> with your name.")
        assert UNFINISHED in _rule_ids(path)

    def test_todo_marker(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "u4", "TODO: add deployment instructions here.")
        assert UNFINISHED in _rule_ids(path)

    def test_fixme_marker(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "u5", "FIXME: this section is incomplete.")
        assert UNFINISHED in _rule_ids(path)

    def test_bracket_allcaps_placeholder(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "u6", "Set [YOUR_API_KEY] in the environment.")
        assert UNFINISHED in _rule_ids(path)

    def test_no_flag_in_code_block(self, tmp_path: Path) -> None:
        body = "```yaml\n# TODO: configure this\nkey: value\n```"
        path = _make_skill(tmp_path, "u7", body)
        assert len(_findings_for(path, UNFINISHED)) == 0

    def test_no_flag_rfc_reference(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "u8", "Follow [RFC 2119] for keywords.")
        assert len(_findings_for(path, UNFINISHED)) == 0

    def test_no_flag_normal_brackets(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "u9", "Use [Section 3.1] as a reference.")
        assert len(_findings_for(path, UNFINISHED)) == 0

    def test_no_flag_todo_without_colon(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "u10", "We need to decide the todo list format.")
        assert len(_findings_for(path, UNFINISHED)) == 0

    def test_placeholder_marker(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "u11", "Description: [PLACEHOLDER]")
        assert UNFINISHED in _rule_ids(path)

    def test_tbd_marker(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "u12", "Deployment strategy: TBD")
        assert UNFINISHED in _rule_ids(path)

    def test_coming_soon(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "u13", "This feature is coming soon.")
        assert UNFINISHED in _rule_ids(path)

    def test_not_yet_implemented(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "u14", "Error handling is not yet implemented.")
        assert UNFINISHED in _rule_ids(path)

    def test_empty_section(self, tmp_path: Path) -> None:
        body = "Some intro text.\n\n## Empty Section\n\n## Next Section\n\nContent here."
        path = _make_skill(tmp_path, "u15", body)
        msgs = [d.message for d in _findings_for(path, UNFINISHED)]
        assert any("Empty Section" in m for m in msgs)

    def test_no_flag_section_with_content(self, tmp_path: Path) -> None:
        body = "## Filled Section\n\nThis has content.\n\n## Another\n\nAlso has content."
        path = _make_skill(tmp_path, "u16", body)
        empty_findings = [d for d in _findings_for(path, UNFINISHED) if "no content" in d.message]
        assert len(empty_findings) == 0

    def test_work_in_progress(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "u17", "This section is a work in progress.")
        assert UNFINISHED in _rule_ids(path)


# --- ExampleGap ---


class TestExampleGap:
    def _long_instructions(self) -> str:
        return "\n".join(
            [
                "Always use TypeScript strict mode.",
                "Never commit directly to main.",
                "Use conventional commits for all messages.",
                "Run the linter before every push.",
                "Ensure all tests pass before merging.",
                "Follow the project naming conventions.",
                "Use absolute imports throughout.",
                "Avoid circular dependencies between modules.",
                "Set environment variables via the .env file.",
                "Do not hardcode API endpoints.",
            ]
        )

    def test_no_examples_triggers(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "e1", self._long_instructions())
        assert EXAMPLE_GAP in _rule_ids(path)

    def test_with_code_block_passes(self, tmp_path: Path) -> None:
        body = self._long_instructions() + "\n\n```ts\nconst x = 1;\n```"
        path = _make_skill(tmp_path, "e2", body)
        assert len(_findings_for(path, EXAMPLE_GAP)) == 0

    def test_short_skill_not_flagged(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "e3", "Use TypeScript.")
        assert len(_findings_for(path, EXAMPLE_GAP)) == 0

    def test_few_instructions_not_flagged(self, tmp_path: Path) -> None:
        body = "Some background context about the project.\n" * 10
        path = _make_skill(tmp_path, "e4", body)
        assert len(_findings_for(path, EXAMPLE_GAP)) == 0


# --- StaleReferences ---


class TestStaleReferences:
    def test_gpt35_turbo(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "st1", "Use gpt-3.5-turbo for summarization.")
        assert STALE in _rule_ids(path)

    def test_text_davinci(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "st2", "Use text-davinci-003 for completions.")
        assert STALE in _rule_ids(path)

    def test_claude_v1(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "st3", "Use claude-v1 for this task.")
        assert STALE in _rule_ids(path)

    def test_claude_2(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "st4", "Use claude-2.1 as the model.")
        assert STALE in _rule_ids(path)

    def test_tslint(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "st5", "Run tslint before committing.")
        assert STALE not in _rule_ids(path)

    def test_create_react_app(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "st6", "Bootstrap with create-react-app.")
        assert STALE not in _rule_ids(path)

    def test_python_37(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "st7", "Requires Python 3.7 or higher.")
        assert STALE not in _rule_ids(path)

    def test_current_model_no_flag(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "st8", "Use claude-sonnet-4-6 for code generation.")
        assert len(_findings_for(path, STALE)) == 0

    def test_no_flag_in_code_block(self, tmp_path: Path) -> None:
        body = "```\n# legacy: text-davinci-003\n```"
        path = _make_skill(tmp_path, "st9", body)
        assert len(_findings_for(path, STALE)) == 0

    def test_modern_tools_no_flag(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "st10", "Use eslint with @typescript-eslint.")
        assert len(_findings_for(path, STALE)) == 0

    def test_includes_replacement(self, tmp_path: Path) -> None:
        path = _make_skill(tmp_path, "st11", "Run tslint on all files.")
        msgs = [d.message for d in _findings_for(path, STALE)]
        assert msgs == []
