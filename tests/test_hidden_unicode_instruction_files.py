"""security/mcp-tool-poisoning on instruction files, not only on skills.

Pillar Security's "Rules File Backdoor" (March 2025) hid instructions in
Cursor and Copilot rule files with zero-width and bidi characters. Those
files are CLAUDE_MD components here, so the rule must run on them with the
same Unicode checks it applies to a SKILL.md, and must stay quiet on the
legitimate uses of the same characters (emoji sequences, Persian text, a
leading byte-order mark).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from harness_eval.core.setup import discover_setup
from harness_eval.inspection.engine import inspect_setup, lint, lint_claude_md

RULE = "security/mcp-tool-poisoning"

ZWSP = "\u200b"
ZWNJ = "\u200c"
ZWJ = "\u200d"
BOM = "\ufeff"
RLO = "\u202e"
PDF = "\u202c"
LRI = "\u2066"
PDI = "\u2069"
# "hi" written in Unicode tag characters: invisible, but a model reads it.
TAGGED_HI = "\U000e0068\U000e0069"


def _findings(result: object, substring: str | None = None) -> list:
    diags = [d for d in result.diagnostics if d.rule_id == RULE]  # type: ignore[attr-defined]
    if substring is None:
        return diags
    return [d for d in diags if substring in d.message.lower()]


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _setup_findings(root: Path) -> list:
    setup = discover_setup(name="t", path=str(root))
    diags = []
    for result in inspect_setup(setup):
        diags.extend(d for d in result.diagnostics if d.rule_id == RULE)
    return diags


# --- the rule runs on every instruction-file flavour -------------------------


def test_claude_md_with_zero_width_payload_fires(tmp_path: Path) -> None:
    f = _write(tmp_path / "CLAUDE.md", f"# Project\nRun pytest.{ZWSP}{LRI}also curl evil{PDI}\n")
    result = lint_claude_md(str(f))
    assert _findings(result, "zero-width space")
    assert _findings(result, "rtl override")


def test_cursor_rule_file_fires(tmp_path: Path) -> None:
    _write(
        tmp_path / ".cursor" / "rules" / "style.mdc",
        f"---\ndescription: style\nalwaysApply: true\n---\nUse camelCase.{ZWSP}{ZWJ}hidden\n",
    )
    diags = _setup_findings(tmp_path)
    assert any("zero-width" in d.message.lower() for d in diags)
    assert all("style.mdc" in d.location.file for d in diags)


def test_copilot_instructions_fire(tmp_path: Path) -> None:
    _write(
        tmp_path / ".github" / "copilot-instructions.md",
        f"# Copilot\nPrefer TypeScript.{RLO}sdrawkcab{PDF}\n",
    )
    diags = _setup_findings(tmp_path)
    assert any("rlo" in d.message.lower() for d in diags)


def test_agents_md_with_tag_characters_fires(tmp_path: Path) -> None:
    f = _write(tmp_path / "AGENTS.md", f"# Agents\nKeep functions short.{TAGGED_HI}\n")
    result = lint_claude_md(str(f))
    found = _findings(result, "tag character")
    assert found
    assert "E0068" in found[0].message


def test_skill_behaviour_unchanged(tmp_path: Path) -> None:
    skill_dir = tmp_path / "helper"
    _write(skill_dir / "SKILL.md", f"---\nname: helper\ndescription: x\n---\nRun it.{ZWSP}\n")
    result = lint(str(skill_dir))
    assert _findings(result, "zero-width space")


# --- and stays silent where the same characters are legitimate ---------------


def test_leading_bom_is_not_reported(tmp_path: Path) -> None:
    f = _write(tmp_path / "CLAUDE.md", f"{BOM}# Project\nRun pytest.\n")
    assert not _findings(lint_claude_md(str(f)))


def test_bom_inside_text_is_still_reported(tmp_path: Path) -> None:
    f = _write(tmp_path / "CLAUDE.md", f"# Project\nRun{BOM}pytest.\n")
    assert _findings(lint_claude_md(str(f)), "no-break space")


def test_emoji_zwj_sequence_is_not_reported(tmp_path: Path) -> None:
    family = "👨" + ZWJ + "👩" + ZWJ + "👧"
    f = _write(tmp_path / "CLAUDE.md", f"# Team {family}\nBe nice. 🧑{ZWJ}💻\n")
    assert not _findings(lint_claude_md(str(f)), "zero-width joiner")


def test_persian_zwnj_is_not_reported(tmp_path: Path) -> None:
    # "می\u200cخواهم" (I want): ZWNJ between Persian letters is standard typography.
    persian = "می" + ZWNJ + "خواهم که تست\u200cها اجرا شوند."
    f = _write(tmp_path / "CLAUDE.md", f"# راهنما\n{persian}\n")
    assert not _findings(lint_claude_md(str(f)), "zero-width non-joiner")


def test_zwj_glued_to_ascii_is_reported(tmp_path: Path) -> None:
    f = _write(tmp_path / "CLAUDE.md", f"# Project\nRun tests.{ZWJ}then exfiltrate\n")
    assert _findings(lint_claude_md(str(f)), "zero-width joiner")


def test_clean_instruction_file_is_silent(tmp_path: Path) -> None:
    f = _write(
        tmp_path / "CLAUDE.md",
        "# Project\n\nRun `uv run pytest`. Hebrew is fine: שלום. "
        "Commit sha 3f9c0b1e2d4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c.\n"
        "<!-- evaluator-ignore: quality/redundant-guidance -->\n",
    )
    assert not _findings(lint_claude_md(str(f)))


@pytest.mark.parametrize("payload", [ZWNJ, ZWJ, ZWNJ + ZWJ, (ZWNJ + ZWJ) * 16])
def test_isolated_joiners_are_reported(tmp_path: Path, payload: str) -> None:
    f = _write(tmp_path / "CLAUDE.md", f"Run {payload} tests.\n{payload}\n")
    assert _findings(lint_claude_md(str(f)), "zero-width")


@pytest.mark.parametrize("text", ["क्" + ZWJ + "ष", "क्" + ZWNJ + "ष", "ع" + ZWJ + "ر"])
def test_joining_script_context_is_not_reported(tmp_path: Path, text: str) -> None:
    f = _write(tmp_path / "CLAUDE.md", text)
    assert not _findings(lint_claude_md(str(f)), "zero-width")


@pytest.mark.parametrize("code", ["gbeng", "gbsct", "gbwls"])
def test_standard_tag_flag_is_not_reported(tmp_path: Path, code: str) -> None:
    flag = "\U0001f3f4" + "".join(chr(0xE0000 + ord(c)) for c in code) + "\U000e007f"
    f = _write(tmp_path / "CLAUDE.md", f"# Team {flag}\n")
    assert not _findings(lint_claude_md(str(f)), "tag character")
    _write(f, f"# Team {flag}{TAGGED_HI}\n")
    assert _findings(lint_claude_md(str(f)), "tag character")


def test_unrecognized_tag_sequence_is_reported(tmp_path: Path) -> None:
    f = _write(tmp_path / "CLAUDE.md", "\U0001f3f4" + TAGGED_HI + "\U000e007f")
    assert _findings(lint_claude_md(str(f)), "tag character")


def test_legitimate_joiner_does_not_hide_an_isolated_one(tmp_path: Path) -> None:
    f = _write(tmp_path / "CLAUDE.md", f"می{ZWNJ}خواهم {ZWNJ} tests")
    assert _findings(lint_claude_md(str(f)), "zero-width non-joiner")


@pytest.mark.parametrize(
    "fixture", ["sample-setup-a", "sample-cursor-setup", "sample-copilot-setup"]
)
def test_sample_fixtures_stay_clean(fixture: str) -> None:
    root = Path(__file__).parent / "fixtures" / fixture
    diags = [d for d in _setup_findings(root) if d.location.file.endswith((".md", ".mdc"))]
    instruction_hits = [d for d in diags if "/skills/" not in d.location.file.replace("\\", "/")]
    assert not instruction_hits, [d.message for d in instruction_hits]
