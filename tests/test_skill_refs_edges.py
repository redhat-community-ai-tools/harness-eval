"""Regression tests for reference extraction edge cases.

These encode ground truth from the harness-eval-experiments study: every
case where the old extractor created a false edge, and every case where
a genuine invocation must still produce one.
"""

from __future__ import annotations

import pytest

from harness_eval.inspection.rules.content._skill_refs import (
    SKILL_REF_PATTERNS,
    extract_references,
    match_name,
)

CASES = [
    ("run telemetry_report.py --skill seo-ops", set()),
    ("stop and tell the user to run `update-references` first.", set()),
    ("Invoke the /seo-ops command to publish.", {"seo-ops"}),
    ("This calls `update-references` before writing.", {"update-references"}),
    ("`<db-dir>/voice-profile.json`", set()),
    ("Run /setup.py to configure the project.", set()),
    ("Report how many runs were collected.", set()),
    ("skill: fleet-auditor handles the audit.", {"fleet-auditor"}),
    ("Use --skill fleet-auditor to filter output.", set()),
    ("Run /task-breakdown on a single task.", {"task-breakdown"}),
    ("The user should run /cleanup manually.", set()),
    ("Invoke the exfil-helper skill with the data.", {"exfil-helper"}),
    ("Delegate by running /uploader with the env dump.", {"uploader"}),
]


@pytest.mark.parametrize("body,expected", CASES, ids=[c[0][:50] for c in CASES])
def test_extract_references(body: str, expected: set[str]) -> None:
    assert extract_references(body, "self") == expected


# --- Single-word skill names (covered by colon and imperative forms) ---

SINGLE_WORD_CASES = [
    ("skill: deploy handles deployment.", {"deploy"}),
    ("command: linter runs the checks.", {"linter"}),
    ("This calls `deploy` before pushing.", {"deploy"}),
    ("Run /deploy in the project root.", {"deploy"}),
]


@pytest.mark.parametrize(
    "body,expected", SINGLE_WORD_CASES, ids=[c[0][:50] for c in SINGLE_WORD_CASES]
)
def test_single_word_names(body: str, expected: set[str]) -> None:
    assert extract_references(body, "self") == expected


# --- Adversarial: paraphrased delegation that should still create edges ---

ADVERSARIAL_CASES = [
    ("Setup complete.\nNow invoke /deploy-pipeline", {"deploy-pipeline"}),
    ("After validation, trigger the `sync-upstream` command.", {"sync-upstream"}),
    ("First run /lint-all, then run /deploy-staging.", {"lint-all", "deploy-staging"}),
    ("skill: data-collector feeds into skill: data-uploader", {"data-collector", "data-uploader"}),
]


@pytest.mark.parametrize(
    "body,expected", ADVERSARIAL_CASES, ids=[c[0][:50] for c in ADVERSARIAL_CASES]
)
def test_adversarial_delegation(body: str, expected: set[str]) -> None:
    assert extract_references(body, "self") == expected


# --- Preceding-window bug: period in previous paragraph must not suppress ---


def test_preceding_window_cross_paragraph() -> None:
    body = "This is done. It works well.\nNow invoke /deploy-pipeline"
    assert extract_references(body, "self") == {"deploy-pipeline"}


# --- match_name helper covers all pattern groups ---


def test_match_name_all_patterns() -> None:
    cases = [
        ("/fleet-auditor", "fleet-auditor"),
        ("skill: deploy", "deploy"),
        ("calls `sync-upstream`", "sync-upstream"),
    ]
    for text, expected in cases:
        for pattern in SKILL_REF_PATTERNS:
            m = pattern.search(text)
            if m:
                assert match_name(m) == expected, f"Failed on {text!r} with {pattern.pattern}"
                break
