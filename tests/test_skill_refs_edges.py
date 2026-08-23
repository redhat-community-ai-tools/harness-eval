"""Regression tests for reference extraction edge cases.

These encode ground truth from the harness-eval-experiments study: every
case where the old extractor created a false edge, and every case where
a genuine invocation must still produce one.
"""

from __future__ import annotations

import pytest

from harness_eval.inspection.rules.content._skill_refs import extract_references

CASES = [
    ("run telemetry_report.py --skill seo-ops", set()),
    ("stop and tell the user to run `update-references` first.", set()),
    ("Invoke the /seo-ops command to publish.", {"seo-ops"}),
    ("This calls `update-references` before writing.", {"update-references"}),
    ("`<db-dir>/voice-profile.json`", set()),
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
