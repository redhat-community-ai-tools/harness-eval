"""Regression test: lint must not be quadratic in the number of skills.

Covers the fix for #153 — vectorising once per scan instead of once per pair.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from harness_eval.core.setup import discover_setup
from harness_eval.inspection.engine import inspect_setup
from harness_eval.utils.similarity import (
    build_similarity_matrix,
    build_tfidf_index,
)

# ---------------------------------------------------------------------------
# Unit tests for the batch-similarity helpers
# ---------------------------------------------------------------------------


class TestSimilarityMatrix:
    def test_identical_texts(self) -> None:
        texts = {"a": "deploy the application", "b": "deploy the application"}
        matrix = build_similarity_matrix(texts)
        assert matrix.get("a", "b") == pytest.approx(1.0)

    def test_disjoint_texts(self) -> None:
        texts = {
            "a": "deploy the application to production",
            "b": "quantum physics experiments in laboratory",
        }
        matrix = build_similarity_matrix(texts)
        assert matrix.get("a", "b") < 0.3

    def test_missing_key_returns_zero(self) -> None:
        texts = {"a": "hello world"}
        matrix = build_similarity_matrix(texts)
        assert matrix.get("a", "nonexistent") == 0.0

    def test_pairs_above_threshold(self) -> None:
        texts = {
            "a": "deploy the app to production server",
            "b": "deploy the app to production server",
            "c": "quantum physics experiments in laboratory",
        }
        matrix = build_similarity_matrix(texts)
        pairs = matrix.pairs_above(0.9)
        names = {(a, b) for a, b, _ in pairs}
        assert ("a", "b") in names
        assert ("a", "c") not in names
        assert ("b", "c") not in names

    def test_empty_dict(self) -> None:
        matrix = build_similarity_matrix({})
        assert matrix.pairs_above(0.0) == []

    def test_single_text(self) -> None:
        matrix = build_similarity_matrix({"only": "some text here"})
        assert matrix.pairs_above(0.0) == []


class TestTfidfIndex:
    def test_query_identical(self) -> None:
        texts = {"skill-a": "deploy to production using docker containers"}
        index = build_tfidf_index(texts)
        sims = index.query("deploy to production using docker containers")
        assert sims["skill-a"] == pytest.approx(1.0, abs=0.01)

    def test_query_disjoint(self) -> None:
        texts = {"skill-a": "deploy to production using docker containers"}
        index = build_tfidf_index(texts)
        sims = index.query("quantum physics laboratory experiments")
        assert sims.get("skill-a", 0.0) < 0.3

    def test_empty_index(self) -> None:
        index = build_tfidf_index({})
        assert index.query("anything") == {}

    def test_empty_query(self) -> None:
        index = build_tfidf_index({"a": "some text"})
        assert index.query("") == {}
        assert index.query("   ") == {}


# ---------------------------------------------------------------------------
# Scaling regression test (#153)
# ---------------------------------------------------------------------------


def _make_skills(tmp_path: Path, n: int) -> Path:
    """Create *n* synthetic skills with unique content."""
    skills_dir = tmp_path / "skills"
    skills_dir.mkdir()
    for i in range(n):
        d = skills_dir / f"skill-{i}"
        d.mkdir()
        # Each skill has unique words so duplicates are not flagged, but
        # the corpus is large enough to exercise the vectoriser.
        body = (
            f"Skill number {i}. "
            f"Unique-token-{i} alpha-{i} bravo-{i} charlie-{i}. "
            f"This skill handles task category {i % 7} in domain {i % 11}. "
            f"It processes items from queue {i} and writes results to output {i}."
        )
        (d / "SKILL.md").write_text(
            f"---\nname: skill-{i}\ndescription: Handle task {i}\n---\n\n{body}\n"
        )
    (tmp_path / "CLAUDE.md").write_text("# Scaling test\n")
    return tmp_path


class TestLintScaling:
    @pytest.mark.timeout(30)
    def test_200_skills_under_10s(self, tmp_path: Path) -> None:
        """Lint 200 synthetic skills in under 10 seconds (was ~60 s before #153)."""
        root = _make_skills(tmp_path, 200)
        setup = discover_setup(name="scale-test", path=str(root))

        start = time.monotonic()
        results = inspect_setup(setup, {"content/duplicate-detection": "warning"})
        elapsed = time.monotonic() - start

        assert elapsed < 10, f"Lint took {elapsed:.1f}s for 200 skills (expected < 10s)"
        # Sanity: every skill produced a result
        skill_results = [r for r in results if r.target_type == "skill"]
        assert len(skill_results) == 200
