"""Verify expensive dependencies are not imported at module load time."""

from __future__ import annotations

import importlib
import sys


def test_sklearn_not_imported_at_module_load():
    """sklearn should only be imported when tfidf_similarity() is called."""
    # Remove any cached imports of similarity and sklearn
    mods_to_remove = [m for m in sys.modules if "sklearn" in m or "similarity" in m]
    removed = {m: sys.modules.pop(m) for m in mods_to_remove}
    try:
        importlib.import_module("harness_eval.utils.similarity")
        assert not any("sklearn" in m for m in sys.modules), (
            "sklearn was imported at module load time"
        )
    finally:
        # Restore removed modules so other tests are not affected
        sys.modules.update(removed)


def test_tfidf_similarity_produces_correct_results():
    """Calling tfidf_similarity() after the lazy import must succeed and return valid scores."""
    from harness_eval.utils.similarity import tfidf_similarity

    # Identical texts should have similarity close to 1.0
    score = tfidf_similarity("hello world", "hello world")
    assert score > 0.99, f"Expected ~1.0 for identical texts, got {score}"

    # Completely different texts should have low similarity
    score_diff = tfidf_similarity("hello world", "foo bar baz")
    assert score_diff < 0.5, f"Expected low similarity for different texts, got {score_diff}"

    # Empty text should return 0.0
    assert tfidf_similarity("", "hello world") == 0.0
    assert tfidf_similarity("hello world", "") == 0.0
