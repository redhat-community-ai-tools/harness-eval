"""Verify expensive dependencies are not imported at module load time."""

from __future__ import annotations

import subprocess
import sys

import pytest

_PROBE = """
import sys
import harness_eval.cli  # noqa: F401
heavy = sorted({m.split(".")[0] for m in sys.modules} & {"sklearn", "scipy", "numpy"})
print(",".join(heavy))
"""


def _heavy_modules_after_cli_import() -> set[str]:
    """Import the CLI in a fresh interpreter and report which heavy packages loaded.

    A subprocess is required: inside the test process, modules that already
    imported ``utils.similarity`` stay cached in ``sys.modules``, so re-importing
    the CLI there proves nothing.
    """
    out = subprocess.run(
        [sys.executable, "-c", _PROBE], capture_output=True, text=True, check=True
    ).stdout.strip()
    return set(out.split(",")) - {""}


@pytest.mark.parametrize("package", ["sklearn", "scipy", "numpy"])
def test_heavy_package_not_imported_at_cli_load(package: str) -> None:
    """Importing the CLI must not import scikit-learn, scipy or numpy (#140)."""
    loaded = _heavy_modules_after_cli_import()
    assert package not in loaded, f"{package} was imported at CLI load time"


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
