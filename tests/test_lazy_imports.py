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
        assert not any(
            "sklearn" in m for m in sys.modules
        ), "sklearn was imported at module load time"
    finally:
        # Restore removed modules so other tests are not affected
        sys.modules.update(removed)
