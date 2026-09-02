"""Test that version strings are consistent across all distribution artifacts."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _read_pyproject_version() -> str:
    text = (ROOT / "pyproject.toml").read_text()
    match = re.search(r'^version\s*=\s*"(.+?)"', text, re.MULTILINE)
    assert match, "Could not find version in pyproject.toml"
    return match.group(1)


def test_marketplace_json_version_matches_pyproject() -> None:
    expected = _read_pyproject_version()
    marketplace = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
    actual = marketplace["plugins"][0]["version"]
    assert actual == expected, (
        f"marketplace.json version ({actual}) does not match "
        f"pyproject.toml ({expected}). Run: uv run scripts/release.py"
    )


def test_plugin_json_version_matches_pyproject() -> None:
    expected = _read_pyproject_version()
    plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
    actual = plugin["version"]
    assert actual == expected, (
        f"plugin.json version ({actual}) does not match "
        f"pyproject.toml ({expected}). Run: uv run scripts/release.py"
    )


def test_package_dunder_version_matches_pyproject() -> None:
    from harness_eval import __version__

    expected = _read_pyproject_version()
    assert __version__ == expected, (
        f"harness_eval.__version__ ({__version__}) does not match pyproject.toml ({expected})"
    )


def test_tekton_version_matches_pyproject() -> None:
    expected = _read_pyproject_version()
    text = (ROOT / "tekton" / "task-harness-eval.yaml").read_text()
    match = re.search(r'app\.kubernetes\.io/version:\s*"(.+?)"', text)
    assert match, "Could not find app.kubernetes.io/version in tekton/task-harness-eval.yaml"
    assert match.group(1) == expected, (
        f"Tekton version label ({match.group(1)}) does not match pyproject.toml ({expected})"
    )
