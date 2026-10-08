"""fullsend harness discoverer.

A `fullsend <https://fullsend.sh>`_ scaffold keeps one YAML per unattended
agent under ``harness/``. Each file binds an agent prompt (``agent:``) to a
model, sandbox image, pre/post scripts, an output contract and environment.
The file is discovered as a ``HARNESS`` component; the key mapping into the
normalized harness model lives in ``inspection.harness_formats.fullsend``.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from harness_eval.core.discoverers.base import (
    ToolDiscoverer,
    _is_excluded_path,
    _recursive_glob,
    parse_file,
)
from harness_eval.core.types import ComponentType, ParsedComponent

HARNESS_DIR = "harness"
_YAML_SUFFIXES = (".yaml", ".yml")
# A harness is a mapping with an agent prompt, or one that inherits from a
# base harness (and may therefore leave ``agent`` to the base).
_MARKER_KEYS = ("agent", "base")


def _is_excluded_from_scan(filepath: Path) -> bool:
    from harness_eval.core.setup import is_excluded_during_scan

    return is_excluded_during_scan(filepath)


def is_harness_file(path: Path) -> bool:
    """True if *path* is a YAML mapping carrying a fullsend harness marker key."""
    if path.suffix not in _YAML_SUFFIXES or not path.is_file():
        return False
    if _is_excluded_from_scan(path):
        return False
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return False
    except yaml.YAMLError:
        # A file in harness/ that no longer parses is still a harness, now a
        # broken one. Dropping it here would let the parse error vanish from
        # the result and a gate pass on a change that broke the file; the
        # parser records the error and the engine reports it instead.
        return path.parent.name == "harness"
    return isinstance(data, dict) and any(isinstance(data.get(k), str) for k in _MARKER_KEYS)


def _candidate_files(root: Path, *, recursive: bool) -> list[Path]:
    """YAML files under a ``harness/`` directory, without reading them."""
    found: list[Path] = []
    harness_dir = root / HARNESS_DIR
    if harness_dir.is_dir():
        for f in sorted(harness_dir.iterdir()):
            if f.is_file() and f.suffix in _YAML_SUFFIXES:
                found.append(f)
    if recursive:
        for suffix in _YAML_SUFFIXES:
            for f in _recursive_glob(root, f"{HARNESS_DIR}/*{suffix}"):
                if f not in found and not _is_excluded_path(f, root):
                    found.append(f)
    return found


class FullsendDiscoverer(ToolDiscoverer):
    """Discovers fullsend harness definitions (``harness/*.yaml``)."""

    @property
    def tool_name(self) -> str:
        return "fullsend"

    @property
    def source_tool(self) -> str:
        return "fullsend"

    def detect(self, root: Path) -> bool:
        return any(is_harness_file(f) for f in _candidate_files(root, recursive=False))

    def discover(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[ParsedComponent]:
        results: list[ParsedComponent] = []
        for f in _candidate_files(root, recursive=recursive):
            if is_harness_file(f):
                results.append(
                    parse_file(f, ComponentType.HARNESS, name=f.stem, source_tool="fullsend")
                )
        return results

    def collect_paths(
        self, root: Path, user_config_dir: Path | None = None, *, recursive: bool = False
    ) -> list[Path]:
        # Every candidate is read once to decide whether it is a harness, so
        # every candidate is inventoried, whether or not it becomes a component.
        return _candidate_files(root, recursive=recursive)
