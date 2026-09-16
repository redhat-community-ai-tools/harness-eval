"""Shared CLI helpers."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

import click

from harness_eval.core.types import ScanLimits

_F = TypeVar("_F", bound=Callable[..., Any])

_LIMIT_OPTIONS: tuple[tuple[str, int, str], ...] = (
    ("--max-file-bytes", ScanLimits.max_file_bytes, "Largest agent-setup file to read."),
    ("--max-total-bytes", ScanLimits.max_total_bytes, "Total bytes of agent-setup files to read."),
    ("--max-files", ScanLimits.max_files, "Most agent-setup files to read."),
    ("--max-depth", ScanLimits.max_depth, "Deepest directory nesting to read."),
)


def scan_limit_options(func: _F) -> _F:
    """Attach the scan-limit options shared by every command that discovers a setup.

    The decorated command receives ``max_file_bytes``, ``max_total_bytes``,
    ``max_files`` and ``max_depth`` keyword arguments; pass them through
    ``scan_limits_from`` to build a ``ScanLimits``.
    """
    for flag, default, help_text in reversed(_LIMIT_OPTIONS):
        func = click.option(flag, type=int, default=default, show_default=True, help=help_text)(
            func
        )
    return func


def scan_limits_from(
    max_file_bytes: int, max_total_bytes: int, max_files: int, max_depth: int
) -> ScanLimits:
    return ScanLimits(
        max_file_bytes=max_file_bytes,
        max_total_bytes=max_total_bytes,
        max_files=max_files,
        max_depth=max_depth,
    )


def emit_output(text: str, output_path: str | None) -> None:
    if output_path:
        Path(output_path).write_text(text)
    else:
        click.echo(text)
