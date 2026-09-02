"""Watch mode for lint: monitor files and re-run lint on changes."""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING

import click

from harness_eval.core.setup import collect_setup_file_paths

if TYPE_CHECKING:
    from collections.abc import Callable

    from watchfiles import Change

# Debounce window in milliseconds
DEBOUNCE_MS = 300


def _get_watch_directories(paths: list[Path]) -> set[Path]:
    """Get unique parent directories to watch."""
    dirs: set[Path] = set()
    for p in paths:
        dirs.add(p.parent)
    return dirs


def _build_filter(
    watch_paths: list[Path],
) -> Callable[[Change, str], bool]:
    """Build a filter function for watchfiles that only passes watched files."""
    resolved = {str(p.resolve()) for p in watch_paths}

    def _filter(change: Change, path: str) -> bool:
        return path in resolved

    return _filter


def _clear_terminal() -> None:
    """Clear the terminal screen."""
    click.echo("\033[2J\033[H", nl=False)


def run_watch(
    path: str,
    preset: str,
    fmt: str,
    user_config: str | None,
    debounce_ms: int = DEBOUNCE_MS,
    recursive: bool = False,
    load_target_yaml: bool = False,
) -> None:
    """Run lint in watch mode, re-running on file changes.

    Args:
        path: Directory to lint and watch.
        preset: Lint preset name.
        fmt: Output format ('terminal' or 'json').
        user_config: Optional user config directory.
        debounce_ms: Debounce window in milliseconds.
        recursive: Search for agent configs in nested directories.
    """
    root = Path(path)
    if not root.is_dir():
        raise click.ClickException(f"'{path}' is not a directory. Watch mode requires a directory.")

    try:
        from watchfiles import watch
    except ImportError as err:
        raise click.ClickException(
            "Watch mode requires the 'watchfiles' package. "
            "Install it with: pip install 'harness-eval[watch]'"
        ) from err

    from harness_eval.analysis.system import analyze_system
    from harness_eval.config.presets import PRESETS
    from harness_eval.core.setup import discover_setup
    from harness_eval.inspection.engine import inspect_setup
    from harness_eval.output.report import format_json, format_terminal

    config_rules = PRESETS.get(preset, {})

    user_config_path = Path(user_config) if user_config else None
    watch_paths = collect_setup_file_paths(
        root, user_config_dir=user_config_path, recursive=recursive
    )
    watch_dirs = _get_watch_directories(watch_paths)

    if not watch_dirs:
        raise click.ClickException(f"No agent setup files found in '{path}'.")

    def _run_lint() -> None:
        """Run lint and display results."""
        setup = discover_setup(
            name=root.name, path=path, user_config_dir=user_config, recursive=recursive
        )
        results = inspect_setup(setup, config_rules, load_target_yaml=load_target_yaml)
        system = analyze_system(setup)

        if fmt == "json":
            click.echo(format_json(system, results))
        else:
            click.echo(format_terminal(system, results))

    # Initial run
    _clear_terminal()
    click.echo(f"👀 Watching {len(watch_paths)} files for changes... (Ctrl+C to stop)\n")
    _run_lint()

    # Watch loop.
    # NOTE: The watched file set and directories are fixed for the lifetime of
    # the iterator.  If new setup files are created after watch mode starts they
    # will not be picked up — the user must restart watch mode.  Restarting the
    # iterator on every change would be more complex and risk missed events.
    watch_filter = _build_filter(watch_paths)

    try:
        for changes in watch(
            *watch_dirs,
            watch_filter=watch_filter,
            debounce=debounce_ms,
            rust_timeout=0,
        ):
            # Identify which files changed
            changed_files = [Path(p).name for _, p in changes]
            changed_list = ", ".join(changed_files)

            _clear_terminal()
            timestamp = time.strftime("%H:%M:%S")
            click.echo(f"👀 [{timestamp}] Change detected: {changed_list}\n")

            try:
                _run_lint()
            except Exception as e:
                click.echo(f"\nError during lint: {e}", err=True)

            click.echo("\nWatching for changes... (Ctrl+C to stop)")
    except KeyboardInterrupt:
        click.echo("\n\nWatch mode stopped.")
