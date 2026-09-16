"""Setup discovery: walk a directory and parse all agent components."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from fnmatch import fnmatch
from pathlib import Path

from harness_eval.core.discoverers import get_all_discoverers
from harness_eval.core.discoverers.base import parse_file as _parse_file
from harness_eval.core.fingerprint import fingerprint_setup
from harness_eval.core.inventory import collect_setup_file_paths as _collect_setup_file_paths
from harness_eval.core.inventory import uncategorized_candidate_paths
from harness_eval.core.types import (
    ComponentType,
    ParsedComponent,
    ScanLimitExceeded,
    ScanLimits,
    Setup,
)

# Active --exclude patterns for this scan. Discoverer reads (parse_file,
# is_agent_file, JSON key peeks) consult it so an excluded file is never opened.
_scan_exclude: ContextVar[tuple[Path, tuple[str, ...]] | None] = ContextVar(
    "harness_eval_scan_exclude", default=None
)

# ponytail: default excludes keep credential files out of scan copies (HE-3).
DEFAULT_SCAN_EXCLUDES: tuple[str, ...] = (
    "**/.env",
    "**/.env.*",
    "**/credentials/**",
    "**/credentials.*",
    "**/*.pem",
    "**/*.key",
    "**/*id_rsa*",
)


def merge_scan_excludes(user_excludes: tuple[str, ...] = ()) -> tuple[str, ...]:
    """Return default credential excludes plus any user-supplied patterns."""
    if not user_excludes:
        return DEFAULT_SCAN_EXCLUDES
    merged = list(DEFAULT_SCAN_EXCLUDES)
    for pattern in user_excludes:
        if pattern not in merged:
            merged.append(pattern)
    return tuple(merged)


def matches_exclude(component_path: str, root_resolved: Path, patterns: tuple[str, ...]) -> bool:
    """Check if a component path matches any exclude pattern.

    *root_resolved* is resolved by the caller: ``resolve()`` is a realpath
    syscall walk, so a scan of a few thousand files would otherwise resolve the
    same root a few thousand times.
    """
    if not patterns:
        return False

    path = Path(component_path)
    resolved = path.resolve()
    abs_path = str(resolved)
    try:
        rel_path = str(resolved.relative_to(root_resolved))
    except ValueError:
        rel_path = component_path
    filename = path.name

    for pattern in patterns:
        if fnmatch(rel_path, pattern) or fnmatch(filename, pattern) or fnmatch(abs_path, pattern):
            return True
    return False


@contextmanager
def scanning_with_excludes(root: Path, patterns: tuple[str, ...]) -> Iterator[None]:
    """Bound discoverer file reads to the same exclude set as the inventory."""
    token = _scan_exclude.set((root.resolve(), patterns))
    try:
        yield
    finally:
        _scan_exclude.reset(token)


def is_excluded_during_scan(path: Path) -> bool:
    """True when a discoverer is running under ``scanning_with_excludes`` and *path* matches."""
    ctx = _scan_exclude.get()
    if ctx is None:
        return False
    root_resolved, patterns = ctx
    return matches_exclude(str(path), root_resolved, patterns)


def _enforce_scan_limits(root: Path, paths: list[Path], limits: ScanLimits) -> None:
    """Reject a setup whose discovered files exceed *limits* before any is read.

    Only the setup inventory is measured, so the check costs one ``stat`` per
    setup file and unrelated repository content never trips a limit. *paths* is
    expected to be exclude-filtered already, so the same file set is measured,
    hashed, and parsed.
    """
    root_resolved = root.resolve()
    total_bytes = 0
    file_count = 0

    for path in paths:
        try:
            size = path.stat().st_size
            resolved = path.resolve()
        except OSError:
            continue
        try:
            depth = len(resolved.relative_to(root_resolved).parts) - 1
        except ValueError:
            depth = 0  # user-config files live outside the scanned tree
        if depth > limits.max_depth:
            raise ScanLimitExceeded(
                f"{path} is nested {depth} directories deep, exceeding max_depth={limits.max_depth}"
            )
        file_count += 1
        if file_count > limits.max_files:
            raise ScanLimitExceeded(
                f"setup has more than max_files={limits.max_files} agent-setup files"
            )
        if size > limits.max_file_bytes:
            raise ScanLimitExceeded(
                f"{path} is {size} bytes, exceeding max_file_bytes={limits.max_file_bytes}"
            )
        total_bytes += size
        if total_bytes > limits.max_total_bytes:
            raise ScanLimitExceeded(
                f"agent-setup files exceed max_total_bytes={limits.max_total_bytes}"
            )


def discover_setup(
    name: str,
    path: str,
    user_config_dir: str | None = None,
    *,
    recursive: bool = False,
    exclude: tuple[str, ...] = (),
    limits: ScanLimits | None = None,
) -> Setup:
    """Walk a directory and discover all agent-relevant components."""
    root = Path(path)
    if not root.is_dir():
        raise FileNotFoundError(f"Setup path does not exist: {path}")

    user_dir = Path(user_config_dir) if user_config_dir else None
    exclude = merge_scan_excludes(exclude)
    root_resolved = root.resolve()

    # One sweep of the config directories feeds both the inventory and the
    # uncategorized components, and --exclude is applied once so the same files
    # are measured, hashed, and parsed.
    uncategorized = uncategorized_candidate_paths(root)
    inventory = [
        p
        for p in _collect_setup_file_paths(
            root, user_config_dir=user_dir, recursive=recursive, uncategorized=uncategorized
        )
        if not matches_exclude(str(p), root_resolved, exclude)
    ]
    applied_limits = limits or ScanLimits()
    _enforce_scan_limits(root, inventory, applied_limits)

    components: list[ParsedComponent] = []

    # Discoverers still glob the tree; scanning_with_excludes stops them from
    # reading excluded files. The post-filter drops dummy components.
    with scanning_with_excludes(root, exclude):
        for discoverer in get_all_discoverers():
            components.extend(
                discoverer.discover(root, user_config_dir=user_dir, recursive=recursive)
            )

        components = _deduplicate_components(components)
        components.extend(_discover_uncategorized(root, components, uncategorized))

        if not components and (root / "SKILL.md").exists():
            skill_md = root / "SKILL.md"
            if not is_excluded_during_scan(skill_md):
                components.append(
                    _parse_file(
                        skill_md,
                        ComponentType.SKILL,
                        name=root.name,
                        source_tool="unknown",
                    )
                )

    components = [c for c in components if not matches_exclude(c.path, root_resolved, exclude)]

    detected = _detect_tools(root)
    fp = fingerprint_setup(path, user_config_dir=user_config_dir, paths=inventory)
    total = sum(c.token_count for c in components)

    return Setup(
        name=name,
        path=path,
        fingerprint=fp,
        components=list(components),
        total_tokens=total,
        detected_tools=detected,
        limits=applied_limits,
        inventory_paths=tuple(str(p.resolve()) for p in inventory),
    )


def collect_setup_file_paths(
    root: Path,
    user_config_dir: Path | None = None,
    *,
    recursive: bool = False,
) -> list[Path]:
    """Compatibility wrapper around the shared setup inventory."""
    return _collect_setup_file_paths(root, user_config_dir=user_config_dir, recursive=recursive)


def _detect_tools(root: Path) -> tuple[str, ...]:
    tools = []
    for discoverer in get_all_discoverers():
        if discoverer.detect(root):
            tools.append(discoverer.tool_name)
    return tuple(tools)


def _deduplicate_components(components: list[ParsedComponent]) -> list[ParsedComponent]:
    seen: set[str] = set()
    deduped: list[ParsedComponent] = []
    for c in components:
        resolved = str(Path(c.path).resolve())
        if resolved not in seen:
            seen.add(resolved)
            deduped.append(c)
    return deduped


def _discover_uncategorized(
    root: Path,
    known_components: list[ParsedComponent],
    candidates: list[Path] | None = None,
) -> list[ParsedComponent]:
    """Parse config-directory files that no tool-specific discoverer claimed.

    *candidates* is the shared sweep from ``uncategorized_candidate_paths``;
    it is re-collected when a caller does not supply one.
    """
    known_paths = {str(Path(c.path).resolve()) for c in known_components}
    results = []

    skill_dirs = set()
    for c in known_components:
        if c.component_type == ComponentType.SKILL:
            skill_dirs.add(str(Path(c.path).parent.resolve()))

    if candidates is None:
        candidates = uncategorized_candidate_paths(root)

    for f in candidates:
        resolved = str(f.resolve())
        if resolved in known_paths:
            continue
        if any(resolved.startswith(sd + "/") for sd in skill_dirs):
            continue
        results.append(_parse_file(f, ComponentType.UNCATEGORIZED, name=str(f.relative_to(root))))

    return results
