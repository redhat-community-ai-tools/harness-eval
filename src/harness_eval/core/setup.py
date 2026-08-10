"""Setup discovery: walk a directory and parse all agent components."""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path

from harness_eval.core.discoverers import get_all_discoverers
from harness_eval.core.discoverers.base import parse_file as _parse_file
from harness_eval.core.fingerprint import fingerprint_setup
from harness_eval.core.types import (
    ComponentType,
    ParsedComponent,
    Setup,
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


def _matches_exclude(component_path: str, root: Path, patterns: tuple[str, ...]) -> bool:
    """Check if a component path matches any exclude pattern."""
    abs_path = str(Path(component_path).resolve())
    try:
        rel_path = str(Path(component_path).resolve().relative_to(root.resolve()))
    except ValueError:
        rel_path = component_path
    filename = Path(component_path).name

    for pattern in patterns:
        if fnmatch(rel_path, pattern) or fnmatch(filename, pattern) or fnmatch(abs_path, pattern):
            return True
    return False


def discover_setup(
    name: str,
    path: str,
    user_config_dir: str | None = None,
    *,
    recursive: bool = False,
    exclude: tuple[str, ...] = (),
) -> Setup:
    """Walk a directory and discover all agent-relevant components."""
    root = Path(path)
    if not root.is_dir():
        raise FileNotFoundError(f"Setup path does not exist: {path}")

    user_dir = Path(user_config_dir) if user_config_dir else None
    exclude = merge_scan_excludes(exclude)

    components: list[ParsedComponent] = []

    for discoverer in get_all_discoverers():
        components.extend(discoverer.discover(root, user_config_dir=user_dir, recursive=recursive))

    components = _deduplicate_components(components)
    components.extend(_discover_uncategorized(root, components))

    if not components and (root / "SKILL.md").exists():
        comp = _parse_file(
            root / "SKILL.md",
            ComponentType.SKILL,
            name=root.name,
            source_tool="unknown",
        )
        components.append(comp)

    if exclude:
        components = [c for c in components if not _matches_exclude(c.path, root, exclude)]

    detected = _detect_tools(root)
    fp = fingerprint_setup(path, user_config_dir=user_config_dir)
    total = sum(c.token_count for c in components)

    return Setup(
        name=name,
        path=path,
        fingerprint=fp,
        components=list(components),
        total_tokens=total,
        detected_tools=detected,
    )


def collect_setup_file_paths(
    root: Path,
    user_config_dir: Path | None = None,
    *,
    recursive: bool = False,
) -> list[Path]:
    """Return deduplicated file paths that ``discover_setup`` would scan.

    This is the single source of truth for which files constitute an agent
    setup.  Both ``discover_setup`` (for parsing) and watch mode (for
    monitoring) consume this list so they stay in sync automatically.
    """
    paths: list[Path] = []

    for discoverer in get_all_discoverers():
        paths.extend(
            discoverer.collect_paths(root, user_config_dir=user_config_dir, recursive=recursive)
        )

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[Path] = []
    for p in paths:
        resolved = str(p.resolve())
        if resolved not in seen:
            seen.add(resolved)
            unique.append(p)

    return unique


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
    root: Path, known_components: list[ParsedComponent]
) -> list[ParsedComponent]:
    known_paths = {str(Path(c.path).resolve()) for c in known_components}
    results = []

    skill_dirs = set()
    for c in known_components:
        if c.component_type == ComponentType.SKILL:
            skill_dirs.add(str(Path(c.path).parent.resolve()))

    scan_dirs = [
        root / ".claude",
        root / ".cursor",
        root / ".github",
        root / ".gemini",
        root / ".opencode",
        root / ".lola",
        root / "skills",
        root / "commands",
    ]

    for scan_dir in scan_dirs:
        if not scan_dir.is_dir():
            continue
        for f in sorted(scan_dir.rglob("*")):
            if not f.is_file():
                continue
            if ".git" in f.parts or "__pycache__" in f.parts:
                continue
            resolved = str(f.resolve())
            if resolved in known_paths:
                continue
            if f.name.startswith("."):
                continue
            if any(resolved.startswith(sd + "/") for sd in skill_dirs):
                continue
            results.append(
                _parse_file(f, ComponentType.UNCATEGORIZED, name=str(f.relative_to(root)))
            )

    return results
