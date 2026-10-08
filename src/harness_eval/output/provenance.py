"""What a scan result was computed from.

A lint result is only usable as evidence downstream (a merge policy, an audit
record) if it says which files, which revision, and which rule set produced
it. ``ScanEvidence`` carries that: the setup fingerprint the inventory already
computes, the enclosing git revision, a digest of the effective rule catalog
and severities, and what a baseline hid. Everything is read from the
filesystem; no subprocess, no network.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from harness_eval.core.types import Setup
    from harness_eval.inspection.registry import RuleCatalog
    from harness_eval.inspection.types import Rule

_SHA_RE = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")
_MAX_ANCESTORS = 32


@dataclass(frozen=True)
class ScanEvidence:
    setup_fingerprint: str
    scan_root: str
    vcs_revision: str | None
    rules_digest: str
    rules_count: int
    target_rules_loaded: bool
    config_digest: str
    vcs_remote: str | None = None
    preset: str | None = None
    baseline_digest: str | None = None
    baseline_suppressed: int = 0
    inventory_files: int = 0
    excludes: tuple[str, ...] = ()
    limits: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "setup_fingerprint": self.setup_fingerprint,
            "scan_root": self.scan_root,
            "vcs": {"revision": self.vcs_revision, "remote": self.vcs_remote},
            "rules": {
                "digest": self.rules_digest,
                "count": self.rules_count,
                "target_rules_loaded": self.target_rules_loaded,
            },
            "config": {"preset": self.preset, "digest": self.config_digest},
            "baseline": {"digest": self.baseline_digest, "suppressed": self.baseline_suppressed},
            "inventory": {
                "files": self.inventory_files,
                "excludes": list(self.excludes),
                "limits": dict(self.limits),
            },
        }


def _git_dir(start: Path) -> Path | None:
    """The ``.git`` directory governing *start*, following worktree pointers."""
    cur = start.resolve()
    if cur.is_file():
        cur = cur.parent
    for _ in range(_MAX_ANCESTORS):
        candidate = cur / ".git"
        if candidate.is_dir():
            return candidate
        if candidate.is_file():
            try:
                text = candidate.read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                return None
            if text.startswith("gitdir:"):
                target = Path(text[len("gitdir:") :].strip())
                return (cur / target).resolve() if not target.is_absolute() else target
            return None
        if cur.parent == cur:
            return None
        cur = cur.parent
    return None


def _read_ref(git_dir: Path, ref: str) -> str | None:
    """Resolve *ref* (``refs/heads/x``) from loose refs or packed-refs."""
    search_dirs = [git_dir]
    common = git_dir / "commondir"
    if common.is_file():
        try:
            rel = common.read_text(encoding="utf-8", errors="replace").strip()
            search_dirs.append((git_dir / rel).resolve())
        except OSError:
            pass
    for d in search_dirs:
        loose = d / ref
        if loose.is_file():
            try:
                sha = loose.read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                continue
            return sha if _SHA_RE.match(sha) else None
    for d in search_dirs:
        packed = d / "packed-refs"
        if not packed.is_file():
            continue
        try:
            lines = packed.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            if line.startswith(("#", "^")) or " " not in line:
                continue
            sha, _, name = line.partition(" ")
            if name.strip() == ref and _SHA_RE.match(sha):
                return sha
    return None


def git_revision(root: Path | str) -> str | None:
    """HEAD commit of the git checkout enclosing *root*, or None.

    Read from ``.git`` directly so the result is the same with or without a
    git binary on the PATH. A dirty worktree is not detected; the setup
    fingerprint covers the content that was actually scanned.
    """
    git_dir = _git_dir(Path(root))
    if git_dir is None:
        return None
    head = git_dir / "HEAD"
    try:
        text = head.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    if text.startswith("ref:"):
        return _read_ref(git_dir, text[len("ref:") :].strip())
    return text if _SHA_RE.match(text) else None


_SSH_REMOTE_RE = re.compile(r"^(?:ssh://)?(?:[\w.-]+@)?([\w.-]+)[:/](.+?)(?:\.git)?/?$")


def git_remote_url(root: Path | str, remote: str = "origin") -> str | None:
    """The fetch URL of *remote* from ``.git/config``, as an https URL without
    credentials, or None. Read from the file; no git binary involved."""
    git_dir = _git_dir(Path(root))
    if git_dir is None:
        return None
    candidates = [git_dir / "config"]
    common = git_dir / "commondir"
    if common.is_file():
        with contextlib.suppress(OSError):
            candidates.append((git_dir / common.read_text().strip()).resolve() / "config")
    for cfg in candidates:
        try:
            lines = cfg.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        section = None
        for raw in lines:
            line = raw.strip()
            if line.startswith("["):
                section = line
                continue
            if section == f'[remote "{remote}"]' and line.startswith("url"):
                _, _, value = line.partition("=")
                return _normalize_remote(value.strip())
    return None


def _normalize_remote(url: str) -> str | None:
    if not url:
        return None
    if url.startswith(("http://", "https://")):
        scheme, _, rest = url.partition("://")
        rest = rest.rsplit("@", 1)[-1]  # drop embedded credentials
        return f"{scheme}://{rest.removesuffix('.git').rstrip('/')}"
    m = _SSH_REMOTE_RE.match(url)
    if m and "." in m.group(1):
        return f"https://{m.group(1)}/{m.group(2)}"
    return None


def rules_digest(rules: Iterable[Rule]) -> str:
    """Order-independent sha256 over (id, tier, scope, default severity) of *rules*."""
    lines = sorted(
        f"{r.meta.id}|{r.meta.tier}|{r.meta.scope}|{r.meta.default_severity.value}" for r in rules
    )
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def config_digest(config_rules: dict[str, Any] | None) -> str:
    """sha256 over the effective rule configuration (severities and options)."""
    canonical = json.dumps(config_rules or {}, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def file_digest(path: Path | str) -> str | None:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def collect_scan_evidence(
    setup: Setup,
    catalog: RuleCatalog,
    config_rules: dict[str, Any] | None,
    *,
    preset: str | None = None,
    target_rules_loaded: bool = False,
    excludes: Iterable[str] = (),
    baseline_path: Path | str | None = None,
    baseline_suppressed: int = 0,
) -> ScanEvidence:
    limits = setup.limits
    return ScanEvidence(
        setup_fingerprint=setup.fingerprint,
        scan_root=str(Path(setup.path).resolve()),
        vcs_revision=git_revision(setup.path),
        vcs_remote=git_remote_url(setup.path),
        rules_digest=rules_digest(catalog.all()),
        rules_count=len(catalog.all()),
        target_rules_loaded=target_rules_loaded,
        config_digest=config_digest(config_rules),
        preset=preset,
        baseline_digest=file_digest(baseline_path) if baseline_path else None,
        baseline_suppressed=baseline_suppressed,
        inventory_files=len(setup.inventory_paths or ()),
        excludes=tuple(excludes),
        limits=(
            {
                "max_file_bytes": limits.max_file_bytes,
                "max_total_bytes": limits.max_total_bytes,
                "max_files": limits.max_files,
                "max_depth": limits.max_depth,
            }
            if limits is not None
            else {}
        ),
    )


__all__ = [
    "ScanEvidence",
    "collect_scan_evidence",
    "config_digest",
    "file_digest",
    "git_remote_url",
    "git_revision",
    "rules_digest",
]
