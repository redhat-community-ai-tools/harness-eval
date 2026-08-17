"""Setup fingerprinting for change detection and deduplication."""

from __future__ import annotations

import hashlib
from pathlib import Path

RELEVANT_PATTERNS = [
    "CLAUDE.md",
    "**/CLAUDE.md",
    "skills/**/*.md",
    "commands/**/*.md",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude/agents/**/*.md",
    ".mcp.json",
    "**/.mcp.json",
    ".cursor/rules/*.mdc",
    ".cursor/rules/**/*.mdc",
    ".cursorrules",
    "**/.cursorrules",
    ".cursor/commands/*.md",
    ".cursor/skills/**/*.md",
    ".cursor/hooks.json",
    ".cursor/mcp.json",
    # Copilot
    ".github/skills/**/SKILL.md",
    ".github/prompts/*.prompt.md",
    ".github/prompts/*.md",
    ".github/agents/*.agent.md",
    ".github/agents/*.md",
    # Gemini CLI
    "GEMINI.md",
    ".gemini/commands/*.toml",
    ".gemini/commands/*.md",
    # OpenCode
    "AGENTS.md",
    ".opencode/commands/*.md",
    ".opencode/agents/*.md",
    # Codex CLI
    ".codex/instructions.md",
    ".codex/setup.sh",
    "codex.json",
    # Third-party modules
    ".lola/modules/**/SKILL.md",
    ".lola/modules/**/commands/*.md",
    ".lola/modules/**/agents/*.md",
]


def fingerprint_setup(
    setup_path: str,
    user_config_dir: str | None = None,
) -> str:
    """Compute a stable SHA256 of all agent-relevant files in a setup directory."""
    root = Path(setup_path)
    if not root.is_dir():
        raise FileNotFoundError(f"Setup path does not exist: {setup_path}")

    file_hashes: list[tuple[str, str]] = []

    for pattern in RELEVANT_PATTERNS:
        for filepath in sorted(root.glob(pattern)):
            if filepath.is_file():
                rel = str(filepath.relative_to(root))
                content_hash = hashlib.sha256(filepath.read_bytes()).hexdigest()
                file_hashes.append((rel, content_hash))

    user_dir = Path(user_config_dir) if user_config_dir else None
    if user_dir and user_dir.is_dir():
        user_global = user_dir / "CLAUDE.md"
        if user_global.is_file():
            content_hash = hashlib.sha256(user_global.read_bytes()).hexdigest()
            file_hashes.append(("~user/CLAUDE.md", content_hash))
        projects_dir = user_dir / "projects"
        if projects_dir.is_dir():
            for f in sorted(projects_dir.glob("*/CLAUDE.md")):
                if f.is_file():
                    rel = f"~user/projects/{f.parent.name}/CLAUDE.md"
                    content_hash = hashlib.sha256(f.read_bytes()).hexdigest()
                    file_hashes.append((rel, content_hash))

    file_hashes.sort(key=lambda x: x[0])

    combined = hashlib.sha256()
    for rel_path, content_hash in file_hashes:
        combined.update(f"{rel_path}:{content_hash}\n".encode())

    return combined.hexdigest()


def fingerprints_match(a: str, b: str) -> bool:
    return a == b
