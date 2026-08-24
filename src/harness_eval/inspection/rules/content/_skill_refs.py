"""Shared skill-reference patterns for content rules."""

from __future__ import annotations

import re
from pathlib import Path

_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "the",
        "and",
        "or",
        "but",
        "in",
        "on",
        "at",
        "to",
        "for",
        "of",
        "with",
        "by",
        "from",
        "as",
        "is",
        "was",
        "are",
        "were",
        "be",
        "been",
        "being",
        "have",
        "has",
        "had",
        "do",
        "does",
        "did",
        "will",
        "would",
        "could",
        "should",
        "may",
        "might",
        "shall",
        "can",
        "not",
        "no",
        "if",
        "then",
        "else",
        "when",
        "where",
        "how",
        "what",
        "which",
        "who",
        "whom",
        "this",
        "that",
        "these",
        "those",
        "it",
        "its",
        "all",
        "each",
        "every",
        "any",
        "some",
        "up",
        "out",
        "so",
        "than",
        "too",
        "very",
        "just",
        "about",
        "above",
        "after",
        "before",
        "between",
        "into",
        "through",
        "during",
        "until",
        "against",
        "over",
        "under",
        "again",
    }
)

_FILE_EXT_RE = re.compile(r"\.\w{1,5}$")

_SLASH_CMD_RE = re.compile(r"(?<![.\w/\-<>])/([\w][\w-]+)")

_DECL_COLON_RE = re.compile(
    r"(?<!-)(?:skill|command):\s*[\"'`]?([\w][\w-]+)[\"'`]?",
    re.IGNORECASE,
)

_DECL_SPACE_RE = re.compile(
    r"(?<!-)(?:skill|command)\s+(\w+(?:-\w+)+)",
    re.IGNORECASE,
)

_INVOKE_MARKED_RE = re.compile(
    r"(?:invokes?|calls?|triggers?|runs?)\s+"
    r"(?:"
    r"/([\w][\w-]+)"  # /name
    r"|[`\"']([\w][\w-]+)[`\"']"  # `name` or "name" or 'name'
    r"|the\s+/([\w][\w-]+)"  # the /name
    r"|the\s+[`\"']([\w][\w-]+)[`\"']"  # the `name`
    r"|the\s+([\w]+(?:-[\w]+)+)\s+(?:skill|command)"  # the name skill/command
    r"|([\w]+(?:-[\w]+)+)"  # hyphenated-slug
    r")",
    re.IGNORECASE,
)

SKILL_REF_PATTERNS = [_SLASH_CMD_RE, _DECL_COLON_RE, _DECL_SPACE_RE, _INVOKE_MARKED_RE]


def match_name(match: re.Match[str]) -> str | None:
    """Extract the captured name from any SKILL_REF_PATTERNS match."""
    for i in range(1, match.lastindex + 1 if match.lastindex else 1):
        g = match.group(i)
        if g:
            return g
    return None


_HUMAN_DIRECTED_RE = re.compile(
    r"(?:tell|ask|advise|remind|instruct)\s+the\s+user"
    r"|the\s+user\s+(?:should|must|can|to|needs)"
    r"|\bmanually\b",
    re.IGNORECASE,
)


def _preceding_window(body: str, match_start: int, max_chars: int = 120) -> str:
    start = max(0, match_start - max_chars)
    window = body[start:match_start]
    best = -1
    for sep in (".", "!", "?", "\n"):
        idx = window.rfind(sep)
        if idx > best:
            best = idx
    if best >= 0:
        window = window[best + 1 :]
    return window


def _is_human_directed(body: str, match_start: int) -> bool:
    window = _preceding_window(body, match_start)
    return bool(_HUMAN_DIRECTED_RE.search(window))


def extract_references(body: str, own_name: str) -> set[str]:
    """Extract skill/command references from body text, excluding self-references.

    Creates edges only from explicit invocation constructs, not from CLI flags
    or phrasing addressed to the human operator.
    """
    refs: set[str] = set()
    if not body:
        return refs

    for match in _SLASH_CMD_RE.finditer(body):
        name = match.group(1)
        if _FILE_EXT_RE.search(name):
            continue
        if (
            name != own_name
            and name.lower() not in _STOPWORDS
            and len(name) > 1
            and not _is_human_directed(body, match.start())
        ):
            refs.add(name)

    for pattern in (_DECL_COLON_RE, _DECL_SPACE_RE):
        for match in pattern.finditer(body):
            name = match.group(1)
            if name != own_name and name.lower() not in _STOPWORDS and len(name) > 1:
                refs.add(name)

    for match in _INVOKE_MARKED_RE.finditer(body):
        name = (
            match.group(1)
            or match.group(2)
            or match.group(3)
            or match.group(4)
            or match.group(5)
            or match.group(6)
        )
        if not name:
            continue
        if (
            name != own_name
            and name.lower() not in _STOPWORDS
            and len(name) > 1
            and not _is_human_directed(body, match.start())
        ):
            refs.add(name)

    return refs


def find_project_root(start_path: str) -> Path | None:
    """Walk up from a path to find the project root (containing CLAUDE.md or .claude/)."""
    current = Path(start_path).resolve()
    for _ in range(10):
        if (current / "CLAUDE.md").is_file() or (current / ".claude").is_dir():
            return current
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None
