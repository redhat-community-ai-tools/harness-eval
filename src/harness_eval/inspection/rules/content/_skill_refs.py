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
    r"|the\s+users?\s+(?:should|must|can|to|needs?|sees?|runs?|types?|will|may"
    r"|invokes?|calls?|executes?|is|are)"
    r"|\b(?:they|you|users?|operators?)\s+(?:run|type|invoke|call|execute)s?\s*[`\"']?$"
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


def _followed_by_extension(body: str, match: re.Match[str]) -> bool:
    end = match.end()
    return end < len(body) and body[end] == "." and end + 1 < len(body) and body[end + 1].isalpha()


def _is_human_directed(body: str, match_start: int, match_end: int | None = None) -> bool:
    window = _preceding_window(body, match_start)
    if _HUMAN_DIRECTED_RE.search(window):
        return True
    if match_end is not None:
        return bool(_FOLLOWING_HUMAN_RE.search(body[match_end : match_end + 100]))
    return False


_INVOKE_VERB_RE = re.compile(
    r"\b(?:run(?:ning|s)?|invoke[sd]?|invoking|call(?:s|ing|ed)?|trigger(?:s|ing|ed)?"
    r"|execute[sd]?|executing|use|using|start(?:s|ing)?|launch(?:es|ing)?|delegate[sd]?"
    r"|delegating|chain(?:s|ing)?|then|type)\s*(?:the\s+|to\s+|by\s+running\s+)?[`\"']?$",
    re.IGNORECASE,
)

_FOLLOWING_HUMAN_RE = re.compile(
    r"^[^.\n!?]{0,80}?\b(?:manually|yourself|by hand)\b", re.IGNORECASE
)

_LINE_START_RE = re.compile(r"(?:^|\n)[ \t]*(?:[-*+]|\d+[.)])?[ \t]*$")


def _inside_quotes(body: str, pos: int) -> bool:
    """True when ``pos`` sits inside a double-quoted string on its line.

    A slash token inside quotes is displayed text ("Run /clarify-intent
    first."), addressed to whoever reads the message, not an instruction the
    agent executes.
    """
    line_start = body.rfind("\n", 0, pos) + 1
    return body.count('"', line_start, pos) % 2 == 1


def _slash_is_invocation(body: str, match: re.Match[str]) -> bool:
    """Decide whether a ``/name`` token is an invocation or a bare mention.

    A slash token is an invocation when it follows an invocation verb in the
    same clause (``run /deploy``, ``then invoke `/beta```) or opens a line or
    list item. Backticks alone are not enough: a skill that documents another
    skill's user-facing commands (``5. `/capture keywords {site}```) is
    describing what the operator types, not delegating. A slash token that
    continues into a path (``/docs/api``) or sits after a locative preposition
    with no verb (``output goes to /build``) is a mention.
    """
    start, end = match.start(), match.end()
    if end < len(body) and body[end] == "/":
        return False
    if _inside_quotes(body, start):
        return False
    window = body[max(0, start - 40) : start]
    if _INVOKE_VERB_RE.search(window):
        return True
    at_line_start = start == 0 or "\n" in window or window.strip() == ""
    return bool(_LINE_START_RE.search(window)) and at_line_start


def extract_mentions(body: str, own_name: str) -> set[str]:
    """Extract bare ``/name`` mentions that do not qualify as invocations.

    These are a lower-confidence signal suitable for reachability questions
    ("is anything pointing at this skill at all?") but never for security or
    cycle findings, where a manufactured edge is worse than a missed one.
    """
    refs: set[str] = set()
    if not body:
        return refs
    for match in _SLASH_CMD_RE.finditer(body):
        name = match.group(1)
        if _followed_by_extension(body, match) or _slash_is_invocation(body, match):
            continue
        if match.end() < len(body) and body[match.end()] == "/":
            continue  # multi-segment path, not a component mention
        if name != own_name and name.lower() not in _STOPWORDS and len(name) > 1:
            refs.add(name)
    return refs


def extract_references(body: str, own_name: str) -> set[str]:
    """Extract skill/command references from body text, excluding self-references.

    Creates edges only from explicit invocation constructs, not from CLI flags,
    filesystem paths that collide with a component name, or phrasing addressed
    to the human operator. Use :func:`extract_mentions` for the lower tier.
    """
    refs: set[str] = set()
    if not body:
        return refs

    for match in _SLASH_CMD_RE.finditer(body):
        name = match.group(1)
        if _followed_by_extension(body, match):
            continue
        if not _slash_is_invocation(body, match):
            continue
        if (
            name != own_name
            and name.lower() not in _STOPWORDS
            and len(name) > 1
            and not _is_human_directed(body, match.start(), match.end())
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
        if _followed_by_extension(body, match) or _inside_quotes(body, match.start()):
            continue
        if (
            name != own_name
            and name.lower() not in _STOPWORDS
            and len(name) > 1
            and not _is_human_directed(body, match.start(), match.end())
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
