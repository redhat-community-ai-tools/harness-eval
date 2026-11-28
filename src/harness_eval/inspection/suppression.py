from __future__ import annotations

import logging
import os
import re

logger = logging.getLogger(__name__)

_FILE_WIDE_RE = re.compile(r"<!--\s*evaluator-ignore:\s*([\w/,\s-]+)\s*-->", re.IGNORECASE)
_NEXT_LINE_RE = re.compile(
    r"<!--\s*evaluator-ignore-next-line:\s*([\w/,\s-]+)\s*-->", re.IGNORECASE
)

# Hash-comment variants for YAML and TOML files.
_HASH_FILE_WIDE_RE = re.compile(r"#\s*evaluator-ignore:\s*([\w/,\s-]+)", re.IGNORECASE)
_HASH_NEXT_LINE_RE = re.compile(r"#\s*evaluator-ignore-next-line:\s*([\w/,\s-]+)", re.IGNORECASE)

_HASH_COMMENT_EXTENSIONS = frozenset({".yaml", ".yml", ".toml"})


def _find_hash_comment(line: str) -> int:
    """Return the index of the first ``#`` that starts a comment, or -1.

    A ``#`` inside a single- or double-quoted string is not a comment.
    Backslash escapes are honoured inside double-quoted strings (YAML and
    TOML basic strings).  Single-quoted strings use no backslash escaping
    in either format.
    """
    in_single = False
    in_double = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and in_double:
            i += 2  # skip escaped character in double-quoted string
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "'" and not in_double:
            in_single = not in_single
        elif ch == "#" and not in_single and not in_double:
            return i
        i += 1
    return -1


def _extract_rule_ids(match: re.Match[str]) -> set[str]:
    """Split the captured group into individual rule IDs."""
    return {r.strip() for r in match.group(1).split(",")}


def parse_suppressions(
    raw_content: str,
    file_path: str = "",
) -> dict[int | None, set[str]]:
    """Parse suppression comments from file content.

    Returns a dict mapping:
      - line number (1-indexed) -> set of suppressed rule IDs (next-line suppression)
      - None -> set of suppressed rule IDs (file-wide suppression)

    Comment syntax is chosen by file extension:

    * ``.yaml``, ``.yml``, ``.toml``: ``# evaluator-ignore: rule/id``
      and ``# evaluator-ignore-next-line: rule/id``.  A ``#`` inside a
      quoted string is not treated as a comment.
    * All other files (Markdown, etc.): the HTML-comment form
      ``<!-- evaluator-ignore: rule/id -->``.
    """
    suppressions: dict[int | None, set[str]] = {}
    lines = raw_content.split("\n")
    unknown_ids: list[str] = []

    ext = os.path.splitext(file_path)[1].lower() if file_path else ""
    use_hash = ext in _HASH_COMMENT_EXTENSIONS

    for i, line in enumerate(lines):
        if use_hash:
            comment_start = _find_hash_comment(line)
            if comment_start < 0:
                continue
            comment_text = line[comment_start:]

            file_match = _HASH_FILE_WIDE_RE.match(comment_text)
            if file_match:
                rule_ids = _extract_rule_ids(file_match)
                suppressions.setdefault(None, set()).update(rule_ids)
                unknown_ids.extend(rule_ids)
                continue

            next_match = _HASH_NEXT_LINE_RE.match(comment_text)
            if next_match:
                rule_ids = _extract_rule_ids(next_match)
                target_line = i + 2  # 1-indexed, next line
                suppressions.setdefault(target_line, set()).update(rule_ids)
                unknown_ids.extend(rule_ids)
        else:
            file_match = _FILE_WIDE_RE.search(line)
            if file_match:
                rule_ids = _extract_rule_ids(file_match)
                suppressions.setdefault(None, set()).update(rule_ids)
                unknown_ids.extend(rule_ids)
                continue

            next_line_match = _NEXT_LINE_RE.search(line)
            if next_line_match:
                rule_ids = _extract_rule_ids(next_line_match)
                target_line = i + 2  # 1-indexed, next line
                suppressions.setdefault(target_line, set()).update(rule_ids)
                unknown_ids.extend(rule_ids)

    _warn_unknown_rule_ids(unknown_ids, file_path)

    return suppressions


def _warn_unknown_rule_ids(rule_ids: list[str], file_path: str) -> None:
    """Log warnings for suppressed rule IDs that don't match any registered rule."""
    from harness_eval.inspection.registry import DEPRECATED_RULES, get_rule, suggest_rule_id

    for rule_id in rule_ids:
        if get_rule(rule_id) is not None or rule_id in DEPRECATED_RULES:
            continue
        suggestions = suggest_rule_id(rule_id)
        location = f" in {file_path}" if file_path else ""
        if suggestions:
            logger.warning(
                "Suppression references unknown rule '%s'%s. Did you mean: %s?",
                rule_id,
                location,
                ", ".join(suggestions),
            )
        else:
            logger.warning(
                "Suppression references unknown rule '%s'%s.",
                rule_id,
                location,
            )


def is_suppressed(
    suppressions: dict[int | None, set[str]],
    rule_id: str,
    line: int | None,
) -> bool:
    """Check if a rule is suppressed at a given line."""
    file_wide = suppressions.get(None, set())
    if rule_id in file_wide:
        return True

    if line is not None:
        line_specific = suppressions.get(line, set())
        if rule_id in line_specific:
            return True

    return False
