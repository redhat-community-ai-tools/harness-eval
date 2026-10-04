"""Small JSONC normalizer for client configuration files."""

from __future__ import annotations


def strip_jsonc(raw: str) -> str:
    """Remove JSONC comments and trailing commas without changing strings."""
    uncommented: list[str] = []
    index = 0
    in_string = False
    escaped = False
    while index < len(raw):
        char = raw[index]
        next_char = raw[index + 1] if index + 1 < len(raw) else ""
        if in_string:
            uncommented.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            uncommented.append(char)
            index += 1
        elif char == "/" and next_char == "/":
            index += 2
            while index < len(raw) and raw[index] not in "\r\n":
                index += 1
        elif char == "/" and next_char == "*":
            index += 2
            while index + 1 < len(raw) and raw[index : index + 2] != "*/":
                if raw[index] in "\r\n":
                    uncommented.append(raw[index])
                index += 1
            index = min(index + 2, len(raw))
        else:
            uncommented.append(char)
            index += 1

    text = "".join(uncommented)
    normalized: list[str] = []
    index = 0
    in_string = False
    escaped = False
    while index < len(text):
        char = text[index]
        if in_string:
            normalized.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
        elif char == ",":
            lookahead = index + 1
            while lookahead < len(text) and text[lookahead].isspace():
                lookahead += 1
            if lookahead < len(text) and text[lookahead] in "}]":
                index += 1
                continue
        normalized.append(char)
        index += 1
    return "".join(normalized)
