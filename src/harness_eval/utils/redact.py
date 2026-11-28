"""Redact likely secrets before sending text to remote LLM providers (HE-2)."""

from __future__ import annotations

import re

from harness_eval.data import load_secret_prefixes

_REDACTED = "[REDACTED]"

_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-+/=]{8,}\b")

# A value: an already redacted one (so a second pass changes nothing), a
# quoted string, so that a secret containing spaces is taken whole, or a run
# of non-blank characters.
_VALUE_RE = re.compile(
    re.escape(_REDACTED) + r"|\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'|`[^`\n]*`|\S+"
)

# `KEY=value`, `key: value` and the JSON spelling `"key": "value"`. Only the
# key and the separator are matched here; whether the key names a credential
# is decided on the capture, and the value is read afterwards. Matching the
# value in the same expression would let a non-credential key swallow the
# credential that follows it (`"env": {"API_KEY": ...`).
_KEYED_RE = re.compile(r"(?<![\w-])(-{0,2}[A-Za-z_][\w.-]*)([\"'`]?[ \t]*[:=][ \t]*)")

# `--token value`: a flag and its value separated by blanks.
_FLAG_RE = re.compile(r"(?<!\S)(--?[A-Za-z][\w-]*)([ \t]+)(?=[^\s-])")
# In prose a flag is followed by an ordinary word ("pass --token to the
# command"). An unquoted value this short is not worth hiding.
_MIN_BARE_FLAG_VALUE = 6

# An Authorization header keeps a scheme it recognises, which says how the
# credential is used and is not secret. With any other first word (`NTLM`,
# `AWS4-HMAC-SHA256`, or the credential itself) nothing tells the scheme from
# the secret, so that word and the one after it are both hidden.
_AUTHORIZATION_RE = re.compile(
    r"(?i)\b((?:proxy-)?authorization[\"']?[ \t]*[:=][ \t]*[\"']?)"
    r"(?:((?:basic|bearer|token|digest|negotiate|apikey|key|bot|ssws)[ \t]+)[^\s\"',;]+"
    r"|" + re.escape(_REDACTED) + r"|[^\s\"',;]+(?:[ \t]+[^\s\"',;]+)?)"
)

# A quote, and any closing punctuation after it, at the end of an unquoted
# value: `config: "API_KEY=abc"` gives the value `abc"`, whose quote closes
# the string around the pair and is not part of the secret.
_CLOSING_QUOTE_RE = re.compile(r"[\"'`][)}\],;]*$")

# `scheme://user:password@host`, and `scheme://token@host` when the user part
# is long enough to be a token and not a login name (`git@`, `deploy@`).
_URL_USERINFO_RE = re.compile(
    r"\b([A-Za-z][A-Za-z0-9+.-]*://)([^\s/@:\"'`<>]+)(?::([^\s/@\"'`<>]*))?@(?=[^\s/@])"
)
_MIN_TOKEN_USERINFO = 16

_KEY_WORD_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")

# A word of a key that names a credential when it ends the word (`mysecret`,
# `githubtoken`) or, except for `token`, when it starts it (`secrets`,
# `passwordhash`). `tokens`, `tokenizer` and `tokenize` are not credentials.
_CREDENTIAL_SUFFIXES = (
    "token",
    "secret",
    "password",
    "passwd",
    "passphrase",
    "credential",
    "apikey",
)
_CREDENTIAL_PREFIXES = ("secret", "password", "passwd", "passphrase", "credential")
# `key` names a credential only after one of these (`api_key`, `privateKey`).
_KEY_QUALIFIERS = frozenset({"api", "private", "access", "secret", "signing", "encryption"})
# `token` next to one of these counts model tokens (`token_budget`, `max_token_count`).
_TOKEN_MEASURES = frozenset(
    {"budget", "count", "limit", "usage", "window", "size", "length", "max", "min", "total"}
)


def _names_credential(key: str) -> bool:
    words = [w.lower() for w in _KEY_WORD_RE.findall(key)]
    for i, word in enumerate(words):
        before = words[i - 1] if i else ""
        after = words[i + 1] if i + 1 < len(words) else ""
        if word == "key" and before in _KEY_QUALIFIERS:
            return True
        if word.startswith(_CREDENTIAL_PREFIXES):
            return True
        if word.endswith(_CREDENTIAL_SUFFIXES):
            if word == "token" and (before in _TOKEN_MEASURES or after in _TOKEN_MEASURES):
                continue
            return True
    return False


def _secret_end(value: re.Match[str]) -> int:
    """Where the secret ends inside a matched value."""
    text = value.group(0)
    if text == _REDACTED or text[0] in "\"'`":
        return value.end()
    closing = _CLOSING_QUOTE_RE.search(text)
    if closing is not None and closing.start() > 0:
        return value.start() + closing.start()
    return value.end()


def _redact_keyed(text: str) -> str:
    out: list[str] = []
    pos = 0
    while True:
        match = _KEYED_RE.search(text, pos)
        if match is None:
            break
        if not _names_credential(match.group(1)):
            # Resume right after the key, so a credential key inside this
            # key's value is still examined.
            out.append(text[pos : match.end(1)])
            pos = match.end(1)
            continue
        value = _VALUE_RE.match(text, match.end())
        if value is None:
            out.append(text[pos : match.end()])
            pos = match.end()
            continue
        out.append(text[pos : match.end()])
        out.append(_REDACTED)
        pos = _secret_end(value)
    out.append(text[pos:])
    return "".join(out)


def _redact_flags(text: str) -> str:
    out: list[str] = []
    pos = 0
    while True:
        match = _FLAG_RE.search(text, pos)
        if match is None:
            break
        value = _VALUE_RE.match(text, match.end())
        quoted = value is not None and value.group(0)[0] in "\"'`"
        if (
            value is None
            or not _names_credential(match.group(1))
            or (not quoted and len(value.group(0)) < _MIN_BARE_FLAG_VALUE)
        ):
            out.append(text[pos : match.end(1)])
            pos = match.end(1)
            continue
        out.append(text[pos : match.end()])
        out.append(_REDACTED)
        pos = _secret_end(value)
    out.append(text[pos:])
    return "".join(out)


def _redact_userinfo(match: re.Match[str]) -> str:
    scheme, user, password = match.group(1), match.group(2), match.group(3)
    if password is not None:
        return f"{scheme}{user}:{_REDACTED}@"
    if len(user) >= _MIN_TOKEN_USERINFO:
        return f"{scheme}{_REDACTED}@"
    return match.group(0)


def redact_secrets(text: str) -> str:
    """Replace likely secret material with a fixed placeholder."""
    if not text:
        return text

    redacted = _PEM_BLOCK_RE.sub(_REDACTED, text)
    redacted = _AUTHORIZATION_RE.sub(
        lambda m: f"{m.group(1)}{m.group(2) or ''}{_REDACTED}", redacted
    )
    redacted = _redact_keyed(redacted)
    redacted = _redact_flags(redacted)
    redacted = _URL_USERINFO_RE.sub(_redact_userinfo, redacted)
    redacted = _BEARER_RE.sub(f"Bearer {_REDACTED}", redacted)

    for prefix in load_secret_prefixes():
        if not prefix:
            continue
        redacted = re.sub(
            re.escape(prefix) + r"[A-Za-z0-9_\-./+=]{4,}",
            _REDACTED,
            redacted,
        )

    return redacted
