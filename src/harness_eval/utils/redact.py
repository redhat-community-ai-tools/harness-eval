"""Redact likely secrets before sending text to remote LLM providers (HE-2)."""

from __future__ import annotations

import re

from harness_eval.data import load_secret_prefixes

_REDACTED = "[REDACTED]"

_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
_ASSIGNMENT_RE = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[A-Z0-9_]*)\s*[:=]\s*\S+"
)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-+/=]{8,}\b")


def redact_secrets(text: str) -> str:
    """Replace likely secret material with a fixed placeholder."""
    if not text:
        return text

    redacted = _PEM_BLOCK_RE.sub(_REDACTED, text)
    redacted = _ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}={_REDACTED}", redacted)
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
