"""Token counting with offline-safe fallback.

Uses tiktoken's cl100k_base encoding when available. Falls back to a
chars/4 heuristic if tiktoken fails to load (e.g. air-gapped CI runners
where the BPE file cannot be downloaded from OpenAI's CDN).

Note: cl100k_base is OpenAI's tokenizer. Token counts are approximations
for non-OpenAI models (Claude, Gemini, etc.).
"""

from __future__ import annotations

import logging
import warnings

_log = logging.getLogger(__name__)

_ENCODER = None
_FALLBACK = False
_WARNED = False


def _init_encoder():
    global _ENCODER, _FALLBACK
    try:
        import tiktoken

        _ENCODER = tiktoken.get_encoding("cl100k_base")
    except Exception:
        _FALLBACK = True
        _log.debug("tiktoken unavailable, using chars/4 heuristic for token counts")


def _reset():
    """Reset module state. Used by tests only."""
    global _ENCODER, _FALLBACK, _WARNED
    _ENCODER = None
    _FALLBACK = False
    _WARNED = False


def is_fallback() -> bool:
    if _ENCODER is None and not _FALLBACK:
        _init_encoder()
    return _FALLBACK


def count_tokens(text: str) -> int:
    global _WARNED

    if _ENCODER is None and not _FALLBACK:
        _init_encoder()

    if _ENCODER is not None:
        return len(_ENCODER.encode(text))

    if not _WARNED:
        warnings.warn(
            "tiktoken not available; token counts use chars/4 approximation",
            stacklevel=2,
        )
        _WARNED = True
    return len(text) // 4
