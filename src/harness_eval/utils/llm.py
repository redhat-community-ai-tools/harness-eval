"""LLM client abstraction for rubric scoring and adjudication.

Three providers share one interface: Gemini and Anthropic through their own
SDKs, and ``openai`` for any server that speaks the OpenAI chat-completions
protocol (OpenAI itself, Azure OpenAI, vLLM, Ollama, LiteLLM, OpenRouter, a
corporate gateway). The OpenAI-compatible client uses only the standard
library, so it needs no extra dependency.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Protocol

PROVIDERS: tuple[str, ...] = ("gemini", "anthropic", "openai")

# Environment variables each provider reads for its key and, for the
# OpenAI-compatible provider, its endpoint. ``create_client`` resolves them so
# commands only need to say which provider they want.
PROVIDER_KEY_ENV: dict[str, tuple[str, ...]] = {
    "gemini": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
    "anthropic": ("ANTHROPIC_API_KEY",),
    "openai": ("OPENAI_API_KEY",),
}
OPENAI_BASE_URL_ENV = "OPENAI_BASE_URL"
DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"

DEFAULT_MODELS: dict[str, str] = {
    "gemini": "gemini-2.0-flash",
    "anthropic": "claude-sonnet-4-20250514",
    "openai": "gpt-4o-mini",
}


def key_hint(provider: str) -> str:
    """The environment variable a user should set for *provider*."""
    return PROVIDER_KEY_ENV.get(provider, ("API key",))[0]


class LLMClient(Protocol):
    def generate(self, system: str, prompt: str) -> str: ...


class GeminiClient:
    def __init__(self, model: str = DEFAULT_MODELS["gemini"]) -> None:
        self.model = model
        self._client: object | None = None
        self.calls_total: int = 0
        self.calls_succeeded: int = 0
        self.provider_name: str = "gemini"

    def _ensure_client(self) -> None:
        if self._client is not None:
            return
        try:
            from google import genai
        except ImportError as e:
            raise ImportError(
                'LLM dependencies not installed. Install with: pip install "harness-eval[llm]"'
                "  (or: uv sync --extra llm). Run `harness-eval doctor` to check what is installed."
            ) from e

        api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("Set GEMINI_API_KEY or GOOGLE_API_KEY environment variable")

        self._client = genai.Client(api_key=api_key)

    def generate(self, system: str, prompt: str) -> str:
        self._ensure_client()
        from google.genai import types

        self.calls_total += 1
        response = self._client.models.generate_content(  # type: ignore[union-attr]
            model=self.model,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=system,
                temperature=0.2,
            ),
        )
        self.calls_succeeded += 1
        return response.text or ""


class AnthropicClient:
    def __init__(self, model: str = DEFAULT_MODELS["anthropic"]) -> None:
        self.model = model
        self._client: object | None = None
        self.calls_total: int = 0
        self.calls_succeeded: int = 0
        self.provider_name: str = "anthropic"

    def _ensure_client(self) -> None:
        if self._client is not None:
            return
        try:
            import anthropic
        except ImportError as e:
            raise ImportError(
                'LLM dependencies not installed. Install with: pip install "harness-eval[llm]"'
                "  (or: uv sync --extra llm). Run `harness-eval doctor` to check what is installed."
            ) from e

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("Set ANTHROPIC_API_KEY environment variable")

        self._client = anthropic.Anthropic(api_key=api_key)

    def generate(self, system: str, prompt: str) -> str:
        self._ensure_client()
        self.calls_total += 1
        response = self._client.messages.create(  # type: ignore[union-attr]
            model=self.model,
            max_tokens=2048,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        self.calls_succeeded += 1
        return response.content[0].text


class OpenAICompatibleClient:
    """Chat-completions client for any OpenAI-protocol endpoint.

    Reads ``OPENAI_API_KEY`` and, unless ``base_url`` is given,
    ``OPENAI_BASE_URL``. A server that needs no key (a local vLLM or Ollama)
    accepts any non-empty value, so the key is required only when the base URL
    is the public OpenAI endpoint.
    """

    def __init__(
        self,
        model: str = DEFAULT_MODELS["openai"],
        base_url: str | None = None,
        *,
        timeout: float = 120.0,
    ) -> None:
        self.model = model
        self.base_url = (
            base_url or os.environ.get(OPENAI_BASE_URL_ENV) or DEFAULT_OPENAI_BASE_URL
        ).rstrip("/")
        self.timeout = timeout
        self.calls_total: int = 0
        self.calls_succeeded: int = 0
        self.provider_name: str = "openai"
        self._api_key: str | None = None

    def _ensure_client(self) -> None:
        if self._api_key is not None:
            return
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            if self.base_url == DEFAULT_OPENAI_BASE_URL:
                raise ValueError("Set OPENAI_API_KEY environment variable")
            api_key = "none"  # a self-hosted endpoint that does not check keys
        if not self.base_url.startswith(("https://", "http://localhost", "http://127.0.0.1")):
            raise ValueError(
                f"Refusing to send prompts over plain HTTP to {self.base_url}; use https:// "
                "or a loopback address."
            )
        self._api_key = api_key

    def generate(self, system: str, prompt: str) -> str:
        self._ensure_client()
        body = json.dumps(
            {
                "model": self.model,
                "temperature": 0.2,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            }
        ).encode()
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
        )
        self.calls_total += 1
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as resp:  # nosec B310
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")[:300]
            if e.code in (401, 403):
                raise PermissionError(f"Authentication failed ({e.code}): {detail}") from e
            raise RuntimeError(f"LLM endpoint returned HTTP {e.code}: {detail}") from e
        choices = payload.get("choices") or []
        if not choices:
            raise RuntimeError(f"LLM endpoint returned no choices: {str(payload)[:300]}")
        content = str((choices[0].get("message") or {}).get("content") or "")
        self.calls_succeeded += 1
        return content


def create_client(
    provider: str, model: str | None = None, *, base_url: str | None = None
) -> LLMClient:
    if provider == "gemini":
        return GeminiClient(model=model or DEFAULT_MODELS["gemini"])
    if provider == "anthropic":
        return AnthropicClient(model=model or DEFAULT_MODELS["anthropic"])
    if provider == "openai":
        return OpenAICompatibleClient(model=model or DEFAULT_MODELS["openai"], base_url=base_url)
    raise ValueError(f"Unknown LLM provider: {provider}")
