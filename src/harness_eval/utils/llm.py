"""LLM client abstraction for rubric scoring."""

from __future__ import annotations

import os
from typing import Protocol


class LLMClient(Protocol):
    def generate(self, system: str, prompt: str) -> str: ...


class GeminiClient:
    def __init__(self, model: str = "gemini-2.0-flash") -> None:
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
                "  (or: uv sync --extra llm)"
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
    def __init__(self, model: str = "claude-sonnet-4-20250514") -> None:
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
                "  (or: uv sync --extra llm)"
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


def create_client(provider: str, model: str | None = None) -> LLMClient:
    if provider == "gemini":
        return GeminiClient(model=model or "gemini-2.0-flash")
    elif provider == "anthropic":
        return AnthropicClient(model=model or "claude-sonnet-4-20250514")
    else:
        raise ValueError(f"Unknown LLM provider: {provider}")
