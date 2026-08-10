"""Tests for LLM client abstraction (utils/llm.py)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from harness_eval.utils.llm import AnthropicClient, GeminiClient, create_client


class TestCreateClient:
    def test_gemini_default(self) -> None:
        client = create_client("gemini")
        assert isinstance(client, GeminiClient)
        assert client.model == "gemini-2.0-flash"

    def test_anthropic_default(self) -> None:
        client = create_client("anthropic")
        assert isinstance(client, AnthropicClient)
        assert client.model == "claude-sonnet-4-20250514"

    def test_custom_model(self) -> None:
        client = create_client("gemini", model="gemini-1.5-pro")
        assert isinstance(client, GeminiClient)
        assert client.model == "gemini-1.5-pro"

    def test_unknown_provider(self) -> None:
        with pytest.raises(ValueError, match="Unknown LLM provider"):
            create_client("openai")


class TestGeminiClient:
    def test_missing_import_raises(self) -> None:
        client = GeminiClient()
        with (
            patch.dict("sys.modules", {"google": None, "google.genai": None}),
            pytest.raises(ImportError, match="LLM dependencies not installed"),
        ):
            client._ensure_client()

    def test_missing_api_key_raises(self) -> None:
        client = GeminiClient()
        with patch.dict("os.environ", {}, clear=True), pytest.raises((ImportError, ValueError)):
            client._ensure_client()

    def test_call_counters_init(self) -> None:
        client = GeminiClient()
        assert client.calls_total == 0
        assert client.calls_succeeded == 0


class TestAnthropicClient:
    def test_missing_import_raises(self) -> None:
        client = AnthropicClient()
        with (
            patch.dict("sys.modules", {"anthropic": None}),
            pytest.raises(ImportError, match="LLM dependencies not installed"),
        ):
            client._ensure_client()

    def test_missing_api_key_raises(self) -> None:
        client = AnthropicClient()
        with patch.dict("os.environ", {}, clear=True), pytest.raises((ImportError, ValueError)):
            client._ensure_client()

    def test_call_counters_init(self) -> None:
        client = AnthropicClient()
        assert client.calls_total == 0
        assert client.calls_succeeded == 0
