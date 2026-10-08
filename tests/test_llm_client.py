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
            create_client("cohere")


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


class TestOpenAICompatibleClient:
    def test_create_client_returns_openai_client(self) -> None:
        from harness_eval.utils.llm import OpenAICompatibleClient, create_client

        client = create_client("openai", "my-model", base_url="https://gw.example/v1/")
        assert isinstance(client, OpenAICompatibleClient)
        assert client.model == "my-model"
        assert client.base_url == "https://gw.example/v1"

    def test_requires_key_only_for_public_endpoint(self, monkeypatch) -> None:
        import pytest

        from harness_eval.utils.llm import OpenAICompatibleClient

        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        with pytest.raises(ValueError, match="OPENAI_API_KEY"):
            OpenAICompatibleClient()._ensure_client()
        local = OpenAICompatibleClient(base_url="http://localhost:11434/v1")
        local._ensure_client()  # a self-hosted endpoint needs no key

    def test_refuses_plain_http_to_remote_host(self, monkeypatch) -> None:
        import pytest

        from harness_eval.utils.llm import OpenAICompatibleClient

        monkeypatch.setenv("OPENAI_API_KEY", "k")
        with pytest.raises(ValueError, match="plain HTTP"):
            OpenAICompatibleClient(base_url="http://gw.example/v1")._ensure_client()

    def test_generate_parses_chat_completion(self, monkeypatch) -> None:
        import io
        import json as json_mod
        import urllib.request

        from harness_eval.utils.llm import OpenAICompatibleClient

        monkeypatch.setenv("OPENAI_API_KEY", "k")
        captured = {}

        class _Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout):
            captured["url"] = req.full_url
            captured["body"] = json_mod.loads(req.data)
            captured["auth"] = req.get_header("Authorization")
            return _Resp(json_mod.dumps({"choices": [{"message": {"content": "ok"}}]}).encode())

        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        client = OpenAICompatibleClient(model="m", base_url="https://gw.example/v1")
        assert client.generate("sys", "hi") == "ok"
        assert captured["url"] == "https://gw.example/v1/chat/completions"
        assert captured["body"]["messages"][0] == {"role": "system", "content": "sys"}
        assert captured["auth"] == "Bearer k"
        assert client.calls_succeeded == 1

    def test_key_hint_per_provider(self) -> None:
        from harness_eval.utils.llm import key_hint

        assert key_hint("openai") == "OPENAI_API_KEY"
        assert key_hint("anthropic") == "ANTHROPIC_API_KEY"
        assert key_hint("gemini") == "GEMINI_API_KEY"
