"""Tests for secret redaction before LLM calls (HE-2)."""

from harness_eval.utils.redact import redact_secrets


def test_redacts_pem_private_key_block() -> None:
    text = "key = '''-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----'''"
    assert "abc" not in redact_secrets(text)
    assert "[REDACTED]" in redact_secrets(text)


def test_redacts_known_token_prefixes() -> None:
    text = "export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    redacted = redact_secrets(text)
    assert "ghp_" not in redacted
    assert "[REDACTED]" in redacted


def test_redacts_assignment_patterns() -> None:
    text = "API_KEY=super-secret-value"
    redacted = redact_secrets(text)
    assert "super-secret-value" not in redacted
    assert "API_KEY=[REDACTED]" in redacted


def test_leaves_benign_content_unchanged() -> None:
    text = "Use pytest to run unit tests."
    assert redact_secrets(text) == text
