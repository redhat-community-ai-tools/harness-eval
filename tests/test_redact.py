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


def test_redacts_json_style_key() -> None:
    """The form an MCP config uses: the key is quoted, and so is the value."""
    text = '"env": {"API_KEY": "abcdef0123456789", "DEBUG": "1"}'
    redacted = redact_secrets(text)
    assert "abcdef0123456789" not in redacted
    assert '"DEBUG": "1"' in redacted


def test_redacts_whole_quoted_value_with_spaces() -> None:
    redacted = redact_secrets('password: "correct horse battery staple"')
    assert redacted == "password: [REDACTED]"


def test_redacts_single_quoted_key_and_value() -> None:
    assert "hunter2" not in redact_secrets("'password': 'hunter2hunter2'")


def test_redacts_credential_flag_value() -> None:
    redacted = redact_secrets("mytool --token abc123def456 --verbose")
    assert redacted == "mytool --token [REDACTED] --verbose"


def test_redacts_quoted_credential_flag_value() -> None:
    redacted = redact_secrets('mytool --password "correct horse" run')
    assert redacted == "mytool --password [REDACTED] run"


def test_leaves_flag_mentioned_in_prose() -> None:
    text = "Pass --token to the command, or --verbose --token --other."
    assert redact_secrets(text) == text


def test_redacts_url_password() -> None:
    redacted = redact_secrets("git clone https://deploy:s3cr3tpass@git.example.com/org/repo.git")
    assert redacted == "git clone https://deploy:[REDACTED]@git.example.com/org/repo.git"


def test_redacts_token_used_as_url_user() -> None:
    redacted = redact_secrets("curl https://abcdef0123456789@api.example.com/v1")
    assert redacted == "curl https://[REDACTED]@api.example.com/v1"


def test_leaves_url_login_name_and_port() -> None:
    text = "ssh://git@github.com/org/repo and http://localhost:8080/a@b"
    assert redact_secrets(text) == text


def test_redacts_authorization_header_and_keeps_the_scheme() -> None:
    assert (
        redact_secrets("Authorization: Basic dXNlcjpwYXNzd29yZA==")
        == "Authorization: Basic [REDACTED]"
    )
    assert "0123456789abcdef" not in redact_secrets(
        'curl -H "Authorization: token 0123456789abcdef" https://x'
    )
    assert redact_secrets('"Authorization": "Bearer abcdefgh12345678"') == (
        '"Authorization": "Bearer [REDACTED]"'
    )


def test_redacts_more_credential_key_names() -> None:
    for text, secret in [
        ("PASSPHRASE=opensesame123", "opensesame123"),
        ("private_key: abcdefabcdef", "abcdefabcdef"),
        ("export DB_PASSWD=abc12345", "abc12345"),
        ("MYSECRET=abc12345", "abc12345"),
        ('apiKey: "abc12345"', "abc12345"),
        ("AWS_SECRET_ACCESS_KEY=abc12345", "abc12345"),
        ("X-Api-Key: abc12345", "abc12345"),
    ]:
        assert secret not in redact_secrets(text), text


def test_leaves_model_token_settings_readable() -> None:
    """A reviewer needs these numbers; they count tokens, they are not tokens."""
    for text in [
        "max_tokens: 4096",
        "token_budget: 20000",
        "MAX_TOKENS=8000",
        "max_token_count: 5",
        "tokenizer: gpt2",
    ]:
        assert redact_secrets(text) == text


def test_leaves_ordinary_keys_unchanged() -> None:
    text = "cache_key: abc; key: value; PWD=/home/x"
    assert redact_secrets(text) == text


def test_key_without_value_does_not_consume_the_next_line() -> None:
    text = "password:\n  next_key: value"
    assert redact_secrets(text) == text


def test_redaction_is_idempotent() -> None:
    text = (
        '"env": {"API_KEY": "abcdef0123456789", "DEBUG": "1"}\n'
        "Authorization: Basic dXNlcjpwYXNzd29yZA==\n"
        "https://deploy:s3cr3tpass@git.example.com/x\n"
        "mytool --token abc123def456 --verbose\n"
    )
    once = redact_secrets(text)
    assert redact_secrets(once) == once
