"""Tests for mcp/no-plaintext-secrets rule."""

from __future__ import annotations

import json
from pathlib import Path

from harness_eval.inspection.engine import lint_mcp_config

RULE_CONFIG = {"mcp/no-plaintext-secrets": "error"}


def _make_mcp_config(tmp_path: Path, servers: dict) -> str:
    config_path = tmp_path / ".mcp.json"
    config_path.write_text(json.dumps({"mcpServers": servers}))
    return str(config_path)


class TestMcpNoPlaintextSecrets:
    def test_flags_known_prefix_ghp(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {
                "my-server": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {"GITHUB_TOKEN": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"},
                }
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/no-plaintext-secrets"]
        assert len(diags) == 1
        assert "my-server" in diags[0].message
        assert "GITHUB_TOKEN" in diags[0].message

    def test_flags_high_entropy_credential_key(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {
                "api-server": {
                    "command": "python",
                    "args": ["server.py"],
                    "env": {"API_SECRET": "aB3xK9mP2qR7wZ5nL8vJ4hF6dY1cT0eU"},
                }
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/no-plaintext-secrets"]
        assert len(diags) == 1

    def test_skips_env_reference(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {
                "safe-server": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {"API_KEY": "${MY_KEY}"},
                }
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/no-plaintext-secrets"]
        assert len(diags) == 0

    def test_skips_placeholder(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {
                "placeholder-server": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {"API_KEY": "your_api_key_here"},
                }
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/no-plaintext-secrets"]
        assert len(diags) == 0

    def test_skips_url_without_credential_key(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {
                "url-server": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {"ENDPOINT": "https://api.example.com/v2/long/path/endpoint"},
                }
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/no-plaintext-secrets"]
        assert len(diags) == 0

    def test_sk_prefix_short_not_flagged(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {
                "short-sk": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {"API_KEY": "sk-short"},
                }
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/no-plaintext-secrets"]
        assert len(diags) == 0

    def test_sk_prefix_long_flagged(self, tmp_path: Path) -> None:
        secret = "sk-" + "a" * 40
        path = _make_mcp_config(
            tmp_path,
            {
                "long-sk": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {"API_KEY": secret},
                }
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/no-plaintext-secrets"]
        assert len(diags) == 1

    def test_secret_value_never_in_diagnostic(self, tmp_path: Path) -> None:
        secret_value = "ghp_SuperSecretTokenValue12345678"
        path = _make_mcp_config(
            tmp_path,
            {
                "leak-test": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {"TOKEN": secret_value},
                }
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/no-plaintext-secrets"]
        assert len(diags) == 1
        assert secret_value not in diags[0].message

    def test_flags_header_secret(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {
                "url-server": {
                    "url": "https://api.example.com/mcp",
                    "headers": {
                        "Authorization": "sk-ant-api03-reallyLongSecretKeyHere12345678901234567890"
                    },
                }
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/no-plaintext-secrets"]
        assert len(diags) == 1

    def test_skips_dollar_prefix_env_ref(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {
                "dollar-ref": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {"API_KEY": "$MY_API_KEY"},
                }
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/no-plaintext-secrets"]
        assert len(diags) == 0

    # --- args scanning ---

    def test_flags_secret_in_args_key_equals_value(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {
                "args-server": {
                    "command": "npx",
                    "args": ["-y", "pkg-b@1.2.3", "--api-key=ghp_abc123"],
                }
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/no-plaintext-secrets"]
        assert len(diags) == 1
        assert "args-server" in diags[0].message

    def test_flags_secret_in_args_flag_then_value(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {
                "args2-server": {
                    "command": "npx",
                    "args": ["-y", "pkg-c@1.2.3", "--token", "ghp_abc123"],
                }
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/no-plaintext-secrets"]
        assert len(diags) == 1
        assert "args2-server" in diags[0].message

    def test_skips_env_ref_in_args_flag_then_value(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {
                "safe-args": {
                    "command": "npx",
                    "args": ["-y", "pkg@1.0.0", "--token", "$API_KEY"],
                }
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/no-plaintext-secrets"]
        assert len(diags) == 0

    def test_skips_env_ref_in_args_key_equals_value(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {
                "safe-args": {
                    "command": "npx",
                    "args": ["--api-key=${MY_KEY}"],
                }
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/no-plaintext-secrets"]
        assert len(diags) == 0

    # --- URL query string scanning ---

    def test_flags_secret_in_url_query_param(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {
                "url-server": {
                    "type": "sse",
                    "url": "https://api.example.com/sse?api_key=ghp_urltoken123",
                }
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/no-plaintext-secrets"]
        assert len(diags) == 1
        assert "url-server" in diags[0].message

    def test_skips_url_without_query_string(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {
                "clean-url": {
                    "type": "sse",
                    "url": "https://api.example.com/mcp",
                }
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/no-plaintext-secrets"]
        assert len(diags) == 0

    # --- Inline shell assignment scanning ---

    def test_flags_secret_in_sh_c_inline_env(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {
                "cmd-server": {
                    "command": "sh",
                    "args": ["-c", "GITHUB_TOKEN=ghp_abc123 npx -y pkg-d@1.0.0"],
                }
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/no-plaintext-secrets"]
        assert len(diags) == 1
        assert "cmd-server" in diags[0].message

    def test_skips_sh_c_env_ref_inline(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {
                "safe-cmd": {
                    "command": "sh",
                    "args": ["-c", "GITHUB_TOKEN=$GH_TOKEN npx -y pkg@1.0.0"],
                }
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/no-plaintext-secrets"]
        assert len(diags) == 0

    def test_flags_nested_var_value_in_flag_equals(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {
                "nested-server": {
                    "command": "tool",
                    "args": ["--env=GITHUB_TOKEN=ghp_abc123"],
                }
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/no-plaintext-secrets"]
        assert len(diags) >= 1
        assert "nested-server" in diags[0].message

    def test_flags_bare_secret_in_positional_arg(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {
                "bare-arg-server": {
                    "command": "tool",
                    "args": ["ghp_abc123"],
                }
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/no-plaintext-secrets"]
        assert len(diags) == 1
        assert "bare-arg-server" in diags[0].message

    def test_flags_secret_in_quoted_shell_assignment(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {
                "quoted-cmd": {
                    "command": "sh",
                    "args": ["-c", 'GITHUB_TOKEN="ghp_abc123" npx pkg'],
                }
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/no-plaintext-secrets"]
        assert len(diags) == 1

    def test_flags_secret_in_single_quoted_shell_assignment(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {
                "sq-cmd": {
                    "command": "sh",
                    "args": ["-c", "GITHUB_TOKEN='ghp_abc123' npx pkg"],
                }
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/no-plaintext-secrets"]
        assert len(diags) == 1

    def test_skips_command_without_inline_assignment(self, tmp_path: Path) -> None:
        path = _make_mcp_config(
            tmp_path,
            {
                "normal-cmd": {
                    "command": "npx",
                    "args": ["-y", "pkg@1.0.0"],
                }
            },
        )
        result = lint_mcp_config(path, RULE_CONFIG)
        diags = [d for d in result.diagnostics if d.rule_id == "mcp/no-plaintext-secrets"]
        assert len(diags) == 0
