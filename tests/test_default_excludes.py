"""Tests for default credential file scan excludes (HE-3)."""

from __future__ import annotations

from pathlib import Path

from harness_eval.core.setup import DEFAULT_SCAN_EXCLUDES, discover_setup


def _make_skill(tmp: Path, name: str) -> None:
    skill_dir = tmp / "skills" / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    (skill_dir / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: Test skill\n---\n\nTest."
    )


class TestDefaultScanExcludes:
    def test_env_file_excluded_by_default(self, tmp_path: Path) -> None:
        _make_skill(tmp_path, "my-skill")
        (tmp_path / "CLAUDE.md").write_text("# Test")
        (tmp_path / ".env").write_text("API_KEY=secret")

        setup = discover_setup("test", str(tmp_path))
        paths = [c.path for c in setup.components]
        assert not any(".env" in p for p in paths)

    def test_pem_and_key_globs_excluded_by_default(self, tmp_path: Path) -> None:
        _make_skill(tmp_path, "my-skill")
        (tmp_path / "CLAUDE.md").write_text("# Test")
        secrets = tmp_path / "credentials"
        secrets.mkdir()
        (secrets / "client.pem").write_text("-----BEGIN PRIVATE KEY-----")
        (secrets / "server.key").write_text("key-material")

        setup = discover_setup("test", str(tmp_path))
        paths = [c.path for c in setup.components]
        assert not any("client.pem" in p for p in paths)
        assert not any("server.key" in p for p in paths)

    def test_default_excludes_include_env_and_credentials(self) -> None:
        joined = " ".join(DEFAULT_SCAN_EXCLUDES)
        assert ".env" in joined
        assert "credentials" in joined
        assert ".pem" in joined
