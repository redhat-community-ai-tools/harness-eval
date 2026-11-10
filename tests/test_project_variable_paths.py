"""Project variables contain literal paths, never regex replacement syntax."""

from pathlib import Path

import pytest

from harness_eval.inspection.rules._config_fs import expand_project_vars


@pytest.mark.parametrize("root", [r"C:\Users\research\repo", r"C:\temp\new\1", "/tmp/repo"])
@pytest.mark.parametrize("variable", ["${CLAUDE_PROJECT_DIR:-.}", "${PROJECT_DIR:=.}", "$PWD"])
def test_project_path_is_literal(root: str, variable: str) -> None:
    assert expand_project_vars(variable + "/hook.py", Path(root)) == str(Path(root)) + "/hook.py"
