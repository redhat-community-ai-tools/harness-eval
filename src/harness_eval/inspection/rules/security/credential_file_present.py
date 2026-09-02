"""Flag secret files committed inside a skill directory.

Exact filename globs, no prose: `.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa`,
`credentials.json`, `*-service-account*.json`. Complements the textual
credential-access rule with a decidable one.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path

from harness_eval.core.types import ComponentType
from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_GLOBS = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "id_rsa",
    "id_ed25519",
    "credentials.json",
    "*-service-account*.json",
    "*.p12",
    "*.pfx",
    ".netrc",
    ".npmrc",
    ".pypirc",
)
_ALLOW = (".env.example", ".env.sample", ".env.template", "*.pub", ".env.md")


class SecurityCredentialFilePresent:
    meta = RuleMeta(
        id="security/credential-file-present",
        tier="gating",
        scope="FILE_FS",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Flag a file inside a skill directory whose name matches a secret-file pattern",
        category=RuleCategory.SECURITY,
        messages={
            "present": "'{{file}}' matches secret-file pattern '{{pattern}}' and is committed inside the skill."
        },
        target_type=ComponentType.SKILL,
        default_suggestion="Remove the file from version control and load secrets from the environment.",
    )

    def create(self, context: RuleContext) -> None:
        skill_dir = Path(context.skill.skill_md_path).parent
        for p in skill_dir.rglob("*"):
            if not p.is_file() or any(fnmatch.fnmatch(p.name, a) for a in _ALLOW):
                continue
            for g in _GLOBS:
                if fnmatch.fnmatch(p.name, g):
                    context.report(
                        ReportDescriptor(
                            message_id="present",
                            data={"file": str(p.relative_to(skill_dir)), "pattern": g},
                            location=Location(file=str(p)),
                        )
                    )
                    break
