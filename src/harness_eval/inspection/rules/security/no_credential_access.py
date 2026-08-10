from __future__ import annotations

import re

from harness_eval.inspection.rules.security._shared import (
    extract_all_skill_md_content,
    scan_lines_for_credential_patterns,
)
from harness_eval.inspection.types import (
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_HOME_PREFIX = r"(?:~/|\$HOME/|/home/\w+/)"

_SENSITIVE_PATHS = [
    re.compile(_HOME_PREFIX + r"\.ssh/", re.I),
    re.compile(_HOME_PREFIX + r"\.aws/credentials", re.I),
    re.compile(_HOME_PREFIX + r"\.config/gcloud", re.I),
    re.compile(_HOME_PREFIX + r"\.kube/config", re.I),
    re.compile(r"/etc/shadow", re.I),
    re.compile(_HOME_PREFIX + r"\.netrc", re.I),
    re.compile(_HOME_PREFIX + r"\.env\b"),
    re.compile(_HOME_PREFIX + r"\.docker/config\.json", re.I),
    re.compile(_HOME_PREFIX + r"\.npmrc\b"),
    re.compile(_HOME_PREFIX + r"\.pypirc\b"),
]

_SENSITIVE_ENV_VARS = [
    re.compile(r"\$(?:ANTHROPIC|OPENAI|GEMINI|GOOGLE)_API_KEY"),
    re.compile(r"\$(?:AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)"),
    re.compile(r"\$(?:DATABASE_URL|DB_PASSWORD)"),
    re.compile(r"\$(?:GITHUB_TOKEN|GH_TOKEN)"),
    re.compile(r"\$(?:SECRET_KEY|PRIVATE_KEY)"),
    re.compile(r"\$SLACK_TOKEN"),
    re.compile(r"\$STRIPE_SECRET_KEY"),
    re.compile(r"\$JWT_SECRET"),
    re.compile(r"\$ENCRYPTION_KEY"),
]

_DANGEROUS_COMMANDS = [
    (
        re.compile(
            r"\bsudo\s+(?!"
            r"apt\b|apt-get\b|dnf\b|yum\b|pip\b|npm\b|"
            r"tar\b|ln\b|cp\b|mv\b|mkdir\b|tee\b|install\b|"
            r"systemctl\b|service\b|update-alternatives\b|"
            r"useradd\b|groupadd\b|usermod\b|"
            r"mount\b|umount\b|modprobe\b|sysctl\b|"
            r"apparmor_parser\b|aa-enforce\b|"
            r"make\b|cmake\b"
            r")"
        ),
        "sudo (non-install)",
    ),
    (re.compile(r"\bchmod\s+777\b"), "chmod 777"),
    (re.compile(r"\bchown\s+root\b"), "chown root"),
]


class NoCredentialAccess:
    meta: RuleMeta = RuleMeta(
        id="security/no-credential-access",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Skill should not reference sensitive file paths or environment variables",
        category=RuleCategory.SECURITY,
        messages={
            "sensitive_path": "References sensitive path '{{match}}' at line {{line}}",
            "sensitive_env": "References sensitive environment variable '{{match}}' at line {{line}}",
            "dangerous_command": "Contains dangerous command '{{match}}' at line {{line}}",
        },
        frameworks={"owasp_llm": "LLM06", "owasp_agentic": "AG05"},
        default_suggestion="Remove direct credential access and use environment variables instead.",
    )

    def create(self, context: RuleContext) -> None:
        for content, file_path in extract_all_skill_md_content(context):
            scan_lines_for_credential_patterns(
                content,
                file_path,
                context,
                [
                    ("sensitive_path", _SENSITIVE_PATHS),
                    ("sensitive_env", _SENSITIVE_ENV_VARS),
                    ("dangerous_command", _DANGEROUS_COMMANDS),
                ],
                code_block_msg="skip",
                suggestion=(
                    "Use a secret manager or environment variable injection instead of hardcoded paths."
                ),
            )
