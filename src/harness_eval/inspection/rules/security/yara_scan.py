from __future__ import annotations

from pathlib import Path

from harness_eval.inspection.types import (
    Location,
    ReportDescriptor,
    RuleCategory,
    RuleContext,
    RuleMeta,
    Severity,
)

_YARA_RULES_SOURCE = r"""
rule webshell_indicators {
    meta:
        description = "Common webshell patterns"
        category = "webshell"
    strings:
        $php_eval = /eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/
        $php_system = /system\s*\(\s*\$_(GET|POST|REQUEST)/
        $php_passthru = /passthru\s*\(\s*\$/
        $php_shell_exec = /shell_exec\s*\(\s*\$/
        $cmd_shell = /cmd\.exe\s*\/c/
        $powershell_enc = /powershell\s+-enc/i
        $powershell_hidden = /powershell\s+.*-w\s+hidden/i
    condition:
        any of them
}

rule cryptominer_indicators {
    meta:
        description = "Cryptocurrency mining indicators"
        category = "cryptominer"
    strings:
        $stratum = "stratum+tcp://"
        $stratum_ssl = "stratum+ssl://"
        $xmrig = "xmrig" nocase
        $monero_addr = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/
        $pool_port = /:\s*(3333|4444|5555|7777|8888|9999)\b/
        $mining_pool = /pool\.(minergate|supportxmr|hashvault)/i
    condition:
        any of them
}

rule hacktool_indicators {
    meta:
        description = "Common attack tool signatures"
        category = "hacktool"
    strings:
        $mimikatz = "mimikatz" nocase
        $meterpreter = "meterpreter" nocase
        $cobaltstrike = /cobalt\s*strike/i
        $bloodhound = "bloodhound" nocase
        $lazagne = "lazagne" nocase
        $empire = /Invoke-Empire|Empire\s+listener/i
    condition:
        any of them
}

rule malware_indicators {
    meta:
        description = "Generic malware behavioral patterns"
        category = "malware"
    strings:
        $persistence_cron = /echo\s+.*>>\s*\/etc\/crontab/
        $persistence_rc = /echo\s+.*>>\s*\/etc\/rc\.local/
        $persistence_bashrc = /echo\s+.*>>\s*~?\/?\.bashrc/
        $disable_firewall = /ufw\s+disable|iptables\s+-F/
        $disable_av = /Set-MpPreference\s+-DisableRealtimeMonitoring/i
        $kill_process = /taskkill\s+\/f\s+\/im/i
    condition:
        any of them
}
"""

_CATEGORY_MAP = {
    "webshell": "webshell pattern",
    "cryptominer": "cryptocurrency mining indicator",
    "hacktool": "attack tool signature",
    "malware": "malware behavioral pattern",
}


class YaraScan:
    meta: RuleMeta = RuleMeta(
        id="security/yara-signatures",
        default_severity=Severity.ERROR,
        fixable=False,
        description="Scan skill files for malware, webshell, cryptominer, and hack tool signatures using YARA",
        category=RuleCategory.SECURITY,
        messages={
            "yara_match": "{{file}}: YARA rule '{{rule}}' matched ({{category}}). Review this file for malicious content.",
            "yara_skipped": "YARA scanning skipped: {{reason}}. Install with: pip install yara-python",
        },
        frameworks={"mitre_atlas": "AML.T0054"},
        default_suggestion="Remove or replace the content matched by the YARA rule.",
    )

    def create(self, context: RuleContext) -> None:
        skill = context.skill
        if skill is None:
            return
        if not skill.dir_path:
            return
        skill_dir = Path(skill.dir_path)
        if not skill_dir.is_dir():
            return

        try:
            import yara  # type: ignore[import-not-found]
        except ImportError:
            context.report(
                ReportDescriptor(
                    message_id="yara_skipped",
                    data={"reason": "yara-python not installed"},
                    location=Location(file=skill.skill_md_path),
                    severity_override=Severity.INFO,
                )
            )
            return

        try:
            rules = yara.compile(source=_YARA_RULES_SOURCE)
        except yara.SyntaxError:
            context.report(
                ReportDescriptor(
                    message_id="yara_skipped",
                    data={"reason": "built-in YARA rules failed to compile"},
                    location=Location(file=skill.skill_md_path),
                    severity_override=Severity.WARNING,
                )
            )
            return

        for file_path in sorted(skill_dir.rglob("*")):
            if not file_path.is_file():
                continue
            if ".git" in file_path.parts or "__pycache__" in file_path.parts:
                continue

            try:
                data = file_path.read_bytes()
            except OSError:
                continue

            matches = rules.match(data=data)
            for match in matches:
                cat_str = (
                    match.meta.get("category", "unknown") if hasattr(match, "meta") else "unknown"
                )
                cat_label = _CATEGORY_MAP.get(cat_str, cat_str)

                context.report(
                    ReportDescriptor(
                        message_id="yara_match",
                        data={
                            "file": file_path.name,
                            "rule": match.rule,
                            "category": cat_label,
                        },
                        location=Location(file=skill.skill_md_path),
                    )
                )
