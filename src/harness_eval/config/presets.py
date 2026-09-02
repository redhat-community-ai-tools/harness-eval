from __future__ import annotations

# recommended and strict are derived from the rule registry so a new rule is
# on by default. Overrides below are the only hand-maintained bits: extras that
# must stay off, and severities that differ from RuleMeta.default_severity.

# Off, or severity different from default_severity.
RECOMMENDED_OVERRIDES: dict[str, str] = {
    "agent/model-specified": "off",
    "content/missing-boundary-policy": "off",
    "security/yara-signatures": "off",
    "security/cve-lookup": "off",
    "submission/file-completeness": "off",
    "mcp/suspicious-endpoint": "warning",
    "quality/scope-overreach": "info",
    "security/ast-behavioral": "warning",
    "security/bash-taint-flow": "warning",
    "security/cross-component-flow": "warning",
    "security/mcp-tool-poisoning": "warning",
    "security/taint-flow": "warning",
}

# Promotions relative to recommended. Keys absent here inherit recommended.
STRICT_OVERRIDES: dict[str, str] = {
    "agent/constraint-body-match": "error",
    "agent/disallowed-tools-parseable": "error",
    "agent/excessive-permissions": "error",
    "agent/memory-write-unscoped": "error",
    "agent/model-specified": "info",
    "agent/unbounded-delegation": "error",
    "claude-md/exists": "error",
    "command/allowed-tools-coverage": "error",
    "command/references-nonexistent-skill": "error",
    "content/allowed-tools-auto-approve": "error",
    "content/circular-references": "error",
    "content/description-length": "error",
    "content/hardcoded-machine-path": "error",
    "content/mcp-skill-alignment": "error",
    "content/missing-boundary-policy": "warning",
    "content/orphan-skills": "error",
    "content/permission-escalation": "error",
    "content/token-budget": "error",
    "content/total-context-budget": "error",
    "content/total-description-budget": "error",
    "cross/config-instruction-conflict": "error",
    "cross/multi-assistant-drift": "error",
    "cross/overpermissive-grants": "error",
    "frontmatter/description-quality": "error",
    "frontmatter/format-valid": "error",
    "hooks/env-credential-override": "error",
    "hooks/local-settings-committed": "error",
    "hooks/matcher-matches-no-tool": "error",
    "hooks/no-audit-trail": "warning",
    "hooks/no-commit-guard": "error",
    "hooks/permission-contradiction": "error",
    "hooks/pre-trust-permissions": "error",
    "hooks/silent-failure-masking": "error",
    "mcp/auto-approve-risk": "error",
    "mcp/cross-assistant-divergence": "error",
    "mcp/no-wildcard-tools": "warning",
    "mcp/suspicious-endpoint": "error",
    "mcp/unpinned-package": "error",
    "mcp/valid-config": "error",
    "quality/example-gap": "warning",
    "quality/imprecise-instruction": "error",
    "quality/redundant-guidance": "error",
    "quality/scope-grab-description": "error",
    "quality/stale-references": "error",
    "quality/unfinished-content": "error",
    "security/ast-behavioral": "error",
    "security/bash-taint-flow": "error",
    "security/cross-component-flow": "error",
    "security/mcp-least-privilege": "error",
    "security/mcp-tool-poisoning": "error",
    "security/memory-write-unscoped": "error",
    "security/taint-flow": "error",
    "security/unbounded-delegation": "error",
}


def _registered_default_severities() -> dict[str, str]:
    import harness_eval.inspection  # noqa: F401 — registers all rules
    from harness_eval.inspection.registry import get_all_rules

    return {r.meta.id: r.meta.default_severity.value for r in get_all_rules()}


def recommended_rules() -> dict[str, str]:
    """Every registered rule at default_severity, plus RECOMMENDED_OVERRIDES."""
    rules = _registered_default_severities()
    rules.update(RECOMMENDED_OVERRIDES)
    return rules


def strict_rules() -> dict[str, str]:
    """Recommended, with STRICT_OVERRIDES applied on top."""
    rules = recommended_rules()
    rules.update(STRICT_OVERRIDES)
    return rules


RECOMMENDED: dict[str, str] = recommended_rules()
STRICT: dict[str, str] = strict_rules()

SECURITY: dict[str, str] = {
    "structural/skill-md-exists": "off",
    "frontmatter/description-required": "off",
    "frontmatter/description-quality": "off",
    "frontmatter/format-valid": "off",
    "content/token-budget": "off",
    "content/broken-references": "off",
    "content/duplicate-detection": "off",
    "security/no-prompt-injection": "error",
    "security/no-credential-access": "error",
    "security/reverse-shell": "error",
    "security/obfuscation": "error",
    "security/data-exfiltration": "error",
    "security/ast-behavioral": "error",
    "security/taint-flow": "error",
    "security/bash-taint-flow": "error",
    "security/mcp-least-privilege": "error",
    "security/mcp-tool-poisoning": "error",
    "security/cross-component-flow": "error",
    "agent/excessive-permissions": "error",
    "security/memory-write-unscoped": "error",
    "agent/memory-write-unscoped": "error",
    "security/unbounded-delegation": "error",
    "agent/unbounded-delegation": "error",
    "mcp/valid-config": "off",
    "mcp/suspicious-endpoint": "warning",
    "mcp/no-wildcard-tools": "off",
    "mcp/no-plaintext-secrets": "error",
    "mcp/unpinned-package": "warning",
    "mcp/auto-approve-risk": "error",
    "security/yara-signatures": "error",
    "security/cve-lookup": "error",
    # Command security rules
    "command/no-prompt-injection": "error",
    "command/no-credential-access": "error",
    "command/reverse-shell": "error",
    "command/obfuscation": "error",
    "command/data-exfiltration": "error",
    # Hooks rules
    "hooks/script-boundary": "error",
    "hooks/dangerous-command": "error",
    "hooks/env-leakage": "warning",
    "hooks/network-access": "warning",
    "hooks/silent-failure-masking": "warning",
    # CLAUDE.md rules
    "claude-md/exists": "off",
    # Agent rules
    "agent/description-required": "off",
    "agent/referenced-skills-exist": "off",
    "agent/disallowed-tools-parseable": "off",
    "agent/constraint-body-match": "off",
    "agent/no-prompt-injection": "error",
    "agent/no-credential-access": "error",
    "agent/reverse-shell": "error",
    "agent/obfuscation": "error",
    "agent/data-exfiltration": "error",
    "agent/model-specified": "off",
    # Quality rules
    "quality/imprecise-instruction": "off",
    "quality/redundant-guidance": "off",
    "quality/unfinished-content": "off",
    "quality/example-gap": "off",
    "quality/stale-references": "off",
    "quality/scope-overreach": "off",
    "quality/trigger-manipulation": "off",
    "quality/negative-only": "off",
    "security/coercive-override": "error",
    "security/stealth-persistence": "error",
    "security/prompt-exfiltration": "error",
    "cross/overpermissive-grants": "error",
    "hooks/permission-contradiction": "error",
    "hooks/permission-prompt-disabled": "error",
    "hooks/local-settings-committed": "error",
    "mcp/cross-assistant-divergence": "error",
    "claude-md/include-exists": "error",
    "hooks/command-script-exists": "error",
    "mcp/endpoint-integrity": "error",
    "security/credential-file-present": "error",
    "mcp/json-duplicate-keys": "error",
    "hooks/json-duplicate-keys": "error",
    "structural/symlink-escape": "error",
    # Pre-trust config rules
    "hooks/base-url-override": "error",
    "hooks/api-key-helper": "error",
    "hooks/env-credential-override": "warning",
    "hooks/pre-trust-permissions": "warning",
    # Allowed-tools auto-approve
    "content/allowed-tools-auto-approve": "warning",
    # Setup gap detection
    "hooks/no-commit-guard": "warning",
    "security/dangerous-permission-grant": "error",
}

PRE_WORKFLOW: dict[str, str] = {
    "structural/skill-md-exists": "off",
    "frontmatter/description-required": "off",
    "frontmatter/description-quality": "off",
    "frontmatter/format-valid": "off",
    "content/token-budget": "off",
    "content/broken-references": "error",
    "content/duplicate-detection": "off",
    "security/no-prompt-injection": "error",
    "security/no-credential-access": "error",
    "command/description-required": "off",
    "command/description-quality": "off",
    "command/script-exists": "off",
    "command/skill-overlap": "off",
    "command/duplicate-detection": "off",
    "command/shadows-builtin": "off",
    "command/no-prompt-injection": "error",
    "command/no-credential-access": "error",
    "command/reverse-shell": "error",
    "security/ast-behavioral": "error",
    "security/taint-flow": "error",
    "security/bash-taint-flow": "error",
    "mcp/valid-config": "off",
    "mcp/suspicious-endpoint": "off",
    "mcp/no-wildcard-tools": "off",
    "claude-md/exists": "off",
    "claude-md/skill-duplication": "off",
    "claude-md/generic-advice": "off",
    "hooks/valid-structure": "error",
    "hooks/script-boundary": "error",
    "hooks/dangerous-command": "error",
    "hooks/env-leakage": "warning",
    "hooks/network-access": "warning",
    "hooks/base-url-override": "error",
    "hooks/api-key-helper": "error",
    "hooks/env-credential-override": "warning",
    "hooks/pre-trust-permissions": "warning",
    "agent/description-required": "off",
    "agent/referenced-skills-exist": "error",
    "agent/disallowed-tools-parseable": "off",
    "agent/constraint-body-match": "off",
    "agent/no-prompt-injection": "error",
    "agent/no-credential-access": "error",
    "agent/reverse-shell": "error",
    "agent/obfuscation": "error",
    "agent/data-exfiltration": "error",
    "agent/model-specified": "off",
    # Config-integrity rules: security-critical ones gate a pre-workflow run,
    # the rest are consistency/integrity checks left off to keep this preset
    # focused on "is it dangerous to run this now?".
    "mcp/endpoint-integrity": "error",
    "security/credential-file-present": "error",
    "structural/symlink-escape": "error",
    "hooks/permission-prompt-disabled": "error",
    "mcp/json-duplicate-keys": "off",
    "hooks/json-duplicate-keys": "off",
    "claude-md/include-exists": "off",
    "hooks/command-script-exists": "off",
    "hooks/permission-contradiction": "off",
    "hooks/local-settings-committed": "off",
    "mcp/cross-assistant-divergence": "off",
    # Quality rules
    "quality/imprecise-instruction": "off",
    "quality/redundant-guidance": "off",
    "quality/unfinished-content": "off",
    "quality/example-gap": "off",
    "quality/stale-references": "off",
}

SKILL_SUBMISSION: dict[str, str] = {
    # --- Security rules (error) ---
    "security/no-prompt-injection": "error",
    "security/no-credential-access": "error",
    "security/coercive-override": "error",
    "security/obfuscation": "error",
    "security/stealth-persistence": "error",
    "security/prompt-exfiltration": "error",
    "security/data-exfiltration": "error",
    "security/reverse-shell": "error",
    "security/mcp-tool-poisoning": "error",
    # --- Content rules ---
    "frontmatter/description-required": "warning",
    "frontmatter/description-quality": "warning",
    "frontmatter/format-valid": "warning",
    "content/token-budget": "warning",
    "content/broken-references": "warning",
    "content/circular-references": "warning",
    "content/description-length": "warning",
    # --- Quality rules ---
    "quality/imprecise-instruction": "warning",
    "quality/redundant-guidance": "warning",
    "quality/unfinished-content": "warning",
    "quality/example-gap": "info",
    "quality/stale-references": "warning",
    "quality/negative-only": "warning",
    "quality/scope-overreach": "info",
    "quality/trigger-manipulation": "warning",
    "quality/scope-grab-description": "warning",
    # --- Submission-specific ---
    "submission/file-completeness": "warning",
    # --- OFF: structural ---
    "structural/skill-md-exists": "off",
    # --- OFF: security (agent-setup-specific) ---
    "security/memory-write-unscoped": "off",
    "security/unbounded-delegation": "off",
    "security/mcp-least-privilege": "off",
    "security/ast-behavioral": "off",
    "security/taint-flow": "off",
    "security/bash-taint-flow": "off",
    "security/cross-component-flow": "off",
    "security/yara-signatures": "off",
    "security/cve-lookup": "off",
    "security/dangerous-permission-grant": "off",
    # --- OFF: content (setup-specific) ---
    "content/allowed-tools-auto-approve": "off",
    "content/duplicate-detection": "off",
    "content/hardcoded-machine-path": "off",
    "content/mcp-skill-alignment": "off",
    "content/missing-boundary-policy": "off",
    "content/orphan-skills": "off",
    "content/permission-escalation": "off",
    "content/total-context-budget": "off",
    "content/total-description-budget": "off",
    # --- OFF: agent rules ---
    "agent/constraint-body-match": "off",
    "agent/data-exfiltration": "off",
    "agent/description-required": "off",
    "agent/disallowed-tools-parseable": "off",
    "agent/excessive-permissions": "off",
    "agent/memory-write-unscoped": "off",
    "agent/model-specified": "off",
    "agent/no-credential-access": "off",
    "agent/no-prompt-injection": "off",
    "agent/obfuscation": "off",
    "agent/referenced-skills-exist": "off",
    "agent/reverse-shell": "off",
    "agent/unbounded-delegation": "off",
    # --- OFF: command rules ---
    "command/allowed-tools-coverage": "off",
    "command/data-exfiltration": "off",
    "command/description-required": "off",
    "command/description-quality": "off",
    "command/duplicate-detection": "off",
    "command/no-credential-access": "off",
    "command/no-prompt-injection": "off",
    "command/obfuscation": "off",
    "command/references-nonexistent-skill": "off",
    "command/reverse-shell": "off",
    "command/script-exists": "off",
    "command/shadows-builtin": "off",
    "command/skill-overlap": "off",
    # --- OFF: claude-md rules ---
    "claude-md/exists": "off",
    "claude-md/generic-advice": "off",
    "claude-md/skill-duplication": "off",
    # --- OFF: hooks rules ---
    "hooks/api-key-helper": "off",
    "hooks/base-url-override": "off",
    "hooks/dangerous-command": "off",
    "hooks/env-credential-override": "off",
    "hooks/env-leakage": "off",
    "hooks/matcher-matches-no-tool": "off",
    "hooks/network-access": "off",
    "hooks/no-audit-trail": "off",
    "hooks/no-commit-guard": "off",
    "hooks/pre-trust-permissions": "off",
    "hooks/script-boundary": "off",
    "hooks/silent-failure-masking": "off",
    "hooks/valid-structure": "off",
    # --- OFF: MCP rules ---
    "mcp/auto-approve-risk": "off",
    "mcp/no-plaintext-secrets": "off",
    "mcp/no-wildcard-tools": "off",
    "mcp/suspicious-endpoint": "off",
    "mcp/unpinned-package": "off",
    "mcp/valid-config": "off",
    # --- OFF: cross-component rules ---
    "cross/config-instruction-conflict": "off",
    "cross/multi-assistant-drift": "off",
    "cross/overpermissive-grants": "off",
    "hooks/permission-contradiction": "off",
    "hooks/permission-prompt-disabled": "off",
    "hooks/local-settings-committed": "off",
    "mcp/cross-assistant-divergence": "off",
    "claude-md/include-exists": "off",
    "hooks/command-script-exists": "off",
    "mcp/endpoint-integrity": "off",
    "security/credential-file-present": "off",
    "mcp/json-duplicate-keys": "off",
    "hooks/json-duplicate-keys": "off",
    "structural/symlink-escape": "off",
}


def gate_rules(include_provisional: bool = False) -> dict[str, str]:
    """Rules for the harness-gate command, derived from the registry so the set
    can never drift from RuleMeta.tier. Gating tier only by default; provisional
    tier is added on request. Loads no LLM extras."""
    import harness_eval.inspection  # noqa: F401 — registers all rules
    from harness_eval.inspection.registry import get_all_rules

    tiers = {"gating", "provisional"} if include_provisional else {"gating"}
    return {
        r.meta.id: r.meta.default_severity.value for r in get_all_rules() if r.meta.tier in tiers
    }


# The gate preset enables exactly the gating-tier rules (see docs/rule-taxonomy.md).
GATE: dict[str, str] = gate_rules()

PRESETS: dict[str, dict[str, str]] = {
    "recommended": RECOMMENDED,
    "strict": STRICT,
    "security": SECURITY,
    "pre-workflow": PRE_WORKFLOW,
    "skill-submission": SKILL_SUBMISSION,
    "gate": GATE,
}

__all__ = [
    "PRESETS",
    "RECOMMENDED",
    "STRICT",
    "SECURITY",
    "PRE_WORKFLOW",
    "SKILL_SUBMISSION",
    "GATE",
    "gate_rules",
    "recommended_rules",
    "strict_rules",
    "RECOMMENDED_OVERRIDES",
    "STRICT_OVERRIDES",
]
