from __future__ import annotations

from harness_eval.inspection.registry import register_rule


def register_all_rules() -> None:
    """Import and register all built-in rules."""
    # Skill rules
    from harness_eval.inspection.rules.agents.constraint_body_match import ConstraintBodyMatch
    from harness_eval.inspection.rules.agents.data_exfiltration import AgentDataExfiltration
    from harness_eval.inspection.rules.agents.description_required import (
        AgentDescriptionRequired,
    )
    from harness_eval.inspection.rules.agents.disallowed_tools_parseable import (
        DisallowedToolsParseable,
    )

    # Agent rules
    from harness_eval.inspection.rules.agents.excessive_permissions import (
        AgentExcessivePermissions,
    )
    from harness_eval.inspection.rules.agents.memory_write_unscoped import (
        AgentMemoryWriteUnscoped,
    )
    from harness_eval.inspection.rules.agents.model_specified import AgentModelSpecified
    from harness_eval.inspection.rules.agents.no_credential_access import (
        AgentNoCredentialAccess,
    )
    from harness_eval.inspection.rules.agents.no_prompt_injection import AgentNoPromptInjection
    from harness_eval.inspection.rules.agents.obfuscation_detection import (
        AgentObfuscationDetection,
    )
    from harness_eval.inspection.rules.agents.referenced_skills_exist import (
        ReferencedSkillsExist,
    )
    from harness_eval.inspection.rules.agents.reverse_shell_detection import (
        AgentReverseShellDetection,
    )
    from harness_eval.inspection.rules.agents.unbounded_delegation import (
        AgentUnboundedDelegation,
    )

    # CLAUDE.md rules
    from harness_eval.inspection.rules.claude_md.exists import ClaudeMdExists
    from harness_eval.inspection.rules.claude_md.generic_advice import ClaudeMdGenericAdvice
    from harness_eval.inspection.rules.claude_md.include_exists import ClaudeMdIncludeExists
    from harness_eval.inspection.rules.claude_md.skill_duplication import (
        ClaudeMdSkillDuplication,
    )
    from harness_eval.inspection.rules.commands.allowed_tools_coverage import (
        CommandAllowedToolsCoverage,
    )
    from harness_eval.inspection.rules.commands.data_exfiltration import CommandDataExfiltration

    # Command rules
    from harness_eval.inspection.rules.commands.description_required import (
        CommandDescriptionRequired,
    )
    from harness_eval.inspection.rules.commands.duplicate_detection import (
        CommandDuplicateDetection,
    )
    from harness_eval.inspection.rules.commands.no_credential_access import (
        CommandNoCredentialAccess,
    )
    from harness_eval.inspection.rules.commands.no_prompt_injection import (
        CommandNoPromptInjection,
    )
    from harness_eval.inspection.rules.commands.obfuscation_detection import (
        CommandObfuscationDetection,
    )
    from harness_eval.inspection.rules.commands.references_nonexistent_skill import (
        CommandReferencesNonexistentSkill,
    )
    from harness_eval.inspection.rules.commands.reverse_shell_detection import (
        CommandReverseShellDetection,
    )
    from harness_eval.inspection.rules.commands.script_exists import CommandScriptExists
    from harness_eval.inspection.rules.commands.shadows_builtin import CommandShadowsBuiltin
    from harness_eval.inspection.rules.commands.skill_overlap import CommandSkillOverlap
    from harness_eval.inspection.rules.content.allowed_tools_auto_approve import (
        AllowedToolsAutoApprove,
    )
    from harness_eval.inspection.rules.content.broken_references import BrokenReferences
    from harness_eval.inspection.rules.content.circular_references import CircularReferences
    from harness_eval.inspection.rules.content.description_length import DescriptionLength
    from harness_eval.inspection.rules.content.duplicate_detection import DuplicateDetection
    from harness_eval.inspection.rules.content.hardcoded_machine_path import HardcodedMachinePath
    from harness_eval.inspection.rules.content.mcp_skill_alignment import McpSkillAlignment
    from harness_eval.inspection.rules.content.orphan_skills import OrphanSkills
    from harness_eval.inspection.rules.content.permission_escalation import PermissionEscalation
    from harness_eval.inspection.rules.content.token_budget import TokenBudget
    from harness_eval.inspection.rules.content.total_context_budget import TotalContextBudget
    from harness_eval.inspection.rules.content.total_description_budget import (
        TotalDescriptionBudget,
    )
    from harness_eval.inspection.rules.cross.config_instruction_conflict import (
        ConfigInstructionConflict,
    )
    from harness_eval.inspection.rules.cross.multi_assistant_drift import MultiAssistantDrift
    from harness_eval.inspection.rules.cross.overpermissive_grants import OverpermissiveGrants
    from harness_eval.inspection.rules.frontmatter.description_quality import DescriptionQuality
    from harness_eval.inspection.rules.frontmatter.description_required import (
        DescriptionRequired,
    )
    from harness_eval.inspection.rules.frontmatter.format_valid import FormatValid

    # Hooks rules
    from harness_eval.inspection.rules.hooks.api_key_helper import HooksApiKeyHelper
    from harness_eval.inspection.rules.hooks.base_url_override import HooksBaseUrlOverride
    from harness_eval.inspection.rules.hooks.command_script_exists import HooksCommandScriptExists
    from harness_eval.inspection.rules.hooks.dangerous_command import HooksDangerousCommand
    from harness_eval.inspection.rules.hooks.env_credential_override import (
        HooksEnvCredentialOverride,
    )
    from harness_eval.inspection.rules.hooks.env_leakage import HooksEnvLeakage
    from harness_eval.inspection.rules.hooks.local_settings_committed import (
        HooksLocalSettingsCommitted,
    )
    from harness_eval.inspection.rules.hooks.matcher_matches_no_tool import (
        HooksMatcherMatchesNoTool,
    )
    from harness_eval.inspection.rules.hooks.network_access import HooksNetworkAccess
    from harness_eval.inspection.rules.hooks.permission_contradiction import (
        HooksPermissionContradiction,
    )
    from harness_eval.inspection.rules.hooks.permission_prompt_disabled import (
        HooksPermissionPromptDisabled,
    )
    from harness_eval.inspection.rules.hooks.pre_trust_permissions import (
        HooksPreTrustPermissions,
    )
    from harness_eval.inspection.rules.hooks.script_boundary import HooksScriptBoundary
    from harness_eval.inspection.rules.hooks.silent_failure_masking import (
        HooksSilentFailureMasking,
    )
    from harness_eval.inspection.rules.hooks.valid_structure import HooksValidStructure

    # MCP rules
    from harness_eval.inspection.rules.mcp.auto_approve_risk import McpAutoApproveRisk
    from harness_eval.inspection.rules.mcp.cross_assistant_divergence import (
        McpCrossAssistantDivergence,
    )
    from harness_eval.inspection.rules.mcp.endpoint_integrity import McpEndpointIntegrity
    from harness_eval.inspection.rules.mcp.no_plaintext_secrets import McpNoPlaintextSecrets
    from harness_eval.inspection.rules.mcp.no_wildcard_tools import McpNoWildcardTools
    from harness_eval.inspection.rules.mcp.suspicious_endpoint import McpSuspiciousEndpoint
    from harness_eval.inspection.rules.mcp.unpinned_package import McpUnpinnedPackage
    from harness_eval.inspection.rules.mcp.valid_config import McpValidConfig
    from harness_eval.inspection.rules.quality.example_gap import ExampleGap
    from harness_eval.inspection.rules.quality.imprecise_instruction import ImpreciseInstruction
    from harness_eval.inspection.rules.quality.negative_only import NegativeOnly
    from harness_eval.inspection.rules.quality.redundant_guidance import RedundantGuidance
    from harness_eval.inspection.rules.quality.scope_grab_description import (
        ScopeGrabDescription,
    )
    from harness_eval.inspection.rules.quality.scope_overreach import ScopeOverreach
    from harness_eval.inspection.rules.quality.stale_references import StaleReferences
    from harness_eval.inspection.rules.quality.trigger_manipulation import TriggerManipulation
    from harness_eval.inspection.rules.quality.unfinished_content import UnfinishedContent
    from harness_eval.inspection.rules.security.ast_behavioral import AstBehavioral
    from harness_eval.inspection.rules.security.bash_taint_tracking import BashTaintTracking
    from harness_eval.inspection.rules.security.coercive_override import CoerciveOverride
    from harness_eval.inspection.rules.security.credential_file_present import (
        SecurityCredentialFilePresent,
    )
    from harness_eval.inspection.rules.security.cross_component_flow import CrossComponentFlow
    from harness_eval.inspection.rules.security.cve_lookup import CveLookup
    from harness_eval.inspection.rules.security.data_exfiltration import DataExfiltration
    from harness_eval.inspection.rules.security.mcp_least_privilege import McpLeastPrivilege
    from harness_eval.inspection.rules.security.mcp_tool_poisoning import McpToolPoisoning
    from harness_eval.inspection.rules.security.memory_write_unscoped import MemoryWriteUnscoped
    from harness_eval.inspection.rules.security.no_credential_access import NoCredentialAccess
    from harness_eval.inspection.rules.security.no_prompt_injection import NoPromptInjection
    from harness_eval.inspection.rules.security.obfuscation_detection import (
        ObfuscationDetection,
    )
    from harness_eval.inspection.rules.security.prompt_exfiltration import PromptExfiltration
    from harness_eval.inspection.rules.security.reverse_shell_detection import (
        ReverseShellDetection,
    )
    from harness_eval.inspection.rules.security.stealth_persistence import StealthPersistence
    from harness_eval.inspection.rules.security.taint_tracking import TaintTracking
    from harness_eval.inspection.rules.security.unbounded_delegation import UnboundedDelegation
    from harness_eval.inspection.rules.security.yara_scan import YaraScan
    from harness_eval.inspection.rules.structural.json_duplicate_keys import (
        StructuralJsonDuplicateKeysMcp,
        StructuralJsonDuplicateKeysSettings,
    )
    from harness_eval.inspection.rules.structural.skill_md_exists import SkillMdExists
    from harness_eval.inspection.rules.structural.symlink_escape import StructuralSymlinkEscape
    from harness_eval.inspection.rules.submission.file_completeness import FileCompleteness

    for rule_cls in [
        SkillMdExists,
        DescriptionRequired,
        DescriptionQuality,
        FormatValid,
        TokenBudget,
        BrokenReferences,
        CircularReferences,
        DuplicateDetection,
        NoPromptInjection,
        NoCredentialAccess,
        ReverseShellDetection,
        ObfuscationDetection,
        DataExfiltration,
        CommandDescriptionRequired,
        CommandScriptExists,
        CommandNoPromptInjection,
        CommandNoCredentialAccess,
        CommandReverseShellDetection,
        CommandObfuscationDetection,
        CommandDataExfiltration,
        CommandSkillOverlap,
        CommandShadowsBuiltin,
        CommandDuplicateDetection,
        CommandReferencesNonexistentSkill,
        ClaudeMdExists,
        ClaudeMdSkillDuplication,
        ClaudeMdGenericAdvice,
        HooksScriptBoundary,
        HooksValidStructure,
        HooksDangerousCommand,
        HooksEnvLeakage,
        HooksNetworkAccess,
        AgentDescriptionRequired,
        ReferencedSkillsExist,
        DisallowedToolsParseable,
        ConstraintBodyMatch,
        AgentNoPromptInjection,
        AgentNoCredentialAccess,
        AgentReverseShellDetection,
        AgentObfuscationDetection,
        AgentDataExfiltration,
        AgentModelSpecified,
        AstBehavioral,
        TaintTracking,
        BashTaintTracking,
        McpLeastPrivilege,
        McpValidConfig,
        McpSuspiciousEndpoint,
        McpNoWildcardTools,
        McpToolPoisoning,
        YaraScan,
        CveLookup,
        ImpreciseInstruction,
        RedundantGuidance,
        UnfinishedContent,
        ExampleGap,
        StaleReferences,
        NegativeOnly,
        ScopeOverreach,
        TriggerManipulation,
        CoerciveOverride,
        StealthPersistence,
        PromptExfiltration,
        OrphanSkills,
        McpSkillAlignment,
        TotalContextBudget,
        PermissionEscalation,
        CrossComponentFlow,
        AgentExcessivePermissions,
        MemoryWriteUnscoped,
        AgentMemoryWriteUnscoped,
        UnboundedDelegation,
        AgentUnboundedDelegation,
        McpNoPlaintextSecrets,
        McpUnpinnedPackage,
        HooksMatcherMatchesNoTool,
        HardcodedMachinePath,
        ConfigInstructionConflict,
        MultiAssistantDrift,
        CommandAllowedToolsCoverage,
        OverpermissiveGrants,
        HooksPermissionContradiction,
        HooksPermissionPromptDisabled,
        HooksLocalSettingsCommitted,
        McpCrossAssistantDivergence,
        ClaudeMdIncludeExists,
        HooksCommandScriptExists,
        McpEndpointIntegrity,
        SecurityCredentialFilePresent,
        StructuralJsonDuplicateKeysMcp,
        StructuralJsonDuplicateKeysSettings,
        StructuralSymlinkEscape,
        HooksSilentFailureMasking,
        McpAutoApproveRisk,
        HooksBaseUrlOverride,
        HooksApiKeyHelper,
        HooksEnvCredentialOverride,
        HooksPreTrustPermissions,
        AllowedToolsAutoApprove,
        DescriptionLength,
        TotalDescriptionBudget,
        ScopeGrabDescription,
        FileCompleteness,
    ]:
        register_rule(rule_cls())

    from harness_eval.inspection.rules.claude_md.missing_boundary_policy import (
        ClaudeMdMissingBoundaryPolicy,
    )
    from harness_eval.inspection.rules.hooks.dangerous_permission_grant import (
        HooksDangerousPermissionGrant,
    )
    from harness_eval.inspection.rules.hooks.no_audit_trail import HooksNoAuditTrail
    from harness_eval.inspection.rules.hooks.no_commit_guard import HooksNoCommitGuard

    for rule_cls in [
        HooksNoCommitGuard,
        HooksDangerousPermissionGrant,
        HooksNoAuditTrail,
        ClaudeMdMissingBoundaryPolicy,
    ]:
        register_rule(rule_cls())

    from harness_eval.inspection.yaml_rules import load_yaml_rules

    load_yaml_rules()
