"""Known PowerShell attack pattern taxonomy.

The goal here is staged coverage of high-value, well-known PowerShell abuse
families rather than pretending to model every possible attack implementation.
Rules are grouped by category and assigned a level so the pipeline can evolve in
incremental coverage bands.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AttackPatternRule:
    rule_id: str
    name: str
    category: str
    level: int
    severity: str
    weight: float
    description: str
    mitre_techniques: tuple[str, ...]
    regexes: tuple[str, ...]
    requires_all: bool = False


ATTACK_PATTERN_RULES: tuple[AttackPatternRule, ...] = (
    AttackPatternRule(
        rule_id="encoded_execution",
        name="Encoded PowerShell Execution",
        category="obfuscation",
        level=1,
        severity="medium",
        weight=1.5,
        description="Detects encoded command invocation or explicit encoded execution wrappers.",
        mitre_techniques=("T1059.001", "T1027"),
        regexes=(r"(?i)-encodedcommand|-enc\b", r"(?i)frombase64string"),
    ),
    AttackPatternRule(
        rule_id="hidden_bypass_execution",
        name="Hidden or Bypass Execution Wrapper",
        category="execution_evasion",
        level=1,
        severity="medium",
        weight=1.2,
        description="Flags execution wrappers that combine hidden windows, no-profile, or policy bypass.",
        mitre_techniques=("T1059.001",),
        regexes=(r"(?i)-windowstyle\s+hidden", r"(?i)-executionpolicy\s+bypass|-executionpolicy\s+unrestricted"),
    ),
    AttackPatternRule(
        rule_id="invoke_expression",
        name="Invoke-Expression Primitive",
        category="execution",
        level=1,
        severity="medium",
        weight=1.0,
        description="Direct or aliased Invoke-Expression usage.",
        mitre_techniques=("T1059.001",),
        regexes=(r"(?i)\binvoke-expression\b|\biex\b",),
    ),
    AttackPatternRule(
        rule_id="download_primitive",
        name="Network Download Primitive",
        category="ingress_tool_transfer",
        level=1,
        severity="medium",
        weight=1.0,
        description="Network retrieval primitives frequently used in PowerShell download cradles.",
        mitre_techniques=("T1105", "T1059.001"),
        regexes=(
            r"(?i)invoke-webrequest|\biwr\b|\bcurl\b|\bwget\b",
            r"(?i)new-object\s+net\.webclient|downloadstring|downloadfile|webclient",
        ),
    ),
    AttackPatternRule(
        rule_id="download_and_execute_chain",
        name="Download and Immediate Execution Chain",
        category="ingress_tool_transfer",
        level=2,
        severity="high",
        weight=2.5,
        description="Remote content retrieval immediately combined with execution.",
        mitre_techniques=("T1105", "T1059.001"),
        regexes=(
            r"(?i)invoke-webrequest|\biwr\b|downloadstring|downloadfile|new-object\s+net\.webclient",
            r"(?i)\binvoke-expression\b|\biex\b|start-process|powershell\.exe",
        ),
        requires_all=True,
    ),
    AttackPatternRule(
        rule_id="compression_loader",
        name="Compressed or Layered Loader",
        category="obfuscation",
        level=2,
        severity="high",
        weight=2.0,
        description="Compressed, encoded, or multi-layered loader semantics.",
        mitre_techniques=("T1027", "T1059.001"),
        regexes=(
            r"(?i)gzip|deflate|decompress|io\.compression",
            r"(?i)frombase64string|tobase64string",
        ),
        requires_all=True,
    ),
    AttackPatternRule(
        rule_id="reflection_load",
        name="Reflection or Dynamic Assembly Loading",
        category="defense_evasion",
        level=2,
        severity="high",
        weight=2.0,
        description="Reflection-based loading or assembly invocation in memory.",
        mitre_techniques=("T1055", "T1059.001"),
        regexes=(r"(?i)\[reflection\.assembly\]::load|assembly::load|add-type",),
    ),
    AttackPatternRule(
        rule_id="dotnet_runtime_abuse",
        name="Direct System.Management.Automation or Runspace Abuse",
        category="execution_evasion",
        level=2,
        severity="high",
        weight=2.0,
        description="PowerShell engine abuse without straightforward powershell.exe invocation.",
        mitre_techniques=("T1059.001",),
        regexes=(r"(?i)system\.management\.automation|runspacefactory|powershellcreate|addscript",),
    ),
    AttackPatternRule(
        rule_id="amsi_bypass_reference",
        name="AMSI Bypass Reference",
        category="defense_evasion",
        level=3,
        severity="critical",
        weight=3.0,
        description="References commonly associated with AMSI evasion or tampering.",
        mitre_techniques=("T1562.001", "T1059.001"),
        regexes=(r"(?i)\bamsi\b|amsiutils|am si|scancontent",),
    ),
    AttackPatternRule(
        rule_id="run_key_persistence",
        name="Run Key or Startup Persistence",
        category="persistence",
        level=2,
        severity="high",
        weight=2.2,
        description="Persistence via startup-related registry or startup folder references.",
        mitre_techniques=("T1547.001",),
        regexes=(
            r"(?i)set-itemproperty|new-itemproperty|add-itemproperty|reg(?:\.exe)?\s+add|copy-item|move-item|new-item",
            r"(?i)hkcu:.*\\run\b|hklm:.*\\run\b|currentversion\\run\b|startup\\|startup folder|start menu\\programs\\startup",
        ),
        requires_all=True,
    ),
    AttackPatternRule(
        rule_id="scheduled_task_persistence",
        name="Scheduled Task Persistence",
        category="persistence",
        level=2,
        severity="high",
        weight=2.2,
        description="Scheduled task creation, registration, or execution patterns.",
        mitre_techniques=("T1053.005",),
        regexes=(r"(?i)register-scheduledtask|new-scheduledtask|schtasks(?:\.exe)?",),
    ),
    AttackPatternRule(
        rule_id="service_persistence",
        name="Windows Service Persistence",
        category="persistence",
        level=2,
        severity="high",
        weight=2.0,
        description="Service creation or modification for persistence or execution.",
        mitre_techniques=("T1543.003",),
        regexes=(r"(?i)new-service|sc(?:\.exe)?\s+create|win32_service",),
    ),
    AttackPatternRule(
        rule_id="wmi_event_subscription",
        name="WMI Event Subscription",
        category="persistence",
        level=3,
        severity="critical",
        weight=3.0,
        description="WMI event filter, consumer, or binding based persistence.",
        mitre_techniques=("T1546.003",),
        regexes=(r"(?i)__eventfilter|commandlineeventconsumer|filtertoconsumerbinding|set-wmiinstance|wmic",),
    ),
    AttackPatternRule(
        rule_id="psremoting_lateral_movement",
        name="PowerShell Remoting or WinRM",
        category="lateral_movement",
        level=2,
        severity="high",
        weight=1.8,
        description="PowerShell remoting, WinRM, or remote command invocation primitives.",
        mitre_techniques=("T1021.006", "T1059.001"),
        regexes=(r"(?i)invoke-command|new-pssession|enter-pssession|invoke-wmimethod|winrs(?:\.exe)?|winrm\s+(?:invoke|quickconfig|set|create)",),
    ),
    AttackPatternRule(
        rule_id="shadow_copy_deletion",
        name="Shadow Copy or Backup Destruction",
        category="impact",
        level=3,
        severity="critical",
        weight=3.0,
        description="Ransomware-style destruction of recovery artifacts.",
        mitre_techniques=("T1490", "T1059.001"),
        regexes=(r"(?i)vssadmin(?:\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy|wbadmin\s+delete",),
    ),
    AttackPatternRule(
        rule_id="ad_discovery",
        name="AD and Domain Reconnaissance",
        category="discovery",
        level=1,
        severity="medium",
        weight=1.0,
        description="Common directory, host, or domain reconnaissance cmdlets.",
        mitre_techniques=("T1087", "T1018", "T1482", "T1059.001"),
        regexes=(r"(?i)get-aduser|get-adcomputer|get-domain|get-netgroup|nltest|whoami\s+/all",),
    ),
    AttackPatternRule(
        rule_id="credential_theft_loader",
        name="In-Memory Loader or Interop Shellcode Primitives",
        category="credential_access",
        level=3,
        severity="critical",
        weight=3.2,
        description="Interop and memory primitives often seen in shellcode loaders or credential tooling.",
        mitre_techniques=("T1055", "T1106", "T1059.001"),
        regexes=(r"(?i)virtualalloc|createthread|writeprocessmemory|rundll32|marshal|memcpy",),
    ),
)


KNOWN_RULE_IDS = tuple(rule.rule_id for rule in ATTACK_PATTERN_RULES)
KNOWN_RULE_CATEGORIES = tuple(sorted({rule.category for rule in ATTACK_PATTERN_RULES}))
