"""
Governance & Human-in-the-Loop Approval System

Implements the safety controls defined in GOVERNANCE.md:
- Network restrictions (lab-only)
- Triage level assessment
- Human approval workflow
- Audit logging
"""

import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from pathlib import Path
from typing import Callable, Optional


class TriageLevel(IntEnum):
    """
    Triage levels from GOVERNANCE.md

    Level 1-2: Auto-approve (read-only, non-destructive)
    Level 3+:  Human approval required
    """
    INFO = 1      # Read-only reconnaissance
    LOW = 2       # Non-destructive enumeration
    MEDIUM = 3    # State-changing but reversible
    HIGH = 4      # Privilege escalation, persistence
    CRITICAL = 5  # Destructive, exfiltration, lateral movement


@dataclass
class GovernanceConfig:
    """Configuration loaded from GOVERNANCE.md or defaults."""

    allowed_networks: list[str] = field(default_factory=lambda: [
        "127.0.0.0/8",      # Localhost
        "10.0.0.0/8",       # Private (lab VLANs)
        "172.16.0.0/12",    # Private (Docker networks)
        "192.168.0.0/16",   # Private (home/lab)
    ])

    auto_approve_levels: list[int] = field(default_factory=lambda: [1, 2])
    require_approval_levels: list[int] = field(default_factory=lambda: [3, 4, 5])

    audit_log_path: str = "output/logs"

    def is_target_allowed(self, target_ip: str) -> tuple[bool, str]:
        """Check if target IP is in allowed networks."""
        try:
            # Extract IP from "ip:port" format
            ip_str = target_ip.split(":")[0]
            ip = ipaddress.ip_address(ip_str)

            for network_str in self.allowed_networks:
                network = ipaddress.ip_network(network_str, strict=False)
                if ip in network:
                    return True, f"Target {ip_str} is in allowed network {network_str}"

            return False, f"Target {ip_str} is NOT in any allowed network. BLOCKED."

        except ValueError as e:
            return False, f"Invalid IP address: {e}"


@dataclass
class ApprovalRequest:
    """A request for human approval before execution."""

    action: str
    target: str
    triage_level: TriageLevel
    risk_description: str
    commands: list[str]
    governance_check: tuple[bool, str]
    timestamp: datetime = field(default_factory=datetime.now)

    # Approval status
    approved: Optional[bool] = None
    approved_by: Optional[str] = None
    approval_timestamp: Optional[datetime] = None
    rejection_reason: Optional[str] = None

    def to_display(self) -> str:
        """Format for human review."""
        status_icon = "✅" if self.governance_check[0] else "❌"

        commands_block = "\n".join(f"│ {cmd}" for cmd in self.commands)

        return f"""
[APPROVAL REQUIRED]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Action:      {self.action}
Target:      {self.target}
Triage:      {self.triage_level.name} (Level {self.triage_level.value})
Risk:        {self.risk_description}
Governance:  {status_icon} {self.governance_check[1]}

Commands to execute:
┌──────────────────────────────────────────────────────────────
{commands_block}
└──────────────────────────────────────────────────────────────

[A]pprove  [R]eject  [M]odify  [E]xplain
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""


class TriageAssessor:
    """
    Assesses triage level based on command patterns.

    Uses pattern matching to classify commands by risk level.
    """

    # Patterns for each triage level
    PATTERNS = {
        TriageLevel.INFO: [
            r"^nmap\s+-sn",           # Ping scan only
            r"^getprop\b",            # Android property read
            r"^cat\s+/proc/",         # Read proc filesystem
            r"^ls\b",                 # Directory listing
            r"^id\b",                 # User identity
            r"^whoami\b",             # Current user
            r"^uname\b",              # System info
        ],
        TriageLevel.LOW: [
            r"^nmap\s+-sV",           # Service version scan
            r"^pm\s+list",            # Package listing
            r"^dumpsys\b",            # Android service dump
            r"^redis-cli.*INFO",      # Redis info (read-only)
            r"^redis-cli.*GET",       # Redis read
            r"^adb\s+shell\s+.*getprop",
        ],
        TriageLevel.MEDIUM: [
            r"redis-cli.*CONFIG\s+SET",  # Redis config change
            r"redis-cli.*SET\b",         # Redis write
            r"^adb\s+push",              # Push file to device
            r"^chmod\b",                 # Permission change
            r"^mkdir\b",                 # Create directory
        ],
        TriageLevel.HIGH: [
            r"^su\b",                    # Switch user (root)
            r"\bsu\s+-c\b",              # su -c anywhere in command
            r"adb\s+shell\s+su\b",       # ADB shell with su
            r"msfconsole",               # Metasploit
            r"msfvenom",                 # Payload generation
            r"^adb\s+root",              # ADB root mode
            r"redis-cli.*MODULE\s+LOAD", # Redis module (RCE)
            r"frida\b",                  # Dynamic instrumentation
            r"objection\b",              # Mobile manipulation
            r"setenforce\s+0",           # Disable SELinux
            r"mount\s+-o\s+.*remount",   # Remount filesystem
        ],
        TriageLevel.CRITICAL: [
            r"rm\s+-rf",                 # Recursive delete
            r"dd\s+if=",                 # Disk operations
            r"mkfs\.",                   # Format filesystem
            r"reboot|shutdown",          # System control
            r"iptables",                 # Firewall rules
            r"exfil|upload|curl.*POST",  # Data exfiltration
            r"fastboot\s+flash",         # Flash device partitions
            r"fastboot\s+oem\s+unlock",  # Unlock bootloader
            r"fastboot\s+erase",         # Erase partitions
            r"adb\s+sideload",           # Sideload OTA/recovery
        ],
    }

    def assess(self, commands: list[str]) -> tuple[TriageLevel, str]:
        """
        Assess triage level for a list of commands.

        Returns highest level found and explanation.
        """
        highest_level = TriageLevel.INFO
        matched_patterns = []

        for cmd in commands:
            for level in reversed(list(TriageLevel)):  # Check highest first
                for pattern in self.PATTERNS.get(level, []):
                    if re.search(pattern, cmd, re.IGNORECASE):
                        if level > highest_level:
                            highest_level = level
                            matched_patterns.append((cmd, pattern, level.name))
                        break

        if matched_patterns:
            explanations = [f"'{cmd}' matches {level} pattern"
                          for cmd, _, level in matched_patterns[:3]]
            reason = "; ".join(explanations)
        else:
            reason = "No high-risk patterns detected"

        return highest_level, reason


class ApprovalWorkflow:
    """
    Human-in-the-loop approval workflow.

    Handles:
    - Governance validation
    - Triage assessment
    - Approval request/response
    - Audit logging
    """

    def __init__(
        self,
        config: Optional[GovernanceConfig] = None,
        approval_callback: Optional[Callable[[ApprovalRequest], bool]] = None,
    ):
        self.config = config or GovernanceConfig()
        self.approval_callback = approval_callback
        self.assessor = TriageAssessor()
        self._ensure_log_dir()

    def _ensure_log_dir(self):
        """Create audit log directory if needed."""
        Path(self.config.audit_log_path).mkdir(parents=True, exist_ok=True)

    def request_approval(
        self,
        action: str,
        target: str,
        commands: list[str],
        risk_description: str = "",
    ) -> ApprovalRequest:
        """
        Create an approval request.

        Args:
            action: High-level description of the action
            target: Target IP:port or device
            commands: List of commands to execute
            risk_description: Human-readable risk explanation

        Returns:
            ApprovalRequest ready for human review
        """
        # Check governance
        governance_check = self.config.is_target_allowed(target)

        # Assess triage level
        triage_level, triage_reason = self.assessor.assess(commands)

        # Auto-generate risk description if not provided
        if not risk_description:
            risk_description = triage_reason

        request = ApprovalRequest(
            action=action,
            target=target,
            triage_level=triage_level,
            risk_description=risk_description,
            commands=commands,
            governance_check=governance_check,
        )

        return request

    def process_approval(
        self,
        request: ApprovalRequest,
        approved: bool,
        approved_by: str = "operator",
        rejection_reason: str = "",
    ) -> ApprovalRequest:
        """
        Process human approval decision.
        """
        request.approved = approved
        request.approved_by = approved_by
        request.approval_timestamp = datetime.now()

        if not approved:
            request.rejection_reason = rejection_reason

        # Log the decision
        self._audit_log(request)

        return request

    def should_auto_approve(self, request: ApprovalRequest) -> bool:
        """
        Check if request can be auto-approved.

        Auto-approve if:
        - Target passes governance check
        - Triage level is in auto_approve_levels (1-2)
        """
        if not request.governance_check[0]:
            return False  # Failed governance = never auto-approve

        return request.triage_level.value in self.config.auto_approve_levels

    def _audit_log(self, request: ApprovalRequest):
        """Write approval decision to audit log."""
        log_file = Path(self.config.audit_log_path) / f"audit_{datetime.now():%Y%m%d}.jsonl"

        log_entry = {
            "timestamp": request.timestamp.isoformat(),
            "action": request.action,
            "target": request.target,
            "triage_level": request.triage_level.name,
            "commands": request.commands,
            "governance_passed": request.governance_check[0],
            "approved": request.approved,
            "approved_by": request.approved_by,
            "approval_time": request.approval_timestamp.isoformat() if request.approval_timestamp else None,
            "rejection_reason": request.rejection_reason,
        }

        with open(log_file, "a") as f:
            f.write(json.dumps(log_entry) + "\n")


# Convenience function for quick checks
def check_governance(target: str) -> tuple[bool, str]:
    """Quick governance check for a target."""
    config = GovernanceConfig()
    return config.is_target_allowed(target)


def assess_triage(commands: list[str]) -> tuple[TriageLevel, str]:
    """Quick triage assessment for commands."""
    assessor = TriageAssessor()
    return assessor.assess(commands)
