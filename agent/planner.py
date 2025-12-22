"""
Planner Module

Inspired by HackSynth's Planner component.
Generates penetration testing strategies and commands based on:
- Current phase (recon, scan, exploit, escalate, verify)
- Target information
- Previous results from Summarizer

The Planner is the "strategic brain" that decides WHAT to do next.
"""

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .llm_client import BaseLLMClient, LLMClient


class PentestPhase(Enum):
    """
    Android penetration testing phases.

    Extended from basic pentest methodology to include Android-specific techniques:
    - Intent/IPC attacks
    - Traffic interception (MITM)
    - ADB-specific abuse
    - Persistence mechanisms
    """
    # Core phases (original)
    RECONNAISSANCE = "recon"
    SCANNING = "scan"
    EXPLOITATION = "exploit"
    PRIVILEGE_ESCALATION = "escalate"
    VERIFICATION = "verify"

    # Extended phases (Android-specific)
    INFO_GATHERING = "info_gather"      # Deep application analysis
    ADB_ABUSE = "adb_abuse"             # ADB-specific attack vectors
    INTENT_HIJACKING = "intent_hijack"  # Intent/IPC exploitation
    MITM_SETUP = "mitm_setup"           # Traffic interception prep
    PERSISTENCE = "persistence"          # Maintaining access
    DATA_EXFIL = "data_exfil"           # Data extraction (authorized)


@dataclass
class PlanStep:
    """A single step in the penetration testing plan."""
    phase: PentestPhase
    action: str
    command: Optional[str]
    rationale: str
    risk_level: str  # low | medium | high
    requires_confirmation: bool = True


@dataclass
class PentestPlan:
    """Complete penetration testing plan."""
    target: str
    objective: str
    steps: list[PlanStep] = field(default_factory=list)
    current_step: int = 0


class Planner:
    """
    Strategic planning module for Android penetration testing.

    Generates step-by-step attack plans based on:
    1. Target configuration (device, Android version, etc.)
    2. Objective (root access, data extraction, etc.)
    3. Feedback from previous actions (via Summarizer)
    """

    def __init__(self, llm_client: Optional[BaseLLMClient] = None):
        self.llm = llm_client or LLMClient.create()
        self.prompts_dir = os.path.join(os.path.dirname(__file__), "prompts")

    def _load_prompt(self, phase: PentestPhase) -> str:
        """Load phase-specific prompt template."""
        prompt_file = os.path.join(self.prompts_dir, f"{phase.value}.md")
        if os.path.exists(prompt_file):
            with open(prompt_file) as f:
                return f.read()
        return self._get_default_prompt(phase)

    def _get_default_prompt(self, phase: PentestPhase) -> str:
        """Minimal fallback prompt if template file is missing."""
        return f"""
You are an expert Android penetration tester. Your task is to plan actions for the {phase.name} phase.

Target: {{target}}
Objective: {{objective}}
Previous findings: {{context}}

Provide actionable steps with:
- ACTION: <description>
- COMMAND: <adb or shell command>
- RATIONALE: <why this helps>
"""

    def create_plan(
        self,
        target: str,
        objective: str,
        context: str = "",
    ) -> PentestPlan:
        """
        Generate a complete penetration testing plan.

        Args:
            target: Target device description
            objective: Goal (e.g., "achieve root access")
            context: Additional context from previous runs

        Returns:
            PentestPlan with ordered steps
        """
        system_prompt = """You are PentestGPT, an expert penetration testing AI.
You specialize in Android security assessment and exploitation.
Generate detailed, actionable penetration testing plans.
Always consider safety and require confirmation for high-risk actions."""

        plan_prompt = f"""
Create a comprehensive penetration testing plan for:

TARGET: {target}
OBJECTIVE: {objective}
CONTEXT: {context or "Initial assessment - no prior data"}

Output a structured plan covering all phases:
1. Reconnaissance
2. Vulnerability Scanning
3. Exploitation
4. Privilege Escalation
5. Verification

For each step provide:
- Phase
- Action description
- Specific command(s)
- Rationale
- Risk level (low/medium/high)
"""

        response = self.llm.complete(plan_prompt, system=system_prompt)
        return self._parse_plan_response(response.content, target, objective)

    def get_next_action(
        self,
        phase: PentestPhase,
        target: str,
        objective: str,
        context: str,
    ) -> PlanStep:
        """
        Get the next recommended action for a specific phase.

        This is the iterative planning approach - called after each
        action's results are summarized.
        """
        prompt_template = self._load_prompt(phase)
        prompt = prompt_template.format(
            target=target,
            objective=objective,
            context=context,
        )

        response = self.llm.complete(prompt)
        return self._parse_step_response(response.content, phase)

    def _parse_plan_response(
        self, response: str, target: str, objective: str
    ) -> PentestPlan:
        """Parse LLM response into structured PentestPlan."""
        plan = PentestPlan(target=target, objective=objective)

        # Phase keywords to detect which phase a section belongs to
        phase_keywords = {
            PentestPhase.RECONNAISSANCE: ["reconnaissance", "recon", "information gathering", "enumeration"],
            PentestPhase.SCANNING: ["scanning", "vulnerability scan", "vuln scan", "cve"],
            PentestPhase.EXPLOITATION: ["exploitation", "exploit", "attack"],
            PentestPhase.PRIVILEGE_ESCALATION: ["privilege escalation", "privesc", "root", "escalat"],
            PentestPhase.VERIFICATION: ["verification", "verify", "confirm", "validate"],
        }

        # Split response into sections and parse each
        sections = re.split(r'\n(?=\d+\.|\*\*|\#)', response)

        for section in sections:
            if not section.strip():
                continue

            # Determine phase from section content
            detected_phase = None
            section_lower = section.lower()
            for phase, keywords in phase_keywords.items():
                if any(kw in section_lower for kw in keywords):
                    detected_phase = phase
                    break

            if not detected_phase:
                detected_phase = PentestPhase.RECONNAISSANCE  # Default

            # Extract structured fields
            step = self._extract_step_fields(section, detected_phase)
            if step.action:  # Only add if we extracted something meaningful
                plan.steps.append(step)

        # Ensure at least one step per core phase if none were parsed
        core_phases = [
            PentestPhase.RECONNAISSANCE,
            PentestPhase.SCANNING,
            PentestPhase.EXPLOITATION,
            PentestPhase.PRIVILEGE_ESCALATION,
            PentestPhase.VERIFICATION,
        ]
        existing_phases = {s.phase for s in plan.steps}
        for phase in core_phases:
            if phase not in existing_phases:
                plan.steps.append(
                    PlanStep(
                        phase=phase,
                        action=f"Execute {phase.value} phase",
                        command=None,
                        rationale=f"Standard {phase.value} procedures",
                        risk_level="medium",
                    )
                )

        return plan

    def _parse_step_response(self, response: str, phase: PentestPhase) -> PlanStep:
        """Parse single step from LLM response."""
        return self._extract_step_fields(response, phase)

    def _extract_step_fields(self, text: str, phase: PentestPhase) -> PlanStep:
        """
        Extract structured fields from LLM response text.

        Looks for patterns like:
        - ACTION: <description>
        - COMMAND: <command>
        - RATIONALE: <reason>
        - RISK_LEVEL: <low|medium|high>
        """
        # Extract ACTION
        action_match = re.search(
            r'(?:ACTION|STEP|TASK|DESCRIPTION)[:\s]*(.+?)(?=\n(?:COMMAND|RATIONALE|RISK)|$)',
            text,
            re.IGNORECASE | re.DOTALL
        )
        action = action_match.group(1).strip() if action_match else ""

        # If no ACTION field, try to extract first meaningful line
        if not action:
            lines = [l.strip() for l in text.split('\n') if l.strip() and not l.startswith('#')]
            # Skip numbered prefixes like "1." or "**"
            for line in lines[:3]:
                cleaned = re.sub(r'^[\d\.\*\-\s]+', '', line).strip()
                if len(cleaned) > 10:
                    action = cleaned[:500]
                    break

        # Extract COMMAND
        command_match = re.search(
            r'(?:COMMAND|CMD|EXECUTE|RUN)[:\s]*[`\'"]?([^`\'"]+?)[`\'"]?(?=\n|$)',
            text,
            re.IGNORECASE
        )
        command = command_match.group(1).strip() if command_match else None

        # Also look for code blocks
        if not command:
            code_match = re.search(r'```(?:bash|shell|sh)?\n?(.*?)```', text, re.DOTALL)
            if code_match:
                command = code_match.group(1).strip()

        # Extract RATIONALE
        rationale_match = re.search(
            r'(?:RATIONALE|REASON|WHY|PURPOSE)[:\s]*(.+?)(?=\n(?:COMMAND|RISK|ACTION)|$)',
            text,
            re.IGNORECASE | re.DOTALL
        )
        rationale = rationale_match.group(1).strip() if rationale_match else "Generated by Planner"

        # Extract RISK_LEVEL
        risk_match = re.search(
            r'(?:RISK_LEVEL|RISK|SEVERITY)[:\s]*(low|medium|high|critical)',
            text,
            re.IGNORECASE
        )
        risk_level = risk_match.group(1).lower() if risk_match else "medium"

        # Normalize risk level
        if risk_level == "critical":
            risk_level = "high"

        # Determine if confirmation required based on risk and keywords
        high_risk_keywords = ["root", "exploit", "inject", "delete", "flash", "format", "su ", "sudo"]
        requires_confirmation = (
            risk_level == "high" or
            any(kw in text.lower() for kw in high_risk_keywords)
        )

        return PlanStep(
            phase=phase,
            action=action or f"Execute {phase.value} phase",
            command=command,
            rationale=rationale[:500] if rationale else "Generated by Planner",
            risk_level=risk_level,
            requires_confirmation=requires_confirmation,
        )
