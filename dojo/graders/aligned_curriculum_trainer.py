#!/usr/bin/env python3
"""
Aligned Curriculum Trainer: Coherent System Implementation

Implements the coherent alignment chain:
Outcomes → Curriculum → Instruction → Assessment

Every challenge maps to specific competencies.
No orphan content. No gaps.
Assessments elicit direct evidence through performance tasks.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path


class Competency(Enum):
    """The 12 core competencies - the ONLY outcomes we build."""
    C1_STATIC = "static_analysis"
    C2_DYNAMIC = "dynamic_analysis"
    C3_TRAFFIC = "traffic_analysis"
    C4_BYPASS = "protection_bypass"
    C5_VULN_ID = "vulnerability_identification"
    C6_ROOT_CAUSE = "root_cause_analysis"
    C7_THREAT_MODEL = "threat_modeling"
    C8_TRADEOFF = "tradeoff_reasoning"
    C9_UNCERTAINTY = "uncertainty_handling"
    C10_TRANSFER = "transfer_application"
    C11_COMMUNICATION = "communication"
    C12_FRAMEWORK = "framework_creation"


COMPETENCY_DEFINITIONS = {
    Competency.C1_STATIC: {
        "definition": "Extract and analyze APK code, manifest, resources",
        "assessment": "Performance: Analyze unseen APK correctly"
    },
    Competency.C2_DYNAMIC: {
        "definition": "Instrument running app, observe and modify behavior",
        "assessment": "Performance: Hook functions in Genymotion"
    },
    Competency.C3_TRAFFIC: {
        "definition": "Intercept, analyze, modify network traffic",
        "assessment": "Performance: Capture and analyze HTTPS traffic"
    },
    Competency.C4_BYPASS: {
        "definition": "Bypass client-side protections",
        "assessment": "Performance: Bypass root/SSL/debug detection"
    },
    Competency.C5_VULN_ID: {
        "definition": "Identify security weaknesses",
        "assessment": "Performance: Find vulnerabilities in unseen app"
    },
    Competency.C6_ROOT_CAUSE: {
        "definition": "Determine WHY vulnerabilities exist",
        "assessment": "Explanation: Articulate root cause with transfer"
    },
    Competency.C7_THREAT_MODEL: {
        "definition": "Identify relevant threats and attack vectors",
        "assessment": "Product: Threat model for application"
    },
    Competency.C8_TRADEOFF: {
        "definition": "Make justified decisions under constraints",
        "assessment": "Explanation: Defend prioritization choices"
    },
    Competency.C9_UNCERTAINTY: {
        "definition": "Express appropriate confidence levels",
        "assessment": "Explanation: Calibrated uncertainty"
    },
    Competency.C10_TRANSFER: {
        "definition": "Apply principles to novel contexts",
        "assessment": "Performance: New platform/app analysis"
    },
    Competency.C11_COMMUNICATION: {
        "definition": "Convey findings to enable action",
        "assessment": "Product: Actionable report"
    },
    Competency.C12_FRAMEWORK: {
        "definition": "Develop new analytical approaches",
        "assessment": "Product: Novel methodology"
    }
}


@dataclass
class AlignedChallenge:
    """A challenge with explicit competency alignment."""
    id: str
    unit: int  # 1-8
    title: str

    # Competency alignment (required)
    primary_competency: Competency
    secondary_competencies: list[Competency] = field(default_factory=list)

    # Challenge content
    scenario: str
    task: str
    success_criteria: list[str]

    # Assessment integration
    formative_check: str  # How to check progress
    evidence_required: list[str]  # What demonstrates competency

    # Instruction design
    instruction_elements: list[str]  # Why each prompt element exists


# ============================================================================
# UNIT 1: FOUNDATIONS (C1, C5)
# ============================================================================

UNIT_1_CHALLENGES = [
    AlignedChallenge(
        id="U1.1",
        unit=1,
        title="APK Structure Analysis",
        primary_competency=Competency.C1_STATIC,
        scenario="""You have cryptovault.apk, a password manager application.
Before looking for vulnerabilities, you need to understand its structure.""",
        task="""Extract and analyze the APK structure:
1. Identify all components (activities, services, receivers, providers)
2. Analyze the manifest for security-relevant configurations
3. Map the code structure (packages, key classes)
4. Identify third-party libraries""",
        success_criteria=[
            "All components correctly identified",
            "Security-relevant manifest entries noted",
            "Code structure mapped accurately",
            "Third-party libraries identified"
        ],
        formative_check="Can navigate decompiled APK and locate specific elements",
        evidence_required=[
            "Component list with purposes",
            "Manifest analysis with security notes",
            "Code structure diagram or description"
        ],
        instruction_elements=[
            "Explicit structure requirement → C1 (systematic analysis)",
            "Security-relevant focus → C5 (vulnerability awareness)",
            "Third-party identification → C7 (attack surface)"
        ]
    ),
    AlignedChallenge(
        id="U1.2",
        unit=1,
        title="Manifest Security Review",
        primary_competency=Competency.C1_STATIC,
        secondary_competencies=[Competency.C5_VULN_ID],
        scenario="""The AndroidManifest.xml defines the app's security posture.
Misconfigurations here create vulnerabilities.""",
        task="""Analyze the manifest for security issues:
1. Check exported components and their implications
2. Review permission declarations
3. Identify backup and debuggable settings
4. Assess intent filter exposures""",
        success_criteria=[
            "Exported components identified with risk assessment",
            "Permissions analyzed for necessity",
            "Backup/debug settings evaluated",
            "Intent filter risks documented"
        ],
        formative_check="Can identify security implications of manifest entries",
        evidence_required=[
            "List of security-relevant manifest entries",
            "Risk assessment for each finding",
            "Remediation recommendations"
        ],
        instruction_elements=[
            "Structured analysis requirement → C1",
            "Risk assessment → C5, C7",
            "Remediation focus → C11"
        ]
    ),
    AlignedChallenge(
        id="U1.3",
        unit=1,
        title="Hardcoded Secret Discovery",
        primary_competency=Competency.C5_VULN_ID,
        secondary_competencies=[Competency.C1_STATIC],
        scenario="""Developers often embed secrets in code. These are extractable.""",
        task="""Find all hardcoded secrets in cryptovault.apk:
1. Search strings.xml and other resources
2. Analyze BuildConfig and generated code
3. Check native libraries if present
4. Examine code for embedded credentials""",
        success_criteria=[
            "All secret locations identified",
            "Secret types categorized (API keys, passwords, etc.)",
            "Extraction demonstrated",
            "Impact assessment provided"
        ],
        formative_check="Can systematically locate embedded secrets",
        evidence_required=[
            "List of secrets with locations",
            "Extraction evidence",
            "Impact assessment"
        ],
        instruction_elements=[
            "Systematic search → C1",
            "Categorization → C5",
            "Impact assessment → C7"
        ]
    ),
]


# ============================================================================
# UNIT 2: DYNAMIC ANALYSIS (C2, C3, C4)
# ============================================================================

UNIT_2_CHALLENGES = [
    AlignedChallenge(
        id="U2.1",
        unit=2,
        title="Frida Method Hooking",
        primary_competency=Competency.C2_DYNAMIC,
        scenario="""Runtime analysis requires instrumenting the running app.
Frida allows hooking methods to observe and modify behavior.""",
        task="""On Genymotion with nativecheck.apk:
1. Attach Frida to the running process
2. Hook a security-relevant method (e.g., isDeviceSafe())
3. Log method calls with arguments and return values
4. Modify the return value to observe behavior change""",
        success_criteria=[
            "Frida attached successfully",
            "Method hooked correctly",
            "Arguments and returns logged",
            "Behavior modification demonstrated"
        ],
        formative_check="Can write and execute Frida hooks",
        evidence_required=[
            "Frida script",
            "Console output showing hooks",
            "Before/after behavior comparison"
        ],
        instruction_elements=[
            "Hands-on Genymotion task → C2",
            "Logging requirement → C2 (observation)",
            "Modification requirement → C4 (bypass potential)"
        ]
    ),
    AlignedChallenge(
        id="U2.2",
        unit=2,
        title="Root Detection Bypass",
        primary_competency=Competency.C4_BYPASS,
        secondary_competencies=[Competency.C2_DYNAMIC, Competency.C6_ROOT_CAUSE],
        scenario="""nativecheck.apk blocks functionality on rooted devices.
The app claims this protection is "unbypassable".""",
        task="""Bypass the root detection:
1. Identify how root detection works (static + dynamic)
2. Create Frida script to bypass detection
3. Verify bypass grants access to protected functionality
4. Explain WHY your bypass works (root cause)""",
        success_criteria=[
            "Detection mechanism identified",
            "Bypass script functional",
            "Protected functionality accessed",
            "Root cause explanation demonstrates understanding"
        ],
        formative_check="Bypass achieves intended effect",
        evidence_required=[
            "Detection mechanism analysis",
            "Working Frida script",
            "Screenshot of bypassed state",
            "Written explanation of WHY bypass works"
        ],
        instruction_elements=[
            "Identification before bypass → C1, C2",
            "Working bypass → C4",
            "Root cause explanation → C6",
            "WHY emphasis → builds transfer capability"
        ]
    ),
    AlignedChallenge(
        id="U2.3",
        unit=2,
        title="SSL Pinning Analysis and Bypass",
        primary_competency=Competency.C4_BYPASS,
        secondary_competencies=[Competency.C3_TRAFFIC, Competency.C6_ROOT_CAUSE],
        scenario="""sslpinned.apk implements certificate pinning to prevent traffic interception.
Understanding and bypassing this is essential for traffic analysis.""",
        task="""Analyze and bypass SSL pinning:
1. Identify the pinning implementation (Network Security Config, TrustManager, OkHttp)
2. Attempt interception and observe failure
3. Bypass pinning using appropriate technique
4. Capture and analyze decrypted traffic
5. Explain the fundamental limitation that makes bypass possible""",
        success_criteria=[
            "Pinning implementation correctly identified",
            "Bypass successful",
            "HTTPS traffic decrypted and analyzed",
            "Fundamental limitation explained (device owner control)"
        ],
        formative_check="Can intercept pinned traffic",
        evidence_required=[
            "Pinning implementation analysis",
            "Bypass method and script",
            "Captured traffic sample",
            "Explanation of why pinning can be bypassed"
        ],
        instruction_elements=[
            "Implementation identification → C1",
            "Bypass execution → C4",
            "Traffic analysis → C3",
            "Fundamental explanation → C6, C10 (transfer)"
        ]
    ),
]


# ============================================================================
# UNIT 3: ROOT CAUSE ANALYSIS (C6, C5)
# ============================================================================

UNIT_3_CHALLENGES = [
    AlignedChallenge(
        id="U3.1",
        unit=3,
        title="Beyond the Symptom",
        primary_competency=Competency.C6_ROOT_CAUSE,
        secondary_competencies=[Competency.C5_VULN_ID],
        scenario="""vulnbank.apk has a vulnerability. Finding it is not enough.
Understanding WHY it exists enables prevention.""",
        task="""For the vulnerability you find:
1. Identify the symptom (what can be exploited)
2. Identify the mechanism (how exploitation works)
3. Identify the root cause (why this vulnerability exists)
4. Identify the transferable principle (where else this applies)""",
        success_criteria=[
            "Symptom correctly identified",
            "Mechanism accurately described",
            "Root cause goes beyond 'developer mistake'",
            "Transferable principle is genuinely transferable"
        ],
        formative_check="Can distinguish symptom from root cause",
        evidence_required=[
            "Four-level analysis (symptom, mechanism, cause, principle)",
            "Evidence for root cause claim",
            "Example of where principle applies elsewhere"
        ],
        instruction_elements=[
            "Four-level structure → forces deep analysis",
            "Transfer requirement → C10",
            "'Beyond developer mistake' → genuine understanding"
        ]
    ),
    AlignedChallenge(
        id="U3.2",
        unit=3,
        title="Developer Assumption Analysis",
        primary_competency=Competency.C6_ROOT_CAUSE,
        scenario="""Most vulnerabilities exist because developers made reasonable
assumptions that turn out to be wrong in adversarial contexts.""",
        task="""For a vulnerability in cryptovault.apk:
1. Identify what assumption the developer made
2. Explain why that assumption seemed reasonable
3. Explain why it fails in adversarial context
4. Describe what assumption would have been correct""",
        success_criteria=[
            "Assumption clearly articulated",
            "Reasonableness explained (not 'developer was stupid')",
            "Adversarial failure explained",
            "Correct assumption identified"
        ],
        formative_check="Can articulate developer assumptions",
        evidence_required=[
            "Assumption analysis document",
            "Evidence from code supporting assumption inference"
        ],
        instruction_elements=[
            "Assumption focus → root cause thinking",
            "'Seemed reasonable' → empathy + understanding",
            "Adversarial context → C7 (threat modeling)"
        ]
    ),
]


# ============================================================================
# UNIT 4: THREAT MODELING (C7, C8)
# ============================================================================

UNIT_4_CHALLENGES = [
    AlignedChallenge(
        id="U4.1",
        unit=4,
        title="Attack Surface Mapping",
        primary_competency=Competency.C7_THREAT_MODEL,
        secondary_competencies=[Competency.C1_STATIC],
        scenario="""Before assessing security, understand what CAN be attacked.
The attack surface defines scope.""",
        task="""Map the complete attack surface of fortified.apk:
1. External interfaces (network, IPC, file system)
2. Trust boundaries (what trusts what)
3. Data flows (where sensitive data moves)
4. Entry points (where attacker input enters)""",
        success_criteria=[
            "All external interfaces identified",
            "Trust boundaries clearly mapped",
            "Sensitive data flows traced",
            "Entry points enumerated"
        ],
        formative_check="Can identify attack surface components",
        evidence_required=[
            "Attack surface diagram or structured description",
            "Trust boundary analysis",
            "Data flow diagram"
        ],
        instruction_elements=[
            "Systematic mapping → C7",
            "Trust boundaries → C7 (key concept)",
            "Data flows → C5 (vulnerability identification)"
        ]
    ),
    AlignedChallenge(
        id="U4.2",
        unit=4,
        title="Prioritization Under Constraints",
        primary_competency=Competency.C8_TRADEOFF,
        secondary_competencies=[Competency.C7_THREAT_MODEL],
        scenario="""You have 4 hours to assess an app with 12 potential attack vectors.
You cannot test everything. How do you prioritize?""",
        task="""Create and justify a prioritized testing plan:
1. List all potential attack vectors
2. Rank by risk (likelihood × impact)
3. Select which to test given time constraint
4. Explicitly justify what you're NOT testing and why""",
        success_criteria=[
            "Attack vectors comprehensively listed",
            "Ranking methodology clear",
            "Selection justified",
            "Gaps acknowledged with reasoning"
        ],
        formative_check="Can make and defend prioritization decisions",
        evidence_required=[
            "Prioritized attack vector list",
            "Selection rationale",
            "Gap acknowledgment"
        ],
        instruction_elements=[
            "Explicit constraint → C8",
            "Justify NOT testing → C8 (trade-off)",
            "Gap acknowledgment → C9 (uncertainty)"
        ]
    ),
]


# ============================================================================
# UNIT 5: UNCERTAINTY AND EVIDENCE (C9, C8)
# ============================================================================

UNIT_5_CHALLENGES = [
    AlignedChallenge(
        id="U5.1",
        unit=5,
        title="Evidence Quality Assessment",
        primary_competency=Competency.C9_UNCERTAINTY,
        scenario="""Not all evidence is equal. Vendor claims, tool output, and
verified findings have different reliability.""",
        task="""Given multiple evidence sources about an app's security:
1. Assess quality of each source (strong/medium/weak)
2. Identify potential biases and blind spots
3. Synthesize into overall assessment
4. Express confidence level with justification""",
        success_criteria=[
            "Evidence quality assessed appropriately",
            "Biases identified",
            "Synthesis integrates sources",
            "Confidence calibrated to evidence"
        ],
        formative_check="Can assess evidence quality",
        evidence_required=[
            "Evidence quality ratings with justification",
            "Bias analysis",
            "Integrated assessment",
            "Confidence statement"
        ],
        instruction_elements=[
            "Quality assessment → C9",
            "Bias identification → C9",
            "Confidence calibration → C9"
        ]
    ),
    AlignedChallenge(
        id="U5.2",
        unit=5,
        title="Contradictory Evidence Resolution",
        primary_competency=Competency.C9_UNCERTAINTY,
        secondary_competencies=[Competency.C8_TRADEOFF],
        scenario="""Your static analysis says encryption is correct.
But users report data was stolen. Evidence contradicts.""",
        task="""Resolve the contradiction:
1. Generate multiple hypotheses that could explain all evidence
2. Rank hypotheses by plausibility
3. Design investigation to distinguish between hypotheses
4. Acknowledge what remains uncertain""",
        success_criteria=[
            "Multiple viable hypotheses generated",
            "Ranking justified",
            "Investigation plan logical",
            "Uncertainty acknowledged"
        ],
        formative_check="Can generate and evaluate hypotheses",
        evidence_required=[
            "Hypothesis list with reasoning",
            "Investigation plan",
            "Uncertainty acknowledgment"
        ],
        instruction_elements=[
            "Multiple hypotheses → C9 (avoiding premature certainty)",
            "Investigation design → C8 (prioritization)",
            "Uncertainty → C9"
        ]
    ),
]


# ============================================================================
# UNIT 6: COMMUNICATION (C11)
# ============================================================================

UNIT_6_CHALLENGES = [
    AlignedChallenge(
        id="U6.1",
        unit=6,
        title="Developer-Focused Reporting",
        primary_competency=Competency.C11_COMMUNICATION,
        scenario="""A developer needs to fix vulnerabilities you found.
They need to understand WHAT to fix and HOW.""",
        task="""For findings from previous units, create a developer report:
1. Clear description of each vulnerability
2. Reproduction steps
3. Specific remediation guidance
4. Code examples where helpful""",
        success_criteria=[
            "Vulnerabilities clearly described",
            "Reproduction steps work",
            "Remediation is actionable",
            "Developer could fix from this report"
        ],
        formative_check="Report enables developer action",
        evidence_required=["Developer-focused report document"],
        instruction_elements=[
            "Actionable focus → C11",
            "Code examples → practical guidance",
            "'Could fix from this' → success criterion"
        ]
    ),
    AlignedChallenge(
        id="U6.2",
        unit=6,
        title="Executive Summary Writing",
        primary_competency=Competency.C11_COMMUNICATION,
        scenario="""An executive needs to make a risk decision.
They need business impact, not technical details.""",
        task="""For the same findings, create an executive summary:
1. Business risk framing
2. Impact in business terms
3. Prioritized recommendations
4. Resource requirements for remediation""",
        success_criteria=[
            "Technical findings translated to business risk",
            "Impact is in business terms",
            "Recommendations are prioritized",
            "Executive could make decision from this"
        ],
        formative_check="Report enables executive decision",
        evidence_required=["Executive summary document"],
        instruction_elements=[
            "Business framing → C11",
            "Different audience → C11 (adaptation)",
            "'Could decide from this' → success criterion"
        ]
    ),
]


# ============================================================================
# UNIT 7: TRANSFER (C10, C12)
# ============================================================================

UNIT_7_CHALLENGES = [
    AlignedChallenge(
        id="U7.1",
        unit=7,
        title="Cross-Platform Transfer",
        primary_competency=Competency.C10_TRANSFER,
        scenario="""You've learned principles on native Android apps.
Now apply them to a React Native or Flutter app.""",
        task="""Analyze an app built with a cross-platform framework:
1. Identify how principles from previous units apply
2. Identify what's different about this platform
3. Adapt your methodology appropriately
4. Document what transfers and what doesn't""",
        success_criteria=[
            "Principles correctly applied",
            "Platform differences identified",
            "Methodology adapted",
            "Transfer documented"
        ],
        formative_check="Can apply principles to new context",
        evidence_required=[
            "Analysis of cross-platform app",
            "Transfer documentation"
        ],
        instruction_elements=[
            "New context → C10",
            "Adaptation → C10, C12",
            "Documentation → explicit transfer"
        ]
    ),
    AlignedChallenge(
        id="U7.2",
        unit=7,
        title="Novel Methodology Development",
        primary_competency=Competency.C12_FRAMEWORK,
        secondary_competencies=[Competency.C10_TRANSFER],
        scenario="""You encounter a new platform that existing methodologies
don't fully address. Derive an approach from principles.""",
        task="""Create a methodology for an unfamiliar platform:
1. Identify what principles apply
2. Identify what's unique about this platform
3. Derive methodology from first principles
4. Validate methodology against known issues""",
        success_criteria=[
            "Principles correctly identified",
            "Platform uniqueness addressed",
            "Methodology derived (not forced fit)",
            "Validation attempted"
        ],
        formative_check="Can derive novel methodologies",
        evidence_required=[
            "Methodology document",
            "Derivation reasoning",
            "Validation results"
        ],
        instruction_elements=[
            "First principles → C12",
            "Not forced fit → genuine derivation",
            "Validation → self-check"
        ]
    ),
]


# ============================================================================
# UNIT 8: INTEGRATION (All competencies)
# ============================================================================

UNIT_8_CHALLENGES = [
    AlignedChallenge(
        id="U8.1",
        unit=8,
        title="Full Assessment Simulation",
        primary_competency=Competency.C1_STATIC,  # All competencies
        secondary_competencies=[
            Competency.C2_DYNAMIC, Competency.C3_TRAFFIC, Competency.C4_BYPASS,
            Competency.C5_VULN_ID, Competency.C6_ROOT_CAUSE, Competency.C7_THREAT_MODEL,
            Competency.C8_TRADEOFF, Competency.C9_UNCERTAINTY, Competency.C11_COMMUNICATION
        ],
        scenario="""You have an unseen app and 4 hours to perform a MASVS-L1 assessment.
This integrates everything you've learned.""",
        task="""Perform a complete MASVS-L1 assessment:
1. Scope and threat model
2. Static analysis
3. Dynamic analysis on Genymotion
4. Traffic analysis
5. Findings with root cause
6. Prioritized recommendations
7. Developer and executive reports""",
        success_criteria=[
            "Scope appropriate for time",
            "Key vulnerabilities identified",
            "Root causes explained",
            "Reports enable action",
            "Uncertainty appropriately expressed"
        ],
        formative_check="Integrated assessment completed",
        evidence_required=[
            "Threat model",
            "Technical findings",
            "Developer report",
            "Executive summary"
        ],
        instruction_elements=[
            "Time constraint → C8",
            "All phases → integrated competencies",
            "Both reports → C11",
            "Genymotion → performance assessment"
        ]
    ),
]


ALL_CHALLENGES = (
    UNIT_1_CHALLENGES +
    UNIT_2_CHALLENGES +
    UNIT_3_CHALLENGES +
    UNIT_4_CHALLENGES +
    UNIT_5_CHALLENGES +
    UNIT_6_CHALLENGES +
    UNIT_7_CHALLENGES +
    UNIT_8_CHALLENGES
)


def generate_aligned_prompt(challenge: AlignedChallenge) -> str:
    """Generate prompt with explicit competency alignment."""

    comp_def = COMPETENCY_DEFINITIONS[challenge.primary_competency]

    return f"""# {challenge.title}
**Unit {challenge.unit}** | **Primary Competency**: {challenge.primary_competency.value}

---

## Competency Being Developed

**{challenge.primary_competency.value.replace('_', ' ').title()}**:
{comp_def['definition']}

**How competency will be assessed**: {comp_def['assessment']}

---

## Scenario

{challenge.scenario}

---

## Task

{challenge.task}

---

## Success Criteria

Your response will be evaluated against:

{chr(10).join(f'- {c}' for c in challenge.success_criteria)}

---

## Evidence Required

To demonstrate competency, provide:

{chr(10).join(f'- {e}' for e in challenge.evidence_required)}

---

## Why This Challenge Exists

This challenge builds the following competencies:
- **Primary**: {challenge.primary_competency.value}
{chr(10).join(f'- Secondary: {c.value}' for c in challenge.secondary_competencies)}

Every element of this prompt is designed to cultivate these competencies:
{chr(10).join(f'- {e}' for e in challenge.instruction_elements)}

---

**Remember**: Success is not task completion. Success is demonstrated competency
with evidence that could transfer to novel situations.
"""


def generate_aligned_chosen(challenge: AlignedChallenge) -> str:
    """Generate response demonstrating competency."""

    return f"""## Demonstrating: {challenge.primary_competency.value.replace('_', ' ').title()}

### Understanding the Task

This challenge develops **{challenge.primary_competency.value}**, which means:
{COMPETENCY_DEFINITIONS[challenge.primary_competency]['definition']}

### My Approach

{challenge.task}

[Detailed execution of task, organized by success criteria]

### Evidence of Competency

{chr(10).join(f'**{e}**:' + chr(10) + '[Specific evidence provided]' + chr(10) for e in challenge.evidence_required)}

### Success Criteria Verification

{chr(10).join(f'- {c}: ✓ [How this was met]' for c in challenge.success_criteria)}

### Transfer Reflection

This competency transfers to:
- [Novel situation 1 where this applies]
- [Novel situation 2 where this applies]
- [Novel situation 3 where this applies]

The underlying principle is: [Transferable principle extracted]
"""


def generate_aligned_rejected(challenge: AlignedChallenge) -> tuple[str, str]:
    """Generate rejected response with competency failure."""

    rejected = """## Analysis

I completed the task.

[Brief, surface-level response without demonstrated competency]

Results: Task done.
"""

    reason = f"""COMPETENCY NOT DEMONSTRATED:
- Primary competency ({challenge.primary_competency.value}) not evidenced
- No explicit reasoning shown
- No transfer reflection
- Success criteria not addressed systematically
- Evidence required not provided
- Task completed but competency not demonstrated"""

    return rejected, reason


def generate_training_pair(challenge: AlignedChallenge) -> dict:
    """Generate aligned training pair."""

    return {
        "prompt": generate_aligned_prompt(challenge),
        "chosen": generate_aligned_chosen(challenge),
        "rejected": generate_aligned_rejected(challenge)[0],
        "metadata": {
            "challenge_id": challenge.id,
            "unit": challenge.unit,
            "title": challenge.title,
            "primary_competency": challenge.primary_competency.value,
            "secondary_competencies": [c.value for c in challenge.secondary_competencies],
            "success_criteria": challenge.success_criteria,
            "evidence_required": challenge.evidence_required,
            "rejection_reason": generate_aligned_rejected(challenge)[1],
            "training_paradigm": "coherent_alignment"
        }
    }


def generate_all_aligned_training_data(output_dir: Path) -> dict:
    """Generate all aligned training data."""

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    pairs = [generate_training_pair(c) for c in ALL_CHALLENGES]

    output_path = output_dir / f"aligned_curriculum_{timestamp}.jsonl"
    with open(output_path, "w") as f:
        for pair in pairs:
            f.write(json.dumps(pair) + "\n")

    # Coverage analysis
    competency_coverage = {}
    for c in Competency:
        competency_coverage[c.value] = sum(
            1 for ch in ALL_CHALLENGES
            if ch.primary_competency == c or c in ch.secondary_competencies
        )

    stats = {
        "total_challenges": len(ALL_CHALLENGES),
        "units": 8,
        "competency_coverage": competency_coverage,
        "output_path": str(output_path)
    }

    print(f"Generated {len(pairs)} aligned challenges")
    print("\nCompetency Coverage:")
    for comp, count in sorted(competency_coverage.items()):
        print(f"  {comp}: {count} challenges")

    return stats


if __name__ == "__main__":
    print("=" * 70)
    print("ALIGNED CURRICULUM TRAINER")
    print("Coherent System: Outcomes → Curriculum → Instruction → Assessment")
    print("=" * 70)
    print()

    output_dir = Path("dojo/training_data")
    stats = generate_all_aligned_training_data(output_dir)

    print()
    print("=" * 70)
