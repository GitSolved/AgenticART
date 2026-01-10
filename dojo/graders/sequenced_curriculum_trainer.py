#!/usr/bin/env python3
"""
Sequenced Curriculum Trainer: Learning-Order-Aware Training Data Generator

Key insight: Random exposure doesn't build robust knowledge.
Learning must be sequenced so each challenge builds on previous foundations.

This trainer generates training data in pedagogically correct order with:
- Explicit prerequisite relationships
- Phase-based progression
- Methods taught before application
- False beliefs dispelled before related challenges
- Bad habits corrected before compound failures
"""

import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path


class Phase(Enum):
    """Learning phases in correct sequence."""
    PHASE_0_FOUNDATIONS = 0  # Explicit instruction before any challenges
    PHASE_1_WHITE = 1        # Foundation challenges with heavy scaffolding
    PHASE_2_YELLOW = 2       # Independent application
    PHASE_3_ORANGE = 3       # Integration of methods
    PHASE_4_GREEN = 4        # Cognitive flexibility
    PHASE_5_BLUE = 5         # Synthesis
    PHASE_6_PURPLE = 6       # Teaching
    PHASE_7_BROWN = 7        # Mastery
    PHASE_8_BLACK = 8        # Creation


@dataclass
class SequencedChallenge:
    """A challenge with explicit sequence metadata."""
    id: str
    title: str
    phase: Phase
    position_in_phase: int  # Order within phase
    prerequisites: list[str]  # Challenge IDs that must come before
    enables: list[str]       # Challenge IDs this enables

    # Challenge content
    prompt: str
    chosen_response: str
    rejected_response: str
    rejection_reason: str

    # Pedagogical metadata
    primary_skill: str
    knowledge_built: str
    transfer_principle: str


# ============================================================================
# PHASE 0: FOUNDATIONS - Explicit instruction before any challenges
# ============================================================================

PHASE_0_EXPLICIT_INSTRUCTION = [
    # 0.1 Deductive Reasoning
    {
        "id": "P0_deductive",
        "title": "What is Deductive Reasoning?",
        "phase": Phase.PHASE_0_FOUNDATIONS,
        "position": 1,
        "prerequisites": [],
        "enables": ["W2_deductive", "O1_deductive_evidence"],
        "prompt": """# Explicit Instruction: Deductive Reasoning

## What You Will Learn
This instruction teaches you deductive reasoning - a method for drawing
necessary conclusions from given premises.

## Why This Matters
Deductive reasoning lets you derive certain conclusions from established principles.
In security analysis, this means you can KNOW (not guess) what must be true
if certain conditions hold.

---

## The Structure of Deductive Reasoning

```
Premise 1: [General principle or rule]
Premise 2: [Specific observation that falls under the rule]
Conclusion: [What necessarily follows]
```

**Key Property**: If premises are TRUE, conclusion MUST be true.

---

## Example in Security Context

```
Premise 1: All client-side code can be modified by the device owner.
Premise 2: This root detection check is client-side code.
Conclusion: Therefore, this root detection check can be modified by the device owner.
```

The conclusion is CERTAIN because:
- Premise 1 is a known truth about device ownership
- Premise 2 is an observable fact about the code
- The conclusion follows necessarily

---

## Key Questions to Ask When Using Deductive Reasoning

1. What general principle applies here?
2. Does my specific case fall under that principle?
3. Is my general principle actually true?
4. Does my conclusion follow necessarily?

## Common Errors to Avoid

1. **Invalid premise**: The general rule might be wrong
2. **False application**: The specific case might not fall under the rule
3. **Non-sequitur**: The conclusion might not actually follow from the premises

---

## Your Task

Demonstrate your understanding by constructing a valid deductive argument
about a security scenario. Follow the exact structure above.

**Success Criteria**: Valid deductive argument with true premises and necessary conclusion.
""",
        "chosen": """## Demonstrating Deductive Reasoning

### My Deductive Argument

**Premise 1 (General Principle)**:
All data stored on the device's local filesystem can be accessed by someone with root access to that device.

This premise is true because:
- Root access grants full filesystem permissions
- No local storage mechanism can prevent root-level reads
- This is a fundamental property of operating system architecture

**Premise 2 (Specific Observation)**:
This application stores the encryption key in SharedPreferences on the local filesystem.

This is verified by:
- Examining the code that writes the key
- Confirming SharedPreferences maps to local XML files
- Testing that the file exists at /data/data/[package]/shared_prefs/

**Conclusion (What Follows Necessarily)**:
Therefore, someone with root access can retrieve this encryption key.

**Why This Conclusion is Certain**:
- IF Premise 1 is true (all local data accessible to root)
- AND Premise 2 is true (key is stored locally)
- THEN the conclusion MUST be true (root can access key)

This is not a probability or a likelihood. It is a logical necessity.

### Self-Check: Validating My Reasoning

**Is Premise 1 actually true?**
Yes - this is a fundamental property of how operating systems work.

**Is Premise 2 actually true?**
Yes - I verified through code examination and file system inspection.

**Does the conclusion follow necessarily?**
Yes - the specific case (key in SharedPreferences) falls exactly under
the general principle (local data accessible to root).

### Transfer Understanding

This same deductive structure applies whenever:
- I have a general security principle
- I can verify a specific implementation falls under it
- I need to determine what must be true

The power is in the CERTAINTY - not "probably exploitable" but "necessarily exploitable."
""",
        "rejected": """## Deductive Reasoning

The app stores keys locally. Root users can access local data. So the key
can be stolen.

This is a vulnerability. The app should store keys differently.
""",
        "rejection_reason": "IMPLICIT REASONING: Correct conclusion but structure not explicit. Premises not clearly stated. Validity of reasoning not demonstrated. Cannot verify the logic is sound. No self-check or transfer understanding.",
        "primary_skill": "deductive_reasoning",
        "knowledge_built": "Deductive reasoning produces CERTAIN conclusions when premises are true",
        "transfer_principle": "Use deductive reasoning when you have general principles and specific observations to connect"
    },

    # 0.2 Inductive Reasoning
    {
        "id": "P0_inductive",
        "title": "What is Inductive Reasoning?",
        "phase": Phase.PHASE_0_FOUNDATIONS,
        "position": 2,
        "prerequisites": [],
        "enables": ["W3_inductive", "O2_inductive_systems"],
        "prompt": """# Explicit Instruction: Inductive Reasoning

## What You Will Learn
This instruction teaches you inductive reasoning - a method for building
general principles from specific observations.

## Why This Matters
Inductive reasoning lets you discover patterns and form hypotheses.
In security analysis, this means you can identify vulnerability patterns
that might apply beyond the specific cases you've observed.

---

## The Structure of Inductive Reasoning

```
Observation 1: [Specific instance]
Observation 2: [Another instance]
Observation 3: [Another instance]
Pattern: [What the observations have in common]
Hypothesis: [Proposed general principle]
Test: [How to verify the hypothesis]
Conclusion: [Supported/refined/refuted, with confidence level]
```

**Key Property**: Conclusions are PROBABLE, not certain. More observations = more confidence.

---

## Example in Security Context

```
Observation 1: App A stores API key in strings.xml - key was extracted
Observation 2: App B stores API key in BuildConfig - key was extracted
Observation 3: App C stores API key in native library - key was extracted

Pattern: All apps stored secrets client-side, all were compromised

Hypothesis: No client-side storage location can protect embedded secrets

Test: Search for ANY client-side storage method that has resisted extraction

Conclusion: SUPPORTED with HIGH confidence - no counterexamples found
```

---

## Key Questions to Ask When Using Inductive Reasoning

1. What specific instances have I observed?
2. What pattern connects them?
3. What general principle might explain the pattern?
4. How can I test if this principle holds more broadly?
5. What would disprove my hypothesis?

## Common Errors to Avoid

1. **Small sample size**: Too few observations to justify generalization
2. **Selection bias**: Only seeing confirming instances
3. **Hasty generalization**: Concluding too quickly without adequate testing

---

## Your Task

Demonstrate your understanding by building a hypothesis from observations
about a security pattern. Follow the exact structure above.

**Success Criteria**: Valid inductive argument with multiple observations, explicit hypothesis, and testable conclusion.
""",
        "chosen": """## Demonstrating Inductive Reasoning

### My Observations

**Observation 1**:
Banking App A implements root detection using filesystem checks.
Result: Bypassed in 30 seconds with Magisk Hide.

**Observation 2**:
Banking App B implements root detection using native library.
Result: Bypassed in 2 minutes with Frida hooking.

**Observation 3**:
Security App C implements root detection using SafetyNet.
Result: Bypassed in 5 minutes with custom ROM modifications.

**Observation 4**:
Enterprise App D implements root detection using multiple checks.
Result: Bypassed in 10 minutes with generic Frida script.

### Pattern Identification

What these observations have in common:
- All apps implemented root detection differently
- All detections were bypassed
- All detections ran on the device being checked
- Time to bypass varied, but success was consistent

### Hypothesis Formation

**Proposed General Principle**:
Client-side root detection can always be bypassed given sufficient effort,
regardless of implementation complexity.

### Testing the Hypothesis

**Test Method**:
Search for ANY root detection implementation that has proven unbypassable.

**Search Results**:
- Reviewed 20+ root detection implementations
- All have documented bypasses
- No counterexamples found

**Potential Counterargument**:
"Newer, more sophisticated checks might be unbypassable"

**Response**:
Each "sophisticated" new check has eventually been bypassed.
The pattern persists across time and complexity levels.

### Conclusion

**Status**: SUPPORTED

**Confidence Level**: HIGH

**Justification**:
- Multiple independent observations
- Pattern persists across varied implementations
- No counterexamples found
- Theoretical basis aligns (device owner controls device)

**What would change my conclusion**:
- Discovery of a root detection that resists all known bypasses
- Change in device architecture that removes owner control

### Transfer Understanding

This inductive process applies whenever:
- I observe multiple instances of a phenomenon
- I want to determine if there's an underlying pattern
- I need to form a testable hypothesis

The power is in PATTERN DISCOVERY - finding principles from instances.
""",
        "rejected": """## Analysis

Root detection can be bypassed. I've seen it bypassed many times.

So root detection doesn't work.
""",
        "rejection_reason": "NO EXPLICIT INDUCTIVE PROCESS: Conclusion stated without showing observations, pattern identification, or hypothesis testing. No confidence level. No consideration of counterexamples. Cannot verify if conclusion is well-supported.",
        "primary_skill": "inductive_reasoning",
        "knowledge_built": "Inductive reasoning produces PROBABLE conclusions based on pattern observation",
        "transfer_principle": "Use inductive reasoning when you want to discover patterns from multiple instances"
    },

    # 0.3 Evidence Evaluation
    {
        "id": "P0_evidence",
        "title": "What is Evidence Evaluation?",
        "phase": Phase.PHASE_0_FOUNDATIONS,
        "position": 3,
        "prerequisites": [],
        "enables": ["W1_evidence", "O1_deductive_evidence"],
        "prompt": """# Explicit Instruction: Evidence Evaluation

## What You Will Learn
This instruction teaches you evidence evaluation - a method for assessing
the quality and relevance of evidence for claims.

## Why This Matters
Security is full of claims. Vendors claim their products are secure.
Documentation claims implementations are correct. Experts claim best practices.
Learning to evaluate evidence for these claims is essential.

---

## The Structure of Evidence Evaluation

```
Claim: [What is being asserted]
Source: [Who is making the claim, what's their incentive]
Evidence Type: [Assertion, authority, demonstration, verification]
Evidence Quality: [Strong, medium, weak - with justification]
Alternative Explanations: [What else could explain this]
Verification: [How I tested this myself]
Conclusion: [Supported/not supported, with confidence level]
```

**Key Property**: Weight evidence by QUALITY, not source authority.

---

## Evidence Types (Weakest to Strongest)

1. **Assertion**: "Trust me, it's secure" - No evidence, just claim
2. **Authority**: "The expert says it's secure" - Relies on reputation
3. **Demonstration**: "Here's how it works" - Shows mechanism
4. **Verification**: "Here's the test results" - Independently tested

---

## Example in Security Context

```
Claim: "Our app uses military-grade encryption"
Source: Marketing material (incentive: sell product)
Evidence Type: Assertion (no technical details provided)
Evidence Quality: WEAK (vague term, no verification)
Alternative: "Military-grade" might mean standard AES
Verification: Decompiled app, found AES-128 with hardcoded key
Conclusion: NOT SUPPORTED - encryption exists but implementation is flawed
```

---

## Key Questions for Evidence Evaluation

1. What specifically is being claimed?
2. Who benefits from this claim being believed?
3. What evidence actually supports it?
4. How can I verify this independently?
5. What's my confidence level based on evidence quality?

## Common Errors to Avoid

1. **Appeal to authority**: Accepting because source is prestigious
2. **Confirmation bias**: Only seeing supporting evidence
3. **Insufficient verification**: Not testing claims independently

---

## Your Task

Demonstrate your understanding by evaluating a security claim using
explicit evidence evaluation. Follow the exact structure above.

**Success Criteria**: Explicit evidence evaluation with appropriate confidence level.
""",
        "chosen": """## Demonstrating Evidence Evaluation

### The Claim Under Evaluation

**Claim**: "Our application is secure because it passed penetration testing
by a certified security firm."

### Source Assessment

**Who made this claim?**
The vendor's security page / marketing material.

**What is their incentive?**
To build trust with customers and increase sales. They benefit
financially from this claim being believed.

**Potential conflict of interest?**
YES - The vendor selected and paid the pentest firm. The vendor
controls what findings are published. Vendor has clear interest
in positive results.

### Evidence Type Classification

This is **Authority** evidence (level 2 of 4):
- References the reputation of a certified firm
- Does not show the testing methodology
- Does not reveal what was tested vs. not tested
- Does not show findings or remediation

### Evidence Quality Assessment

**Quality**: WEAK to MEDIUM

**Justification**:
- Certification of the firm doesn't guarantee thoroughness
- Scope of testing is unknown (what was out of scope?)
- Time-boxed pentests often miss complex vulnerabilities
- "Passed" could mean "no critical findings" not "no vulnerabilities"
- Age of test unknown - app may have changed since

### Alternative Explanations

What else could explain a "passed" pentest?
- Limited scope excluded vulnerable areas
- Time constraints prevented deep analysis
- Testers focused on known patterns, missed novel issues
- Findings were disputed or downgraded
- Test was against older version of app

### Independent Verification

**What I would test**:
1. Request the actual pentest report (not summary)
2. Verify scope covered all critical functionality
3. Check date of test vs. current app version
4. Conduct own analysis of critical areas
5. Look for vulnerability classes pentests commonly miss

**What I found**:
[Would include actual verification results here]

### Conclusion

**Claim Status**: PARTIALLY SUPPORTED with LOW confidence

**Reasoning**:
- Pentest was conducted (some evidence)
- But scope, depth, and currency are unknown
- Conflict of interest in reporting
- "Passed" is vague - doesn't mean "secure"

**What would increase my confidence**:
- Full pentest report with methodology
- Confirmation of comprehensive scope
- Recent test date relative to current version
- Independent verification of key findings

### Transfer Understanding

This evidence evaluation process applies to ANY security claim:
- Vendor security assertions
- Documentation accuracy claims
- Expert recommendations
- Tool output

The key is: Weight by evidence QUALITY, not source prestige.
""",
        "rejected": """## Analysis

The vendor says they passed a pentest by a certified firm. That sounds
legitimate. Certified firms know what they're doing.

The app is probably secure since it passed professional testing.
""",
        "rejection_reason": "APPEAL TO AUTHORITY: Accepted claim based on source prestige without evaluating evidence quality. No independent verification. No assessment of incentives or conflicts. Confidence not calibrated to evidence. Classic evidence evaluation failure.",
        "primary_skill": "evidence_evaluation",
        "knowledge_built": "Evidence quality matters more than source authority",
        "transfer_principle": "Evaluate all claims against evidence quality, not source prestige"
    },

    # 0.4 Systems Analysis
    {
        "id": "P0_systems",
        "title": "What is Systems Analysis?",
        "phase": Phase.PHASE_0_FOUNDATIONS,
        "position": 4,
        "prerequisites": [],
        "enables": ["O2_inductive_systems", "B3_complex_systems"],
        "prompt": """# Explicit Instruction: Systems Analysis

## What You Will Learn
This instruction teaches you systems analysis - a method for understanding
how component interactions create emergent behavior.

## Why This Matters
Security vulnerabilities often emerge from interactions between components
that are individually secure. Understanding systems helps you see what
component-focused analysis misses.

---

## The Structure of Systems Analysis

```
Components: [Individual parts of the system]
Interactions: [How components affect each other]
Boundaries: [Where the system meets external entities]
Emergent Properties: [Behaviors that arise from interaction]
Feedback Loops: [How outputs become inputs]
Vulnerabilities: [Where interactions create unexpected weaknesses]
```

**Key Property**: The whole behaves differently than the sum of its parts.

---

## Example in Security Context

```
Components:
- Mobile app (client)
- Backend server (API)
- Third-party auth provider (OAuth)

Interactions:
- App → Server: Authenticated requests with token
- App → Auth Provider: Token acquisition
- Server → Auth Provider: Token validation (supposedly)

Boundaries:
- User ↔ App (user input)
- App ↔ Network (traffic)
- Server ↔ Database (data)

Emergent Property:
Server trusts app-provided tokens without calling auth provider
(discovered through traffic analysis)

Vulnerability:
Token forgery possible because server-side validation is assumed
but not implemented. No single component is "wrong" - the gap
exists in the interaction.
```

---

## Key Questions for Systems Analysis

1. What are the individual components?
2. How do they interact with each other?
3. What emerges from their interaction that isn't in any single part?
4. Where are the trust boundaries?
5. What assumptions do components make about each other?

## Common Errors to Avoid

1. **Reductionism**: Only analyzing parts, missing interactions
2. **Missing boundaries**: Not seeing where system meets environment
3. **Ignoring feedback loops**: Missing how outputs affect inputs

---

## Your Task

Demonstrate your understanding by analyzing a system for emergent properties.
Follow the exact structure above.

**Success Criteria**: Identify something that emerges from interaction, not present in any single component.
""",
        "chosen": """## Demonstrating Systems Analysis

### System Under Analysis: Mobile Banking Suite

### Components Identification

**Component A: Main Banking App**
- Role: Primary user interface for banking
- Individual security: Strong authentication, encrypted storage

**Component B: Authentication Companion App**
- Role: Generates 2FA codes
- Individual security: Secure code generation algorithm

**Component C: Balance Widget**
- Role: Displays account summary on home screen
- Individual security: Read-only, no transaction capability

### Interaction Mapping

**A → B Interaction**:
Main app requests 2FA code from companion via Intent
- Data passed: Request for code
- Response: Current 2FA code
- Trust assumption: Only legitimate app can request

**A → C Interaction**:
Main app updates widget with balance data
- Data passed: Account balance, account ID
- Trust assumption: Widget doesn't expose sensitive paths

**B → A Interaction**:
Companion confirms successful authentication
- Data passed: Auth confirmation
- Trust assumption: Confirmation means legitimate auth

### Boundary Analysis

**User ↔ System Boundary**:
- User input via main app UI
- User visibility via widget

**System ↔ Network Boundary**:
- Main app communicates with backend
- Other apps assumed local-only

**Inter-App Boundary**:
- Apps communicate via Android Intents
- Assumption: Intent communication is private

### Emergent Properties

**Property 1: Combined Attack Surface**
No single app exposes full credentials, but the combination does:
- Widget exposes account IDs
- Intent communication can be intercepted
- Combined: Account ID + intercepted auth flow

**Property 2: Trust Chain Vulnerability**
The authentication companion trusts any Intent with correct format.
This trust was designed for the main app but extends to:
- Any app that can craft the right Intent
- Malicious apps can request 2FA codes

### Feedback Loop Identified

**Loop**: Widget refresh → triggers auth check → generates network traffic
- Widget refresh is periodic
- Each refresh validates session
- Traffic pattern reveals app usage
- Usage pattern enables targeted attacks

### Emergent Vulnerability

**Vulnerability**: Authentication bypass via companion app
- No single app has this vulnerability
- Main app's auth is strong
- Companion app's code generation is strong
- BUT: The interaction assumes only main app requests codes
- A malicious app can request codes directly
- Server sees valid 2FA, assumes legitimate

**Root Cause**: Trust boundary between apps is permeable
Components assume cooperation; attacker doesn't cooperate.

### Why Component Analysis Missed This

Analyzing each app individually:
- Main app: ✓ Strong auth
- Companion: ✓ Secure generation
- Widget: ✓ Read-only

All pass individual review. Vulnerability exists in the INTERACTION.

### Transfer Understanding

Systems analysis applies whenever:
- Multiple components work together
- Components make assumptions about each other
- Security depends on interaction patterns

The key insight: Secure parts can combine insecurely.
Look for where component assumptions about each other break down.
""",
        "rejected": """## Analysis

I analyzed each component:
- Main app: secure
- Auth companion: secure
- Widget: secure (read-only)

Each component passed individual security review.

The system is secure.
""",
        "rejection_reason": "REDUCTIONISM: Analyzed parts but not interactions. Missed emergent properties. Concluded system security from component security - this is the exact error systems analysis prevents. No boundary analysis. No interaction mapping.",
        "primary_skill": "systems_analysis",
        "knowledge_built": "Emergent vulnerabilities arise from interactions, not components",
        "transfer_principle": "Security of parts ≠ security of whole. Always analyze interactions."
    },
]


def generate_phase_0_training_data() -> list[dict]:
    """Generate Phase 0 explicit instruction training data."""
    pairs = []

    for item in PHASE_0_EXPLICIT_INSTRUCTION:
        pair = {
            "prompt": item["prompt"],
            "chosen": item["chosen"],
            "rejected": item["rejected"],
            "metadata": {
                "challenge_id": item["id"],
                "title": item["title"],
                "phase": item["phase"].value,
                "phase_name": item["phase"].name,
                "position_in_phase": item["position"],
                "prerequisites": item["prerequisites"],
                "enables": item["enables"],
                "primary_skill": item["primary_skill"],
                "knowledge_built": item["knowledge_built"],
                "transfer_principle": item["transfer_principle"],
                "rejection_reason": item["rejection_reason"],
                "training_paradigm": "sequenced_curriculum"
            }
        }
        pairs.append(pair)

    return pairs


def generate_all_sequenced_training_data(output_dir: Path) -> dict:
    """Generate all sequenced training data."""

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Phase 0
    phase_0_pairs = generate_phase_0_training_data()
    phase_0_path = output_dir / f"phase_0_foundations_{timestamp}.jsonl"
    with open(phase_0_path, "w") as f:
        for pair in phase_0_pairs:
            f.write(json.dumps(pair) + "\n")

    print(f"Phase 0 (Foundations): {len(phase_0_pairs)} pairs")
    print(f"  Saved to: {phase_0_path}")

    # Summary
    stats = {
        "phase_0_pairs": len(phase_0_pairs),
        "total_pairs": len(phase_0_pairs),
        "timestamp": timestamp,
        "output_files": [str(phase_0_path)]
    }

    return stats


def main():
    print("=" * 70)
    print("SEQUENCED CURRICULUM TRAINER")
    print("Learning-Order-Aware Training Data Generation")
    print("=" * 70)
    print()
    print("Key Principle: Methods taught BEFORE application")
    print("Phase 0 must come before any challenges")
    print()

    output_dir = Path("dojo/training_data")
    stats = generate_all_sequenced_training_data(output_dir)

    print()
    print("=" * 70)
    print(f"Total pairs generated: {stats['total_pairs']}")
    print("=" * 70)


if __name__ == "__main__":
    main()
