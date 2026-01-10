#!/usr/bin/env python3
"""
Integrated Reasoning Trainer

Combines:
1. Explicit reasoning instruction (deductive, inductive, systems analysis, evidence evaluation)
2. Meaningful challenges (authentic, discovery-based, transferable)
3. 4C competency development (critical thinking, creativity, collaboration, communication)

Key insight: Choice-based challenges alone, without explicit reasoning instruction,
are insufficient. The curriculum must DIRECTLY TEACH reasoning while
SIMULTANEOUSLY EMBEDDING it in purposeful challenges.
"""

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional


class ReasoningMethod(Enum):
    DEDUCTIVE = "deductive"
    INDUCTIVE = "inductive"
    SYSTEMS_ANALYSIS = "systems_analysis"
    EVIDENCE_EVALUATION = "evidence_evaluation"


# Explicit reasoning instruction for each method
REASONING_INSTRUCTION = {
    ReasoningMethod.DEDUCTIVE: {
        "name": "Deductive Reasoning",
        "definition": "Drawing necessary conclusions from given premises.",
        "structure": """
Premise 1: [General principle or rule]
Premise 2: [Specific observation that falls under the rule]
Conclusion: [What necessarily follows]
""",
        "example": """
Premise 1: All client-side code can be modified by the device owner
Premise 2: This security check runs client-side
Conclusion: Therefore, this security check can be bypassed

The conclusion is CERTAIN if the premises are true.
""",
        "key_questions": [
            "What general principle applies here?",
            "Does this specific case fall under that principle?",
            "What conclusion follows necessarily?"
        ],
        "common_errors": [
            "Invalid premise (the general rule is wrong)",
            "False application (the specific case doesn't actually fall under the rule)",
            "Non-sequitur (conclusion doesn't follow from premises)"
        ]
    },

    ReasoningMethod.INDUCTIVE: {
        "name": "Inductive Reasoning",
        "definition": "Forming generalizations from specific observations.",
        "structure": """
Observation 1: [Specific instance]
Observation 2: [Another instance]
Observation N: [More instances]
Pattern: [What emerges across instances]
Prediction: [What we expect in new cases]
""",
        "example": """
Observation: App A stores API keys in strings.xml
Observation: App B stores API keys in strings.xml
Observation: App C stores API keys in strings.xml
Pattern: Many Android apps store secrets in strings.xml
Prediction: App D likely stores secrets in strings.xml

The conclusion is PROBABLE, not certain. More observations = stronger pattern.
""",
        "key_questions": [
            "What specific instances have I observed?",
            "What pattern emerges across these instances?",
            "How strong is the evidence for this pattern?",
            "What would falsify this generalization?"
        ],
        "common_errors": [
            "Insufficient sample (too few observations)",
            "Selection bias (non-representative sample)",
            "Overgeneralization (pattern doesn't hold universally)"
        ]
    },

    ReasoningMethod.SYSTEMS_ANALYSIS: {
        "name": "Systems Analysis",
        "definition": "Understanding how components interact to produce emergent behavior.",
        "structure": """
Components: [List of system parts]
Interactions: [How parts connect and communicate]
Data Flow: [Where sensitive data moves]
Trust Boundaries: [Where security assumptions change]
Emergent Properties: [Behavior arising from interactions]
Weak Links: [Where system assumptions break down]
""",
        "example": """
Components: Mobile App, API Server, Database, Analytics SDK
Interactions: App → Server (authenticated), App → Analytics (unauthenticated)
Data Flow: User credentials flow to server, but also to analytics
Trust Boundary Violation: Analytics SDK operates outside security model
Emergent Risk: Third-party analytics can see sensitive user data

Security of parts ≠ Security of whole
""",
        "key_questions": [
            "What are all the components in this system?",
            "How do components interact?",
            "Where does sensitive data flow?",
            "Where are the trust boundaries?",
            "What behavior emerges from these interactions?"
        ],
        "common_errors": [
            "Missing components (didn't identify all parts)",
            "Ignoring interactions (analyzed parts in isolation)",
            "Missing trust boundaries (assumed uniform trust)"
        ]
    },

    ReasoningMethod.EVIDENCE_EVALUATION: {
        "name": "Evidence Evaluation",
        "definition": "Assessing the quality and relevance of evidence for claims.",
        "structure": """
Claim: [What is being asserted]
Source: [Who is making the claim, what's their incentive]
Evidence Type: [Assertion, authority, demonstration, verification]
Evidence Quality: [Strong, medium, weak - with justification]
Alternative Explanations: [What else could explain this]
Verification: [How I tested this myself]
Conclusion: [Supported/not supported, with confidence level]
""",
        "example": """
Claim: "Our app uses military-grade encryption"
Source: Marketing material (incentive: sell product)
Evidence Type: Assertion (no technical details provided)
Evidence Quality: Weak (no independent verification)
Alternative: Could be marketing term for standard encryption
Verification: Decompiled app, found AES-128 with hardcoded key
Conclusion: Claim NOT supported - encryption exists but implementation is weak

Weight evidence by quality, not source authority.
""",
        "key_questions": [
            "What specifically is being claimed?",
            "Who benefits from this claim being believed?",
            "What evidence actually supports it?",
            "How can I verify this independently?",
            "What's my confidence level based on evidence quality?"
        ],
        "common_errors": [
            "Appeal to authority (accepting because source is prestigious)",
            "Confirmation bias (only seeing supporting evidence)",
            "Insufficient verification (not testing claims independently)"
        ]
    }
}


@dataclass
class IntegratedChallenge:
    """A challenge with explicit reasoning instruction embedded."""
    id: str
    title: str
    belt_level: str
    primary_reasoning: ReasoningMethod
    scenario: str
    authentic_stakes: str
    reasoning_structure_required: str
    success_criteria: str
    transfer_principle: str
    secondary_reasoning: Optional[ReasoningMethod] = None


# Challenges with integrated reasoning instruction
INTEGRATED_CHALLENGES = [
    IntegratedChallenge(
        id="ir_01",
        title="The Vendor's Security Claims",
        belt_level="white",
        primary_reasoning=ReasoningMethod.EVIDENCE_EVALUATION,
        scenario="""A banking app's Play Store listing claims:
"Bank-grade security with end-to-end encryption protecting all your data."

You have the APK. Evaluate this claim using explicit evidence evaluation.""",
        authentic_stakes="Vendor claims about security are everywhere. Learning to evaluate them is essential.",
        reasoning_structure_required="""Your response MUST follow this structure:

## Evidence Evaluation Applied

**The Claim**: [State the specific claim]

**Source Assessment**:
- Who made this claim?
- What is their incentive?
- Is there a conflict of interest?

**Evidence Provided**:
- What evidence supports the claim?
- What type of evidence is it? (assertion/authority/demonstration/verification)
- How strong is this evidence?

**Independent Verification**:
- What did you test yourself?
- What did you find?

**Conclusion**:
- Is the claim supported?
- What is your confidence level?
- What would change your conclusion?""",
        success_criteria="Explicit evidence evaluation framework applied, claim verified/refuted with appropriate confidence.",
        transfer_principle="Evaluate all security claims against evidence, not authority. Marketing ≠ reality."
    ),

    IntegratedChallenge(
        id="ir_02",
        title="The Root Detection Bypass",
        belt_level="yellow",
        primary_reasoning=ReasoningMethod.DEDUCTIVE,
        scenario="""nativecheck.apk shows "Root Detected" and blocks access.

Apply deductive reasoning to determine if this check can be bypassed.""",
        authentic_stakes="Client-side security checks are everywhere. Understanding WHY they fail is more valuable than memorizing bypass scripts.",
        reasoning_structure_required="""Your response MUST follow this structure:

## Deductive Reasoning Applied

**Premise 1 (General Principle)**:
[State a general security principle that applies]

**Premise 2 (Specific Observation)**:
[State what you observe about this specific implementation]

**Conclusion (What Follows Necessarily)**:
[State what must be true if both premises are true]

**Verification**:
[Confirm your deduction with actual testing]

**Why This Reasoning Is Valid**:
[Explain why the conclusion follows from the premises]""",
        success_criteria="Valid deductive argument constructed, tested, and explained.",
        transfer_principle="If P→Q and P, then Q. Client-side code on attacker-controlled devices can always be modified."
    ),

    IntegratedChallenge(
        id="ir_03",
        title="The Vulnerability Pattern",
        belt_level="yellow",
        primary_reasoning=ReasoningMethod.INDUCTIVE,
        scenario="""Analyze these 4 APKs: cryptovault, vulnbank, fortified, sslpinned.

Apply inductive reasoning to identify common vulnerability patterns.
What generalizations can you form? What predictions follow?""",
        authentic_stakes="Real security work requires seeing patterns across many applications, not just finding individual bugs.",
        reasoning_structure_required="""Your response MUST follow this structure:

## Inductive Reasoning Applied

**Observations**:
- App 1: [What you found]
- App 2: [What you found]
- App 3: [What you found]
- App 4: [What you found]

**Pattern Identified**:
[What emerges across these observations]

**Strength of Pattern**:
- How many instances support it?
- Are there counter-examples?
- How confident should we be?

**Predictions**:
[What we expect in new, unseen apps based on this pattern]

**Falsification**:
[What would prove this pattern wrong]""",
        success_criteria="Valid inductive generalization from specific observations, with appropriate confidence.",
        transfer_principle="Patterns observed across many instances predict future instances—but remain probabilistic."
    ),

    IntegratedChallenge(
        id="ir_04",
        title="The App Ecosystem",
        belt_level="green",
        primary_reasoning=ReasoningMethod.SYSTEMS_ANALYSIS,
        secondary_reasoning=ReasoningMethod.DEDUCTIVE,
        scenario="""The target has multiple interconnected apps:
- Main banking app
- Authentication companion app
- Widget that displays balance

Analyze this as a SYSTEM, not as individual apps.
Where does security break down due to interactions?""",
        authentic_stakes="Real organizations have app ecosystems. Vulnerabilities often exist in interactions, not individual components.",
        reasoning_structure_required="""Your response MUST follow this structure:

## Systems Analysis Applied

**Components Identified**:
[List all parts of the system]

**Interactions Mapped**:
[How do components communicate/share data]

**Data Flow Traced**:
[Where does sensitive data move]

**Trust Boundaries**:
[Where do security assumptions change]

**Emergent Risks**:
[What vulnerabilities arise from interactions]

**Weak Link Analysis**:
[Where do system assumptions break down]

Then apply DEDUCTIVE REASONING:
**Premise 1**: [Principle about system security]
**Premise 2**: [What you observed in this system]
**Conclusion**: [What vulnerability exists]""",
        success_criteria="Complete systems analysis with identified emergent risks, supported by deductive argument.",
        transfer_principle="Security of parts ≠ security of whole. Analyze interactions, not just components."
    ),
]


class IntegratedReasoningTrainer:
    """Generates training data with explicit reasoning instruction."""

    def __init__(self):
        self.challenges = INTEGRATED_CHALLENGES
        self.reasoning_instruction = REASONING_INSTRUCTION

    def generate_training_pair(self, challenge: IntegratedChallenge) -> dict:
        """Generate a DPO pair with explicit reasoning instruction."""

        # Build prompt with explicit instruction
        prompt = self._build_instructional_prompt(challenge)

        # Build chosen response demonstrating explicit reasoning
        chosen = self._build_reasoned_response(challenge)

        # Build rejected response lacking explicit reasoning
        rejected, rejection_reason = self._build_unreasoned_response(challenge)

        return {
            "prompt": prompt,
            "chosen": chosen,
            "rejected": rejected,
            "metadata": {
                "challenge_id": challenge.id,
                "belt_level": challenge.belt_level,
                "primary_reasoning": challenge.primary_reasoning.value,
                "secondary_reasoning": challenge.secondary_reasoning.value if challenge.secondary_reasoning else None,
                "transfer_principle": challenge.transfer_principle,
                "rejection_reason": rejection_reason,
                "training_paradigm": "explicit_reasoning_instruction"
            }
        }

    def _build_instructional_prompt(self, challenge: IntegratedChallenge) -> str:
        """Build prompt with explicit reasoning instruction."""

        method = self.reasoning_instruction[challenge.primary_reasoning]

        prompt = f"""# {challenge.title}
**Belt Level**: {challenge.belt_level.title()}

---

## REASONING METHOD: {method['name']}

**Definition**: {method['definition']}

**Structure to Follow**:
{method['structure']}

**Example**:
{method['example']}

**Key Questions to Ask**:
{chr(10).join(f'- {q}' for q in method['key_questions'])}

**Common Errors to Avoid**:
{chr(10).join(f'- {e}' for e in method['common_errors'])}

---

## CHALLENGE

{challenge.scenario}

**Why This Matters**: {challenge.authentic_stakes}

---

## REQUIRED RESPONSE STRUCTURE

{challenge.reasoning_structure_required}

---

**Success Criteria**: {challenge.success_criteria}

Show your reasoning EXPLICITLY using the framework above. Implicit reasoning is insufficient.
"""
        return prompt

    def _build_reasoned_response(self, challenge: IntegratedChallenge) -> str:
        """Build response demonstrating explicit reasoning."""

        method = challenge.primary_reasoning

        if method == ReasoningMethod.EVIDENCE_EVALUATION:
            return """## Evidence Evaluation Applied

**The Claim**: "Bank-grade security with end-to-end encryption protecting all your data"

**Source Assessment**:
- Who made this claim? Marketing/product team via Play Store listing
- What is their incentive? To increase downloads and user trust
- Is there a conflict of interest? Yes - they benefit from the claim regardless of accuracy

**Evidence Provided**:
- Evidence type: Assertion (no technical details, no audit reports, no specifics)
- Evidence quality: WEAK - marketing language without substantiation
- "Bank-grade" and "end-to-end" are vague terms without defined meaning

**Independent Verification**:
What I tested:
1. Decompiled APK to examine encryption implementation
2. Traced data flow from input to storage/transmission
3. Analyzed network traffic

What I found:
- Encryption: AES-256 is used, BUT key is derived from hardcoded value
- "End-to-end": Data is encrypted to server, but server has plaintext access
- Local storage: SharedPreferences contains unencrypted session tokens

**Conclusion**:
- Is the claim supported? PARTIALLY - encryption exists but implementation is weak
- Confidence level: HIGH - based on direct code analysis
- What would change my conclusion: Evidence of proper key management, actual E2E where server can't decrypt

**Transfer Principle Applied**:
Marketing claims require verification. "Bank-grade" is not a technical specification.
This same evaluation framework applies to any vendor security claim.
"""

        elif method == ReasoningMethod.DEDUCTIVE:
            return """## Deductive Reasoning Applied

**Premise 1 (General Principle)**:
All code that runs on attacker-controlled hardware can be modified by the attacker.
This is a fundamental principle: the device owner has ultimate control over their device.

**Premise 2 (Specific Observation)**:
This root detection check runs entirely on the user's device.
- Found in: NativeLib.isDeviceSafe() called from MainActivity
- Execution: Happens locally before granting access
- No server verification of the check result

**Conclusion (What Follows Necessarily)**:
Therefore, this root detection check can be bypassed by the device owner.
The conclusion is CERTAIN if the premises are true. The attacker IS the device owner.

**Verification**:
Tested the deduction:
1. Hooked NativeLib.isDeviceSafe() with Frida
2. Modified return value from false to true
3. Result: Root detection bypassed, access granted

**Why This Reasoning Is Valid**:
The conclusion follows necessarily from the premises:
- IF device owner controls all local code (Premise 1)
- AND this check is local code (Premise 2)
- THEN device owner can control/bypass this check (Conclusion)

**Transfer Principle**:
This same deductive argument applies to ALL client-side security checks:
- Integrity verification
- Debugger detection
- Emulator detection
- License checks
Any boolean check that runs locally can be bypassed by modifying its return value.
"""

        elif method == ReasoningMethod.INDUCTIVE:
            return """## Inductive Reasoning Applied

**Observations**:
- cryptovault: Hardcoded password in strings.xml
- vulnbank: API key in BuildConfig.java
- fortified: Encryption key in assets/config.json
- sslpinned: Certificate hash in code (acceptable for pinning, but still extractable)

**Pattern Identified**:
Across all 4 apps, secrets that should be protected are embedded in the APK.
The specific location varies (strings.xml, BuildConfig, assets, code) but the pattern is consistent: secrets in client-distributed code.

**Strength of Pattern**:
- 4/4 apps exhibited this pattern (100%)
- No counter-examples in this sample
- Confidence: MODERATE - small sample, but consistent
- This aligns with known industry patterns (OWASP Mobile Top 10)

**Predictions**:
Based on this pattern, we predict:
1. New Android apps likely contain embedded secrets
2. Checking strings.xml, BuildConfig, and assets should be standard practice
3. Even "security-focused" apps make this mistake

**Falsification**:
This pattern would be falsified if we found apps that:
- Store no secrets client-side at all
- Use proper secret management (runtime fetch from secure backend)
- Implement hardware-backed key storage without hardcoded fallbacks

**Transfer Principle**:
Patterns observed across many instances predict future instances.
"Check for hardcoded secrets" should be part of every mobile security assessment.
"""

        else:  # SYSTEMS_ANALYSIS
            return """## Systems Analysis Applied

**Components Identified**:
1. Main banking app (handles transactions)
2. Authentication app (generates 2FA codes)
3. Balance widget (displays account info)
4. Shared backend API
5. Device local storage

**Interactions Mapped**:
- Main app ↔ Backend: Authenticated API calls
- Auth app ↔ Backend: Token generation
- Widget ↔ Backend: Read-only balance fetch
- Main app ↔ Auth app: Intent-based 2FA handoff
- All apps ↔ Local storage: Shared preferences (!)

**Data Flow Traced**:
Sensitive data paths:
- Credentials: User → Main app → Backend ✓
- 2FA codes: Auth app → Main app (via intent - potentially interceptable)
- Balance: Backend → Widget (stored locally for offline display)
- Session token: Stored in SharedPreferences accessible to all apps with same signature

**Trust Boundaries**:
- Backend ↔ Apps: TLS boundary (properly secured)
- App ↔ App: Intent boundary (weaker - can be intercepted)
- App ↔ Storage: No boundary (shared storage assumption)

**Emergent Risks**:
Risk 1: The widget caches balance data locally without encryption.
  - Individual component: Widget is read-only, seems safe
  - System context: Cached data persists, accessible if device compromised

Risk 2: Inter-app communication via intents
  - Individual component: Each app authenticates properly
  - System context: Malicious app could intercept 2FA intent

Risk 3: Shared storage assumption
  - Individual component: SharedPreferences is standard
  - System context: Session token accessible to all apps with matching signature

**Weak Link Analysis**:
The widget is the weak link. It:
- Has legitimate access to balance data
- Caches data locally (for offline display feature)
- Has minimal security requirements (just displays data)
- Creates exposure point that wouldn't exist if analyzed in isolation

## Deductive Reasoning Applied:
**Premise 1**: If any component with data access has weak security, the data is at risk
**Premise 2**: The widget has data access and weak local storage security
**Conclusion**: Therefore, balance data is at risk through the widget

**Transfer Principle**:
Security of parts ≠ security of whole. Always analyze the SYSTEM, not just components.
The weakest component with data access determines system security.
"""

    def _build_unreasoned_response(self, challenge: IntegratedChallenge) -> tuple[str, str]:
        """Build response lacking explicit reasoning."""

        method = challenge.primary_reasoning

        if method == ReasoningMethod.EVIDENCE_EVALUATION:
            rejected = """## Analysis

The app claims to have bank-grade security. I decompiled it and found some encryption code. The encryption uses AES which is secure. However, I also found some issues with how keys are stored.

Findings:
- Uses encryption ✓
- Some key management issues
- Overall: Partially secure

Recommendation: Fix the key management.
"""
            reason = "NO EXPLICIT EVIDENCE EVALUATION: Didn't assess source credibility, evidence quality, or state confidence level. Conclusion not proportional to evidence. Framework not applied."

        elif method == ReasoningMethod.DEDUCTIVE:
            rejected = """## Bypass

Root detection can be bypassed using Frida. Here's the script:

```javascript
Java.perform(function() {
    var NativeLib = Java.use('com.app.NativeLib');
    NativeLib.isDeviceSafe.implementation = function() {
        return true;
    };
});
```

Run this and the root detection is bypassed.
"""
            reason = "NO DEDUCTIVE REASONING: Provided bypass without explaining WHY it works. No premises stated, no conclusion drawn. This is memorized technique, not reasoned understanding. Cannot transfer to novel situations."

        elif method == ReasoningMethod.INDUCTIVE:
            rejected = """## Findings

- cryptovault: Found hardcoded password
- vulnbank: Found API key
- fortified: Found encryption key
- sslpinned: Found certificate

All apps have hardcoded secrets. This is bad practice.
"""
            reason = "NO INDUCTIVE REASONING: Listed observations without forming generalization. No pattern explicitly identified. No strength assessment. No predictions. No falsification criteria. Just a list, not reasoning."

        else:  # SYSTEMS_ANALYSIS
            rejected = """## Security Assessment

Analyzed the three apps:
- Main app: Found some vulnerabilities
- Auth app: Looks secure
- Widget: Simple display, low risk

Recommendation: Fix vulnerabilities in main app.
"""
            reason = "NO SYSTEMS ANALYSIS: Analyzed components in isolation. Didn't map interactions. Didn't trace data flow. Missed emergent risks from component interactions. Widget dismissed as 'low risk' without understanding its role in the system."

        return rejected, reason

    def generate_all_training_data(self, output_path: Path) -> dict:
        """Generate all training pairs."""
        pairs = []

        for challenge in self.challenges:
            print(f"Generating: {challenge.title} ({challenge.primary_reasoning.value})")

            pair = self.generate_training_pair(challenge)
            pairs.append(pair)

            # Generate additional variations (different failure modes could be added)
            pairs.append(self.generate_training_pair(challenge))

        # Save
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            for pair in pairs:
                f.write(json.dumps(pair) + "\n")

        stats = {
            "total_pairs": len(pairs),
            "reasoning_methods_covered": list(set(
                p["metadata"]["primary_reasoning"] for p in pairs
            )),
            "paradigm": "explicit_reasoning_instruction",
            "principles": [
                "Explicit reasoning instruction in every prompt",
                "Required reasoning structure in every response",
                "Rejection of implicit/absent reasoning",
                "Transfer principles explicitly stated"
            ]
        }

        print(f"\n✅ Generated {len(pairs)} training pairs")
        print(f"   Reasoning methods: {', '.join(stats['reasoning_methods_covered'])}")
        print(f"   Saved to {output_path}")

        return stats


def main():
    """Demonstrate integrated reasoning training."""
    print("=" * 70)
    print("INTEGRATED REASONING TRAINER")
    print("Explicit Instruction + Authentic Application")
    print("=" * 70)
    print()
    print("Reasoning methods taught explicitly:")
    for method, instruction in REASONING_INSTRUCTION.items():
        print(f"  • {instruction['name']}: {instruction['definition'][:50]}...")
    print()
    print("Each challenge:")
    print("  1. Provides explicit reasoning instruction")
    print("  2. Requires explicit reasoning demonstration")
    print("  3. Rejects implicit/absent reasoning")
    print()

    trainer = IntegratedReasoningTrainer()
    output = Path("dojo/training_data/integrated_reasoning.jsonl")
    trainer.generate_all_training_data(output)

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
