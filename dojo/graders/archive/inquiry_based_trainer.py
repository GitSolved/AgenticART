#!/usr/bin/env python3
"""
Inquiry-Based Training Generator

Generates training data structured around Big Driving Questions.

Purpose-based learning frames every challenge as an investigation into
real-world questions, building knowledge through active inquiry rather
than passive reception of information.

Key principles:
- Every challenge investigates a driving question
- Learning is knowledge CONSTRUCTION, not accumulation
- Cognitive flexibility through active targeted training
- Transfer to novel situations demonstrates true understanding
"""

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class DrivingQuestion(Enum):
    """Big questions that drive the curriculum."""
    WHY_SECURITY_FAILS = "why_security_fails"
    UNTRUSTED_HARDWARE = "untrusted_hardware"
    THEATER_VS_SECURITY = "theater_vs_security"
    SYSTEMS_COMPLEXITY = "systems_complexity"
    EFFECTIVE_COMMUNICATION = "effective_communication"


# The Big Driving Questions
DRIVING_QUESTIONS = {
    DrivingQuestion.WHY_SECURITY_FAILS: {
        "question": "Why do security measures fail despite good intentions?",
        "real_world_issue": "Developers implement security features, yet apps remain vulnerable.",
        "knowledge_to_build": "Security fails when assumptions about context are wrong.",
        "transfer_domains": [
            "Any security implementation",
            "Threat modeling",
            "Security architecture review"
        ]
    },
    DrivingQuestion.UNTRUSTED_HARDWARE: {
        "question": "How can we protect anything on hardware we don't control?",
        "real_world_issue": "Mobile apps run on user devices. The user IS the attacker.",
        "knowledge_to_build": "Client-side security can only raise effort, not guarantee protection.",
        "transfer_domains": [
            "Any client-side application",
            "DRM systems",
            "License enforcement"
        ]
    },
    DrivingQuestion.THEATER_VS_SECURITY: {
        "question": "What separates security theater from actual security?",
        "real_world_issue": "Many measures look impressive but provide no real protection.",
        "knowledge_to_build": "Effective security addresses real threats; theater addresses perceived threats.",
        "transfer_domains": [
            "Security architecture",
            "Vendor evaluation",
            "Compliance vs security"
        ]
    },
    DrivingQuestion.SYSTEMS_COMPLEXITY: {
        "question": "How do complex systems create unexpected vulnerabilities?",
        "real_world_issue": "Secure components can combine into insecure systems.",
        "knowledge_to_build": "Security of parts ≠ security of whole. Interactions create emergent risks.",
        "transfer_domains": [
            "Enterprise architectures",
            "API ecosystems",
            "Supply chain security"
        ]
    },
    DrivingQuestion.EFFECTIVE_COMMUNICATION: {
        "question": "How do we communicate findings to drive action?",
        "real_world_issue": "Findings are useless if no one acts on them.",
        "knowledge_to_build": "Effective communication enables action by the specific audience.",
        "transfer_domains": [
            "Vulnerability disclosure",
            "Risk communication",
            "Technical writing"
        ]
    }
}


@dataclass
class InquiryChallenge:
    """A challenge structured as investigation of a driving question."""
    id: str
    title: str
    driving_question: DrivingQuestion

    # ENGAGE: Create cognitive dissonance
    scenario: str
    cognitive_dissonance: str  # What makes this puzzling/interesting?

    # EXPLORE: Investigation context
    materials: list[str]
    investigation_prompts: list[str]

    # EXPLAIN: Required reasoning
    reasoning_questions: list[str]

    # ELABORATE: Transfer requirements
    transfer_questions: list[str]

    # EVALUATE: Reflection
    reflection_prompts: list[str]

    # Success criteria
    knowledge_to_construct: str
    flexibility_to_demonstrate: str


# Inquiry-based challenges
INQUIRY_CHALLENGES = [
    InquiryChallenge(
        id="inq_001",
        title="The Secure App Paradox",
        driving_question=DrivingQuestion.WHY_SECURITY_FAILS,
        scenario="""cryptovault.apk was built by a security-conscious team.
They implemented: password protection, encryption, secure storage patterns.
They followed OWASP guidelines. They used security libraries.
Yet within a week of release, user credentials were being stolen.

Investigate: Why did their security measures fail?""",
        cognitive_dissonance="How can an app with 'all the right' security features still be insecure?",
        materials=[
            "cryptovault.apk",
            "Developer's security checklist (all items marked complete)",
            "Incident report: 'User credentials extracted from app'"
        ],
        investigation_prompts=[
            "Examine what 'encryption' actually means in this implementation",
            "Trace where credentials are stored and how they're protected",
            "Identify assumptions the developers made about the attacker"
        ],
        reasoning_questions=[
            "WHAT specifically failed? (the mechanism)",
            "WHY did it fail? (the root cause, not just the symptom)",
            "What ASSUMPTION was wrong?"
        ],
        transfer_questions=[
            "What other apps might have this same vulnerability pattern?",
            "How would you recognize this pattern in an app you've never seen?",
            "What would ACTUALLY fix this, not just patch the symptom?"
        ],
        reflection_prompts=[
            "What assumption did the developers make that was wrong?",
            "How does this change how you evaluate 'secure' apps?",
            "What would YOU do differently when building security features?"
        ],
        knowledge_to_construct="Security fails when assumptions about attacker capabilities are wrong. 'Secure' features on client devices are only as strong as the assumptions they make about the attacker.",
        flexibility_to_demonstrate="Can identify assumption failures in novel app contexts"
    ),

    InquiryChallenge(
        id="inq_002",
        title="The Unbypassable Check",
        driving_question=DrivingQuestion.UNTRUSTED_HARDWARE,
        scenario="""nativecheck.apk implements root detection in three different ways:
1. Java-based filesystem checks
2. Native library signature verification
3. SafetyNet attestation

The developers claim: "Our layered approach makes bypass impossible."

Investigate: Is security possible when the device owner is the attacker?""",
        cognitive_dissonance="If we add more checks, shouldn't it eventually become unbypassable?",
        materials=[
            "nativecheck.apk",
            "Developer blog post: 'Our Unbreakable Security Architecture'",
            "Three detection mechanisms to analyze"
        ],
        investigation_prompts=[
            "Where does each security check execute?",
            "Who controls the execution environment?",
            "What would need to be true for these checks to be unbypassable?"
        ],
        reasoning_questions=[
            "Apply DEDUCTIVE reasoning: If the device owner controls X, what follows?",
            "What's the FUNDAMENTAL limitation being demonstrated here?",
            "Why doesn't adding more checks solve the problem?"
        ],
        transfer_questions=[
            "Does this principle apply to DRM? License checks? Anti-cheat?",
            "What CAN be secured client-side vs. what CANNOT?",
            "How should apps be architected given this limitation?"
        ],
        reflection_prompts=[
            "Has your understanding of 'client-side security' changed?",
            "What would you tell a developer who wants 'unbypassable' client checks?",
            "Where should the security boundary actually be?"
        ],
        knowledge_to_construct="Client-side checks can increase effort but never guarantee security. The device owner has ultimate control. Security enforcement must happen where the attacker doesn't have control.",
        flexibility_to_demonstrate="Can apply hardware trust limitations to novel scenarios"
    ),

    InquiryChallenge(
        id="inq_003",
        title="The Security Checkbox",
        driving_question=DrivingQuestion.THEATER_VS_SECURITY,
        scenario="""fortified.apk passed a security audit with flying colors:
✅ Certificate pinning implemented
✅ Root detection enabled
✅ Code obfuscation applied
✅ Debug detection active

Yet the app was compromised by a moderately skilled attacker in 2 hours.

Investigate: What's the difference between checking security boxes and being secure?""",
        cognitive_dissonance="They implemented everything on the security checklist. How is that not enough?",
        materials=[
            "fortified.apk",
            "Security audit report (all items passed)",
            "Attack timeline: 2 hours from start to full compromise"
        ],
        investigation_prompts=[
            "For each 'passed' security feature, test if it actually provides protection",
            "What threats does each feature address? What threats does it NOT address?",
            "What would an attacker actually need to do to compromise this app?"
        ],
        reasoning_questions=[
            "What's the difference between HAVING a feature and BEING protected?",
            "What threat model were these features designed for?",
            "Does the checklist match the actual threats?"
        ],
        transfer_questions=[
            "How would you evaluate a vendor's security claims?",
            "What questions reveal theater vs. actual security?",
            "How should security audits be structured differently?"
        ],
        reflection_prompts=[
            "What makes security 'real' vs. 'theater'?",
            "How do checklists create false confidence?",
            "What would a meaningful security assessment look like?"
        ],
        knowledge_to_construct="Security theater = measures that address perceived threats but not actual threats. Real security requires threat modeling, not checkbox compliance. Presence of features ≠ presence of protection.",
        flexibility_to_demonstrate="Can distinguish theater from security in novel contexts"
    ),

    InquiryChallenge(
        id="inq_004",
        title="The Ecosystem Effect",
        driving_question=DrivingQuestion.SYSTEMS_COMPLEXITY,
        scenario="""A banking suite consists of three apps:
- Main banking app (heavily secured)
- Authentication companion (generates 2FA codes)
- Balance widget (displays account summary)

Each app passed individual security review.
Combined, they created a vulnerability that didn't exist in any single app.

Investigate: How do secure parts create insecure wholes?""",
        cognitive_dissonance="Each app was secure individually. How did combining them create a vulnerability?",
        materials=[
            "Three APKs that passed individual security reviews",
            "System architecture diagram",
            "The vulnerability: found only when apps interact"
        ],
        investigation_prompts=[
            "Map how the three apps communicate",
            "Trace where sensitive data flows between apps",
            "Identify what assumptions each app makes about the others"
        ],
        reasoning_questions=[
            "Apply SYSTEMS ANALYSIS: What emerges from interaction?",
            "Where are the trust boundaries? Are they properly enforced?",
            "What vulnerability exists in the SYSTEM that doesn't exist in PARTS?"
        ],
        transfer_questions=[
            "How would you assess security of an app ecosystem?",
            "What questions reveal emergent risks?",
            "How should individual app reviews account for system context?"
        ],
        reflection_prompts=[
            "Why did individual reviews miss this?",
            "How does this change how you think about 'secure' components?",
            "What's the relationship between component security and system security?"
        ],
        knowledge_to_construct="Security of parts ≠ security of whole. Emergent risks arise from interactions. System security requires analyzing trust boundaries and data flows across components.",
        flexibility_to_demonstrate="Can identify emergent risks in novel system compositions"
    ),

    InquiryChallenge(
        id="inq_005",
        title="The Unread Report",
        driving_question=DrivingQuestion.EFFECTIVE_COMMUNICATION,
        scenario="""You found a critical vulnerability in sslpinned.apk.
You wrote a detailed 15-page technical report.
Three months later, the vulnerability is still there.

The developer says: "We got your report but couldn't understand what to do."
The executive says: "We got your report but couldn't prioritize it."

Investigate: What makes security communication effective?""",
        cognitive_dissonance="The finding was correct and important. Why didn't it lead to action?",
        materials=[
            "The original 15-page technical report",
            "Developer feedback: 'Too technical, unclear remediation'",
            "Executive feedback: 'Unclear business impact'",
            "The unchanged vulnerable app"
        ],
        investigation_prompts=[
            "What did each audience need that they didn't get?",
            "What would have enabled the developer to fix it?",
            "What would have enabled the executive to prioritize it?"
        ],
        reasoning_questions=[
            "What's the PURPOSE of a vulnerability report?",
            "Who are the audiences and what does each need?",
            "How should communication differ by audience?"
        ],
        transfer_questions=[
            "How would you structure findings for different audiences?",
            "What makes the difference between 'informing' and 'enabling action'?",
            "How do you know if your communication was effective?"
        ],
        reflection_prompts=[
            "What's the point of finding vulnerabilities if they don't get fixed?",
            "How does this change how you'll communicate findings?",
            "What's the definition of 'effective' security communication?"
        ],
        knowledge_to_construct="Effective communication enables specific audiences to take specific actions. A finding that doesn't lead to action is a communication failure, not just an organizational failure.",
        flexibility_to_demonstrate="Can tailor security communication to enable action by different audiences"
    )
]


class InquiryBasedTrainer:
    """Generates training data from inquiry-based challenges."""

    def __init__(self):
        self.challenges = INQUIRY_CHALLENGES
        self.questions = DRIVING_QUESTIONS

    def generate_training_pair(self, challenge: InquiryChallenge) -> dict:
        """Generate a DPO training pair from an inquiry challenge."""

        prompt = self._build_inquiry_prompt(challenge)
        chosen = self._build_inquiry_response(challenge)
        rejected, reason = self._build_surface_response(challenge)

        return {
            "prompt": prompt,
            "chosen": chosen,
            "rejected": rejected,
            "metadata": {
                "challenge_id": challenge.id,
                "driving_question": challenge.driving_question.value,
                "knowledge_constructed": challenge.knowledge_to_construct,
                "flexibility_demonstrated": challenge.flexibility_to_demonstrate,
                "rejection_reason": reason,
                "training_paradigm": "inquiry_based_purpose_driven"
            }
        }

    def _build_inquiry_prompt(self, challenge: InquiryChallenge) -> str:
        """Build prompt following inquiry cycle."""

        dq = self.questions[challenge.driving_question]

        return f"""# {challenge.title}

## THE BIG QUESTION
**Driving Question**: {dq['question']}
**Real-World Issue**: {dq['real_world_issue']}

---

## ENGAGE: The Puzzle

{challenge.scenario}

**The Cognitive Dissonance**: {challenge.cognitive_dissonance}

---

## EXPLORE: Your Investigation

Materials available:
{chr(10).join(f'- {m}' for m in challenge.materials)}

Investigation prompts:
{chr(10).join(f'- {p}' for p in challenge.investigation_prompts)}

---

## EXPLAIN: Required Reasoning

Your response must address:
{chr(10).join(f'- {q}' for q in challenge.reasoning_questions)}

---

## ELABORATE: Transfer

After your analysis, demonstrate transfer by addressing:
{chr(10).join(f'- {q}' for q in challenge.transfer_questions)}

---

## EVALUATE: Reflection

Finally, reflect on:
{chr(10).join(f'- {p}' for p in challenge.reflection_prompts)}

---

**Success**: Construct knowledge that answers the driving question and transfers to novel situations.
"""

    def _build_inquiry_response(self, challenge: InquiryChallenge) -> str:
        """Build response demonstrating full inquiry cycle."""

        dq = self.questions[challenge.driving_question]

        return f"""# Investigation: {challenge.title}

## Understanding the Question

**Driving Question**: {dq['question']}

This matters because: {dq['real_world_issue']}

**The Puzzle**: {challenge.cognitive_dissonance}

---

## EXPLORE: My Investigation

### Investigation Process

{chr(10).join(f'**{i+1}. {p}**' + chr(10) + '   Investigation findings here...' for i, p in enumerate(challenge.investigation_prompts))}

---

## EXPLAIN: What I Discovered

### Answering the Reasoning Questions

{chr(10).join(f'**{q}**' + chr(10) + '   [Explicit reasoning with evidence]' for q in challenge.reasoning_questions)}

### The Root Cause

{challenge.knowledge_to_construct}

This answers the driving question because it explains not just WHAT failed, but WHY—
revealing a principle that applies beyond this specific case.

---

## ELABORATE: Transfer to New Contexts

### Demonstrating Cognitive Flexibility

{chr(10).join(f'**{q}**' + chr(10) + '   [Application of principle to new context]' for q in challenge.transfer_questions)}

### Where This Principle Applies

This understanding transfers to:
{chr(10).join(f'- {d}' for d in dq['transfer_domains'])}

---

## EVALUATE: My Reflection

{chr(10).join(f'**{p}**' + chr(10) + '   [Genuine reflection on learning]' for p in challenge.reflection_prompts)}

### Knowledge Constructed

Through this investigation, I've built understanding that:
- Answers the driving question with evidence
- Explains the underlying principle, not just the symptom
- Transfers to situations I haven't seen before
- Changes how I approach similar problems

**{challenge.flexibility_to_demonstrate}**: Demonstrated through the transfer analysis above.
"""

    def _build_surface_response(self, challenge: InquiryChallenge) -> tuple[str, str]:
        """Build response that stays surface-level without real inquiry."""

        rejected = f"""# Analysis of {challenge.title}

## Findings

I analyzed the app and found vulnerabilities.

### Technical Details
- Found some security issues
- Used tools to identify problems
- Documented the vulnerabilities

### Recommendations
- Fix the vulnerabilities
- Implement better security
- Follow best practices

Done.
"""

        reason = """SURFACE-LEVEL RESPONSE:
- Did not engage with the driving question
- No investigation of WHY, only WHAT
- No reasoning visible
- No transfer to new contexts
- No reflection on learning
- No knowledge constructed—just task completed
- Treats challenge as checklist, not inquiry"""

        return rejected, reason

    def generate_all_training_data(self, output_path: Path) -> dict:
        """Generate all inquiry-based training pairs."""

        pairs = []

        for challenge in self.challenges:
            dq = self.questions[challenge.driving_question]
            print(f"\nGenerating: {challenge.title}")
            print(f"  Driving Question: {dq['question'][:50]}...")

            pair = self.generate_training_pair(challenge)
            pairs.append(pair)

            # Add variation
            pairs.append(self.generate_training_pair(challenge))

        # Save
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            for pair in pairs:
                f.write(json.dumps(pair) + "\n")

        stats = {
            "total_pairs": len(pairs),
            "driving_questions_covered": list(set(
                p["metadata"]["driving_question"] for p in pairs
            )),
            "paradigm": "inquiry_based_purpose_driven",
            "principles": [
                "Every challenge investigates a driving question",
                "Knowledge is constructed through inquiry",
                "Cognitive flexibility through transfer requirements",
                "Reflection completes the learning cycle"
            ]
        }

        print(f"\n✅ Generated {len(pairs)} inquiry-based training pairs")
        questions = list(stats['driving_questions_covered'])  # type: ignore
        print(f"   Driving questions: {len(questions)}")
        print(f"   Saved to {output_path}")

        return stats


def main():
    """Demonstrate inquiry-based training."""
    print("=" * 70)
    print("INQUIRY-BASED TRAINING GENERATOR")
    print("Purpose-Based Learning Through Big Driving Questions")
    print("=" * 70)
    print()

    print("BIG DRIVING QUESTIONS:")
    print("-" * 70)
    for dq, info in DRIVING_QUESTIONS.items():
        print(f"\n📌 {info['question']}")
        print(f"   Issue: {info['real_world_issue'][:60]}...")
        print(f"   Knowledge: {info['knowledge_to_build'][:60]}...")

    print("\n" + "-" * 70)

    trainer = InquiryBasedTrainer()
    output = Path("dojo/training_data/inquiry_based.jsonl")
    trainer.generate_all_training_data(output)

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
