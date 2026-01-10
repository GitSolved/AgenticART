#!/usr/bin/env python3
"""
Meaningful Challenge Generator

Generates training data from challenges that are:
- Authentic (real stakes, not contrived)
- Discovery-based (answer not obvious)
- Multi-approach (creativity possible)
- Transferable (principle applies elsewhere)
- Failure-informative (wrong approaches teach)
- Integration-requiring (skills must combine)

Develops the 4Cs:
- Critical Thinking: Question claims, seek truth
- Creativity: Unique thinking, novel approaches
- Collaboration: Create something bigger together
- Communication: Efficiently convey ideas
"""

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class Competency(Enum):
    CRITICAL_THINKING = "critical_thinking"
    CREATIVITY = "creativity"
    COLLABORATION = "collaboration"
    COMMUNICATION = "communication"


class BeltLevel(Enum):
    WHITE = "white"
    YELLOW = "yellow"
    ORANGE = "orange"
    GREEN = "green"
    BLUE = "blue"
    PURPLE = "purple"
    BROWN = "brown"
    BLACK = "black"


@dataclass
class MeaningfulnessScore:
    """Scores a challenge on meaningfulness criteria."""
    authentic_stakes: int = 0  # 0-2
    genuine_uncertainty: int = 0  # 0-2
    multiple_approaches: int = 0  # 0-2
    transfer_potential: int = 0  # 0-2
    informative_failure: int = 0  # 0-2
    integration_required: int = 0  # 0-2

    @property
    def total(self) -> int:
        return (self.authentic_stakes + self.genuine_uncertainty +
                self.multiple_approaches + self.transfer_potential +
                self.informative_failure + self.integration_required)

    @property
    def is_meaningful(self) -> bool:
        return self.total >= 8


@dataclass
class MeaningfulChallenge:
    """A challenge designed for meaningful learning."""
    id: str
    title: str
    belt_level: BeltLevel

    # The problem
    scenario: str
    authentic_stakes: str
    discovery_required: str

    # The 4Cs
    competencies_developed: list[Competency]
    critical_thinking_aspect: str = ""
    creativity_aspect: str = ""
    collaboration_aspect: str = ""
    communication_aspect: str = ""

    # Learning design
    multiple_approaches: list[str] = field(default_factory=list)
    failure_teaches: list[str] = field(default_factory=list)
    transfer_principle: str = ""

    # Assessment
    success_criteria: str = ""

    # Meaningfulness
    score: Optional[MeaningfulnessScore] = None


# Meaningful challenges organized by belt level
MEANINGFUL_CHALLENGES = {
    BeltLevel.WHITE: [
        MeaningfulChallenge(
            id="wb_01",
            title="The Secure App Claim",
            belt_level=BeltLevel.WHITE,
            scenario="""A developer claims their app is "completely secure" because:
- Passwords are "encrypted"
- Data is stored "safely"
- Network traffic is "protected"

You have cryptovault.apk. Verify or refute EACH claim with evidence.""",
            authentic_stakes="Developers make vague security claims constantly. Your job is to verify, not trust.",
            discovery_required="What do these terms actually mean in implementation? Is the reality as claimed?",
            competencies_developed=[Competency.CRITICAL_THINKING, Competency.COMMUNICATION],
            critical_thinking_aspect="Don't accept 'encrypted' or 'safe' - demand specifics and verify.",
            communication_aspect="Document findings with evidence that would convince a skeptic.",
            multiple_approaches=[
                "Static analysis of decompiled code",
                "Runtime observation with Frida",
                "File system inspection",
                "Network traffic analysis"
            ],
            failure_teaches=[
                "Accepting claims at face value leads to missed vulnerabilities",
                "Vague terms like 'encrypted' can mean anything or nothing"
            ],
            transfer_principle="Never trust security claims without verifiable evidence.",
            success_criteria="Each claim verified or refuted with specific evidence.",
            score=MeaningfulnessScore(
                authentic_stakes=2,
                genuine_uncertainty=2,
                multiple_approaches=2,
                transfer_potential=2,
                informative_failure=2,
                integration_required=1
            )
        ),
        MeaningfulChallenge(
            id="wb_02",
            title="Question the Documentation",
            belt_level=BeltLevel.WHITE,
            scenario="""Official documentation says: "All API endpoints require authentication."

Test this claim against the actual vulnbank.apk implementation.
Document every endpoint and its ACTUAL authentication requirements.""",
            authentic_stakes="Documentation lies. Code is truth. Security depends on knowing which.",
            discovery_required="Does the server actually enforce what documentation claims?",
            competencies_developed=[Competency.CRITICAL_THINKING],
            critical_thinking_aspect="Test claims against reality. Trust code over docs.",
            multiple_approaches=[
                "Intercept traffic and test endpoints",
                "Analyze code for auth checks",
                "Try direct API calls"
            ],
            failure_teaches=[
                "Trusting documentation without verification misses real issues",
                "Authentication intent vs enforcement are different things"
            ],
            transfer_principle="Documentation describes intent; testing reveals reality.",
            success_criteria="Complete mapping of actual vs documented auth requirements.",
            score=MeaningfulnessScore(
                authentic_stakes=2,
                genuine_uncertainty=2,
                multiple_approaches=1,
                transfer_potential=2,
                informative_failure=2,
                integration_required=1
            )
        )
    ],

    BeltLevel.YELLOW: [
        MeaningfulChallenge(
            id="yb_01",
            title="The Pattern Hunt",
            belt_level=BeltLevel.YELLOW,
            scenario="""You've learned hardcoded credentials are a vulnerability.
Now find ALL variations of this pattern across these 4 APKs:
- Different storage locations (strings.xml, code, assets, BuildConfig)
- Different secret types (passwords, API keys, tokens, certificates)

Document the UNDERLYING PRINCIPLE that makes all of these vulnerable.""",
            authentic_stakes="Real codebases hide secrets in many places. Recognizing the pattern matters more than memorizing locations.",
            discovery_required="What's the common principle? Why are ALL of these locations vulnerable?",
            competencies_developed=[Competency.CRITICAL_THINKING, Competency.CREATIVITY],
            critical_thinking_aspect="See past surface differences to the underlying pattern.",
            creativity_aspect="Where else might secrets hide that weren't listed?",
            multiple_approaches=[
                "Systematic search of all storage locations",
                "Pattern-based grep across decompiled code",
                "Runtime extraction via Frida"
            ],
            failure_teaches=[
                "Memorizing specific locations without understanding misses new variants",
                "The principle applies broadly; locations are just examples"
            ],
            transfer_principle="Any secret in client-distributed code is extractable.",
            success_criteria="All secret locations found AND underlying principle articulated.",
            score=MeaningfulnessScore(
                authentic_stakes=2,
                genuine_uncertainty=2,
                multiple_approaches=2,
                transfer_potential=2,
                informative_failure=2,
                integration_required=1
            )
        )
    ],

    BeltLevel.GREEN: [
        MeaningfulChallenge(
            id="gb_01",
            title="The Defended Vault",
            belt_level=BeltLevel.GREEN,
            scenario="""fortified.apk has multiple defense layers:
- Root detection (3 methods)
- SSL pinning (with backup pins)
- Integrity verification
- Frida detection
- Debug detection

Standard bypass scripts are detected and blocked.
Extract the flag anyway.""",
            authentic_stakes="Defense-in-depth is increasingly common. Script kiddies fail; understanding succeeds.",
            discovery_required="Standard approaches fail. What else is possible?",
            competencies_developed=[Competency.CREATIVITY, Competency.CRITICAL_THINKING],
            creativity_aspect="Novel approach required - timing, chaining, overlooked vectors?",
            critical_thinking_aspect="Why do standard bypasses fail? What assumptions do defenses make?",
            multiple_approaches=[
                "Chain multiple partial bypasses",
                "Timing-based attacks to avoid detection",
                "Find overlooked entry points",
                "Develop novel bypass technique"
            ],
            failure_teaches=[
                "Memorized scripts without understanding are brittle",
                "Defenses have assumptions; creativity finds their gaps"
            ],
            transfer_principle="Understanding why things work enables adaptation when scripts don't.",
            success_criteria="Flag extracted. Bonus: novel method not anticipated by design.",
            score=MeaningfulnessScore(
                authentic_stakes=2,
                genuine_uncertainty=2,
                multiple_approaches=2,
                transfer_potential=2,
                informative_failure=2,
                integration_required=2
            )
        ),
        MeaningfulChallenge(
            id="gb_02",
            title="Red Team Report",
            belt_level=BeltLevel.GREEN,
            scenario="""You've compromised sslpinned.apk by bypassing certificate pinning
and intercepting sensitive data.

Write a report for THREE audiences:
1. Executive: Why should they care? What's the business risk?
2. Developer: Exactly how to fix it, with code examples
3. Security Team: Detection opportunities they missed

Each section must enable appropriate action by that audience.""",
            authentic_stakes="A finding without effective communication is worthless.",
            discovery_required="What does each audience need to know to act?",
            competencies_developed=[Competency.COMMUNICATION, Competency.CRITICAL_THINKING],
            communication_aspect="Tailor message to audience. Enable action, not just understanding.",
            critical_thinking_aspect="What matters to each audience? What action can they take?",
            multiple_approaches=[
                "Technical depth for developers",
                "Risk framing for executives",
                "Detection focus for security"
            ],
            failure_teaches=[
                "One-size-fits-all reports serve no one",
                "Communication without enabling action is performance, not value"
            ],
            transfer_principle="Effective communication means the audience can act, not just understand.",
            success_criteria="Each audience member could take appropriate action from the report alone.",
            score=MeaningfulnessScore(
                authentic_stakes=2,
                genuine_uncertainty=1,
                multiple_approaches=2,
                transfer_potential=2,
                informative_failure=2,
                integration_required=2
            )
        )
    ]
}


class MeaningfulChallengeGenerator:
    """Generates training data from meaningful challenges."""

    def __init__(self):
        self.challenges = MEANINGFUL_CHALLENGES

    def generate_challenge_prompt(self, challenge: MeaningfulChallenge) -> str:
        """Generate the prompt that presents the challenge."""
        competency_focus = ", ".join([c.value.replace("_", " ").title()
                                      for c in challenge.competencies_developed])

        prompt = f"""# {challenge.title}
**Belt Level**: {challenge.belt_level.value.title()}
**Competencies**: {competency_focus}

## Scenario
{challenge.scenario}

## Why This Matters
{challenge.authentic_stakes}

## Your Task
{challenge.discovery_required}

## Success Criteria
{challenge.success_criteria}

---
Approach this challenge demonstrating:
"""
        if Competency.CRITICAL_THINKING in challenge.competencies_developed:
            prompt += f"\n- **Critical Thinking**: {challenge.critical_thinking_aspect}"
        if Competency.CREATIVITY in challenge.competencies_developed:
            prompt += f"\n- **Creativity**: {challenge.creativity_aspect}"
        if Competency.COLLABORATION in challenge.competencies_developed:
            prompt += f"\n- **Collaboration**: {challenge.collaboration_aspect}"
        if Competency.COMMUNICATION in challenge.competencies_developed:
            prompt += f"\n- **Communication**: {challenge.communication_aspect}"

        return prompt

    def generate_successful_response(self, challenge: MeaningfulChallenge) -> str:
        """Generate a response that demonstrates meaningful learning."""

        response = f"""## Approach to {challenge.title}

### Understanding the Challenge
{challenge.authentic_stakes}

This requires: {challenge.discovery_required}

### My Approach

"""
        # Show multiple approaches considered
        if challenge.multiple_approaches:
            response += "**Approaches Considered**:\n"
            for approach in challenge.multiple_approaches:
                response += f"- {approach}\n"
            response += "\n"

        # Critical thinking demonstration
        if Competency.CRITICAL_THINKING in challenge.competencies_developed:
            response += f"""### Critical Thinking Applied
{challenge.critical_thinking_aspect}

Before accepting any claim, I verified:
- What evidence supports this claim?
- What would disprove it?
- Have I tested actual behavior, not just read documentation?

"""

        # Creativity demonstration
        if Competency.CREATIVITY in challenge.competencies_developed:
            response += f"""### Creative Problem-Solving
{challenge.creativity_aspect}

When standard approaches failed, I considered:
- What assumptions are being made?
- What hasn't been tried?
- Can I combine techniques in new ways?

"""

        # Communication demonstration
        if Competency.COMMUNICATION in challenge.competencies_developed:
            response += f"""### Clear Communication
{challenge.communication_aspect}

My findings are documented to:
- Enable reproduction by others
- Support decision-making by stakeholders
- Teach the principle for future application

"""

        # Transfer principle
        response += f"""### Transferable Learning
**Principle Discovered**: {challenge.transfer_principle}

This applies beyond this specific challenge to:
- Similar vulnerability patterns
- Different platforms with same underlying issue
- Future problems I haven't seen yet

"""

        response += f"""### Outcome
{challenge.success_criteria} - ACHIEVED

This challenge developed my ability to question claims, think creatively,
and communicate findings effectively.
"""
        return response

    def generate_failed_response(self, challenge: MeaningfulChallenge) -> tuple[str, str]:
        """Generate a response that fails to demonstrate meaningful learning."""

        # Different failure modes
        import random
        failure_mode = random.choice([
            "rote_application",
            "no_critical_thinking",
            "no_transfer"
        ])

        if failure_mode == "rote_application":
            failed = f"""## Attempting {challenge.title}

I'll apply the standard approach:

1. Decompile APK
2. Search for vulnerabilities
3. Run standard scripts
4. Report findings

Results:
- Ran Frida bypass script - it worked
- Found some issues
- Done

"""
            reason = "ROTE APPLICATION: Applied memorized steps without understanding. No critical thinking about WHY these steps work. No creative adaptation when needed. No transferable learning."

        elif failure_mode == "no_critical_thinking":
            failed = f"""## Attempting {challenge.title}

The documentation says this app is secure, so I focused on other areas.
OWASP says these patterns are vulnerabilities, so I reported them.
The scanner found these issues, so they must be real.

Findings: [List of tool outputs]

"""
            reason = "NO CRITICAL THINKING: Accepted claims without verification. Trusted tools without validation. No questioning of assumptions. Failed to develop disposition to reason."

        else:  # no_transfer
            failed = f"""## Attempting {challenge.title}

I found that strings.xml contained the password.

This is a vulnerability. Fixed by removing the password from strings.xml.

Done.

"""
            reason = "NO TRANSFER: Found specific instance without understanding principle. Cannot apply to new situations. No deeper learning occurred. Failed to see pattern behind example."

        return failed, reason

    def generate_training_pair(self, challenge: MeaningfulChallenge) -> dict:
        """Generate a DPO training pair from a meaningful challenge."""

        prompt = self.generate_challenge_prompt(challenge)
        chosen = self.generate_successful_response(challenge)
        rejected, rejection_reason = self.generate_failed_response(challenge)

        return {
            "prompt": prompt,
            "chosen": chosen,
            "rejected": rejected,
            "metadata": {
                "challenge_id": challenge.id,
                "challenge_title": challenge.title,
                "belt_level": challenge.belt_level.value,
                "competencies": [c.value for c in challenge.competencies_developed],
                "transfer_principle": challenge.transfer_principle,
                "meaningfulness_score": challenge.score.total if challenge.score else 0,
                "rejection_reason": rejection_reason,
                "training_paradigm": "meaningful_challenges_4c"
            }
        }

    def generate_all_training_data(self, output_path: Path) -> dict:
        """Generate training data from all meaningful challenges."""
        pairs = []

        for belt_level, challenges in self.challenges.items():
            print(f"\nGenerating {belt_level.value} belt challenges...")
            for challenge in challenges:
                if challenge.score and challenge.score.is_meaningful:
                    pair = self.generate_training_pair(challenge)
                    pairs.append(pair)

                    # Generate variations with different failure modes
                    for _ in range(2):
                        variation = self.generate_training_pair(challenge)
                        pairs.append(variation)
                else:
                    print(f"  Skipping {challenge.id}: Not meaningful enough (score: {challenge.score.total if challenge.score else 0})")

        # Save
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            for pair in pairs:
                f.write(json.dumps(pair) + "\n")

        stats = {
            "total_pairs": len(pairs),
            "by_belt": {},
            "competencies_covered": set(),
            "paradigm": "meaningful_challenges_4c",
            "principles": [
                "Learning through authentic challenges",
                "4C development: Critical Thinking, Creativity, Collaboration, Communication",
                "Transfer over memorization",
                "Meaningful failure as learning"
            ]
        }

        for pair in pairs:
            belt = pair["metadata"]["belt_level"]
            if belt not in stats["by_belt"]:
                stats["by_belt"][belt] = 0
            stats["by_belt"][belt] += 1

            for comp in pair["metadata"]["competencies"]:
                stats["competencies_covered"].add(comp)

        stats["competencies_covered"] = list(stats["competencies_covered"])

        print(f"\n✅ Generated {len(pairs)} training pairs from meaningful challenges")
        print(f"   Saved to {output_path}")

        return stats


def main():
    """Demonstrate meaningful challenge generation."""
    print("=" * 60)
    print("MEANINGFUL CHALLENGE GENERATOR")
    print("=" * 60)
    print()
    print("Generating training data from challenges that develop:")
    print("  • Critical Thinking - Question claims, seek truth")
    print("  • Creativity - Unique thinking, novel approaches")
    print("  • Collaboration - Create something bigger together")
    print("  • Communication - Efficiently convey ideas")
    print()

    generator = MeaningfulChallengeGenerator()

    print("Meaningful Challenges Available:")
    print("-" * 40)
    for belt_level, challenges in MEANINGFUL_CHALLENGES.items():
        print(f"\n{belt_level.value.upper()} BELT:")
        for challenge in challenges:
            score = challenge.score.total if challenge.score else 0
            meaningful = "✅" if challenge.score and challenge.score.is_meaningful else "❌"
            competencies = ", ".join([c.value[:4].upper() for c in challenge.competencies_developed])
            print(f"  {meaningful} {challenge.title} (Score: {score}, {competencies})")

    # Generate training data
    print("\n" + "-" * 40)
    output = Path("dojo/training_data/meaningful_challenges.jsonl")
    generator.generate_all_training_data(output)


if __name__ == "__main__":
    main()
