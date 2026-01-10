#!/usr/bin/env python3
"""
Praxis-Oriented Training Data Generator

Generates training pairs where reasoning and action are inseparable.
Each pair embeds critical reflection within authentic problem-solving context.

"Reasoning without application devolves into abstract verbalism;
 application without reasoning becomes blind activism."
"""

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, cast


@dataclass
class PraxisContext:
    """Authentic problem-solving context from real APK analysis."""
    apk_name: str
    observations: list[str]  # What the model sees (decompiled code, logs, etc.)
    environment: str  # Device state, installed apps, etc.


@dataclass
class PraxisReflection:
    """Critical thinking component - the WHY."""
    vulnerability_pattern: str  # What pattern does this match?
    root_cause: str  # Why does this vulnerability exist?
    severity_reasoning: str  # Why is this serious (or not)?
    assumptions_questioned: list[str]  # What assumptions are we making?


@dataclass
class PraxisAction:
    """Purposeful action component - the HOW."""
    exploit_steps: list[str]  # Concrete commands/actions
    expected_outcome: str  # What should happen if successful
    verification: str  # How to confirm success
    recovery_if_wrong: str  # What to do if this doesn't work


@dataclass
class PraxisTrainingPair:
    """
    A training pair that unifies thought and action.

    Unlike traditional pairs that separate "reasoning" from "doing",
    praxis pairs embed reflection within authentic task completion.
    """
    # Authentic context
    context: PraxisContext

    # The unified response (reflection + action as one)
    chosen_response: str  # Demonstrates praxis
    rejected_response: str  # Fails at praxis (verbalism OR activism)

    # Why the rejected response fails
    rejection_reason: str

    # Metadata
    pillar: str
    challenge_id: str
    difficulty: str


class PraxisTrainer:
    """
    Generates training data grounded in authentic problem-solving.

    Key principle: Every training pair must include:
    1. Real observations from APK analysis
    2. Critical reflection on what those observations mean
    3. Concrete actions to take
    4. Expected outcomes to verify understanding
    """

    def __init__(self, emulator_device: str = "127.0.0.1:6555"):
        self.emulator_device = emulator_device
        self.apk_dir = Path(__file__).parent.parent / "targets" / "vulnerable_apks"

    def generate_authentic_context(self, apk_name: str) -> PraxisContext:
        """
        Generate real observations from actual APK analysis.
        This grounds training in authentic context, not hypotheticals.
        """
        observations = []

        # Get real data from the APK
        self.apk_dir / apk_name / "app" / "build" / "outputs" / "apk" / "debug"

        # Try to get actual APK observations
        try:
            # Check if APK exists on device
            result = subprocess.run(
                ["adb", "-s", self.emulator_device, "shell",
                 f"pm list packages | grep -i {apk_name}"],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout.strip():
                observations.append(f"Package installed: {result.stdout.strip()}")

            # Get app data directory contents
            result = subprocess.run(
                ["adb", "-s", self.emulator_device, "shell",
                 f"ls -la /data/data/com.agentic.{apk_name}/ 2>/dev/null || echo 'Not accessible'"],
                capture_output=True, text=True, timeout=10
            )
            if "Not accessible" not in result.stdout:
                observations.append(f"App data directory:\n{result.stdout.strip()}")

        except Exception:
            observations.append(f"[Simulated] APK {apk_name} analysis context")

        return PraxisContext(
            apk_name=apk_name,
            observations=observations,
            environment="Android 14, Galaxy S24 (Genymotion)"
        )

    def create_praxis_pair(
        self,
        context: PraxisContext,
        reflection: PraxisReflection,
        action: PraxisAction,
        pillar: str,
        challenge_id: str
    ) -> PraxisTrainingPair:
        """
        Create a training pair that demonstrates unified praxis.

        The chosen response integrates reflection and action.
        The rejected response fails at this integration.
        """

        # Build the unified praxis response (chosen)
        chosen = self._build_praxis_response(context, reflection, action)

        # Build a failed response (rejected) - either verbalism or activism
        rejected, rejection_reason = self._build_failed_response(
            context, reflection, action
        )

        return PraxisTrainingPair(
            context=context,
            chosen_response=chosen,
            rejected_response=rejected,
            rejection_reason=rejection_reason,
            pillar=pillar,
            challenge_id=challenge_id,
            difficulty="green"  # TODO: infer from challenge
        )

    def _build_praxis_response(
        self,
        context: PraxisContext,
        reflection: PraxisReflection,
        action: PraxisAction
    ) -> str:
        """
        Build a response that demonstrates true praxis:
        reflection and action as inseparable unity.
        """
        observations_text = "\n".join(f"- {obs}" for obs in context.observations)

        response = f"""## Analysis of {context.apk_name}

### What I Observe
{observations_text}

### Critical Reflection
This matches the pattern of **{reflection.vulnerability_pattern}**.

**Root Cause**: {reflection.root_cause}

**Severity Assessment**: {reflection.severity_reasoning}

**Assumptions to Question**:
{chr(10).join(f'- {a}' for a in reflection.assumptions_questioned)}

### Purposeful Action
Based on this analysis, here's how to exploit this vulnerability:

{chr(10).join(f'{i+1}. {step}' for i, step in enumerate(action.exploit_steps))}

**Expected Outcome**: {action.expected_outcome}

**Verification**: {action.verification}

### If This Doesn't Work
{action.recovery_if_wrong}

---
*This analysis demonstrates praxis: understanding WHY the vulnerability exists (reflection) unified with HOW to exploit it (action). Neither is meaningful without the other.*
"""
        return response

    def _build_failed_response(
        self,
        context: PraxisContext,
        reflection: PraxisReflection,
        action: PraxisAction
    ) -> tuple[str, str]:
        """
        Build a response that fails at praxis.

        Two failure modes:
        1. Abstract verbalism: All theory, no action
        2. Blind activism: All action, no understanding
        """
        import random

        if random.random() < 0.5:
            # Failure mode 1: Abstract verbalism
            rejected = f"""## Analysis of {context.apk_name}

{reflection.vulnerability_pattern} is a well-documented security issue.
According to OWASP, this vulnerability class represents a significant
risk to mobile applications. The CWE database classifies similar
issues under multiple categories.

Theoretically, an attacker could leverage this vulnerability to
compromise the application's security model. The implications
include potential data leakage, unauthorized access, and
violation of the principle of least privilege.

Further research would be needed to determine the exact
exploitation methodology. Security best practices recommend
implementing defense-in-depth strategies.
"""
            reason = "ABSTRACT VERBALISM: Discusses vulnerability theoretically but provides no concrete exploitation steps. The model 'knows about' the vulnerability but cannot act on that knowledge."

        else:
            # Failure mode 2: Blind activism
            rejected = f"""## Exploiting {context.apk_name}

Run these commands:

```bash
adb shell
su
cat /data/data/*/shared_prefs/*.xml
frida -U -f com.app.target -l exploit.js
```

If that doesn't work, try:
```bash
objection -g com.app.target explore
android hooking search classes password
```

Keep trying different commands until something works.
"""
            reason = "BLIND ACTIVISM: Throws commands at the problem without understanding WHY they might work. No analysis of the specific vulnerability, no reasoning about root cause, no verification of assumptions. This is cargo-cult security testing."

        return rejected, reason

    def generate_training_data(
        self,
        challenges: list[dict],
        output_path: Path
    ) -> dict:
        """
        Generate praxis-oriented training pairs from curriculum challenges.

        Each pair grounds critical reflection in authentic action.
        """
        pairs = []
        stats: dict[str, Any] = {
            "total_pairs": 0,
            "by_pillar": {},
            "rejection_types": {
                "abstract_verbalism": 0,
                "blind_activism": 0
            }
        }

        for challenge in challenges:
            # Get authentic context
            apk_name = self._challenge_to_apk(challenge.get("id", ""))
            if not apk_name:
                continue

            context = self.generate_authentic_context(apk_name)

            # Extract reflection and action from challenge
            reflection = PraxisReflection(
                vulnerability_pattern=challenge.get("vulnerability_type", "Unknown"),
                root_cause=challenge.get("root_cause", "Not specified"),
                severity_reasoning=challenge.get("severity_rationale", ""),
                assumptions_questioned=[
                    "Is this the only vulnerability?",
                    "Could there be additional protections?",
                    "What version-specific behaviors might affect exploitation?"
                ]
            )

            action = PraxisAction(
                exploit_steps=challenge.get("exploit_steps", []),
                expected_outcome=challenge.get("expected_flag", "Flag extracted"),
                verification="Compare extracted value against known flag format",
                recovery_if_wrong="Re-examine assumptions, check for additional protections"
            )

            # Generate the pair
            training_pair = cast(PraxisTrainingPair, self.create_praxis_pair(
                context=context,
                reflection=reflection,
                action=action,
                pillar=challenge.get("pillar", "unknown"),
                challenge_id=challenge.get("id", "unknown")
            ))

            # Convert to DPO format
            prompt = self._build_prompt(context, challenge)
            dpo_pair = {
                "prompt": prompt,
                "chosen": training_pair.chosen_response,
                "rejected": training_pair.rejected_response,
                "metadata": {
                    "pillar": training_pair.pillar,
                    "challenge_id": training_pair.challenge_id,
                    "rejection_reason": training_pair.rejection_reason,
                    "praxis_grounded": True
                }
            }
            pairs.append(dpo_pair)

            # Update stats
            stats["total_pairs"] += 1
            pillar = training_pair.pillar
            if pillar not in stats["by_pillar"]:
                stats["by_pillar"][pillar] = 0
            stats["by_pillar"][pillar] += 1

            if "VERBALISM" in training_pair.rejection_reason:
                stats["rejection_types"]["abstract_verbalism"] += 1
            else:
                stats["rejection_types"]["blind_activism"] += 1

        # Save pairs
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            for pair in pairs:
                f.write(json.dumps(pair) + "\n")

        print(f"Generated {len(pairs)} praxis-oriented training pairs")
        print(f"Saved to {output_path}")

        return stats

    def _challenge_to_apk(self, challenge_id: str) -> Optional[str]:
        """Map challenge ID to APK name."""
        mapping = {
            "green_persona_001": "cryptovault",
            "green_persona_002": "nativecheck",
            "green_persona_003": "sslpinned",
            "green_persona_004": "fortified",
        }
        return mapping.get(challenge_id)

    def _build_prompt(self, context: PraxisContext, challenge: dict) -> str:
        """Build the prompt that presents the authentic context."""
        observations = "\n".join(f"- {obs}" for obs in context.observations)

        return f"""You are analyzing {context.apk_name} on {context.environment}.

## Observations
{observations}

## Task
{challenge.get('description', 'Analyze this application for security vulnerabilities.')}

Provide your analysis demonstrating PRAXIS: unified critical reflection (WHY this vulnerability exists) and purposeful action (HOW to exploit it). Neither alone is sufficient.
"""


def main():
    """Demonstrate praxis-oriented training generation."""
    print("=" * 60)
    print("PRAXIS TRAINING DATA GENERATOR")
    print("=" * 60)
    print()
    print("Praxis = Unity of critical reflection + purposeful action")
    print()
    print("This generator creates training pairs where:")
    print("  ✓ Reasoning is grounded in authentic APK analysis")
    print("  ✓ Action is informed by critical understanding")
    print("  ✓ Neither verbalism nor activism is acceptable")
    print()

    trainer = PraxisTrainer()

    # Check emulator
    try:
        result = subprocess.run(
            ["adb", "-s", trainer.emulator_device, "shell", "echo", "connected"],
            capture_output=True, text=True, timeout=10
        )
        if "connected" in result.stdout:
            print(f"✅ Emulator connected: {trainer.emulator_device}")
            print("   Training will use REAL observations from APK analysis")
        else:
            print("⚠️  Emulator not connected")
            print("   Training will use simulated observations")
    except Exception:
        print("⚠️  Could not connect to emulator")

    print()
    print("To generate praxis training data:")
    print("  trainer = PraxisTrainer()")
    print("  trainer.generate_training_data(challenges, output_path)")


if __name__ == "__main__":
    main()
