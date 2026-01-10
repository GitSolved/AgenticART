#!/usr/bin/env python3
"""
Emergent Reasoning Trainer

Training data generator where reasoning emerges through problem-solving,
not as a prerequisite taught in isolation.

Key insight: We don't teach "how to reason about buffer overflows."
We present a binary with a buffer overflow and let the model discover
reasoning patterns through attempting to exploit it.

The training signal comes from:
- Successful exploitation trajectories (what worked)
- Failed attempts with course corrections (learning from mistakes)
- The gap between "tried this" and "this actually worked"
"""

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AttemptStep:
    """A single step in a problem-solving attempt."""
    action: str  # What was tried
    observation: str  # What happened
    reflection: str  # What this tells us (emerges from observation)


@dataclass
class ProblemSolvingTrajectory:
    """
    A complete trajectory of attempting to solve a problem.

    Reasoning isn't prescribed - it emerges from the sequence of
    attempts, observations, and adjustments.
    """
    problem: str  # The authentic challenge
    steps: list[AttemptStep] = field(default_factory=list)
    outcome: str = ""  # Success/failure
    emerged_insight: str = ""  # What reasoning crystallized


class EmergentReasoningTrainer:
    """
    Generates training data from problem-solving trajectories.

    Instead of teaching "correct reasoning patterns," we:
    1. Present authentic problems (vulnerable APKs)
    2. Record trajectories of solution attempts
    3. Mark successful trajectories as "chosen"
    4. Mark failed/inefficient trajectories as "rejected"

    Reasoning emerges as the difference between what works and what doesn't.
    """

    def __init__(self, emulator_device: str = "127.0.0.1:6555"):
        self.emulator_device = emulator_device
        self.apks = {
            "cryptovault": {
                "package": "com.agentic.cryptovault",
                "vulnerability": "hardcoded_credentials",
                "flag_location": "displayed after correct password"
            },
            "nativecheck": {
                "package": "com.agentic.nativecheck",
                "vulnerability": "bypassable_root_detection",
                "flag_location": "displayed when checks pass"
            },
            "sslpinned": {
                "package": "com.agentic.sslpinned",
                "vulnerability": "bypassable_ssl_pinning",
                "flag_location": "returned from server after bypass"
            },
            "fortified": {
                "package": "com.agentic.fortified",
                "vulnerability": "multi_layer_bypass",
                "flag_location": "displayed after all bypasses"
            }
        }

    def execute_on_device(self, command: str) -> str:
        """Execute a command on the Android device."""
        try:
            result = subprocess.run(
                ["adb", "-s", self.emulator_device, "shell", command],
                capture_output=True, text=True, timeout=30
            )
            return result.stdout + result.stderr
        except Exception as e:
            return f"Error: {e}"

    def generate_successful_trajectory(self, apk_name: str) -> ProblemSolvingTrajectory:
        """
        Generate a successful problem-solving trajectory.

        This represents what WORKED - the model learns from seeing
        the sequence of actions that led to flag extraction.
        """
        apk_info = self.apks.get(apk_name, {})
        trajectory = ProblemSolvingTrajectory(
            problem=f"Extract the flag from {apk_name}.apk"
        )

        if apk_name == "cryptovault":
            trajectory.steps = [
                AttemptStep(
                    action="Decompile APK to examine source",
                    observation="Found MainActivity.java with password check against hardcoded value",
                    reflection=""  # Emerges later
                ),
                AttemptStep(
                    action="Search strings.xml for password values",
                    observation="Found 'vault_password' = 'sup3rs3cr3t123'",
                    reflection=""
                ),
                AttemptStep(
                    action="Launch app and enter discovered password",
                    observation="Vault unlocked, flag displayed: flag{cr4ck3d_th3_v4ult}",
                    reflection=""
                )
            ]
            trajectory.outcome = "SUCCESS: Flag extracted"
            trajectory.emerged_insight = (
                "Hardcoded credentials in client-side code are always extractable. "
                "The 'security' existed only as obscurity. This pattern applies to "
                "any secret embedded in APK resources or code."
            )

        elif apk_name == "nativecheck":
            trajectory.steps = [
                AttemptStep(
                    action="Run app normally to see what checks fail",
                    observation="'Root detected' message, button disabled",
                    reflection=""
                ),
                AttemptStep(
                    action="Decompile to find native library doing checks",
                    observation="libnative.so contains isRooted() function",
                    reflection=""
                ),
                AttemptStep(
                    action="Write Frida script to hook isRooted() return value",
                    observation="Hook successful, function now returns false",
                    reflection=""
                ),
                AttemptStep(
                    action="Relaunch app with Frida injection",
                    observation="All checks pass, flag displayed: flag{n4t1v3_byp4ss3d}",
                    reflection=""
                )
            ]
            trajectory.outcome = "SUCCESS: Flag extracted"
            trajectory.emerged_insight = (
                "Client-side security checks are advisory, not enforceable. "
                "Any check that runs on attacker-controlled hardware can be bypassed. "
                "The same Frida pattern works for any boolean security check."
            )

        # Fill in emergent reflections based on trajectory
        trajectory = self._crystallize_reasoning(trajectory)

        return trajectory

    def generate_failed_trajectory(self, apk_name: str) -> ProblemSolvingTrajectory:
        """
        Generate a failed/inefficient trajectory.

        This represents what DIDN'T work - the model learns that
        these approaches are less effective.
        """
        trajectory = ProblemSolvingTrajectory(
            problem=f"Extract the flag from {apk_name}.apk"
        )

        if apk_name == "cryptovault":
            # Failure mode: Trying to brute force instead of analyzing
            trajectory.steps = [
                AttemptStep(
                    action="Try common passwords: admin, password, 123456",
                    observation="All rejected",
                    reflection=""
                ),
                AttemptStep(
                    action="Try to bypass login with SQL injection",
                    observation="No effect - this isn't a SQL-based auth",
                    reflection=""
                ),
                AttemptStep(
                    action="Try to intercept network traffic",
                    observation="No network calls during auth - it's local",
                    reflection=""
                )
            ]
            trajectory.outcome = "FAILED: No flag extracted"
            trajectory.emerged_insight = (
                "Blind attacks without understanding the target waste time. "
                "Should have analyzed the APK first to understand the auth mechanism."
            )

        elif apk_name == "nativecheck":
            # Failure mode: Trying to patch APK instead of runtime bypass
            trajectory.steps = [
                AttemptStep(
                    action="Decompile APK and try to modify smali code",
                    observation="Changed check, but signature verification fails on reinstall",
                    reflection=""
                ),
                AttemptStep(
                    action="Try to disable signature verification",
                    observation="Complex, multiple layers of verification",
                    reflection=""
                ),
                AttemptStep(
                    action="Give up on static patching",
                    observation="Wasted 30 minutes on wrong approach",
                    reflection=""
                )
            ]
            trajectory.outcome = "FAILED: Approach too complex"
            trajectory.emerged_insight = (
                "Static patching fights against the entire Android security model. "
                "Runtime instrumentation (Frida) bypasses these checks entirely. "
                "Choose the path of least resistance."
            )

        trajectory = self._crystallize_reasoning(trajectory)
        return trajectory

    def _crystallize_reasoning(
        self,
        trajectory: ProblemSolvingTrajectory
    ) -> ProblemSolvingTrajectory:
        """
        Add emergent reflections to trajectory steps.

        Reasoning crystallizes AFTER action - it's the understanding
        that emerges from observing what happened.
        """
        for i, step in enumerate(trajectory.steps):
            # Reflection emerges from the gap between expectation and observation
            if "found" in step.observation.lower():
                step.reflection = "This observation narrows the search space."
            elif "failed" in step.observation.lower() or "rejected" in step.observation.lower():
                step.reflection = "This approach doesn't work for this target. Adjust."
            elif "success" in step.observation.lower() or "flag" in step.observation.lower():
                step.reflection = "This confirms the vulnerability hypothesis."
            else:
                step.reflection = "Noted. Continue gathering information."

        return trajectory

    def trajectory_to_training_pair(
        self,
        successful: ProblemSolvingTrajectory,
        failed: ProblemSolvingTrajectory
    ) -> dict:
        """
        Convert trajectories to DPO training pair.

        The chosen response is the successful trajectory.
        The rejected response is the failed trajectory.

        Reasoning isn't explicitly taught - it emerges from seeing
        which approaches work and which don't.
        """
        def format_trajectory(t: ProblemSolvingTrajectory) -> str:
            lines = [f"## Problem: {t.problem}\n"]

            for i, step in enumerate(t.steps, 1):
                lines.append(f"### Step {i}")
                lines.append(f"**Action**: {step.action}")
                lines.append(f"**Observation**: {step.observation}")
                if step.reflection:
                    lines.append(f"**Reflection**: {step.reflection}")
                lines.append("")

            lines.append(f"### Outcome: {t.outcome}")
            lines.append(f"\n### Insight Emerged: {t.emerged_insight}")

            return "\n".join(lines)

        prompt = f"""You are attempting to extract a flag from a vulnerable Android APK.

Problem: {successful.problem}

Environment: Android 14, Galaxy S24 (Genymotion emulator)
Available tools: adb, frida, jadx, apktool

Show your problem-solving process step by step. Include what you try, what you observe, and how observations inform your next action.
"""

        return {
            "prompt": prompt,
            "chosen": format_trajectory(successful),
            "rejected": format_trajectory(failed),
            "metadata": {
                "apk": successful.problem.split()[-1].replace(".apk", ""),
                "training_paradigm": "emergent_reasoning",
                "insight": successful.emerged_insight
            }
        }

    def generate_training_data(self, output_path: Path) -> dict:
        """Generate training data from problem-solving trajectories."""
        pairs = []

        for apk_name in self.apks:
            print(f"Generating trajectories for {apk_name}...")

            successful = self.generate_successful_trajectory(apk_name)
            failed = self.generate_failed_trajectory(apk_name)

            pair = self.trajectory_to_training_pair(successful, failed)
            pairs.append(pair)

        # Save to file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            for pair in pairs:
                f.write(json.dumps(pair) + "\n")

        print(f"\nGenerated {len(pairs)} trajectory-based training pairs")
        print(f"Saved to {output_path}")

        return {
            "total_pairs": len(pairs),
            "paradigm": "emergent_reasoning",
            "principle": "Reasoning crystallizes through problem-solving, not prerequisite instruction"
        }


def main():
    """Demonstrate emergent reasoning training."""
    print("=" * 60)
    print("EMERGENT REASONING TRAINER")
    print("=" * 60)
    print()
    print("Core Principle:")
    print("  Reasoning is not a prerequisite - it EMERGES through application.")
    print()
    print("Training Approach:")
    print("  1. Present authentic problem (vulnerable APK)")
    print("  2. Record solution trajectories (what was tried)")
    print("  3. Chosen = successful trajectory")
    print("  4. Rejected = failed trajectory")
    print("  5. Model learns reasoning from the DIFFERENCE")
    print()

    trainer = EmergentReasoningTrainer()

    # Generate sample trajectory
    print("Sample successful trajectory (cryptovault):")
    print("-" * 40)
    traj = trainer.generate_successful_trajectory("cryptovault")
    for i, step in enumerate(traj.steps, 1):
        print(f"Step {i}: {step.action}")
        print(f"  → {step.observation}")
    print(f"\nOutcome: {traj.outcome}")
    print(f"Emerged Insight: {traj.emerged_insight}")


if __name__ == "__main__":
    main()
