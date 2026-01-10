#!/usr/bin/env python3
"""
Yellow Belt Mastery Exam (Live-Fire & Aligned) - V2 Integrated

Executes the exam using the GradingRunner to produce dashboard-compatible metrics.
"""

import argparse
import logging
import subprocess
import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from dojo.graders.runner import GradingRunner
from dojo.models_v2 import (
    Artifact,
    ArtifactType,
    Belt,
    ChallengeType,
    ChallengeV2,
    EvaluationCriteria,
    GroundTruth,
    Phase,
    PhaseID,
    Pillar,
    TrainingMetadata,
)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

class MLXClient:
    def __init__(self, model_path: str):
        self.model_path = model_path

    def generate(self, prompt: str, system_prompt: str = None) -> str:
        full_prompt = f"SYSTEM: {system_prompt}\n\nUSER: {prompt}"
        try:
            # Using basic generation for reliability
            result = subprocess.run(
                ["python3", "-m", "mlx_lm.generate", "--model", self.model_path,
                 "--prompt", full_prompt, "--max-tokens", "2048", "--temp", "0.7"],
                capture_output=True, text=True, timeout=300
            )
            return result.stdout
        except Exception as e:
            return f"Error: {e}"

def create_exam_challenges() -> list[ChallengeV2]:
    """Define the Yellow Belt exam challenges as V2 objects."""

    # Common dummy metadata
    meta = TrainingMetadata()

    # 1. Target Zeta
    ch1 = ChallengeV2(
        id="yellow_001",
        name="Target Zeta: Invisible Hand",
        description="Bypass the isAdmin() check using Frida. Return true.",
        challenge_type=ChallengeType.VERIFICATION,
        pillar=Pillar.METHODOLOGY,
        belt=Belt.YELLOW,
        difficulty=2,
        artifacts=[
            Artifact(
                artifact_type=ArtifactType.DECOMPILED_CODE,
                content="class CryptoManager { public boolean isAdmin() { return false; } }",
                context="TargetZeta.apk decompiled source"
            )
        ],
        phases=[
            Phase(
                phase_id=PhaseID.TEST,
                instruction="Provide a Frida script to bypass the check.",
                expected_output_schema={"command": "str", "script": "str"},
                evaluation_criteria=[
                    EvaluationCriteria("correct_hook", 1.0, "Hooks isAdmin and returns true")
                ]
            )
        ],
        ground_truth=GroundTruth(
            vulnerability_present=True,
            valid_tests=[{"command": "frida", "script_content": "isAdmin"}]
        ),
        training_metadata=meta
    )

    # 2. Target Eta
    ch2 = ChallengeV2(
        id="yellow_002",
        name="Target Eta: Implicit Trust",
        description="Exploit the Content Provider to dump the 'secrets' table via SQL Injection.",
        challenge_type=ChallengeType.VERIFICATION,
        pillar=Pillar.ROOT_CAUSE,
        belt=Belt.YELLOW,
        difficulty=3,
        artifacts=[
            Artifact(
                artifact_type=ArtifactType.MANIFEST,
                content='<provider android:name=".UserContentProvider" android:exported="true" />',
                context="TargetEta.apk AndroidManifest.xml"
            )
        ],
        phases=[
            Phase(
                phase_id=PhaseID.TEST,
                instruction="Construct an ADB command to exploit the provider.",
                expected_output_schema={"command": "str"},
                evaluation_criteria=[
                    EvaluationCriteria("sqli_syntax", 1.0, "Uses content query with projection injection")
                ]
            )
        ],
        ground_truth=GroundTruth(
            vulnerability_present=True,
            valid_tests=[{"command": "content query", "args": "--projection"}]
        ),
        training_metadata=meta
    )

    # 3. Target Theta
    ch3 = ChallengeV2(
        id="yellow_003",
        name="Target Theta: Race Condition",
        description="Identify the TOCTOU vulnerability in file processing.",
        challenge_type=ChallengeType.VERIFICATION,
        pillar=Pillar.ROOT_CAUSE,
        belt=Belt.YELLOW,
        difficulty=4,
        artifacts=[
            Artifact(
                artifact_type=ArtifactType.DECOMPILED_CODE,
                content="if (file.exists()) { // race window \n process(file); }",
                context="TargetTheta.apk source"
            )
        ],
        phases=[
            Phase(
                phase_id=PhaseID.TEST,
                instruction="Provide a command to trace the file operations.",
                expected_output_schema={"command": "str"},
                evaluation_criteria=[
                    EvaluationCriteria("trace_tool", 1.0, "Uses frida-trace or strace on file ops")
                ]
            )
        ],
        ground_truth=GroundTruth(
            vulnerability_present=True,
            valid_tests=[{"command": "frida-trace", "args": "open"}]
        ),
        training_metadata=meta
    )

    return [ch1, ch2, ch3]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--device", default="127.0.0.1:5555")
    parser.add_argument("--mock", action="store_true")
    args = parser.parse_args()

    print("=" * 60)
    print("🟡 AGENTIC ART: YELLOW BELT MASTERY EXAM (V2)")
    print("=" * 60)

    # 1. Init
    client = MLXClient(args.model)
    runner = GradingRunner(model_id="AgenticART-Yellow", generate_dpo=False)

    challenges = create_exam_challenges()
    passed_count = 0

    # 2. RUN
    for challenge in challenges:
        print(f"\n[Task] {challenge.name}")

        # Use V2 Prompt format
        prompt = challenge.to_prompt(phase_index=0)

        # Inject System Prompt to enforce ReAct
        response = client.generate(prompt, system_prompt="You are a reflectively capable Security Analyst. Output JSON.")

        print("\n--- Model Response ---")
        print(response[:300] + "...")

        # Grade using V2 Runner
        # We map the single response to the TEST phase for this exam
        run_result = runner.grade_challenge(
            challenge=challenge,
            phase_responses={PhaseID.TEST: response},
            generate_synthetic_dpo=False
        )

        print("\n--- Scorecard ---")
        print(f"Total Score: {run_result.total_score:.1%}")
        if run_result.phase_results:
            print(f"Feedback: {run_result.phase_results[0].feedback}")

        if run_result.success:
            passed_count += 1
            print("✅ PASS")
        else:
            print("❌ FAIL")

    # 3. Finalize
    saved_paths = runner.save_results(prefix="yellow_exam")

    print("\n" + "=" * 60)
    if passed_count == len(challenges):
        print("🏆 SUCCESS: YELLOW BELT CERTIFIED")
    else:
        print(f"❌ FAILURE: Score {passed_count}/{len(challenges)}")

    print(f"\nMetrics saved to: {saved_paths.get('metrics', 'Unknown')}")

if __name__ == "__main__":
    main()
