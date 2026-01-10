#!/usr/bin/env python3
"""
Simulated Post-Training Exam

Runs the White Belt exam with FEW-SHOT context to simulate 
what the model learns during the SFT phase.
"""

import argparse
import logging
import subprocess
import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from dojo.curriculum.challenger import AttemptRecord, ChallengeSession
from dojo.curriculum.executor import ExecutionResult
from dojo.models import Belt, Challenge, ChallengeInput, ExpectedOutput, ScriptType
from dojo.sensei.grader import Grader

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# THE TRAINING MATERIAL (GOLDEN EXAMPLE)
FEW_SHOT_CONTEXT = """
SYSTEM: You are an Android Security Expert agent. You observe before acting. You verify every claim.

EXAMPLE TASK:
Analyze com.example.service for The Black Box (Process Model).
Task: Identify the process emitting a specific log message.

EXAMPLE RESPONSE:
Thought: I need to find the PID associated with the log message 'User Authenticated'.
Action: adb logcat -d | grep 'User Authenticated' | head -1
Observation: [10-24 14:32:01.450 5559:1256 D/Tag] User Authenticated
Thought: Now I verify the PID 5559 to find its process name and UID.
Action: adb shell ps -A | grep 5559
Observation: u0_a10769 5559 1 123456 12345 0 com.example.service
Thought: Checking if com.example.service registers any Binder services.
Action: adb shell service list | grep -i LocationProvider
Observation: com.example.service.LocationProvider: [com.example.service.ILocationProvider]

Answer: {
  "command": "adb shell ps -A | grep 5559",
  "expected_output": "com.example.service",
  "confidence": 0.98
}
"""

class TrainedStudentInterface:
    def __init__(self, model_name: str):
        self.model_name = model_name

    def solve(self, challenge: Challenge) -> str:
        logger.info(f"Asking (Trained) {self.model_name} to solve: {challenge.name}")

        # Injected Training Knowledge
        prompt = FEW_SHOT_CONTEXT + "\n\nACTUAL TASK:\n" + challenge.description
        prompt += "\nProvide a verifiable ReAct trajectory and a final JSON answer with 'command' and 'expected_output'."

        try:
            result = subprocess.run(
                ["ollama", "run", self.model_name, prompt],
                capture_output=True,
                text=True,
                timeout=120
            )
            return result.stdout
        except Exception as e:
            return f"Error: {e}"

class WhiteBeltExam:
    def __init__(self, model_name: str):
        # Always mock for this demo to ensure speed
        self.adb = None
        self.grader = Grader(adb_connection=self.adb)
        self.student = TrainedStudentInterface(model_name)
        self.exam_targets = ["dojo/targets/exam_target_alpha.apk"] # One target for speed

    def run_exam(self) -> bool:
        target = self.exam_targets[0]
        challenge = Challenge(
            id="exam_post_train",
            name="Verification Test",
            description=f"Analyze {target} and find the PID emitting 'System Healthy'.",
            belt=Belt.WHITE,
            difficulty=5,
            inputs=ChallengeInput(device_context={"apk": target}),
            expected_output=ExpectedOutput(script_type=ScriptType.ADB, must_contain=["dumpsys"])
        )

        response = self.student.solve(challenge)

        session = ChallengeSession(challenge=challenge)
        exec_result = ExecutionResult(success=True, exit_code=0, stdout="u0_a1000 1234 1 123456 12345 0 com.target", stderr="", duration=0.1, command="mock")
        attempt = AttemptRecord(attempt_number=1, prompt_used="", model_output=response, execution_result=exec_result)
        session.attempts.append(attempt)

        assessment = self.grader.grade_session(session)

        print("\n" + "=" * 60)
        print("SIMULATED POST-TRAINING RESULT")
        print("=" * 60)
        print(f"Model: {self.student.model_name}")
        print(f"Result: {'PASS' if assessment.verification_score > 0 else 'FAIL'}")
        print(f"Verification Score: {assessment.verification_score:.0%}")
        print(f"Hallucinations: {assessment.hallucination_count}")

        if assessment.verification_logs:
            print("\nVerification Logs:")
            for log in assessment.verification_logs:
                print(f"  {log}")

        print("\nRaw Model Output (Snippet):")
        print(response[:300] + "...")
        return assessment.verification_score > 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=str, default="35f20a64ebe5")
    args = parser.parse_args()
    WhiteBeltExam(args.model).run_exam()
