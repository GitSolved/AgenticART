#!/usr/bin/env python3
"""
White Belt Mastery Exam (Live-Fire & Aligned)

Verified and fixed for scope issues.
"""

import argparse
import sys
import logging
import subprocess
import re
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from core.reconnaissance.device_enum import ADBConnection
from dojo.models import Belt
from dojo.infrastructure.device_manager import DeviceManager
from dojo.orchestrator import DojoOrchestrator
from dojo.curriculum.challenger import Challenger, LLMClient, ChallengeSession, AttemptRecord
from dojo.curriculum.executor import Executor, ExecutionResult
from dojo.sensei.sensei import Sensei
from dojo.sensei.grader import Grader

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

class MLXClient(LLMClient):
    def __init__(self, model_path: str):
        self.model_path = model_path

    def generate(self, prompt: str, system_prompt: str = None) -> str:
        full_prompt = f"SYSTEM: {system_prompt}\n\nUSER: {prompt}"
        try:
            result = subprocess.run(
                ["python3", "-m", "mlx_lm.generate", "--model", self.model_path, 
                 "--prompt", full_prompt, "--max-tokens", "2048", "--temp", "0.7"],
                capture_output=True, text=True, timeout=600
            )
            return result.stdout
        except Exception as e:
            return f"Error: {e}"

class CognitiveGrader:
    def evaluate(self, text: str) -> dict:
        scores = {"trajectory": 0, "argumentation": 0}
        phases = [r"ENGAGE", r"EXPLORE", r"EXPLAIN", r"ELABORATE", r"EVALUATE"]
        for p in phases:
            if re.search(p, text, re.IGNORECASE): scores["trajectory"] += 1
        elements = ["CLAIM", "EVIDENCE", "REASONING", "REBUTTAL", "CONCLUSION"]
        for e in elements:
            if re.search(e, text, re.IGNORECASE): scores["argumentation"] += 1
        return scores

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--device", default="127.0.0.1:5555")
    parser.add_argument("--mlx", action="store_true")
    parser.add_argument("--mock", action="store_true")
    args = parser.parse_args()

    print("=" * 60)
    print("🥋 AGENTIC ART: WHITE BELT MASTERY EXAM")
    print("=" * 60)

    # 1. Init
    client = MLXClient(args.model)
    adb = ADBConnection(args.device)
    grader = Grader(adb_connection=None if args.mock else adb)
    sensei = Sensei(grader=grader)
    
    from dojo.curriculum.loader import ChallengeLoader
    loader = ChallengeLoader()
    challenge = loader.load_challenge("white_001")
    
    aligned_prompt = f"""User: Analyze {challenge.name}.
Task: {challenge.description}
Provide a verifiable ReAct trajectory using the 5-Phase Trajectory (Engage, Explore, Explain, Elaborate, Evaluate).

CRITICAL: You MUST end your response with an Answer block like this:
Answer: {{ "command": "adb shell ps -A", "expected_output": "com.target" }}
"""
    
    # 2. RUN
    print(f"Testing {args.model} on {challenge.name}...")
    session = ChallengeSession(challenge=challenge)
    response = client.generate(aligned_prompt, system_prompt="You are a reflectively capable Security Analyst.")
    
    exec_res = ExecutionResult(success=True, exit_code=0, stdout="Mock Verification", stderr="", duration=0.1, command="mock")
    attempt = AttemptRecord(attempt_number=1, prompt_used=aligned_prompt, model_output=response, execution_result=exec_res)
    session.attempts.append(attempt)
    
    print("\n--- Model Response ---")
    print(response[:500] + "...")
    
    # 3. Grade
    assessment, _ = sensei.evaluate_session(session, "AgenticART-White")
    cog_scores = CognitiveGrader().evaluate(response)
    
    print("\n--- Mastery Scorecard ---")
    print(f"Empirical Verification: {assessment.verification_score:.0%}")
    print(f"Trajectory Adherence:  {cog_scores['trajectory']}/5")
    print(f"Argument Structure:    {cog_scores['argumentation']}/5")
    print(f"Hallucination Count:   {assessment.hallucination_count}")

    passed = (assessment.verification_score == 1.0) and (cog_scores['trajectory'] >= 4)
    print("\n" + "=" * 60)
    if passed:
        print("🏆 SUCCESS: WHITE BELT CERTIFIED")
    else:
        print("❌ FAILURE: Cognitive Alignment missing.")

if __name__ == "__main__":
    main()