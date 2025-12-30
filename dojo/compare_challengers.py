import os
import sys
import argparse
from pathlib import Path
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from dojo import Belt, ChallengeLoader
from dojo.curriculum import Executor, Challenger, ContextInjector, ErrorExtractor
from dojo.react_challenger import ReActChallenger
from dojo.trajectory_logger import TrajectoryLogger
from dojo.test_end_to_end import MLXLLMClient

def main():
    parser = argparse.ArgumentParser(description="Compare Basic vs ReAct Challenger")
    parser.add_argument("--mode", choices=["mlx", "live"], default="mlx", help="LLM mode")
    parser.add_argument("--model", default="models/whiterabbit-7b-dojo-4bit", help="Model path/name")
    parser.add_argument("--adapter", default="models/whiterabbit-7b-adapters", help="Path to LoRA adapters")
    parser.add_argument("--device", default="127.0.0.1:6562", help="ADB device ID")
    args = parser.parse_args()

    print("==================================================")
    print("   CHALLENGER COMPARISON: BASIC VS REACT")
    print("==================================================")

    # 1. Setup
    model_id = "compare-run"
    if args.mode == "mlx":
        llm = MLXLLMClient(model_path=args.model, adapter_path=args.adapter)
    else:
        from dojo.test_end_to_end import OllamaLLMClient
        llm = OllamaLLMClient(model=args.model)
    executor = Executor(device_id=args.device)
    loader = ChallengeLoader()
    
    # Select a few representative challenges
    # white_001 (Version), white_002 (Packages), white_005 (Protected Access)
    all_white = loader.load_belt(Belt.WHITE)
    challenges = [c for c in all_white if c.id in ["white_001", "white_002", "white_005"]]

    results = {"basic": {"pass": 0, "fail": 0, "steps": 0}, "react": {"pass": 0, "fail": 0, "steps": 0}}

    # 2. Run Basic Challenger
    print("\n[PHASE 1] Running BASIC Challenger...")
    basic_challenger = Challenger(
        llm_client=llm,
        executor=executor,
        max_retries=3
    )

    for challenge in challenges:
        print(f"\n  Challenge: {challenge.id} ({challenge.name})")
        session = basic_challenger.run_challenge(challenge)
        if session.final_success:
            results["basic"]["pass"] += 1
            print(f"    FINAL RESULT: PASS ({len(session.attempts)} attempts)")
        else:
            results["basic"]["fail"] += 1
            print(f"    FINAL RESULT: FAIL")
        results["basic"]["steps"] += len(session.attempts)

    # 3. Run ReAct Challenger
    print("\n" + "-"*50)
    print("[PHASE 2] Running REACT Challenger...")
    traj_dir = Path("dojo_output/comparison_trajectories")
    traj_logger = TrajectoryLogger(output_dir=str(traj_dir))
    
    def on_step(step_num, parsed, result):
        status = "OK" if result.get("exit_code") == 0 else "FAIL"
        print(f"    Step {step_num}: [{status}] Action: {parsed.action[:50]}")
        print(f"      [DEBUG] Stdout: {result.get('stdout')[:100]}")

    react_challenger = ReActChallenger(
        llm_client=llm,
        executor=executor,
        trajectory_logger=traj_logger,
        max_steps=5,
        on_step=on_step
    )

    for challenge in challenges:
        print(f"\n  Challenge: {challenge.id} ({challenge.name})")
        session = react_challenger.run_challenge(challenge, model_id=model_id)
        if session.final_success:
            results["react"]["pass"] += 1
            print(f"    FINAL RESULT: PASS ({len(session.attempts)} steps)")
        else:
            results["react"]["fail"] += 1
            print(f"    FINAL RESULT: FAIL")
        results["react"]["steps"] += len(session.attempts)

    # 4. Summary
    print("\n" + "="*50)
    print("FINAL COMPARISON SUMMARY")
    print("="*50)
    print(f"BASIC: {results['basic']['pass']}/{len(challenges)} PASS | Total Attempts: {results['basic']['steps']}")
    print(f"REACT: {results['react']['pass']}/{len(challenges)} PASS | Total Steps:    {results['react']['steps']}")
    
    improvement = ((results['react']['pass'] - results['basic']['pass']) / len(challenges)) * 100
    print(f"\nIMPACT: {improvement:+.1f}% improvement in success rate.")
    
    if results['react']['pass'] >= results['basic']['pass']:
        print("CONCLUSION: ReAct is EFFECTIVE at improving task success through reasoning.")
    else:
        print("CONCLUSION: ReAct needs more tuning for this model size.")
    print("="*50)

if __name__ == "__main__":
    main()
