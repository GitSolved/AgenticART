#!/usr/bin/env python3
"""
Example: Running the ReAct Challenger with Trajectory Logging.

This demonstrates how to use the new agentic trajectory system
to capture rich reasoning traces for training data.

Usage:
    python -m dojo.examples.run_react_challenger --mode mock
    python -m dojo.examples.run_react_challenger --mode live --model ollama/llama3
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from dojo import Belt, ChallengeLoader
from dojo.curriculum import Executor
from dojo.react_challenger import ReActChallenger
from dojo.trajectory_logger import TrajectoryLogger


class MockReActLLM:
    """Mock LLM that returns ReAct-formatted responses for testing."""

    RESPONSES = {
        "white_001": [
            """THOUGHT: I need to get the Android version. The hints suggest using getprop to read system properties, specifically ro.build.version.release.

ACTION: shell getprop ro.build.version.release""",
            """THOUGHT: The command returned "11" which is the Android version in the expected format. The task is complete.

ACTION: [DONE]""",
        ],
        "white_002": [
            """THOUGHT: I need to list all installed packages. The hints mention using the package manager (pm) command. The pm list packages command should enumerate all applications.

ACTION: shell pm list packages""",
            """THOUGHT: The command successfully listed all packages. Each line shows a package in the format "package:com.example.app". The task is complete.

ACTION: [DONE]""",
        ],
    }

    def __init__(self):
        self.call_counts: dict[str, int] = {}
        self.current_challenge: str = ""

    def set_challenge(self, challenge_id: str):
        self.current_challenge = challenge_id
        self.call_counts[challenge_id] = 0

    def generate(self, prompt: str, system_prompt: str | None = None) -> str:
        cid = self.current_challenge
        if cid not in self.RESPONSES:
            return """THOUGHT: I'm not sure how to handle this task.

ACTION: [GIVE_UP]"""

        idx = self.call_counts.get(cid, 0)
        responses = self.RESPONSES[cid]

        if idx >= len(responses):
            return """THOUGHT: Task appears complete.

ACTION: [DONE]"""

        self.call_counts[cid] = idx + 1
        return responses[idx]


def run_example(mode: str = "mock", model: str = ""):
    """Run the ReAct challenger example."""

    print("=" * 60)
    print("ReAct Challenger with Trajectory Logging")
    print("=" * 60)

    # Setup
    output_dir = Path("trajectories/")
    output_dir.mkdir(exist_ok=True)

    trajectory_logger = TrajectoryLogger(
        output_dir=str(output_dir),
        auto_save=True,
    )

    # Create executor (mock for demo)
    executor = Executor(device_id="emulator-5554")

    # Create LLM client
    if mode == "mock":
        llm = MockReActLLM()
        print("Using: Mock LLM")
    else:
        # Would use real LLM here
        from dojo.test_end_to_end import OllamaLLMClient
        llm = OllamaLLMClient(model=model)
        print(f"Using: {model}")

    # Create challenger
    def on_step(step_num, parsed, result):
        status = "✓" if result.get("exit_code", -1) == 0 else "✗"
        print(f"  Step {step_num}: {status} {parsed.action[:50]}...")

    challenger = ReActChallenger(
        llm_client=llm,
        executor=executor,
        trajectory_logger=trajectory_logger,
        max_steps=5,
        on_step=on_step,
    )

    # Load challenges
    loader = ChallengeLoader()
    challenges = loader.load_belt(Belt.WHITE)[:2]  # Just first 2 for demo

    print(f"\nLoaded {len(challenges)} challenges")
    print("-" * 60)

    # Run challenges
    for challenge in challenges:
        print(f"\nChallenge: {challenge.id} - {challenge.name}")

        if mode == "mock":
            llm.set_challenge(challenge.id)

        session = challenger.run_challenge(
            challenge=challenge,
            model_id="mock-react-llm" if mode == "mock" else model,
        )

        status = "PASS" if session.final_success else "FAIL"
        print(f"  Result: {status}")

    # Show statistics
    print("\n" + "=" * 60)
    print("Trajectory Statistics")
    print("=" * 60)

    stats = trajectory_logger.get_statistics()
    print(f"Total trajectories: {stats['count']}")
    print(f"Success rate: {stats.get('success_rate', 0) * 100:.1f}%")
    print(f"Total steps: {stats.get('total_steps', 0)}")
    print(f"Avg steps/trajectory: {stats.get('avg_steps_per_trajectory', 0):.1f}")

    # Export training data
    training_file = trajectory_logger.export_training_data()
    print(f"\nTraining data exported to: {training_file}")

    # Show sample trajectory
    print("\n" + "=" * 60)
    print("Sample Trajectory (Pretty Printed)")
    print("=" * 60)

    sample_files = list(output_dir.glob("traj_*.json"))
    if sample_files:
        with open(sample_files[0]) as f:
            sample = json.load(f)

        print(f"\nChallenge: {sample['challenge_id']}")
        print(f"Objective: {sample['objective'][:100]}...")
        print(f"Outcome: {sample['final_outcome']}")

        if sample.get('initial_thought'):
            print(f"\nInitial Thought:")
            print(f"  {sample['initial_thought']['content'][:200]}...")

        for step in sample.get('steps', [])[:2]:
            print(f"\nStep {step['step_number']}:")
            print(f"  Thought: {step['thought']['content'][:100]}...")
            print(f"  Action: {step['action']['command']}")
            if step.get('observation'):
                print(f"  Outcome: {step['observation']['outcome']}")
            if step.get('reflection'):
                print(f"  Reflection: {step['reflection']['what_happened'][:100]}...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["mock", "live"], default="mock")
    parser.add_argument("--model", default="llama3")
    args = parser.parse_args()

    run_example(mode=args.mode, model=args.model)
