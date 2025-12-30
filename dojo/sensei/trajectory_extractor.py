"""
Trajectory Extractor - converts rich JSON trajectories into multi-turn training data.

This component extracts the Thought -> Action -> Observation -> Reflection chains
into formats like ShareGPT, enabling models to learn the ReAct process.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from dojo.trajectory_schema import StepOutcome


class TrajectoryExtractor:
    """Extracts training data from Trajectory JSON files."""

    def __init__(self, trajectories_dir: Path):
        self.trajectories_dir = trajectories_dir

    def extract_all(self, min_outcome: StepOutcome = StepOutcome.SUCCESS) -> List[Dict[str, Any]]:
        """
        Extract all trajectories that meet the minimum outcome requirement.

        Returns a list of ShareGPT-formatted conversations.
        """
        results = []
        for file_path in self.trajectories_dir.glob("*.json"):
            try:
                with open(file_path, "r") as f:
                    data = json.load(f)

                # Check outcome
                # Heuristic: if it's marked success OR if the last step achieved the goal
                marked_success = data.get("final_outcome") == min_outcome.value
                goal_achieved = False
                if data.get("steps"):
                    last_step = data["steps"][-1]
                    progress = last_step.get("reflection", {}).get("goal_progress", "")
                    if progress and "Goal achieved" in progress:
                        goal_achieved = True

                if not (marked_success or goal_achieved):
                    continue

                # Filter out infrastructure errors
                has_infra_error = False
                for step in data.get("steps", []):
                    obs = step.get("observation", {})
                    obs_text = (obs.get("stdout", "") or "") + (obs.get("stderr", "") or "")
                    if (
                        "Executor.execute()" in obs_text
                        or "missing 1 required positional argument" in obs_text
                    ):
                        has_infra_error = True
                        break

                if has_infra_error:
                    continue

                sharegpt = self.to_sharegpt(data)
                results.append(sharegpt)
            except Exception as e:
                print(f"Error processing {file_path}: {e}")
                continue

        return results

    def to_sharegpt(self, traj_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a trajectory to ShareGPT format.

        System: ReAct Instructions
        User: Objective + Context
        Assistant: THOUGHT + ACTION
        User: OBSERVATION
        ...
        """
        messages = []

        # 1. System Prompt (The ReAct Rules)
        from dojo.react_challenger import REACT_SYSTEM_PROMPT

        messages.append({"from": "system", "value": REACT_SYSTEM_PROMPT})

        # 2. Initial User Prompt (Objective + Context)
        # We re-construct the prompt used during the run
        parts = [f"## Objective\n{traj_data.get('objective', '')}"]

        ctx = traj_data.get("device_context", {})
        ctx_lines = [
            "- connection: adb",
            f"- device_id: {ctx.get('device_id', 'unknown')}",
            f"- android_version: {ctx.get('android_version', 'unknown')}",
            f"- task: {traj_data.get('challenge_name', 'Security Task')}",
        ]
        parts.append("## Device Context\n" + "\n".join(ctx_lines))

        hints = traj_data.get("hints", [])
        if hints:
            parts.append("## Hints\n" + "\n".join(f"- {h}" for h in hints))

        parts.append("\nBegin by analyzing the task and stating your first action.")

        messages.append({"from": "human", "value": "\n\n".join(parts)})

        # 3. Step Loop
        for step in traj_data.get("steps", []):
            thought = step.get("thought", {}).get("content", "")
            action = step.get("action", {}).get("command", "")

            # Assistant response
            assistant_val = f"THOUGHT: {thought}\nACTION: {action}"
            messages.append({"from": "assistant", "value": assistant_val})

            # System response (Observation)
            obs = step.get("observation", {})
            stdout = obs.get("stdout", "")
            stderr = obs.get("stderr", "")
            exit_code = obs.get("exit_code", -1)

            error_info = ""
            if obs.get("error_type"):
                error_info = f"Error Type: {obs['error_type']}"

            observation_val = f"OBSERVATION:\n```\n{stdout or stderr}\n```\nExit Code: {exit_code}\n{error_info}\n\nContinue with your analysis and next action."

            messages.append({"from": "human", "value": observation_val})

        # Cleanup: Remove the last human observation if it's just a prompt for next step
        if messages and messages[-1]["from"] == "human" and "OBSERVATION:" in messages[-1]["value"]:
            # Check if the trajectory ended with [DONE]
            last_assistant = messages[-2]["value"] if len(messages) >= 2 else ""
            if "DONE" in last_assistant.upper():
                messages.pop()  # Remove the trailing observation request

        return {"id": traj_data.get("trajectory_id"), "conversations": messages}


if __name__ == "__main__":
    # Test script
    import sys

    proj_root = Path(__file__).parent.parent.parent

    # Check multiple locations
    search_dirs = [
        proj_root / "dojo_output" / "trajectories",
        Path("/Users/QH37/dojo_output/trajectories"),
        proj_root / "dojo_output" / "comparison_trajectories",
    ]

    multi_turn_data = []
    for traj_dir in search_dirs:
        if not traj_dir.exists():
            continue
        print(f"Checking {traj_dir}...")
        extractor = TrajectoryExtractor(traj_dir)
        multi_turn_data.extend(extractor.extract_all(min_outcome=StepOutcome.SUCCESS))

    print(f"Extracted {len(multi_turn_data)} successful trajectories.")
    if multi_turn_data:
        # Sample
        # print("\nSample Conversation:")
        # print(json.dumps(multi_turn_data[0], indent=2))

        output_file = (
            proj_root / "dojo_output" / "training_data" / "react_trajectories_sharegpt.jsonl"
        )
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w") as f:
            for item in multi_turn_data:
                f.write(json.dumps(item) + "\n")
        print(f"\nSaved to {output_file}")
