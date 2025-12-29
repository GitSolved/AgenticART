"""
Trajectory Logger for AgenticART.

This module provides a logging layer that captures rich agentic trajectories
during live challenge runs. It integrates with the Challenger to record
thoughts, actions, observations, and reflections.

Usage:
    logger = TrajectoryLogger(output_dir="trajectories/")

    with logger.start_trajectory(challenge) as traj:
        # Initial planning
        traj.log_initial_thought("I need to query the Android version...")

        # Step 1
        with traj.step() as step:
            step.think("I'll use getprop to read system properties")
            step.act("adb_shell", "shell getprop ro.build.version.release")
            # After execution:
            step.observe(stdout="11", stderr="", exit_code=0)
            step.reflect("Got Android 11, goal achieved")
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

from dojo.trajectory_schema import (
    Action,
    ActionType,
    Observation,
    ReasoningType,
    Reflection,
    Step,
    StepOutcome,
    Thought,
    Trajectory,
)


class StepBuilder:
    """
    Builder for constructing a Step with fluent API.

    Used within a trajectory context to build steps incrementally.
    """

    def __init__(self, step_number: int):
        self.step_number = step_number
        self._thought: Optional[Thought] = None
        self._action: Optional[Action] = None
        self._observation: Optional[Observation] = None
        self._reflection: Optional[Reflection] = None

    def think(
        self,
        content: str,
        reasoning_type: ReasoningType = ReasoningType.TOOL_SELECTION,
        confidence: float = 0.7,
        alternatives: Optional[List[str]] = None,
    ) -> "StepBuilder":
        """Record the agent's thought before acting."""
        self._thought = Thought(
            content=content,
            reasoning_type=reasoning_type,
            confidence=confidence,
            alternatives_considered=alternatives or [],
        )
        return self

    def act(
        self,
        action_type: str,
        command: str,
        rationale: str = "",
        parameters: Optional[Dict[str, Any]] = None,
    ) -> "StepBuilder":
        """Record the action taken."""
        # Parse action type
        try:
            atype = ActionType(action_type)
        except ValueError:
            atype = ActionType.ADB_SHELL  # Default

        # Infer tool name from action type
        tool_map = {
            ActionType.ADB_SHELL: "adb",
            ActionType.ADB_COMMAND: "adb",
            ActionType.FRIDA_SCRIPT: "frida",
            ActionType.NATIVE_EXPLOIT: "gcc/ndk",
            ActionType.FILE_READ: "cat",
            ActionType.FILE_WRITE: "echo",
            ActionType.REASONING: "think",
            ActionType.GIVE_UP: "stop",
        }

        self._action = Action(
            action_type=atype,
            tool_name=tool_map.get(atype, "unknown"),
            command=command,
            parameters=parameters or {},
            rationale=rationale,
        )
        return self

    def observe(
        self,
        stdout: str,
        stderr: str = "",
        exit_code: int = 0,
        execution_time_ms: float = 0.0,
        outcome: Optional[StepOutcome] = None,
        error_type: Optional[str] = None,
        extracted_data: Optional[Dict[str, Any]] = None,
    ) -> "StepBuilder":
        """Record the observation after executing the action."""
        # Infer outcome if not provided
        if outcome is None:
            if exit_code == 0 and not error_type:
                outcome = StepOutcome.SUCCESS
            elif error_type:
                outcome = StepOutcome.ERROR
            else:
                outcome = StepOutcome.FAILURE

        self._observation = Observation(
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            execution_time_ms=execution_time_ms,
            outcome=outcome,
            error_type=error_type,
            extracted_data=extracted_data or {},
        )
        return self

    def reflect(
        self,
        what_happened: str,
        goal_progress: str = "",
        next_step_reasoning: str = "",
        lessons: Optional[List[str]] = None,
        should_continue: bool = True,
    ) -> "StepBuilder":
        """Record reflection after observing the result."""
        self._reflection = Reflection(
            what_happened=what_happened,
            goal_progress=goal_progress,
            next_step_reasoning=next_step_reasoning,
            lessons_learned=lessons or [],
            should_continue=should_continue,
        )
        return self

    def build(self) -> Step:
        """Build the final Step object."""
        if not self._thought:
            self._thought = Thought(
                content="(no thought recorded)",
                reasoning_type=ReasoningType.TOOL_SELECTION,
            )
        if not self._action:
            self._action = Action(
                action_type=ActionType.REASONING,
                tool_name="unknown",
                command="(no action recorded)",
            )

        return Step(
            step_number=self.step_number,
            thought=self._thought,
            action=self._action,
            observation=self._observation,
            reflection=self._reflection,
        )


class TrajectoryBuilder:
    """
    Builder for constructing a Trajectory during a live run.

    Provides a fluent API for logging the full reasoning process.
    """

    def __init__(
        self,
        challenge_id: str,
        challenge_name: str,
        belt: str,
        objective: str,
        device_context: Dict[str, Any],
        hints: List[str],
        model_id: str = "",
    ):
        self._trajectory = Trajectory(
            challenge_id=challenge_id,
            challenge_name=challenge_name,
            belt=belt,
            objective=objective,
            device_context=device_context,
            hints=hints,
            model_id=model_id,
        )
        self._current_step_number = 0
        self._current_step: Optional[StepBuilder] = None

    def log_initial_thought(
        self,
        content: str,
        reasoning_type: ReasoningType = ReasoningType.GOAL_DECOMPOSITION,
        planned_approach: str = "",
    ) -> "TrajectoryBuilder":
        """Log the initial analysis before any actions."""
        self._trajectory.initial_thought = Thought(
            content=content,
            reasoning_type=reasoning_type,
        )
        self._trajectory.planned_approach = planned_approach
        return self

    @contextmanager
    def step(self) -> Generator[StepBuilder, None, None]:
        """
        Context manager for logging a single step.

        Usage:
            with traj.step() as step:
                step.think("I need to...")
                step.act("adb_shell", "shell getprop ...")
                step.observe(stdout="11", exit_code=0)
                step.reflect("Got the version")
        """
        self._current_step_number += 1
        builder = StepBuilder(self._current_step_number)
        self._current_step = builder

        yield builder

        # On exit, build and add the step
        step = builder.build()
        self._trajectory.add_step(step)
        self._current_step = None

    def add_step_direct(self, step: Step) -> "TrajectoryBuilder":
        """Add a pre-built step directly."""
        self._trajectory.add_step(step)
        return self

    def complete(
        self,
        outcome: StepOutcome,
        final_reflection: Optional[str] = None,
    ) -> Trajectory:
        """Mark the trajectory as complete and return it."""
        reflection = None
        if final_reflection:
            reflection = Reflection(
                what_happened=final_reflection,
                goal_progress="Complete" if outcome == StepOutcome.SUCCESS else "Failed",
                next_step_reasoning="N/A - trajectory complete",
            )

        self._trajectory.complete(outcome, reflection)
        return self._trajectory

    @property
    def trajectory(self) -> Trajectory:
        """Get the current trajectory (even if incomplete)."""
        return self._trajectory


class TrajectoryLogger:
    """
    Main logger class for capturing agentic trajectories.

    Manages trajectory lifecycle and persistence.
    """

    def __init__(
        self,
        output_dir: str = "trajectories/",
        auto_save: bool = True,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.auto_save = auto_save
        self._trajectories: List[Trajectory] = []
        self._current: Optional[TrajectoryBuilder] = None

    @contextmanager
    def start_trajectory(
        self,
        challenge_id: str,
        challenge_name: str,
        belt: str,
        objective: str,
        device_context: Optional[Dict[str, Any]] = None,
        hints: Optional[List[str]] = None,
        model_id: str = "",
    ) -> Generator[TrajectoryBuilder, None, None]:
        """
        Start logging a new trajectory.

        Usage:
            with logger.start_trajectory(challenge) as traj:
                traj.log_initial_thought("...")
                with traj.step() as step:
                    step.think("...")
                    step.act("...")
        """
        builder = TrajectoryBuilder(
            challenge_id=challenge_id,
            challenge_name=challenge_name,
            belt=belt,
            objective=objective,
            device_context=device_context or {},
            hints=hints or [],
            model_id=model_id,
        )
        self._current = builder

        try:
            yield builder
        finally:
            # Save on exit if auto_save enabled
            trajectory = builder.trajectory
            self._trajectories.append(trajectory)

            if self.auto_save:
                self._save_trajectory(trajectory)

            self._current = None

    def _save_trajectory(self, trajectory: Trajectory) -> Path:
        """Save a single trajectory to disk."""
        filename = f"traj_{trajectory.challenge_id}_{trajectory.trajectory_id[:8]}.json"
        filepath = self.output_dir / filename

        with open(filepath, "w") as f:
            json.dump(trajectory.to_dict(), f, indent=2)

        return filepath

    def save_all(self, filename: str = "all_trajectories.jsonl") -> Path:
        """Save all trajectories to a JSONL file."""
        filepath = self.output_dir / filename

        with open(filepath, "w") as f:
            for traj in self._trajectories:
                f.write(json.dumps(traj.to_dict()) + "\n")

        return filepath

    def export_training_data(self, filename: str = "training_trajectories.jsonl") -> Path:
        """Export trajectories in training-ready format."""
        filepath = self.output_dir / filename

        with open(filepath, "w") as f:
            for traj in self._trajectories:
                f.write(json.dumps(traj.to_training_format()) + "\n")

        return filepath

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about logged trajectories."""
        if not self._trajectories:
            return {"count": 0}

        success_count = sum(
            1 for t in self._trajectories
            if t.final_outcome == StepOutcome.SUCCESS
        )

        total_steps = sum(len(t.steps) for t in self._trajectories)

        return {
            "count": len(self._trajectories),
            "success_rate": success_count / len(self._trajectories),
            "total_steps": total_steps,
            "avg_steps_per_trajectory": total_steps / len(self._trajectories),
            "by_belt": self._count_by_belt(),
        }

    def _count_by_belt(self) -> Dict[str, int]:
        """Count trajectories by belt level."""
        counts: Dict[str, int] = {}
        for t in self._trajectories:
            counts[t.belt] = counts.get(t.belt, 0) + 1
        return counts
