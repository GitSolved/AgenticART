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
        hypothesis: Optional[str] = None,
        confidence: float = 0.7,
        alternatives: Optional[List[str]] = None,
    ) -> "StepBuilder":
        """Record the agent's thought before acting."""
        self._thought = Thought(
            content=content,
            reasoning_type=reasoning_type,
            hypothesis=hypothesis,
            confidence=confidence,
            alternatives_considered=alternatives or [],
        )
        return self

    def act(
        self,
        action_type: str,
        command: str,
        rationale: str = "",
        tool_choice: Optional[str] = None,
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
            tool_choice=tool_choice,
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
        state_transition: Optional[str] = None,
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
            state_transition=state_transition,
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

    def add_exploit_step(self, command: str) -> "TrajectoryBuilder":
        """Add a successful command to the exploit chain."""
        self._trajectory.exploit_chain.append(command)
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

    def is_high_quality(
        self,
        trajectory: Trajectory,
        min_action_diversity: float = 0.7,
        max_consecutive_failures: int = 2,
    ) -> bool:
        """
        Assess trajectory quality for training data.

        A high-quality trajectory either:
        1. Succeeds (positive example)
        2. Fails but shows diverse strategies (useful for learning pivots)
        3. Correctly gives up after exhausting options (teaches when to stop)

        Filters out:
        - Repetitive failure loops (same command retried)
        - Trajectories with no meaningful action diversity
        """
        # Always include successful trajectories
        if trajectory.final_outcome == StepOutcome.SUCCESS:
            return True

        # Empty or single-step failures are low quality
        if len(trajectory.steps) < 2:
            return False

        # Check action diversity (unique commands / total steps)
        commands = [s.action.command for s in trajectory.steps]
        unique_commands = len(set(commands))
        diversity_ratio = unique_commands / len(commands)

        if diversity_ratio < min_action_diversity:
            return False

        # Check for consecutive identical failures (retry loops)
        consecutive_same = 1
        for i in range(1, len(commands)):
            if commands[i] == commands[i - 1]:
                consecutive_same += 1
                if consecutive_same > max_consecutive_failures:
                    return False
            else:
                consecutive_same = 1

        # Check for strategy pivots (indicates learning from errors)
        has_pivot = any(
            s.thought.reasoning_type == ReasoningType.STRATEGY_PIVOT
            for s in trajectory.steps
            if s.thought
        )

        # Check for proper give-up (exhausted options, not just quit early)
        has_give_up = any(
            s.action.action_type == ActionType.GIVE_UP
            for s in trajectory.steps
        )

        # Include if shows strategy diversity or proper termination
        return has_pivot or has_give_up or diversity_ratio >= 0.8

    def get_high_quality_trajectories(
        self,
        min_action_diversity: float = 0.7,
        max_consecutive_failures: int = 2,
    ) -> List[Trajectory]:
        """Get only high-quality trajectories suitable for training."""
        return [
            t for t in self._trajectories
            if self.is_high_quality(t, min_action_diversity, max_consecutive_failures)
        ]

    def export_high_quality_training_data(
        self,
        filename: str = "training_trajectories_filtered.jsonl",
        min_action_diversity: float = 0.7,
        max_consecutive_failures: int = 2,
    ) -> Path:
        """Export only high-quality trajectories for training."""
        filepath = self.output_dir / filename
        high_quality = self.get_high_quality_trajectories(
            min_action_diversity, max_consecutive_failures
        )

        with open(filepath, "w") as f:
            for traj in high_quality:
                f.write(json.dumps(traj.to_training_format()) + "\n")

        # Log filtering stats
        total = len(self._trajectories)
        kept = len(high_quality)
        filtered = total - kept
        print(f"Trajectory quality filter: {kept}/{total} kept, {filtered} filtered out")

        return filepath

    def get_quality_statistics(self) -> Dict[str, Any]:
        """Get statistics about trajectory quality distribution."""
        if not self._trajectories:
            return {"count": 0}

        high_quality = self.get_high_quality_trajectories()
        low_quality = [t for t in self._trajectories if t not in high_quality]

        # Analyze why trajectories were filtered
        low_quality_reasons: Dict[str, int] = {
            "too_short": 0,
            "low_diversity": 0,
            "retry_loops": 0,
        }

        for t in low_quality:
            if len(t.steps) < 2:
                low_quality_reasons["too_short"] += 1
            else:
                commands = [s.action.command for s in t.steps]
                unique = len(set(commands))
                if unique / len(commands) < 0.7:
                    low_quality_reasons["low_diversity"] += 1
                else:
                    low_quality_reasons["retry_loops"] += 1

        return {
            "total": len(self._trajectories),
            "high_quality": len(high_quality),
            "low_quality": len(low_quality),
            "quality_rate": len(high_quality) / len(self._trajectories),
            "filter_reasons": low_quality_reasons,
        }
