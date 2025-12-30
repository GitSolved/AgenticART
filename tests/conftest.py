"""Pytest fixtures for AgenticART tests."""

from __future__ import annotations

import pytest

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


@pytest.fixture
def successful_trajectory() -> Trajectory:
    """Create a successful trajectory for testing."""
    traj = Trajectory(
        challenge_id="white_001",
        challenge_name="Get Android Version",
        belt="white",
        objective="Retrieve the Android version using ADB",
        device_context={"android_version": "11", "device_id": "emulator-5554"},
        hints=["Use getprop command"],
        model_id="test-model",
    )

    # Add a successful step
    step = Step(
        step_number=1,
        thought=Thought(
            content="I'll use getprop to get the Android version",
            reasoning_type=ReasoningType.TOOL_SELECTION,
            confidence=0.8,
        ),
        action=Action(
            action_type=ActionType.ADB_SHELL,
            tool_name="adb",
            command="shell getprop ro.build.version.release",
        ),
        observation=Observation(
            stdout="11",
            stderr="",
            exit_code=0,
            execution_time_ms=100.0,
            outcome=StepOutcome.SUCCESS,
        ),
        reflection=Reflection(
            what_happened="Got Android version 11",
            goal_progress="Complete",
            next_step_reasoning="Task complete, no next step needed",
        ),
    )
    traj.add_step(step)
    traj.complete(
        StepOutcome.SUCCESS,
        Reflection(
            what_happened="Task completed",
            goal_progress="100%",
            next_step_reasoning="N/A",
        ),
    )

    return traj


@pytest.fixture
def failed_trajectory_short() -> Trajectory:
    """Create a short failed trajectory (low quality)."""
    traj = Trajectory(
        challenge_id="white_002",
        challenge_name="List Packages",
        belt="white",
        objective="List all installed packages",
        device_context={},
        hints=[],
        model_id="test-model",
    )

    # Only one step - too short
    step = Step(
        step_number=1,
        thought=Thought(
            content="I'll try pm list",
            reasoning_type=ReasoningType.TOOL_SELECTION,
        ),
        action=Action(
            action_type=ActionType.ADB_SHELL,
            tool_name="adb",
            command="shell pm list packages",
        ),
        observation=Observation(
            stdout="",
            stderr="Permission denied",
            exit_code=1,
            execution_time_ms=50.0,
            outcome=StepOutcome.FAILURE,
        ),
    )
    traj.add_step(step)
    traj.complete(StepOutcome.FAILURE)

    return traj


@pytest.fixture
def failed_trajectory_retry_loop() -> Trajectory:
    """Create a trajectory with retry loops (low quality)."""
    traj = Trajectory(
        challenge_id="yellow_001",
        challenge_name="Access Protected File",
        belt="yellow",
        objective="Read a protected file",
        device_context={},
        hints=[],
        model_id="test-model",
    )

    # Same command repeated 3 times - retry loop
    for i in range(3):
        step = Step(
            step_number=i + 1,
            thought=Thought(
                content="I'll try reading the file",
                reasoning_type=ReasoningType.TOOL_SELECTION,
            ),
            action=Action(
                action_type=ActionType.ADB_SHELL,
                tool_name="adb",
                command="shell cat /data/secret.txt",  # Same command each time
            ),
            observation=Observation(
                stdout="",
                stderr="Permission denied",
                exit_code=1,
                execution_time_ms=50.0,
                outcome=StepOutcome.FAILURE,
            ),
        )
        traj.add_step(step)

    traj.complete(StepOutcome.FAILURE)
    return traj


@pytest.fixture
def failed_trajectory_with_pivot() -> Trajectory:
    """Create a failed trajectory with strategy pivot (high quality)."""
    traj = Trajectory(
        challenge_id="yellow_002",
        challenge_name="Find Sensitive Data",
        belt="yellow",
        objective="Find sensitive data in app storage",
        device_context={},
        hints=[],
        model_id="test-model",
    )

    # Step 1: Initial attempt fails
    step1 = Step(
        step_number=1,
        thought=Thought(
            content="I'll try to read the database directly",
            reasoning_type=ReasoningType.TOOL_SELECTION,
        ),
        action=Action(
            action_type=ActionType.ADB_SHELL,
            tool_name="adb",
            command="shell cat /data/data/com.app/databases/data.db",
        ),
        observation=Observation(
            stdout="",
            stderr="Permission denied",
            exit_code=1,
            execution_time_ms=50.0,
            outcome=StepOutcome.FAILURE,
        ),
    )
    traj.add_step(step1)

    # Step 2: Strategy pivot - try different approach
    step2 = Step(
        step_number=2,
        thought=Thought(
            content="Permission denied. I'll try a different approach using run-as",
            reasoning_type=ReasoningType.STRATEGY_PIVOT,
        ),
        action=Action(
            action_type=ActionType.ADB_SHELL,
            tool_name="adb",
            command="shell run-as com.app cat databases/data.db",
        ),
        observation=Observation(
            stdout="",
            stderr="Package not debuggable",
            exit_code=1,
            execution_time_ms=50.0,
            outcome=StepOutcome.FAILURE,
        ),
    )
    traj.add_step(step2)

    # Step 3: Another pivot - try backup
    step3 = Step(
        step_number=3,
        thought=Thought(
            content="run-as failed. Let me try backup extraction instead",
            reasoning_type=ReasoningType.STRATEGY_PIVOT,
        ),
        action=Action(
            action_type=ActionType.ADB_COMMAND,
            tool_name="adb",
            command="backup -apk com.app",
        ),
        observation=Observation(
            stdout="",
            stderr="Backup not allowed",
            exit_code=1,
            execution_time_ms=50.0,
            outcome=StepOutcome.FAILURE,
        ),
    )
    traj.add_step(step3)

    # Step 4: Give up after exhausting options
    step4 = Step(
        step_number=4,
        thought=Thought(
            content="Exhausted options. App is well-protected.",
            reasoning_type=ReasoningType.ERROR_ANALYSIS,
        ),
        action=Action(
            action_type=ActionType.GIVE_UP,
            tool_name="stop",
            command="[GIVE_UP]",
        ),
    )
    traj.add_step(step4)

    traj.complete(StepOutcome.FAILURE)
    return traj


@pytest.fixture
def failed_trajectory_low_diversity() -> Trajectory:
    """Create a failed trajectory with low action diversity (low quality)."""
    traj = Trajectory(
        challenge_id="orange_001",
        challenge_name="Extract APK",
        belt="orange",
        objective="Extract and decompile APK",
        device_context={},
        hints=[],
        model_id="test-model",
    )

    # 5 steps but only 2 unique commands - low diversity
    commands = [
        "shell pm path com.app",
        "shell pm path com.app",
        "pull /data/app/com.app/base.apk",
        "shell pm path com.app",
        "pull /data/app/com.app/base.apk",
    ]

    for i, cmd in enumerate(commands):
        step = Step(
            step_number=i + 1,
            thought=Thought(
                content=f"Trying command {i+1}",
                reasoning_type=ReasoningType.TOOL_SELECTION,
            ),
            action=Action(
                action_type=ActionType.ADB_SHELL,
                tool_name="adb",
                command=cmd,
            ),
            observation=Observation(
                stdout="",
                stderr="Failed",
                exit_code=1,
                execution_time_ms=50.0,
                outcome=StepOutcome.FAILURE,
            ),
        )
        traj.add_step(step)

    traj.complete(StepOutcome.FAILURE)
    return traj
