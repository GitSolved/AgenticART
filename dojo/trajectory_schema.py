"""
Agentic Trajectory Schema for AgenticART.

This module defines rich trajectory data structures that capture the full
reasoning process of an LLM agent, not just input/output pairs.

A trajectory is a sequence of Steps, where each Step contains:
- Thought: The agent's reasoning before acting
- Action: The tool/command chosen and its parameters
- Observation: The result of executing the action
- Reflection: Post-hoc analysis of what happened

This enables training models that learn HOW to reason about security tasks,
not just WHAT command to output.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class ActionType(Enum):
    """Types of actions the agent can take."""
    ADB_SHELL = "adb_shell"
    ADB_COMMAND = "adb_command"  # Non-shell ADB (push, pull, install)
    FRIDA_SCRIPT = "frida_script"
    NATIVE_EXPLOIT = "native_exploit"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    REASONING = "reasoning"  # Pure reasoning step, no execution
    GIVE_UP = "give_up"  # Agent decides task is not possible


class StepOutcome(Enum):
    """Outcome of a step's action."""
    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"  # Partial success (e.g., got output but not expected)
    ERROR = "error"  # Execution error (crash, timeout)
    SKIPPED = "skipped"  # Action was planned but not executed


class ReasoningType(Enum):
    """Types of reasoning captured in thoughts."""
    GOAL_DECOMPOSITION = "goal_decomposition"  # Breaking down the objective
    TOOL_SELECTION = "tool_selection"  # Choosing which tool to use
    PARAMETER_PLANNING = "parameter_planning"  # Figuring out arguments
    ERROR_ANALYSIS = "error_analysis"  # Analyzing why something failed
    STRATEGY_PIVOT = "strategy_pivot"  # Changing approach
    HYPOTHESIS = "hypothesis"  # Forming a theory to test
    VERIFICATION = "verification"  # Checking if goal is met


@dataclass
class Thought:
    """
    Represents the agent's reasoning before or after an action.

    This is the key missing piece in current training data.
    """
    content: str  # The actual reasoning text
    reasoning_type: ReasoningType
    confidence: float = 0.0  # 0-1, how confident the agent is
    alternatives_considered: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": self.content,
            "reasoning_type": self.reasoning_type.value,
            "confidence": self.confidence,
            "alternatives_considered": self.alternatives_considered,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class Action:
    """
    Represents a concrete action taken by the agent.
    """
    action_type: ActionType
    tool_name: str  # e.g., "adb", "frida", "gcc"
    command: str  # The actual command/script
    parameters: Dict[str, Any] = field(default_factory=dict)
    rationale: str = ""  # Why this action was chosen
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_type": self.action_type.value,
            "tool_name": self.tool_name,
            "command": self.command,
            "parameters": self.parameters,
            "rationale": self.rationale,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class Observation:
    """
    Represents the result of executing an action.
    """
    stdout: str
    stderr: str
    exit_code: int
    execution_time_ms: float
    outcome: StepOutcome
    error_type: Optional[str] = None  # e.g., "permission_denied", "timeout"
    extracted_data: Dict[str, Any] = field(default_factory=dict)  # Parsed info
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "execution_time_ms": self.execution_time_ms,
            "outcome": self.outcome.value,
            "error_type": self.error_type,
            "extracted_data": self.extracted_data,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class Reflection:
    """
    Post-action reasoning about what happened and what to do next.
    """
    what_happened: str  # Summary of the observation
    goal_progress: str  # How this moves toward the goal
    next_step_reasoning: str  # Why the next action makes sense
    lessons_learned: List[str] = field(default_factory=list)
    should_continue: bool = True
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "what_happened": self.what_happened,
            "goal_progress": self.goal_progress,
            "next_step_reasoning": self.next_step_reasoning,
            "lessons_learned": self.lessons_learned,
            "should_continue": self.should_continue,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class Step:
    """
    A single step in an agentic trajectory.

    Each step follows the ReAct pattern:
    Thought → Action → Observation → Reflection
    """
    step_number: int
    thought: Thought
    action: Action
    observation: Optional[Observation] = None  # None if not yet executed
    reflection: Optional[Reflection] = None  # None if not yet reflected
    step_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "step_number": self.step_number,
            "thought": self.thought.to_dict(),
            "action": self.action.to_dict(),
            "observation": self.observation.to_dict() if self.observation else None,
            "reflection": self.reflection.to_dict() if self.reflection else None,
        }


@dataclass
class Trajectory:
    """
    A complete agentic trajectory for a single challenge.

    This is the rich training data format that captures reasoning,
    not just instruction → output.
    """
    trajectory_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    challenge_id: str = ""
    challenge_name: str = ""
    belt: str = ""

    # The objective and context
    objective: str = ""
    device_context: Dict[str, Any] = field(default_factory=dict)
    hints: List[str] = field(default_factory=list)

    # Initial planning
    initial_thought: Optional[Thought] = None
    planned_approach: str = ""

    # The sequence of steps
    steps: List[Step] = field(default_factory=list)

    # Final outcome
    final_outcome: StepOutcome = StepOutcome.FAILURE
    final_reflection: Optional[Reflection] = None
    total_attempts: int = 0
    total_time_ms: float = 0.0

    # Metadata
    model_id: str = ""
    teacher_model_id: Optional[str] = None  # If distillation
    timestamp_start: datetime = field(default_factory=datetime.now)
    timestamp_end: Optional[datetime] = None

    def add_step(self, step: Step) -> None:
        """Add a step to the trajectory."""
        self.steps.append(step)
        self.total_attempts = len(self.steps)

    def complete(
        self,
        outcome: StepOutcome,
        final_reflection: Optional[Reflection] = None
    ) -> None:
        """Mark the trajectory as complete."""
        self.final_outcome = outcome
        self.final_reflection = final_reflection
        self.timestamp_end = datetime.now()
        if self.timestamp_start:
            delta = self.timestamp_end - self.timestamp_start
            self.total_time_ms = delta.total_seconds() * 1000

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "trajectory_id": self.trajectory_id,
            "challenge_id": self.challenge_id,
            "challenge_name": self.challenge_name,
            "belt": self.belt,
            "objective": self.objective,
            "device_context": self.device_context,
            "hints": self.hints,
            "initial_thought": self.initial_thought.to_dict() if self.initial_thought else None,
            "planned_approach": self.planned_approach,
            "steps": [s.to_dict() for s in self.steps],
            "final_outcome": self.final_outcome.value,
            "final_reflection": self.final_reflection.to_dict() if self.final_reflection else None,
            "total_attempts": self.total_attempts,
            "total_time_ms": self.total_time_ms,
            "model_id": self.model_id,
            "teacher_model_id": self.teacher_model_id,
            "timestamp_start": self.timestamp_start.isoformat(),
            "timestamp_end": self.timestamp_end.isoformat() if self.timestamp_end else None,
        }

    def to_training_format(self) -> Dict[str, Any]:
        """
        Convert to a format suitable for training.

        This creates a rich prompt/completion pair that includes
        the full reasoning trace.
        """
        # Build the full reasoning trace as the "prompt"
        trace_parts = []

        trace_parts.append(f"## Objective\n{self.objective}")
        trace_parts.append(f"## Context\n{self.device_context}")

        if self.hints:
            trace_parts.append("## Hints\n" + "\n".join(f"- {h}" for h in self.hints))

        if self.initial_thought:
            trace_parts.append(f"## Initial Analysis\n{self.initial_thought.content}")

        for step in self.steps:
            trace_parts.append(f"\n### Step {step.step_number}")
            trace_parts.append(f"**Thought:** {step.thought.content}")
            trace_parts.append(f"**Action:** `{step.action.command}`")
            if step.observation:
                trace_parts.append(f"**Observation:** {step.observation.stdout[:500]}")
            if step.reflection:
                trace_parts.append(f"**Reflection:** {step.reflection.what_happened}")

        return {
            "trajectory_id": self.trajectory_id,
            "challenge_id": self.challenge_id,
            "belt": self.belt,
            "objective": self.objective,
            "reasoning_trace": "\n\n".join(trace_parts),
            "steps": [s.to_dict() for s in self.steps],
            "final_outcome": self.final_outcome.value,
            "total_attempts": self.total_attempts,
            "model_id": self.model_id,
        }
