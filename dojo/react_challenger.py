"""
ReAct-style Challenger for AgenticART.

This module implements a Challenger that uses ReAct (Reason + Act) prompting
to generate rich trajectories with explicit thoughts, actions, and observations.

The key difference from the basic Challenger:
1. Prompts the LLM for THOUGHT before each action
2. Captures the reasoning in structured format
3. Logs full trajectories for training data

ReAct Pattern:
    Hypothesis: The device is likely running an older Android version.
    Thought: I need to find the Android version to verify my hypothesis.
    Tool_Choice: 'getprop' is the standard tool for reading system properties.
    Action: shell getprop ro.build.version.release
    Observation: 11
    Thought: I got Android 11, which matches the expected format...
    Action: [DONE] or [NEXT_STEP]
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Protocol

from dojo.curriculum.challenger import AttemptRecord, ChallengeSession
from dojo.curriculum.executor import ExecutionResult
from dojo.models import Challenge
from dojo.trajectory_logger import TrajectoryLogger
from dojo.trajectory_schema import (
    ReasoningType,
    StepOutcome,
)

# ReAct prompt templates
REACT_SYSTEM_PROMPT = """You are a security research agent specializing in Android penetration testing.

Your goal is to autonomously solve the challenge. Do not ask for user permission.

For each step, you MUST follow the ReAct format:

HYPOTHESIS: [What do you expect this action to achieve?]
THOUGHT: [Your reasoning about the situation and plan]
TOOL_CHOICE: [Why are you choosing this specific tool?]
ACTION: [The exact command to execute]

After seeing the result, you will provide:
THOUGHT: [Your analysis of what happened. If failed, analyze why and propose a workaround.]
ACTION: [DONE] if the task is complete, or [CONTINUE] with next command

Rules:
- Always explain your reasoning in THOUGHT before acting
- ACTION must be a single executable command (no markdown, no explanation)
- If a command fails (e.g. Permission Denied), do NOT stop. Try a workaround (e.g. run-as, different path).
- Say ACTION: [DONE] when the objective is achieved
- Say ACTION: [GIVE_UP] if the task is impossible after multiple attempts

Available tools:
- ADB shell commands (shell <command>)
- ADB commands (push, pull, install, etc.)
- Frida scripts (for dynamic instrumentation)
"""

REACT_INITIAL_PROMPT = """## Objective
{objective}

## Device Context
{device_context}

## Hints
{hints}

---

Begin by analyzing the task and stating your first action.

HYPOTHESIS:"""

REACT_OBSERVATION_PROMPT = """
OBSERVATION:
```
{observation}
```
Exit Code: {exit_code}
{error_info}

Continue with your analysis and next action.

THOUGHT:"""


@dataclass
class ReActResponse:
    """Parsed response from ReAct-style LLM output."""
    thought: str
    action: str
    action_type: str  # "command", "done", "give_up", "continue"
    raw_response: str
    hypothesis: str = ""
    tool_choice: str = ""


class LLMClient(Protocol):
    """Protocol for LLM clients."""
    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        ...


class ReActChallenger:
    """
    A Challenger that uses ReAct prompting to generate rich trajectories.

    This captures the full reasoning process for training data.
    """

    def __init__(
        self,
        llm_client: LLMClient,
        executor: Any,  # Executor from curriculum
        trajectory_logger: TrajectoryLogger,
        max_steps: int = 5,
        on_step: Optional[Callable] = None,
    ):
        self.llm = llm_client
        self.executor = executor
        self.trajectory_logger = trajectory_logger
        self.max_steps = max_steps
        self.on_step = on_step

    def run_challenge(
        self,
        challenge: Challenge,
        model_id: str = "",
    ) -> ChallengeSession:
        """
        Run a challenge using ReAct prompting.

        Returns a ChallengeSession with the results.
        """
        # Format device context
        device_info = self.executor.get_device_info()
        device_context = self._format_device_context(challenge, device_info)
        hints = "\n".join(f"- {h}" for h in challenge.hints)

        # Start trajectory logging
        with self.trajectory_logger.start_trajectory(
            challenge_id=challenge.id,
            challenge_name=challenge.name,
            belt=challenge.belt.value,
            objective=challenge.description,
            device_context=device_info,
            hints=challenge.hints,
            model_id=model_id,
        ) as traj:

            # Initial prompt
            initial_prompt = REACT_INITIAL_PROMPT.format(
                objective=challenge.description,
                device_context=device_context,
                hints=hints,
            )

            # Get initial thought and action
            print(f"\n[DEBUG] Prompting ReAct model for {challenge.id}...")
            response = self.llm.generate(
                initial_prompt,
                system_prompt=REACT_SYSTEM_PROMPT,
            )
            
            # Since we forced "HYPOTHESIS:" in the prompt, some models won't repeat it.
            if not response.strip().upper().startswith("HYPOTHESIS:") and not response.strip().upper().startswith("THOUGHT:"):
                 response = "HYPOTHESIS: " + response

            print(f"[DEBUG] Raw response: {response[:100]}...")
            parsed = self._parse_react_response(response)
            print(f"[DEBUG] Parsed action: {parsed.action_type} - {parsed.action}")

            # Log initial thought
            traj.log_initial_thought(
                content=parsed.thought,
                reasoning_type=ReasoningType.GOAL_DECOMPOSITION,
                planned_approach=parsed.action if parsed.action_type == "command" else "",
            )

            # Execute steps
            conversation = initial_prompt + response
            final_success = False
            attempts = []

            for step_num in range(self.max_steps):
                if parsed.action_type == "done":
                    final_success = True
                    break
                elif parsed.action_type == "give_up":
                    break
                elif parsed.action_type != "command":
                    # Try to extract command anyway
                    if not parsed.action.strip():
                        break

                # Log step with thought and action
                with traj.step() as step:
                    # Record thought
                    step.think(
                        content=parsed.thought,
                        reasoning_type=self._infer_reasoning_type(parsed.thought),
                        hypothesis=parsed.hypothesis,
                        confidence=self._estimate_confidence(parsed.thought),
                    )

                    # Record action
                    action_type = self._infer_action_type(parsed.action)
                    step.act(
                        action_type=action_type,
                        command=parsed.action,
                        rationale=parsed.thought[:200],
                        tool_choice=parsed.tool_choice,
                    )

                    # Execute
                    result = self._execute_action(parsed.action, action_type, challenge)

                    # Record observation
                    step.observe(
                        stdout=result.get("stdout", ""),
                        stderr=result.get("stderr", ""),
                        exit_code=result.get("exit_code", -1),
                        execution_time_ms=result.get("duration_ms", 0),
                        error_type=result.get("error_type"),
                    )

                    # Add to exploit chain if successful
                    if result.get("exit_code", -1) == 0:
                        traj.add_exploit_step(parsed.action)

                    # Build observation prompt
                    error_info = ""
                    if result.get("error_type"):
                        error_info = f"Error Type: {result['error_type']}"

                    obs_prompt = REACT_OBSERVATION_PROMPT.format(
                        observation=result.get("stdout", "") or result.get("stderr", ""),
                        exit_code=result.get("exit_code", -1),
                        error_info=error_info,
                    )

                    # Get next thought
                    conversation += obs_prompt
                    next_response = self.llm.generate(
                        conversation,
                        system_prompt=REACT_SYSTEM_PROMPT,
                    )
                    conversation += next_response

                    next_parsed = self._parse_react_response(next_response)

                    # Record reflection
                    progress_summary = self._assess_progress(result, challenge)
                    is_goal_met = "Goal achieved" in progress_summary
                    
                    step.reflect(
                        what_happened=self._summarize_observation(result),
                        goal_progress=progress_summary,
                        next_step_reasoning=next_parsed.thought[:200] if next_parsed.thought else "",
                        should_continue=not is_goal_met and next_parsed.action_type not in ("done", "give_up"),
                    )

                    # Store attempt
                    attempts.append({
                        "step": step_num + 1,
                        "command": parsed.action,
                        "success": result.get("exit_code", -1) == 0,
                        "thought": parsed.thought,
                        "hypothesis": parsed.hypothesis,
                        "tool_choice": parsed.tool_choice,
                    })

                    # Callback
                    if self.on_step:
                        self.on_step(step_num + 1, parsed, result)

                    if is_goal_met:
                        final_success = True
                        break

                    parsed = next_parsed

            # Complete trajectory
            outcome = StepOutcome.SUCCESS if final_success else StepOutcome.FAILURE
            traj.complete(
                outcome=outcome,
                final_reflection=f"Task {'completed successfully' if final_success else 'failed'} after {len(attempts)} attempts",
            )

        # Build session result
        return self._build_session(challenge, attempts, final_success)

    def _parse_react_response(self, response: str) -> ReActResponse:
        """Parse a ReAct-format response into structured data."""
        thought = ""
        action = ""
        hypothesis = ""
        tool_choice = ""
        action_type = "command"

        # Extract HYPOTHESIS (Optional, might not be in all responses)
        hyp_match = re.search(
            r"HYPOTHESIS:\s*(.+?)(?=THOUGHT:|TOOL_CHOICE:|ACTION:|$)",
            response,
            re.DOTALL | re.IGNORECASE,
        )
        if hyp_match:
            hypothesis = hyp_match.group(1).strip()

        # Extract THOUGHT
        thought_match = re.search(
            r"THOUGHT:\s*(.+?)(?=TOOL_CHOICE:|ACTION:|$)",
            response,
            re.DOTALL | re.IGNORECASE,
        )
        if thought_match:
            thought = thought_match.group(1).strip()
        elif not hypothesis: 
            # Fallback if neither HYPOTHESIS nor THOUGHT found cleanly, maybe it started with thought
            # Check if entire string is thought until ACTION
            pre_action = re.split(r"ACTION:", response, flags=re.IGNORECASE)[0]
            if "HYPOTHESIS:" not in pre_action.upper():
                 thought = pre_action.strip()

        # Extract TOOL_CHOICE
        tool_match = re.search(
            r"TOOL_CHOICE:\s*(.+?)(?=ACTION:|$)",
            response,
            re.DOTALL | re.IGNORECASE,
        )
        if tool_match:
            tool_choice = tool_match.group(1).strip()

        # Extract ACTION
        action_match = re.search(
            r"ACTION:\s*(.+?)(?=THOUGHT:|OBSERVATION:|$)",
            response,
            re.DOTALL | re.IGNORECASE,
        )
        if action_match:
            action = action_match.group(1).strip()

            # Clean up action
            action = action.replace("```", "").strip()

            # Check for special actions
            action_upper = action.upper()
            if "DONE" in action_upper or "[DONE]" in action_upper:
                action_type = "done"
                action = "DONE"
            elif "GIVE_UP" in action_upper or "[GIVE_UP]" in action_upper:
                action_type = "give_up"
                action = "GIVE_UP"
            elif "CONTINUE" in action_upper or "[CONTINUE]" in action_upper:
                action_type = "continue"
                # Extract actual command if present
                action = re.sub(r"(\[?CONTINUE\]?)", "", action, flags=re.IGNORECASE).strip()

        return ReActResponse(
            thought=thought,
            action=action,
            action_type=action_type,
            raw_response=response,
            hypothesis=hypothesis,
            tool_choice=tool_choice,
        )

    def _infer_action_type(self, action: str) -> str:
        """Infer the action type from the command."""
        action_lower = action.lower()

        if action_lower.startswith("shell "):
            return "adb_shell"
        elif action_lower.startswith(("push ", "pull ", "install ")):
            return "adb_command"
        elif "frida" in action_lower or action.strip().startswith("Java."):
            return "frida_script"
        else:
            return "adb_shell"

    def _infer_reasoning_type(self, thought: str) -> ReasoningType:
        """Infer the reasoning type from thought content."""
        thought_lower = thought.lower()

        if any(w in thought_lower for w in ("fail", "error", "denied", "wrong")):
            return ReasoningType.ERROR_ANALYSIS
        elif any(w in thought_lower for w in ("try", "instead", "different", "alternative")):
            return ReasoningType.STRATEGY_PIVOT
        elif any(w in thought_lower for w in ("first", "start", "begin", "need to")):
            return ReasoningType.GOAL_DECOMPOSITION
        elif any(w in thought_lower for w in ("use", "command", "tool", "adb", "frida")):
            return ReasoningType.TOOL_SELECTION
        elif any(w in thought_lower for w in ("check", "verify", "confirm", "success")):
            return ReasoningType.VERIFICATION
        else:
            return ReasoningType.TOOL_SELECTION

    def _estimate_confidence(self, thought: str) -> float:
        """Estimate confidence from thought content."""
        thought_lower = thought.lower()

        # High confidence indicators
        if any(w in thought_lower for w in ("definitely", "clearly", "obviously", "know")):
            return 0.9

        # Low confidence indicators
        if any(w in thought_lower for w in ("maybe", "might", "try", "not sure", "guess")):
            return 0.4

        # Medium confidence
        return 0.7

    def _execute_action(self, action: str, action_type: str, challenge: Challenge) -> Dict[str, Any]:
        """Execute an action and return the result."""
        try:
            # Clean action: remove "adb shell " or "adb " prefix if the model added it redundantly
            # The executor.execute_adb method expects the command without the 'adb ' part.
            clean_action = action.strip()
            
            # Recursive stripping of redundant prefixes
            while True:
                lower_action = clean_action.lower()
                if lower_action.startswith("adb shell "):
                    clean_action = clean_action[10:].strip()
                elif lower_action.startswith("adb "):
                    clean_action = clean_action[4:].strip()
                else:
                    break

            if action_type in ("adb_shell", "adb_command"):
                # Use execute_adb for direct command execution
                result = self.executor.execute_adb(clean_action)
                return {
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "exit_code": result.exit_code,
                    "duration_ms": result.duration * 1000,
                    "error_type": result.error_type if hasattr(result, 'error_type') else None,
                }
            elif action_type == "frida_script":
                # For frida, we might need a target process
                target = challenge.inputs.device_context.get("target_package") 
                if not target and hasattr(challenge.inputs, "target_class"):
                    target = challenge.inputs.target_class
                
                target = target or "com.android.settings"
                result = self.executor.execute_frida(clean_action, target_process=target)
                return {
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "exit_code": result.exit_code,
                    "duration_ms": result.duration * 1000,
                }
            else:
                return {
                    "stdout": "",
                    "stderr": f"Unknown action type: {action_type}",
                    "exit_code": -1,
                }
        except Exception as e:
            return {
                "stdout": "",
                "stderr": str(e),
                "exit_code": -1,
                "error_type": "execution_error",
            }

    def _summarize_observation(self, result: Dict[str, Any]) -> str:
        """Summarize an observation result."""
        if result.get("exit_code", -1) == 0:
            stdout = result.get("stdout", "")
            if stdout:
                return f"Command succeeded with output: {stdout[:100]}..."
            return "Command succeeded with no output"
        else:
            stderr = result.get("stderr", "")
            error_type = result.get("error_type", "unknown")
            return f"Command failed ({error_type}): {stderr[:100]}..."

    def _assess_progress(self, result: Dict[str, Any], challenge: Challenge) -> str:
        """Assess progress toward the goal."""
        from dojo.curriculum.executor import ExecutionResult
        
        # Create a temporary ExecutionResult to use validate_output
        exec_res = ExecutionResult(
            success=result.get("exit_code") == 0,
            exit_code=result.get("exit_code", -1),
            stdout=result.get("stdout", ""),
            stderr=result.get("stderr", ""),
            duration=result.get("duration_ms", 0) / 1000.0,
            command="",
            error_type=result.get("error_type")
        )
        
        if self.executor.validate_output(challenge, exec_res):
            return "Goal achieved - output passes validation"
        
        if result.get("exit_code", -1) == 0:
            return "Partial progress - command succeeded but objective not yet met"
            
        return "No progress - command failed"

    def _format_device_context(
        self,
        challenge: Challenge,
        device_info: Dict[str, Any],
    ) -> str:
        """Format device context for the prompt."""
        lines = [
            "- connection: adb",
            f"- device_id: {device_info.get('device_id', 'unknown')}",
            f"- android_version: {device_info.get('android_version', 'unknown')}",
            f"- task: {challenge.name}",
        ]
        return "\n".join(lines)

    def _build_session(
        self,
        challenge: Challenge,
        attempts: List[Dict[str, Any]],
        success: bool,
    ) -> ChallengeSession:
        """Build a ChallengeSession from the run results."""
        attempt_records = []
        for att in attempts:
            attempt_records.append(
                AttemptRecord(
                    attempt_number=att["step"],
                    prompt_used="",  # Not storing full prompt
                    model_output=att["command"],
                    execution_result=ExecutionResult(
                        success=att["success"],
                        exit_code=0 if att["success"] else 1,
                        stdout="",
                        stderr="",
                        duration=0,
                        command=att["command"],
                    ),
                )
            )

        return ChallengeSession(
            challenge=challenge,
            attempts=attempt_records,
        )