"""Challenger - orchestrates challenge attempts with feedback loop."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional, Protocol

from dojo.curriculum.context_injector import ContextInjector
from dojo.curriculum.error_extractor import ErrorContext, ErrorExtractor
from dojo.curriculum.executor import ExecutionResult, Executor
from dojo.curriculum.loader import ChallengeLoader
from dojo.models import Belt, Challenge


class LLMClient(Protocol):
    """Protocol for LLM client interface."""

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate a response from the LLM."""
        ...


@dataclass
class AttemptRecord:
    """Record of a single challenge attempt."""

    attempt_number: int
    prompt_used: str
    model_output: str
    execution_result: ExecutionResult
    error_context: Optional[ErrorContext] = None
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "attempt_number": self.attempt_number,
            "prompt_used": self.prompt_used,
            "model_output": self.model_output,
            "execution_result": self.execution_result.to_dict(),
            "error_context": self.error_context.to_dict() if self.error_context else None,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ChallengeSession:
    """Complete record of a challenge session with all attempts."""

    challenge: Challenge
    attempts: list[AttemptRecord] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None

    @property
    def final_success(self) -> bool:
        """Check if the challenge was ultimately successful."""
        if not self.attempts:
            return False
        return self.attempts[-1].execution_result.success

    @property
    def total_attempts(self) -> int:
        """Get total number of attempts."""
        return len(self.attempts)

    @property
    def successful_output(self) -> Optional[str]:
        """Get the output that succeeded, if any."""
        for attempt in self.attempts:
            if attempt.execution_result.success:
                return attempt.model_output
        return None

    @property
    def duration(self) -> float:
        """Get total session duration in seconds."""
        end = self.completed_at or datetime.now()
        return (end - self.started_at).total_seconds()

    @property
    def retry_history(self) -> list[dict]:
        """Get summary of retry history for training data."""
        history = []
        for attempt in self.attempts:
            history.append({
                "attempt": attempt.attempt_number,
                "success": attempt.execution_result.success,
                "error_type": attempt.error_context.error_type if attempt.error_context else None,
            })
        return history

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "challenge_id": self.challenge.id,
            "challenge_name": self.challenge.name,
            "belt": self.challenge.belt.value,
            "final_success": self.final_success,
            "total_attempts": self.total_attempts,
            "duration": self.duration,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "attempts": [a.to_dict() for a in self.attempts],
        }


class Challenger:
    """Orchestrate challenge attempts with feedback loop."""

    def __init__(
        self,
        llm_client: LLMClient,
        executor: Executor,
        error_extractor: Optional[ErrorExtractor] = None,
        context_injector: Optional[ContextInjector] = None,
        max_retries: int = 3,
        on_attempt: Optional[Callable[[AttemptRecord], None]] = None,
    ):
        """
        Initialize the challenger.

        Args:
            llm_client: LLM client for generating code.
            executor: Executor for running code on device.
            error_extractor: Error extractor (created if None).
            context_injector: Context injector (created if None).
            max_retries: Maximum retry attempts.
            on_attempt: Optional callback after each attempt.
        """
        self.llm = llm_client
        self.executor = executor
        self.error_extractor = error_extractor or ErrorExtractor(executor)
        self.context_injector = context_injector or ContextInjector(max_retries)
        self.max_retries = max_retries
        self.on_attempt = on_attempt

    def run_challenge(self, challenge: Challenge) -> ChallengeSession:
        """
        Run a challenge with the feedback loop.

        Args:
            challenge: The challenge to attempt.

        Returns:
            ChallengeSession with all attempts recorded.
        """
        session = ChallengeSession(challenge=challenge)

        # Build initial prompt
        prompt = self.context_injector.build_initial_prompt(challenge)
        system_prompt = self.context_injector.build_system_prompt(challenge)

        for attempt_num in range(1, self.max_retries + 1):
            # 1. Generate code from LLM
            model_output = self._generate(prompt, system_prompt)
            model_output = self._clean_output(model_output)

            # 2. Execute on device
            exec_result = self.executor.execute(challenge, model_output)

            # 3. Validate output if execution succeeded
            if exec_result.success:
                validated = self.executor.validate_output(challenge, exec_result)
                if not validated:
                    # Execution succeeded but output didn't meet requirements
                    exec_result.success = False
                    exec_result.error_type = "validation_failed"

            # 4. Extract error context if failed
            error_ctx = None
            if not exec_result.success:
                error_ctx = self.error_extractor.extract(exec_result, model_output)

            # 5. Record attempt
            attempt = AttemptRecord(
                attempt_number=attempt_num,
                prompt_used=prompt,
                model_output=model_output,
                execution_result=exec_result,
                error_context=error_ctx,
            )
            session.attempts.append(attempt)

            # 6. Callback if provided
            if self.on_attempt:
                self.on_attempt(attempt)

            # 7. Success? Done.
            if exec_result.success:
                break

            # 8. Build retry prompt with context for next attempt
            if attempt_num < self.max_retries and error_ctx:
                prompt = self.context_injector.build_retry_prompt(
                    challenge=challenge,
                    previous_output=model_output,
                    error_context=error_ctx,
                    attempt_number=attempt_num + 1,
                )

        session.completed_at = datetime.now()
        return session

    def run_exploration(
        self,
        target: str,
        goal: str = "Identify sensitive exported interfaces or logic flaws",
        depth: int = 5
    ) -> ChallengeSession:
        """
        Exploration Mode: Open-ended probing of a target.
        Unlike a standard challenge, this has no fixed 'correct' answer.
        The goal is to discover new information or trigger crashes.
        """
        # Create a synthetic 'Black Belt' challenge for the exploration
        from dojo.models import Belt, Challenge, ChallengeInput, ExpectedOutput, ScriptType

        exploration_challenge = Challenge(
            id=f"explor_{datetime.now().strftime('%H%M%S')}",
            name=f"Autonomous Probing: {target}",
            description=f"Target: {target}\nGoal: {goal}",
            belt=Belt.BLACK,
            difficulty=5,
            inputs=ChallengeInput(device_context={"target": target, "mode": "exploration"}),
            expected_output=ExpectedOutput(script_type=ScriptType.FRIDA)
        )

        session = ChallengeSession(challenge=exploration_challenge)

        # Initial exploration prompt
        system_prompt = self.context_injector.build_system_prompt(exploration_challenge)
        prompt = f"EXPLORATION MODE\nTarget: {target}\nObjective: {goal}\n\n"
        prompt += "Step 1: Enumerate the target surfaces. Provide a Frida script to start."

        for i in range(depth):
            # 1. Generate exploration logic
            model_output = self._generate(prompt, system_prompt)
            model_output = self._clean_output(model_output)

            # 2. Execute and monitor
            exec_result = self.executor.execute(exploration_challenge, model_output)

            # 3. Analyze discovery
            # In exploration mode, any output that doesn't crash is a 'success'
            # because we are gathering data.
            error_ctx = None
            if not exec_result.success:
                error_ctx = self.error_extractor.extract(exec_result, model_output)

            # 4. Record
            attempt = AttemptRecord(
                attempt_number=i + 1,
                prompt_used=prompt,
                model_output=model_output,
                execution_result=exec_result,
                error_context=error_ctx
            )
            session.attempts.append(attempt)

            if self.on_attempt:
                self.on_attempt(attempt)

            # 5. Recursive Loop: Feed the result back to the model for the next step
            if exec_result.success:
                prompt = f"PREVIOUS DISCOVERY:\n{exec_result.stdout}\n\nNEXT STEP: Refine your probe based on this data. Generate the next Frida script."
            elif error_ctx:
                # If it failed, use the retry logic to fix the probe
                prompt = self.context_injector.build_retry_prompt(
                    challenge=exploration_challenge,
                    previous_output=model_output,
                    error_context=error_ctx,
                    attempt_number=i + 1
                )
            else:
                # Fallback if no error context
                prompt = f"The previous probe failed. Target: {target}. Objective: {goal}. Try an alternative Frida script."

        session.completed_at = datetime.now()
        return session

    def _generate(self, prompt: str, system_prompt: str) -> str:
        """Generate output from LLM."""
        try:
            return self.llm.generate(prompt, system_prompt)
        except Exception as e:
            # Return error message as output so it gets recorded
            return f"[LLM ERROR: {e}]"

    def _clean_output(self, output: str) -> str:
        """
        Aggressively clean LLM output to extract ONLY the executable code.
        Strips markdown, conversational filler, and explanations.
        """
        output = output.strip()

        # 1. Remove markdown code blocks (```javascript ... ```)
        if "```" in output:
            # Extract content between the first and last triple backticks
            parts = output.split("```")
            if len(parts) >= 3:
                # Use the middle part (the code)
                output = parts[1]
                # Remove language identifier if present (e.g., 'javascript\n')
                if "\n" in output:
                    first_line = output.split("\n")[0].lower()
                    if any(lang in first_line for lang in ["js", "javascript", "c", "bash", "python", "adb"]):
                        output = "\n".join(output.split("\n")[1:])
            else:
                # If only one set of backticks, just strip them
                output = output.replace("```", "")

        # 2. Strategic Pivot: Look for code start patterns
        # If the model still included talk, find where the actual code begins
        code_starts = [
            "Java.perform", "Interceptor.attach", "var ", "let ", "const ",
            "#include", "int main", "void ", "shell ", "pm ", "am ", "getprop"
        ]

        lower_output = output.lower()
        earliest_index = len(output)
        found_pattern = False

        for pattern in code_starts:
            idx = lower_output.find(pattern.lower())
            if idx != -1 and idx < earliest_index:
                earliest_index = idx
                found_pattern = True

        if found_pattern:
            output = output[earliest_index:]

        # 3. Final cleanup of common artifacts
        prefixes_to_remove = [
            "Here is the command:", "Here is the script:", "Correction:",
            "Command:", "Output:", "Code:"
        ]
        for prefix in prefixes_to_remove:
            if output.lower().startswith(prefix.lower()):
                output = output[len(prefix):].strip()

        return output.strip()

    def run_belt(
        self,
        belt: Belt,
        loader: ChallengeLoader,
        limit: Optional[int] = None,
    ) -> list[ChallengeSession]:
        """
        Run all challenges for a belt level.

        Args:
            belt: The belt level to run.
            loader: Challenge loader to get challenges.
            limit: Maximum number of challenges to run.

        Returns:
            List of ChallengeSession objects.
        """
        challenges = loader.load_belt(belt)

        if limit:
            challenges = challenges[:limit]

        sessions = []
        for challenge in challenges:
            session = self.run_challenge(challenge)
            sessions.append(session)

        return sessions

    def get_session_summary(self, session: ChallengeSession) -> str:
        """
        Get a human-readable summary of a challenge session.

        Args:
            session: The completed session.

        Returns:
            Summary string.
        """
        status = "PASS" if session.final_success else "FAIL"
        lines = [
            f"Challenge: {session.challenge.name} ({session.challenge.id})",
            f"Belt: {session.challenge.belt.display}",
            f"Status: {status}",
            f"Attempts: {session.total_attempts}/{self.max_retries}",
            f"Duration: {session.duration:.2f}s",
        ]

        if session.final_success and session.successful_output:
            lines.append(f"\nSuccessful output:\n{session.successful_output}")
        elif not session.final_success and session.attempts:
            last_error = session.attempts[-1].error_context
            if last_error:
                lines.append(f"\nFinal error: {last_error.error_type}")
                lines.append(f"Message: {last_error.error_message}")

        return "\n".join(lines)
