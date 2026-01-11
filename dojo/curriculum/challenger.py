"""Challenger - orchestrates challenge attempts with feedback loop."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional, Protocol

from dojo.curriculum.context_injector import ContextInjector
from dojo.curriculum.error_extractor import ErrorContext, ErrorExtractor
from dojo.curriculum.executor import ExecutionResult, Executor
from dojo.curriculum.loader import UnifiedCurriculum
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

    @property
    def time_to_success(self) -> Optional[float]:
        """
        Get seconds from session start to first successful attempt.

        Returns:
            Seconds to success, or None if no successful attempt.
        """
        for attempt in self.attempts:
            if attempt.execution_result.success:
                return (attempt.timestamp - self.started_at).total_seconds()
        return None

    @property
    def avg_attempt_interval(self) -> float:
        """
        Get average seconds between attempts.

        Returns:
            Average interval in seconds, or 0.0 if fewer than 2 attempts.
        """
        if len(self.attempts) < 2:
            return 0.0

        intervals = []
        for i in range(1, len(self.attempts)):
            delta = (self.attempts[i].timestamp - self.attempts[i - 1].timestamp).total_seconds()
            intervals.append(delta)

        return sum(intervals) / len(intervals) if intervals else 0.0

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "challenge_id": self.challenge.id,
            "challenge_name": self.challenge.name,
            "belt": self.challenge.belt.value,
            "final_success": self.final_success,
            "total_attempts": self.total_attempts,
            "duration": self.duration,
            "time_to_success": self.time_to_success,
            "avg_attempt_interval": round(self.avg_attempt_interval, 2),
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

    def run_challenge(self, challenge: Any) -> ChallengeSession:
        """
        Run a challenge with the feedback loop.

        Args:
            challenge: The challenge to attempt (V1 or V2).

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

    def _generate(self, prompt: str, system_prompt: str) -> str:
        """Generate output from LLM."""
        try:
            return self.llm.generate(prompt, system_prompt)
        except Exception as e:
            # Return error message as output so it gets recorded
            return f"[LLM ERROR: {e}]"

    def _clean_output(self, output: str) -> str:
        """Clean LLM output of common artifacts."""
        output = output.strip()

        # Remove markdown code blocks if present
        if output.startswith("```"):
            lines = output.split("\n")
            # Remove first line (```language)
            lines = lines[1:]
            # Remove last line if it's just ```
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            output = "\n".join(lines)

        # Remove common prefixes
        prefixes_to_remove = [
            "Here is the command:",
            "Here's the command:",
            "The command is:",
            "Command:",
            "Output:",
        ]
        for prefix in prefixes_to_remove:
            if output.lower().startswith(prefix.lower()):
                output = output[len(prefix):].strip()

        return output.strip()

    def run_belt(
        self,
        belt: Belt,
        loader: UnifiedCurriculum,
        limit: Optional[int] = None,
    ) -> list[ChallengeSession]:
        """
        Run all challenges for a belt level.

        Args:
            belt: The belt level to run.
            loader: UnifiedCurriculum to get challenges.
            limit: Maximum number of challenges to run.

        Returns:
            List of ChallengeSession objects.
        """
        # Get challenges for this belt from curriculum
        challenge_ids = []
        for stage in loader.stages_in_order():
            if stage.belt == belt:
                challenge_ids.extend(stage.challenge_ids)

        challenges = []
        for cid in challenge_ids:
            try:
                challenges.append(loader.load_challenge(cid))
            except Exception:
                continue

        if limit:
            challenges = challenges[:limit]

        sessions = []
        for challenge in challenges:
            # Cast V2 challenge to V1 challenge if necessary
            # For now, assume strict typing is loose enough or models match
            session = self.run_challenge(challenge) # type: ignore
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
