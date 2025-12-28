"""Challenger - orchestrates challenge attempts with feedback loop."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional, Protocol

from dojo.curriculum.context_injector import ContextInjector
from dojo.curriculum.error_extractor import ErrorContext, ErrorExtractor
from dojo.curriculum.executor import ExecutionResult, Executor
from dojo.curriculum.loader import ChallengeLoader
from dojo.models import Belt, Challenge, ChallengeInput, ExpectedOutput, ScriptType
from dojo.tools.code_interpreter import CodeInterpreter


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
    diagnostics: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "attempt_number": self.attempt_number,
            "prompt_used": self.prompt_used,
            "model_output": self.model_output,
            "execution_result": self.execution_result.to_dict(),
            "error_context": (
                self.error_context.to_dict() if self.error_context else None
            ),
            "diagnostics": self.diagnostics,
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
        """Check success."""
        if not self.attempts:
            return False
        return self.attempts[-1].execution_result.success

    @property
    def total_attempts(self) -> int:
        """Total attempts."""
        return len(self.attempts)

    @property
    def successful_output(self) -> Optional[str]:
        """Successful output."""
        for attempt in self.attempts:
            if attempt.execution_result.success:
                return attempt.model_output
        return None

    @property
    def duration(self) -> float:
        """Total duration."""
        end = self.completed_at or datetime.now()
        return (end - self.started_at).total_seconds()

    def to_dict(self) -> dict:
        """Dictionary representation."""
        return {
            "challenge_id": self.challenge.id,
            "final_success": self.final_success,
            "total_attempts": self.total_attempts,
            "attempts": [a.to_dict() for a in self.attempts],
        }


class Challenger:
    """Orchestrate challenge attempts."""

    def __init__(
        self,
        llm_client: LLMClient,
        executor: Executor,
        error_extractor: Optional[ErrorExtractor] = None,
        context_injector: Optional[ContextInjector] = None,
        max_retries: int = 3,
        on_attempt: Optional[Callable[[AttemptRecord], None]] = None,
    ):
        """Initialize."""
        self.llm = llm_client
        self.executor = executor
        self.error_extractor = error_extractor or ErrorExtractor(executor)
        self.context_injector = context_injector or ContextInjector(max_retries)
        self.code_interpreter = CodeInterpreter()
        self.max_retries = max_retries
        self.on_attempt = on_attempt

    def _check_control_state(self):
        """Check for external pause/stop signals from the dashboard."""
        import json
        import time

        state_path = Path("dojo_output/engine_state.json")
        if not state_path.exists():
            return

        while True:
            try:
                with open(state_path, "r") as f:
                    state = json.load(f)

                status = state.get("status", "running")
                if status == "stopped":
                    print("🛑 Engine Stop Signal Received.")
                    raise InterruptedError("Engine stopped by user")
                if status == "paused":
                    time.sleep(2)  # Wait and check again
                    continue
                break  # Running
            except (json.JSONDecodeError, PermissionError):
                time.sleep(1)
                continue

    def run_challenge(self, challenge: Challenge) -> ChallengeSession:
        """Run a challenge."""
        session = ChallengeSession(challenge=challenge)
        prompt = self.context_injector.build_initial_prompt(challenge)
        system_prompt = self.context_injector.build_system_prompt(challenge)

        for attempt_num in range(1, self.max_retries + 1):
            self._check_control_state()
            model_output = self._generate(prompt, system_prompt)
            model_output = self._clean_output(model_output)
            exec_result = self.executor.execute(challenge, model_output)

            error_ctx = None
            if not exec_result.success:
                error_ctx = self.error_extractor.extract(exec_result, model_output)

            attempt = AttemptRecord(
                attempt_number=attempt_num,
                prompt_used=prompt,
                model_output=model_output,
                execution_result=exec_result,
                error_context=error_ctx,
            )
            session.attempts.append(attempt)
            if self.on_attempt:
                self.on_attempt(attempt)
            if exec_result.success:
                break

            if attempt_num < self.max_retries:
                if error_ctx:
                    prompt = self.context_injector.build_retry_prompt(
                        challenge, model_output, error_ctx, attempt_num + 1
                    )
                else:
                    # Fallback: use raw stderr when error extraction fails
                    prompt = self.context_injector.build_raw_failure_prompt(
                        challenge, model_output, exec_result.stderr, attempt_num + 1
                    )

        session.completed_at = datetime.now()
        return session

    def run_exploration(
        self, target: str, goal: str = "Probe", depth: int = 5
    ) -> ChallengeSession:
        """Probing mode."""
        exploration_challenge = Challenge(
            id=f"explor_{datetime.now().strftime('%H%M%S')}",
            name=f"Probe: {target}",
            description=f"Target: {target}\nGoal: {goal}",
            belt=Belt.BLACK,
            difficulty=5,
            inputs=ChallengeInput(
                device_context={"target_package": target, "mode": "exploration"}
            ),
            expected_output=ExpectedOutput(script_type=ScriptType.FRIDA),
        )
        session = ChallengeSession(challenge=exploration_challenge)
        system_prompt = self.context_injector.build_system_prompt(exploration_challenge)
        prompt = f"EXPLORATION MODE\nTarget: {target}\n"

        for i in range(depth):
            self._check_control_state()
            model_output = self._generate(prompt, system_prompt)
            model_output = self._clean_output(model_output)

            if "import " in model_output or "def " in model_output:
                tools = {
                    "adb": self.executor.execute_adb,
                    "frida": self.executor.execute_frida,
                }
                code_res = self.code_interpreter.execute(
                    model_output, external_tools=tools
                )
                exec_result = ExecutionResult(
                    success=code_res.success,
                    exit_code=0 if code_res.success else 1,
                    stdout=code_res.stdout,
                    stderr=code_res.stderr,
                    duration=0,
                    command="python_analysis",
                )
            else:
                exec_result = self.executor.execute(exploration_challenge, model_output)

            error_ctx = None
            if not exec_result.success:
                error_ctx = self.error_extractor.extract(exec_result, model_output)

            attempt = AttemptRecord(i + 1, prompt, model_output, exec_result, error_ctx)
            session.attempts.append(attempt)
            if self.on_attempt:
                self.on_attempt(attempt)

            if exec_result.success:
                prompt = f"DISCOVERY:\n{exec_result.stdout}\nNEXT STEP: Refine probe."
            elif error_ctx:
                prompt = self.context_injector.build_retry_prompt(
                    exploration_challenge, model_output, error_ctx, i + 1
                )
            else:
                # Fallback: use raw stderr when error extraction fails
                prompt = self.context_injector.build_raw_failure_prompt(
                    exploration_challenge, model_output, exec_result.stderr, i + 1
                )

        session.completed_at = datetime.now()
        return session

    def _generate(self, prompt: str, system_prompt: str) -> str:
        """Generate output from LLM."""
        try:
            return self.llm.generate(prompt, system_prompt)
        except Exception as e:
            return f"[ERROR: {e}]"

    def _clean_output(self, output: str) -> str:
        """Extract ONLY the executable code."""
        output = output.strip()
        if "```" in output:
            parts = output.split("```")
            if len(parts) >= 3:
                output = parts[1]
                if "\n" in output:
                    output = "\n".join(output.split("\n")[1:])
            else:
                output = output.replace("```", "")

        code_starts = [
            "Java.perform",
            "Interceptor.attach",
            "var ",
            "#include",
            "shell ",
        ]
        for p in code_starts:
            idx = output.lower().find(p.lower())
            if idx != -1:
                return output[idx:].strip()
        return output

    def run_belt(
        self, belt: Belt, loader: ChallengeLoader, limit: Optional[int] = None
    ) -> list[ChallengeSession]:
        """Run challenges for a belt level."""
        challenges = loader.load_belt(belt)
        if limit:
            challenges = challenges[:limit]
        return [self.run_challenge(c) for c in challenges]
