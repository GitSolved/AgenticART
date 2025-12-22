"""
Android Root Chain

End-to-end orchestration for achieving root access on Android devices.
Implements the paper's methodology: PentestGPT -> Script Generation -> Execution -> Verification
"""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

from ..memory import WorkingMemory
from ..planner import PentestPhase, Planner, PlanStep
from ..script_generator import ScriptGenerator, ScriptType
from ..summarizer import ActionResult, ExecutionSummary, Summarizer

logger = logging.getLogger(__name__)


class ChainState(Enum):
    IDLE = "idle"
    PLANNING = "planning"
    EXECUTING = "executing"
    SUMMARIZING = "summarizing"
    WAITING_CONFIRMATION = "waiting_confirmation"
    RETRYING = "retrying"  # New state for feedback loop
    COMPLETED = "completed"
    FAILED = "failed"


# Default retry configuration aligned with paper's approach
DEFAULT_MAX_RETRIES_PER_STEP = 3
DEFAULT_RETRY_DELAY_SECONDS = 1


@dataclass
class ChainResult:
    """Result of a chain execution."""
    success: bool
    root_achieved: bool
    phases_completed: list[PentestPhase]
    total_steps: int
    findings: list[str]
    generated_scripts: list[str]
    final_summary: str
    # New fields for feedback loop tracking
    total_retries: int = 0
    successful_retries: int = 0
    failed_after_retries: list[str] | None = None

    def __post_init__(self):
        if self.failed_after_retries is None:
            self.failed_after_retries = []


class AndroidRootChain:
    """
    Orchestrates the complete Android rooting workflow.

    This is the main entry point that ties together:
    1. Planner - Strategic decision making
    2. ScriptGenerator - Converting plans to code
    3. Executor - Running scripts (provided by caller)
    4. Summarizer - Analyzing results
    5. Memory - Maintaining context

    The chain runs iteratively until root is achieved or max attempts reached.
    """

    def __init__(
        self,
        planner: Optional[Planner] = None,
        summarizer: Optional[Summarizer] = None,
        script_generator: Optional[ScriptGenerator] = None,
        max_iterations: int = 20,
        require_confirmation: bool = True,
        max_retries_per_step: int = DEFAULT_MAX_RETRIES_PER_STEP,
        retry_delay: float = DEFAULT_RETRY_DELAY_SECONDS,
    ):
        self.planner = planner or Planner()
        self.summarizer = summarizer or Summarizer()
        self.script_generator = script_generator or ScriptGenerator()
        self.memory = WorkingMemory()

        self.max_iterations = max_iterations
        self.require_confirmation = require_confirmation

        # Feedback loop configuration (paper's approach)
        self.max_retries_per_step = max_retries_per_step
        self.retry_delay = retry_delay

        self.state = ChainState.IDLE
        self.current_phase = PentestPhase.RECONNAISSANCE
        self.iteration = 0
        self.generated_scripts: list[str] = []

        # Retry tracking
        self.total_retries = 0
        self.successful_retries = 0
        self.failed_after_retries: list[str] = []

    def run(
        self,
        target_config: dict,
        objective: str = "Achieve root access",
        executor: Optional[Callable[[str], str]] = None,
        confirmation_callback: Optional[Callable[[PlanStep], bool]] = None,
    ) -> ChainResult:
        """
        Execute the full Android rooting chain.

        Args:
            target_config: Target device configuration dict
            objective: Goal description
            executor: Function that executes scripts and returns output
            confirmation_callback: Function to confirm high-risk actions

        Returns:
            ChainResult with success status and findings
        """
        logger.info(f"Starting Android Root Chain for target: {target_config}")

        # Initialize memory
        self.memory.set("target", target_config)
        self.memory.set("objective", objective)
        self.memory.set("phases_completed", [])
        self.memory.set("findings", [])

        self.state = ChainState.PLANNING

        # Generate initial plan
        target_desc = self._format_target(target_config)
        plan = self.planner.create_plan(
            target=target_desc,
            objective=objective,
            context="",
        )

        logger.info(f"Generated plan with {len(plan.steps)} steps")

        # Execute phases
        phases = [
            PentestPhase.RECONNAISSANCE,
            PentestPhase.SCANNING,
            PentestPhase.EXPLOITATION,
            PentestPhase.PRIVILEGE_ESCALATION,
            PentestPhase.VERIFICATION,
        ]

        for phase in phases:
            self.current_phase = phase
            logger.info(f"Entering phase: {phase.value}")

            phase_result = self._execute_phase(
                phase=phase,
                target_config=target_config,
                objective=objective,
                executor=executor,
                confirmation_callback=confirmation_callback,
            )

            if phase_result.result == ActionResult.SUCCESS:
                self.memory.append("phases_completed", phase)

                # Check for root during/after privilege escalation
                if phase in [PentestPhase.PRIVILEGE_ESCALATION, PentestPhase.VERIFICATION]:
                    if self._check_root_achieved(phase_result):
                        logger.info("Root access achieved!")
                        self.state = ChainState.COMPLETED
                        return self._build_result(success=True, root_achieved=True)

            elif phase_result.result == ActionResult.FAILURE:
                logger.warning(f"Phase {phase.value} failed, attempting recovery")
                # Let planner decide next action based on failure

            self.iteration += 1
            if self.iteration >= self.max_iterations:
                logger.error("Max iterations reached")
                self.state = ChainState.FAILED
                break

        # Final result
        root_achieved = PentestPhase.VERIFICATION in self.memory.get("phases_completed", [])
        self.state = ChainState.COMPLETED if root_achieved else ChainState.FAILED

        return self._build_result(success=root_achieved, root_achieved=root_achieved)

    def _execute_phase(
        self,
        phase: PentestPhase,
        target_config: dict,
        objective: str,
        executor: Optional[Callable],
        confirmation_callback: Optional[Callable],
    ) -> ExecutionSummary:
        """Execute a single phase of the chain."""
        context = self.summarizer.get_context_for_planner()

        # Get next action from planner
        self.state = ChainState.PLANNING
        step = self.planner.get_next_action(
            phase=phase,
            target=self._format_target(target_config),
            objective=objective,
            context=context,
        )

        logger.info(f"Planner suggests: {step.action}")

        # Check for confirmation if required
        if self.require_confirmation and step.requires_confirmation:
            self.state = ChainState.WAITING_CONFIRMATION
            if confirmation_callback:
                if not confirmation_callback(step):
                    logger.info("User declined action")
                    return ExecutionSummary(
                        command="",
                        raw_output="User declined",
                        result=ActionResult.BLOCKED,
                        key_findings=[],
                        vulnerabilities=[],
                        next_steps=[],
                    )

        # Generate initial script
        script = self.script_generator.generate(
            step=step,
            target_config=target_config,
            script_type=ScriptType.PYTHON,
        )

        # Validate script
        valid, issues = self.script_generator.validate(script)
        if not valid:
            logger.error(f"Script validation failed: {issues}")
            return ExecutionSummary(
                command=script.content[:100],
                raw_output=f"Validation failed: {issues}",
                result=ActionResult.BLOCKED,
                key_findings=[],
                vulnerabilities=[],
                next_steps=["Review and fix script"],
            )

        # Execute with retry loop (paper's feedback approach)
        summary = self._execute_with_retry(
            script=script,
            target_config=target_config,
            step=step,
            executor=executor,
        )

        # Store findings
        for finding in summary.key_findings:
            self.memory.append("findings", finding)

        return summary

    def _execute_with_retry(
        self,
        script,
        target_config: dict,
        step: PlanStep,
        executor: Optional[Callable],
    ) -> ExecutionSummary:
        """
        Execute a script with iterative feedback loop.

        This implements the paper's core methodology:
        1. Execute script
        2. If failure, analyze error
        3. Regenerate script with error context
        4. Retry up to max_retries_per_step times
        5. Return final result

        Args:
            script: The GeneratedScript to execute
            target_config: Target configuration
            step: The original PlanStep
            executor: Function to execute scripts

        Returns:
            ExecutionSummary with final result
        """
        import time

        current_script = script
        last_output = ""
        last_summary = None

        for attempt in range(self.max_retries_per_step + 1):  # +1 for initial attempt
            is_retry = attempt > 0

            if is_retry:
                self.state = ChainState.RETRYING
                self.total_retries += 1
                logger.info(f"Retry attempt {attempt}/{self.max_retries_per_step} for: {step.action}")

                # Add delay between retries
                if self.retry_delay > 0:
                    time.sleep(self.retry_delay)

            # Save script
            script_path = self.script_generator.save(current_script)
            self.generated_scripts.append(script_path)
            logger.info(f"Script saved: {script_path}")

            # Execute if executor provided
            self.state = ChainState.EXECUTING
            if executor:
                try:
                    output = executor(script_path)
                except Exception as e:
                    output = f"Execution error: {e}"
            else:
                output = "[DRY RUN] Script generated but not executed"
                # In dry run, don't retry
                break

            last_output = output

            # Summarize results
            self.state = ChainState.SUMMARIZING
            summary = self.summarizer.summarize(
                command=step.action,
                output=output,
            )
            last_summary = summary

            # Check if successful
            if summary.result == ActionResult.SUCCESS:
                if is_retry:
                    self.successful_retries += 1
                    logger.info(f"Retry successful after {attempt} attempts")
                return summary

            # Check if we should retry
            if summary.result in [ActionResult.FAILURE, ActionResult.TIMEOUT]:
                if attempt < self.max_retries_per_step:
                    # Extract error context for feedback
                    error_context = self.script_generator.extract_error_context(output)
                    logger.info(
                        f"Execution failed ({error_context['error_type']}), "
                        f"regenerating with feedback..."
                    )

                    # Regenerate script with error feedback
                    current_script = self.script_generator.regenerate_with_feedback(
                        failed_script=current_script,
                        error_output=output,
                        target_config=target_config,
                        attempt_number=attempt + 1,
                    )

                    # Validate regenerated script
                    valid, issues = self.script_generator.validate(current_script)
                    if not valid:
                        logger.warning(f"Regenerated script failed validation: {issues}")
                        # Continue to next retry attempt anyway
                else:
                    # Max retries reached
                    logger.error(
                        f"Max retries ({self.max_retries_per_step}) reached for: {step.action}"
                    )
                    self.failed_after_retries.append(step.action)
            else:
                # For BLOCKED or PARTIAL, don't retry
                break

        # Return the last summary (failed after all retries or non-retriable)
        if last_summary:
            return last_summary

        # Fallback if no summary was generated
        return ExecutionSummary(
            command=step.action,
            raw_output=last_output or "No output captured",
            result=ActionResult.FAILURE,
            key_findings=[],
            vulnerabilities=[],
            next_steps=["Review execution logs"],
        )

    def _format_target(self, config: dict) -> str:
        """Format target config as string for prompts."""
        return (
            f"Android {config.get('android_version', 'Unknown')} "
            f"on {config.get('device', 'Unknown device')} "
            f"at {config.get('ip', 'unknown IP')}"
        )

    def _check_root_achieved(self, summary: ExecutionSummary) -> bool:
        """Check if root access was achieved based on summary."""
        root_indicators = [
            "uid=0",
            "root@",
            "# " ,  # root shell prompt
            "root access confirmed",
            "successfully rooted",
        ]
        combined = " ".join(summary.key_findings + [summary.raw_output]).lower()
        return any(indicator.lower() in combined for indicator in root_indicators)

    def _build_result(self, success: bool, root_achieved: bool) -> ChainResult:
        """Build final chain result."""
        return ChainResult(
            success=success,
            root_achieved=root_achieved,
            phases_completed=self.memory.get("phases_completed", []),
            total_steps=self.iteration,
            findings=self.memory.get("findings", []),
            generated_scripts=self.generated_scripts,
            final_summary=self.summarizer.compress_context(),
            # Retry statistics
            total_retries=self.total_retries,
            successful_retries=self.successful_retries,
            failed_after_retries=self.failed_after_retries,
        )

    def get_state(self) -> dict:
        """Get current chain state for UI display."""
        return {
            "state": self.state.value,
            "phase": self.current_phase.value,
            "iteration": self.iteration,
            "max_iterations": self.max_iterations,
            "scripts_generated": len(self.generated_scripts),
            "findings_count": len(self.memory.get("findings", [])),
            # Retry loop stats
            "total_retries": self.total_retries,
            "successful_retries": self.successful_retries,
            "failed_after_retries": len(self.failed_after_retries),
        }
