"""
Grading Runner: Execute grading pipeline on model responses.

This module provides two runners:

1. GradingRunner (Static): Grades reasoning quality only - no execution
2. ActiveRunner (Live-Fire): Async runner with MCP execution and self-correction

The ActiveRunner implements the Praxis Loop:
- Reasoning → MCP Verification → Calibration → Self-Correction
- High confidence + failed execution = HALLUCINATION_EVENT
- Failed executions trigger model revision prompts

Usage:
    # Static grading (reasoning only)
    runner = GradingRunner(model_id="qwen")
    run = runner.grade_challenge(challenge, phase_responses)

    # Active grading (with MCP execution and self-correction)
    runner = ActiveRunner(model_id="qwen", llm_client=client)
    run = await runner.run_challenge(challenge, phase_responses)
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Protocol

from dojo.graders.dpo_generator import DPOPair, DPOPairGenerator, export_dpo_dataset
from dojo.graders.metrics import GradingMetrics, TrainingProgressTracker
from dojo.graders.reasoning_grader import GradingResult, ReasoningGrader
from dojo.mcp import MCPExecutor, ToolResult
from dojo.models_v2 import (
    ChallengeV2,
    PhaseID,
    PhaseOutput,
    ReasoningChain,
    ReasoningQuality,
    VerificationTask,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# LLM Client Protocol (for self-correction)
# ─────────────────────────────────────────────────────────────────────────────

class LLMClientProtocol(Protocol):
    """Protocol for LLM clients used in self-correction."""

    async def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate a response from the model."""
        ...


# ─────────────────────────────────────────────────────────────────────────────
# Calibration Types
# ─────────────────────────────────────────────────────────────────────────────

class CalibrationCategory(Enum):
    """Categories of calibration outcomes."""

    TRUE_UNDERSTANDING = "true_understanding"      # High conf + Pass
    HALLUCINATION = "hallucination"                # High conf + Fail
    UNDER_CALIBRATED = "under_calibrated"          # Low conf + Pass
    APPROPRIATE_UNCERTAINTY = "appropriate_uncertainty"  # Low conf + Fail


@dataclass
class VerificationResult:
    """Result of executing a single verification task."""

    task: VerificationTask
    tool_called: str
    tool_args: dict
    raw_output: Any
    exit_code: int
    passed: bool
    execution_time_ms: int
    error: Optional[str] = None
    attempt_number: int = 1

    @property
    def failed(self) -> bool:
        return self.exit_code != 0 or not self.passed

    def to_dict(self) -> dict:
        return {
            "instruction": self.task.instruction,
            "tool": self.tool_called,
            "args": self.tool_args,
            "exit_code": self.exit_code,
            "passed": self.passed,
            "execution_time_ms": self.execution_time_ms,
            "error": self.error,
            "attempt_number": self.attempt_number,
        }


@dataclass
class SelfCorrectionAttempt:
    """Record of a self-correction attempt after execution failure."""

    original_hypothesis: str
    error_message: str
    revised_hypothesis: str
    verification_result: VerificationResult
    correction_prompt: str
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class CalibrationScore:
    """Calibration analysis comparing confidence vs execution reality."""

    stated_confidence: float          # Model's self-reported confidence (0-1)
    execution_pass_rate: float        # % of verification tasks that passed
    calibration_error: float          # |confidence - execution_rate|
    category: CalibrationCategory
    is_hallucination: bool
    verification_results: list[VerificationResult]
    self_corrections: list[SelfCorrectionAttempt] = field(default_factory=list)

    # Thresholds
    CONFIDENCE_THRESHOLD: float = 0.8  # Above this = "high confidence"
    EXECUTION_THRESHOLD: float = 0.3   # Below this = "failed verification"

    @property
    def dpo_signal_strength(self) -> float:
        """
        How strong is this as a DPO training signal?
        Hallucinations are highest value (model was confidently wrong).
        """
        if self.category == CalibrationCategory.HALLUCINATION:
            return 1.0  # Maximum signal - confidently wrong
        elif self.category == CalibrationCategory.TRUE_UNDERSTANDING:
            return 0.8  # Strong positive signal
        elif self.category == CalibrationCategory.UNDER_CALIBRATED:
            return 0.5  # Medium signal - should be more confident
        else:
            return 0.3  # Low signal - appropriately uncertain

    def to_dict(self) -> dict:
        return {
            "stated_confidence": self.stated_confidence,
            "execution_pass_rate": self.execution_pass_rate,
            "calibration_error": self.calibration_error,
            "category": self.category.value,
            "is_hallucination": self.is_hallucination,
            "dpo_signal_strength": self.dpo_signal_strength,
            "verification_results": [v.to_dict() for v in self.verification_results],
            "self_correction_attempts": len(self.self_corrections),
        }


@dataclass
class ActiveRun:
    """Results of an active (live-fire) grading run with MCP execution."""

    challenge_id: str
    model_id: str
    started_at: datetime
    completed_at: datetime

    # Reasoning results (from GradingRunner)
    grading_run: GradingRun

    # Verification results
    calibration: CalibrationScore

    # Self-correction history
    self_corrections: list[SelfCorrectionAttempt] = field(default_factory=list)

    # Generated training data
    dpo_pairs: list[DPOPair] = field(default_factory=list)

    @property
    def total_score(self) -> float:
        return self.grading_run.total_score

    @property
    def is_hallucination(self) -> bool:
        return self.calibration.is_hallucination

    @property
    def execution_passed(self) -> bool:
        return self.calibration.execution_pass_rate >= CalibrationScore.EXECUTION_THRESHOLD


@dataclass
class GradingRun:
    """Results of a complete grading run."""

    challenge_id: str
    model_id: str
    started_at: datetime
    completed_at: datetime

    # Phase results
    phase_results: list[GradingResult]

    # Overall assessment
    reasoning_chain: ReasoningChain
    reasoning_quality: ReasoningQuality

    # Generated training data
    dpo_pairs: list[DPOPair]

    @property
    def total_score(self) -> float:
        return self.reasoning_chain.total_score

    @property
    def success(self) -> bool:
        return self.reasoning_chain.success


class GradingRunner:
    """
    Main grading execution class.

    Orchestrates the grading pipeline:
    1. Grade each phase of model response
    2. Calculate reasoning quality
    3. Generate DPO training pairs
    4. Track metrics
    """

    def __init__(
        self,
        model_id: str,
        output_dir: Optional[Path] = None,
        generate_dpo: bool = True,
        min_dpo_margin: float = 0.1,
    ):
        """
        Initialize grading runner.

        Args:
            model_id: Identifier for the model being evaluated
            output_dir: Where to save results
            generate_dpo: Whether to generate DPO pairs
            min_dpo_margin: Minimum score margin for DPO pairs
        """
        self.model_id = model_id
        self.output_dir = output_dir or Path("grading_output")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.generate_dpo = generate_dpo
        self.dpo_generator = DPOPairGenerator(min_margin=min_dpo_margin)

        # Metrics tracking
        self.metrics = GradingMetrics()
        self.progress_tracker = TrainingProgressTracker(model_id=model_id)

        # Storage
        self.grading_runs: list[GradingRun] = []
        self.all_dpo_pairs: list[DPOPair] = []

    def grade_challenge(
        self,
        challenge: ChallengeV2,
        phase_responses: dict[PhaseID, str],
        generate_synthetic_dpo: bool = True,
    ) -> GradingRun:
        """
        Grade a complete challenge attempt.

        Args:
            challenge: The challenge that was attempted
            phase_responses: Dict mapping phase IDs to model response text
            generate_synthetic_dpo: Whether to generate synthetic rejection pairs

        Returns:
            GradingRun with all results
        """
        started_at = datetime.now()

        # Initialize grader for this challenge
        grader = ReasoningGrader(challenge)

        # Grade each phase
        phase_results = []
        phase_outputs = []
        phase_evaluations = []

        for phase in challenge.phases:
            if phase.phase_id in phase_responses:
                response_text = phase_responses[phase.phase_id]

                # Grade this phase
                result = grader.grade_phase(phase.phase_id, response_text)
                phase_results.append(result)

                # Create phase output and evaluation
                output = PhaseOutput(
                    phase_id=phase.phase_id,
                    raw_output=response_text,
                    parsed_output=grader.phase_graders[phase.phase_id].parse_response(response_text),
                )
                phase_outputs.append(output)
                phase_evaluations.append(result.to_phase_evaluation())

        # Calculate overall reasoning quality
        _, reasoning_quality = grader.grade_full_chain(phase_responses)

        # Determine if vulnerability was correctly identified
        predicted_vulnerable = self._extract_vulnerability_prediction(phase_responses)
        actual_vulnerable = challenge.ground_truth.vulnerability_present
        correctly_identified = predicted_vulnerable == actual_vulnerable

        # Build reasoning chain
        reasoning_chain = ReasoningChain(
            challenge_id=challenge.id,
            model_id=self.model_id,
            started_at=started_at,
            completed_at=datetime.now(),
            phase_outputs=phase_outputs,
            phase_evaluations=phase_evaluations,
            reasoning_quality=reasoning_quality,
            vulnerability_correctly_identified=correctly_identified,
        )

        # Update metrics
        for result in phase_results:
            confidence = self._extract_confidence(phase_responses)
            self.metrics.add_result(
                challenge_id=challenge.id,
                result=result,
                pillar=challenge.pillar,
                belt=challenge.belt,
                actual_vulnerable=actual_vulnerable,
                predicted_vulnerable=predicted_vulnerable,
                confidence=confidence,
            )

        self.metrics.add_reasoning_chain(reasoning_chain)

        # Generate DPO pairs
        dpo_pairs = []
        if self.generate_dpo and phase_results:
            # Find the best phase response for synthetic pair generation
            best_result = max(phase_results, key=lambda r: r.total_score)
            best_phase_id = best_result.phase_id
            best_response = phase_responses.get(best_phase_id, "")

            if generate_synthetic_dpo and best_result.total_score >= 0.7:
                # Generate synthetic rejected pairs
                synthetic_pairs = self.dpo_generator.generate_synthetic_pairs(
                    challenge=challenge,
                    good_response=best_response,
                    good_score=best_result.total_score,
                    phase_id=best_phase_id,
                    num_pairs=3,
                )
                dpo_pairs.extend(synthetic_pairs)

        self.all_dpo_pairs.extend(dpo_pairs)

        # Build run result
        run = GradingRun(
            challenge_id=challenge.id,
            model_id=self.model_id,
            started_at=started_at,
            completed_at=datetime.now(),
            phase_results=phase_results,
            reasoning_chain=reasoning_chain,
            reasoning_quality=reasoning_quality,
            dpo_pairs=dpo_pairs,
        )

        self.grading_runs.append(run)
        return run

    def grade_multiple_responses(
        self,
        challenge: ChallengeV2,
        responses_list: list[dict[PhaseID, str]],
    ) -> list[GradingRun]:
        """
        Grade multiple response attempts for the same challenge.

        This enables comparison-based DPO pair generation.

        Args:
            challenge: The challenge
            responses_list: List of phase_responses dicts from different attempts

        Returns:
            List of GradingRuns
        """
        runs = []

        for responses in responses_list:
            run = self.grade_challenge(
                challenge=challenge,
                phase_responses=responses,
                generate_synthetic_dpo=False,  # Will generate comparison pairs instead
            )
            runs.append(run)

        # Generate comparison-based DPO pairs
        if len(runs) >= 2:
            # Group responses by phase
            for phase in challenge.phases:
                phase_responses_with_grades = []
                for run in runs:
                    matching_results = [r for r in run.phase_results if r.phase_id == phase.phase_id]
                    if matching_results:
                        # Get original response text (from phase outputs)
                        matching_outputs = [o for o in run.reasoning_chain.phase_outputs
                                          if o.phase_id == phase.phase_id]
                        if matching_outputs:
                            phase_responses_with_grades.append(
                                (matching_outputs[0].raw_output, matching_results[0])
                            )

                if len(phase_responses_with_grades) >= 2:
                    pairs = self.dpo_generator.generate_from_responses(
                        challenge=challenge,
                        responses=phase_responses_with_grades,
                        phase_id=phase.phase_id,
                    )
                    self.all_dpo_pairs.extend(pairs)

        return runs

    def save_results(self, prefix: str = "") -> dict[str, Path]:
        """
        Save all grading results to files.

        Returns:
            Dict of result type to file path
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        prefix = f"{prefix}_" if prefix else ""

        saved_files = {}

        # Save grading runs
        runs_file = self.output_dir / f"{prefix}grading_runs_{timestamp}.json"
        with open(runs_file, 'w') as f:
            json.dump(
                [self._run_to_dict(run) for run in self.grading_runs],
                f,
                indent=2
            )
        saved_files["runs"] = runs_file

        # Save metrics
        metrics_file = self.output_dir / f"{prefix}metrics_{timestamp}.json"
        with open(metrics_file, 'w') as f:
            json.dump(self.metrics.to_dict(), f, indent=2)
        saved_files["metrics"] = metrics_file

        # Save DPO pairs
        if self.all_dpo_pairs:
            dpo_file = self.output_dir / f"{prefix}dpo_pairs_{timestamp}.jsonl"
            export_dpo_dataset(self.all_dpo_pairs, str(dpo_file), format="jsonl")
            saved_files["dpo"] = dpo_file

        # Save metrics summary
        summary_file = self.output_dir / f"{prefix}summary_{timestamp}.txt"
        with open(summary_file, 'w') as f:
            f.write(self.metrics.summary())
        saved_files["summary"] = summary_file

        return saved_files

    def add_checkpoint(self, epoch: int, step: int) -> None:
        """Add a training progress checkpoint."""
        self.progress_tracker.add_checkpoint(
            metrics=self.metrics,
            epoch=epoch,
            step=step,
        )

    def _extract_vulnerability_prediction(self, phase_responses: dict[PhaseID, str]) -> bool:
        """Extract whether model predicted a vulnerability exists."""
        all_text = " ".join(phase_responses.values()).lower()

        # Strong indicators of predicting vulnerable
        vulnerable_indicators = [
            "vulnerability found",
            "is vulnerable",
            "vulnerable to",
            "can be exploited",
            "exploitable",
            "is_vulnerable: true",
            "is_vulnerable\":true",
        ]

        # Strong indicators of predicting secure
        secure_indicators = [
            "not vulnerable",
            "is secure",
            "no vulnerability",
            "is_vulnerable: false",
            "is_vulnerable\":false",
        ]

        has_vulnerable = any(ind in all_text for ind in vulnerable_indicators)
        has_secure = any(ind in all_text for ind in secure_indicators)

        if has_vulnerable and not has_secure:
            return True
        elif has_secure and not has_vulnerable:
            return False
        else:
            # Ambiguous - default based on text analysis
            return "vulnerable" in all_text and "not vulnerable" not in all_text

    def _extract_confidence(self, phase_responses: dict[PhaseID, str]) -> float:
        """Extract confidence value from responses."""
        import re

        all_text = " ".join(phase_responses.values())

        # Look for explicit confidence values
        confidence_patterns = [
            r'confidence[:\s]+([0-9.]+)',
            r'confidence.*?([0-9.]+)',
            r'"confidence":\s*([0-9.]+)',
        ]

        for pattern in confidence_patterns:
            match = re.search(pattern, all_text, re.IGNORECASE)
            if match:
                try:
                    value = float(match.group(1))
                    if 0 <= value <= 1:
                        return value
                    elif 1 < value <= 100:
                        return value / 100
                except ValueError:
                    continue

        # Default confidence based on language
        text_lower = all_text.lower()
        if "high confidence" in text_lower or "confident" in text_lower:
            return 0.85
        elif "medium confidence" in text_lower or "likely" in text_lower:
            return 0.65
        elif "low confidence" in text_lower or "possibly" in text_lower:
            return 0.35

        return 0.5  # Default

    def _run_to_dict(self, run: GradingRun) -> dict:
        """Convert GradingRun to serializable dict."""
        return {
            "challenge_id": run.challenge_id,
            "model_id": run.model_id,
            "started_at": run.started_at.isoformat(),
            "completed_at": run.completed_at.isoformat(),
            "total_score": run.total_score,
            "success": run.success,
            "phase_results": [
                {
                    "phase_id": r.phase_id.value,
                    "total_score": r.total_score,
                    "criterion_scores": {cs.name: cs.score for cs in r.criterion_scores},
                    "feedback": r.feedback,
                    "hallucinations": r.hallucinations,
                    "missing_items": r.missing_items,
                }
                for r in run.phase_results
            ],
            "reasoning_quality": run.reasoning_quality.to_dict() if run.reasoning_quality else None,
            "dpo_pairs_generated": len(run.dpo_pairs),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Active Runner (Async with MCP Execution and Self-Correction)
# ─────────────────────────────────────────────────────────────────────────────

class ActiveRunner:
    """
    Async grading runner with live MCP execution and self-correction.

    Orchestrates the full Praxis Loop:
    1. Grade reasoning (CPU: Qwen thinks)
    2. Execute verification_tasks via MCP (ADB: Device responds)
    3. Self-correct on failure (GPU: Qwen revises hypothesis)
    4. Generate calibration score (hallucination detection)

    Architecture:
        M3 Max CPU → orchestrates ADB commands via MCP
        M3 Max GPU → runs Qwen for reasoning and self-correction
    """

    # Self-correction prompts
    SELF_CORRECTION_PROMPT = """Your execution failed. Review the logs and update your hypothesis.

## Failed Verification Task
**Instruction**: {instruction}
**Tool Called**: {tool} with args {args}

## Execution Result
**Exit Code**: {exit_code}
**Error**: {error}
**Output**: {output}

## Your Original Response
{original_response}

---

Based on this execution failure, please:
1. Analyze what went wrong
2. Identify any incorrect assumptions in your hypothesis
3. Provide a REVISED hypothesis that accounts for this new information

Your revised response:"""

    def __init__(
        self,
        model_id: str,
        llm_client: LLMClientProtocol,
        mcp_executor: Optional[MCPExecutor] = None,
        output_dir: Optional[Path] = None,
        max_self_corrections: int = 3,
        confidence_threshold: float = 0.8,
        execution_threshold: float = 0.3,
        auto_init_mcp: bool = True,
    ):
        """
        Initialize Active Runner.

        Args:
            model_id: Identifier for the model being evaluated
            llm_client: LLM client for self-correction (must have async generate())
            mcp_executor: Optional MCPExecutor instance (creates one if None)
            output_dir: Where to save results
            max_self_corrections: Maximum retry attempts on failure
            confidence_threshold: Confidence above this is "high confidence"
            execution_threshold: Pass rate below this is "failed verification"
            auto_init_mcp: Automatically initialize MCP executor
        """
        self.model_id = model_id
        self.llm_client = llm_client
        self.output_dir = output_dir or Path("active_runner_output")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.mcp_executor = mcp_executor or MCPExecutor()
        self.max_self_corrections = max_self_corrections
        self.confidence_threshold = confidence_threshold
        self.execution_threshold = execution_threshold
        self.auto_init_mcp = auto_init_mcp
        self._mcp_initialized = False

        # Underlying static grader for reasoning
        self.grading_runner = GradingRunner(
            model_id=model_id,
            output_dir=output_dir,
            generate_dpo=False,  # We generate calibrated DPO ourselves
        )

        # Storage
        self.active_runs: list[ActiveRun] = []
        self.all_self_corrections: list[SelfCorrectionAttempt] = []

    # -------------------------------------------------------------------------
    # Main Entry Point
    # -------------------------------------------------------------------------

    async def run_challenge(
        self,
        challenge: ChallengeV2,
        phase_responses: dict[PhaseID, str],
    ) -> ActiveRun:
        """
        Execute the full Praxis Loop for a challenge.

        1. Grade reasoning (static)
        2. Execute verification_tasks via MCP
        3. Self-correct on failures (dynamic)
        4. Compute calibration score
        5. Generate DPO signal

        Args:
            challenge: The challenge to grade
            phase_responses: Model's responses for each phase

        Returns:
            ActiveRun with all results including calibration
        """
        # Initialize MCP if needed
        if self.auto_init_mcp and not self._mcp_initialized:
            await self.mcp_executor.initialize()
            self._mcp_initialized = True
            logger.info(f"MCP Executor initialized: {self.mcp_executor.get_status()}")

        started_at = datetime.now()

        # Step 1: Grade reasoning (CPU thinks)
        grading_run = self.grading_runner.grade_challenge(
            challenge=challenge,
            phase_responses=phase_responses,
            generate_synthetic_dpo=False,
        )

        # Step 2: Extract stated confidence
        stated_confidence = self._extract_confidence(phase_responses)
        logger.info(f"Stated confidence: {stated_confidence:.2f}")

        # Step 3: Execute verification tasks with self-correction
        verification_results, self_corrections = await self._execute_with_self_correction(
            challenge=challenge,
            phase_responses=phase_responses,
        )

        # Step 4: Compute calibration
        calibration = self._compute_calibration(
            stated_confidence=stated_confidence,
            verification_results=verification_results,
            self_corrections=self_corrections,
        )

        # Step 5: Tag HALLUCINATION_EVENT if detected
        if calibration.is_hallucination:
            grading_run.reasoning_chain.metadata["HALLUCINATION_EVENT"] = True
            grading_run.reasoning_chain.metadata["calibration"] = calibration.to_dict()
            logger.warning(
                f"🚨 HALLUCINATION_EVENT: {challenge.id} | "
                f"confidence={stated_confidence:.2f}, pass_rate={calibration.execution_pass_rate:.2f}"
            )

        # Step 6: Generate DPO pairs based on calibration
        dpo_pairs = self._generate_calibrated_dpo(
            challenge=challenge,
            phase_responses=phase_responses,
            calibration=calibration,
        )

        completed_at = datetime.now()

        active_run = ActiveRun(
            challenge_id=challenge.id,
            model_id=self.model_id,
            started_at=started_at,
            completed_at=completed_at,
            grading_run=grading_run,
            calibration=calibration,
            self_corrections=self_corrections,
            dpo_pairs=dpo_pairs,
        )

        self.active_runs.append(active_run)
        self.all_self_corrections.extend(self_corrections)

        # Log summary
        self._log_run_summary(active_run)

        return active_run

    # -------------------------------------------------------------------------
    # MCP Execution with Self-Correction
    # -------------------------------------------------------------------------

    async def _execute_with_self_correction(
        self,
        challenge: ChallengeV2,
        phase_responses: dict[PhaseID, str],
    ) -> tuple[list[VerificationResult], list[SelfCorrectionAttempt]]:
        """
        Execute verification tasks, triggering self-correction on failures.

        Returns:
            Tuple of (verification_results, self_correction_attempts)
        """
        results = []
        corrections = []

        for task in challenge.verification_tasks:
            result = await self._execute_single_task(task, attempt=1)
            results.append(result)

            # Self-correction loop on failure
            if result.failed and self.max_self_corrections > 0:
                correction_result, task_corrections = await self._self_correction_loop(
                    task=task,
                    initial_result=result,
                    phase_responses=phase_responses,
                )
                # Use the corrected result
                results[-1] = correction_result
                corrections.extend(task_corrections)

        return results, corrections

    async def _execute_single_task(
        self,
        task: VerificationTask,
        attempt: int = 1,
    ) -> VerificationResult:
        """Execute a single verification task via MCP."""
        start_time = time.time()

        tool_call = task.mcp_tool_call
        tool_name = tool_call.get("tool", "adb_shell")
        tool_args = {k: v for k, v in tool_call.items() if k != "tool"}

        try:
            # Execute via MCPExecutor
            tool_result: ToolResult = await self.mcp_executor.execute_tool(
                tool_name=tool_name,
                tool_args=tool_args,
            )

            raw_output = tool_result.output
            exit_code = 0 if tool_result.success else 1

            # Validate output against task rules
            if tool_result.success:
                passed = self._validate_output(raw_output, task.validation_rule)
            else:
                passed = False

            error = tool_result.error

        except Exception as e:
            raw_output = None
            exit_code = 1
            passed = False
            error = str(e)
            logger.exception(f"MCP execution error: {task.instruction}")

        execution_time = int((time.time() - start_time) * 1000)

        return VerificationResult(
            task=task,
            tool_called=tool_name,
            tool_args=tool_args,
            raw_output=raw_output,
            exit_code=exit_code,
            passed=passed,
            execution_time_ms=execution_time,
            error=error,
            attempt_number=attempt,
        )

    async def _self_correction_loop(
        self,
        task: VerificationTask,
        initial_result: VerificationResult,
        phase_responses: dict[PhaseID, str],
    ) -> tuple[VerificationResult, list[SelfCorrectionAttempt]]:
        """
        Run self-correction loop for a failed task.

        Prompts the model: "Your execution failed. Review the logs and update your hypothesis."
        """
        corrections = []
        current_result = initial_result
        current_responses = phase_responses.copy()

        for attempt in range(1, self.max_self_corrections + 1):
            if not current_result.failed:
                break  # Success, stop correcting

            logger.info(f"Self-correction attempt {attempt}/{self.max_self_corrections} for: {task.instruction[:50]}...")

            # Build correction prompt
            original_response = current_responses.get(PhaseID.HYPOTHESIZE, "")
            if not original_response:
                original_response = current_responses.get(PhaseID.ANALYZE, "")

            correction_prompt = self.SELF_CORRECTION_PROMPT.format(
                instruction=task.instruction,
                tool=current_result.tool_called,
                args=json.dumps(current_result.tool_args),
                exit_code=current_result.exit_code,
                error=current_result.error or "No error message",
                output=str(current_result.raw_output)[:500] if current_result.raw_output else "No output",
                original_response=original_response[:1000],
            )

            # Get revised hypothesis from model (GPU thinks)
            try:
                revised_response = await self.llm_client.generate(
                    prompt=correction_prompt,
                    system_prompt="You are a security analyst revising your hypothesis based on execution feedback.",
                )
            except Exception as e:
                logger.error(f"LLM self-correction failed: {e}")
                break

            # Record the correction attempt
            correction = SelfCorrectionAttempt(
                original_hypothesis=original_response,
                error_message=current_result.error or f"exit_code={current_result.exit_code}",
                revised_hypothesis=revised_response,
                verification_result=current_result,
                correction_prompt=correction_prompt,
            )
            corrections.append(correction)

            # Re-execute the task
            new_result = await self._execute_single_task(task, attempt=attempt + 1)
            current_result = new_result

            # Update responses for potential next iteration
            current_responses[PhaseID.HYPOTHESIZE] = revised_response

        return current_result, corrections

    # -------------------------------------------------------------------------
    # Calibration
    # -------------------------------------------------------------------------

    def _compute_calibration(
        self,
        stated_confidence: float,
        verification_results: list[VerificationResult],
        self_corrections: list[SelfCorrectionAttempt],
    ) -> CalibrationScore:
        """
        Compute calibration score comparing confidence vs execution reality.

        High confidence + failed execution = HALLUCINATION
        """
        # Calculate execution pass rate
        if verification_results:
            passed_count = sum(1 for r in verification_results if r.passed)
            execution_pass_rate = passed_count / len(verification_results)
        else:
            execution_pass_rate = 1.0  # No tasks = assume pass

        # Calculate calibration error
        calibration_error = abs(stated_confidence - execution_pass_rate)

        # Determine category
        high_confidence = stated_confidence >= self.confidence_threshold
        execution_failed = execution_pass_rate < self.execution_threshold

        if high_confidence and not execution_failed:
            category = CalibrationCategory.TRUE_UNDERSTANDING
        elif high_confidence and execution_failed:
            category = CalibrationCategory.HALLUCINATION
        elif not high_confidence and not execution_failed:
            category = CalibrationCategory.UNDER_CALIBRATED
        else:
            category = CalibrationCategory.APPROPRIATE_UNCERTAINTY

        is_hallucination = category == CalibrationCategory.HALLUCINATION

        return CalibrationScore(
            stated_confidence=stated_confidence,
            execution_pass_rate=execution_pass_rate,
            calibration_error=calibration_error,
            category=category,
            is_hallucination=is_hallucination,
            verification_results=verification_results,
            self_corrections=self_corrections,
        )

    # -------------------------------------------------------------------------
    # DPO Generation
    # -------------------------------------------------------------------------

    def _generate_calibrated_dpo(
        self,
        challenge: ChallengeV2,
        phase_responses: dict[PhaseID, str],
        calibration: CalibrationScore,
    ) -> list[DPOPair]:
        """
        Generate DPO pairs based on calibration results.

        Hallucinations become REJECTED samples (highest training value).
        """
        pairs = []

        if calibration.is_hallucination:
            # This is a high-value REJECTED sample
            # The model was confident but wrong
            for phase_id, response in phase_responses.items():
                if response:
                    pair = DPOPair(
                        pair_id=f"praxis_hallucination_{challenge.id}",
                        prompt=challenge.description,
                        chosen="[This response was rejected due to hallucination]",
                        rejected=response,
                        challenge_id=challenge.id,
                        phase_id=phase_id,
                        chosen_score=0.0,
                        rejected_score=calibration.stated_confidence,
                        margin=calibration.calibration_error,
                        metadata={
                            "calibration_category": calibration.category.value,
                            "stated_confidence": calibration.stated_confidence,
                            "execution_pass_rate": calibration.execution_pass_rate,
                            "is_hallucination": True,
                            "dpo_signal_strength": calibration.dpo_signal_strength,
                        },
                    )
                    pairs.append(pair)
                    break  # One pair per challenge for hallucinations

        return pairs

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _validate_output(self, output: Any, validation_rule: dict) -> bool:
        """Validate execution output against the task's validation rule."""
        if not validation_rule:
            return output is not None

        rule_type = validation_rule.get("type", "")
        output_str = str(output) if output else ""

        if rule_type == "output_contains":
            expected = validation_rule.get("expected", "")
            return expected.lower() in output_str.lower()

        elif rule_type == "regex":
            pattern = validation_rule.get("pattern", "")
            try:
                return bool(re.search(pattern, output_str, re.IGNORECASE))
            except re.error:
                return False

        elif rule_type == "json_path":
            # JSON path validation
            try:
                if isinstance(output, dict):
                    path = validation_rule.get("path", "").split(".")
                    value = output
                    for key in path:
                        value = value[key]
                    return value == validation_rule.get("expected")
            except (KeyError, TypeError):
                return False

        elif rule_type == "exit_code":
            expected_code = validation_rule.get("expected", 0)
            return output == expected_code

        return True  # Unknown rule type = pass

    def _extract_confidence(self, phase_responses: dict[PhaseID, str]) -> float:
        """Extract confidence value from responses."""
        all_text = " ".join(phase_responses.values())

        # Look for explicit confidence values
        confidence_patterns = [
            r'confidence[:\s]+(\d+(?:\.\d+)?)',
            r'confidence.*?(\d+(?:\.\d+)?)',
            r'"confidence":\s*(\d+(?:\.\d+)?)',
            r'(\d+(?:\.\d+)?)\s*%?\s*confiden',
        ]

        for pattern in confidence_patterns:
            match = re.search(pattern, all_text, re.IGNORECASE)
            if match:
                try:
                    value = float(match.group(1))
                    if 0 <= value <= 1:
                        return value
                    elif 1 < value <= 100:
                        return value / 100
                except ValueError:
                    continue

        # Default confidence based on language
        text_lower = all_text.lower()
        if "high confidence" in text_lower or "highly confident" in text_lower:
            return 0.85
        elif "medium confidence" in text_lower or "likely" in text_lower:
            return 0.65
        elif "low confidence" in text_lower or "possibly" in text_lower:
            return 0.35

        return 0.5  # Default

    def _log_run_summary(self, run: ActiveRun) -> None:
        """Log summary of an active run."""
        status = "🚨 HALLUCINATION" if run.is_hallucination else "✅ CALIBRATED"
        logger.info(
            f"\n{'='*60}\n"
            f"Active Run Complete: {run.challenge_id}\n"
            f"{'='*60}\n"
            f"  Status: {status}\n"
            f"  Reasoning Score: {run.total_score:.2%}\n"
            f"  Stated Confidence: {run.calibration.stated_confidence:.2%}\n"
            f"  Execution Pass Rate: {run.calibration.execution_pass_rate:.2%}\n"
            f"  Calibration Error: {run.calibration.calibration_error:.2%}\n"
            f"  Category: {run.calibration.category.value}\n"
            f"  Self-Corrections: {len(run.self_corrections)}\n"
            f"  DPO Signal Strength: {run.calibration.dpo_signal_strength:.2f}\n"
            f"{'='*60}"
        )

    # -------------------------------------------------------------------------
    # Statistics
    # -------------------------------------------------------------------------

    def get_hallucination_rate(self) -> float:
        """Get percentage of runs that were hallucinations."""
        if not self.active_runs:
            return 0.0
        hallucinations = sum(1 for r in self.active_runs if r.is_hallucination)
        return hallucinations / len(self.active_runs)

    def get_self_correction_success_rate(self) -> float:
        """Get percentage of self-corrections that led to passing verification."""
        if not self.all_self_corrections:
            return 0.0
        # Check if final result after corrections passed
        successful = sum(
            1 for c in self.all_self_corrections
            if c.verification_result.passed
        )
        return successful / len(self.all_self_corrections)

    async def shutdown(self) -> None:
        """Shutdown MCP executor."""
        if self._mcp_initialized:
            await self.mcp_executor.shutdown()
            self._mcp_initialized = False


# ─────────────────────────────────────────────────────────────────────────────
# Convenience Functions
# ─────────────────────────────────────────────────────────────────────────────

def grade_single_response(
    challenge: ChallengeV2,
    response: str,
    phase_id: PhaseID,
) -> GradingResult:
    """
    Convenience function to grade a single response.

    Args:
        challenge: The challenge
        response: The model's response text
        phase_id: Which phase this response is for

    Returns:
        GradingResult
    """
    grader = ReasoningGrader(challenge)
    return grader.grade_phase(phase_id, response)


def quick_evaluate(
    challenge: ChallengeV2,
    phase_responses: dict[PhaseID, str],
) -> dict:
    """
    Quick evaluation returning summary dict.

    Args:
        challenge: The challenge
        phase_responses: Dict of phase responses

    Returns:
        Summary dict with scores and key findings
    """
    grader = ReasoningGrader(challenge)
    results, quality = grader.grade_full_chain(phase_responses)

    return {
        "total_score": sum(r.total_score for r in results) / len(results) if results else 0,
        "phase_scores": {r.phase_id.value: r.total_score for r in results},
        "reasoning_quality": quality.overall if quality else 0,
        "hallucinations": [h for r in results for h in r.hallucinations],
        "missing_items": [m for r in results for m in r.missing_items],
        "passed": all(r.total_score >= 0.6 for r in results),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Example Usage
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Example usage demonstration
    print("Grading Runner - Example Usage")
    print("=" * 50)

    # This would be loaded from a challenge file
    # For demo, showing the structure:
    print("""
    # Basic usage:

    from dojo.graders import GradingRunner
    from dojo.models_v2 import PhaseID

    # Initialize runner
    runner = GradingRunner(
        model_id="my-model-v1",
        output_dir=Path("./results"),
        generate_dpo=True,
    )

    # Grade a challenge
    run = runner.grade_challenge(
        challenge=my_challenge,
        phase_responses={
            PhaseID.OBSERVE: "My observation response...",
            PhaseID.HYPOTHESIZE: "My hypothesis response...",
        }
    )

    print(f"Score: {run.total_score:.2%}")
    print(f"Success: {run.success}")

    # Save results
    saved = runner.save_results(prefix="training_run")
    print(f"Saved to: {saved}")

    # View metrics
    print(runner.metrics.summary())
    """)
