"""
Praxis Runner: Execute the Reasoning → Verification → Calibration loop.

The Praxis Loop unifies V2 (reasoning) with V1 (execution):
1. Model produces reasoning + confidence about a security hypothesis
2. Verification tasks execute via MCP to get binary ground truth
3. Calibration compares confidence vs reality to detect hallucinations

This generates the highest-quality DPO training signals:
- CHOSEN: High confidence + Passed execution (true understanding)
- REJECTED: High confidence + Failed execution (hallucination)
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

from dojo.graders.dpo_generator import DPOPair
from dojo.graders.runner import GradingRun, GradingRunner
from dojo.mcp import MCPExecutor, ToolResult
from dojo.models_v2 import (
    ChallengeV2,
    PhaseID,
    Pillar,
    VerificationTask,
)

# Optional MLX adapter imports (for Apple Silicon)
try:
    from agent.mlx_adapter_client import (
        AdapterConfig,
        AdapterManager,
        MLXAdapterClient,
    )
    MLX_AVAILABLE = True
except ImportError:
    MLX_AVAILABLE = False
    AdapterConfig = None
    AdapterManager = None
    MLXAdapterClient = None

# Optional RAG imports
try:
    from dojo.rag import RAGPromptAugmenter
    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False
    RAGPromptAugmenter = None

logger = logging.getLogger(__name__)


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
    passed: bool
    execution_time_ms: int
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "instruction": self.task.instruction,
            "tool": self.tool_called,
            "args": self.tool_args,
            "passed": self.passed,
            "execution_time_ms": self.execution_time_ms,
            "error": self.error,
        }


@dataclass
class CalibrationResult:
    """Result of the calibration analysis."""

    reasoning_score: float          # 0.0 - 1.0 from V2 grading
    stated_confidence: float        # Model's self-reported confidence
    execution_pass_rate: float      # % of verification tasks that passed
    calibration_error: float        # |confidence - execution_rate|
    category: CalibrationCategory
    is_hallucination: bool
    verification_results: list[VerificationResult]

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
            "reasoning_score": self.reasoning_score,
            "stated_confidence": self.stated_confidence,
            "execution_pass_rate": self.execution_pass_rate,
            "calibration_error": self.calibration_error,
            "category": self.category.value,
            "is_hallucination": self.is_hallucination,
            "dpo_signal_strength": self.dpo_signal_strength,
            "verification_results": [v.to_dict() for v in self.verification_results],
        }


@dataclass
class PraxisRun:
    """Complete result of a Praxis Loop execution."""

    challenge_id: str
    model_id: str
    started_at: datetime
    completed_at: datetime

    # V2 Reasoning results
    grading_run: GradingRun

    # V1 Verification results
    calibration: CalibrationResult

    # Generated training signal
    dpo_pair: Optional[DPOPair] = None

    @property
    def is_high_quality_signal(self) -> bool:
        """Is this run worth including in training?"""
        return self.calibration.dpo_signal_strength >= 0.5


# =============================================================================
# BEST-OF-N TREE SEARCH DATA STRUCTURES
# =============================================================================

class CandidateStatus(Enum):
    """Status of a candidate in the Best-of-N search."""

    PENDING = "pending"              # Not yet evaluated
    PASSED_EARLY_FILTER = "passed"   # Passed first verification task
    FAILED_EARLY_FILTER = "failed"   # Failed first verification task
    SELECTED = "selected"            # Selected as best candidate
    DISCARDED = "discarded"          # Discarded (not selected)


@dataclass
class CandidateResult:
    """Result of evaluating a single candidate in Best-of-N search."""

    candidate_id: int
    phase_responses: dict[PhaseID, str]
    status: CandidateStatus

    # Early filter results (first verification task only)
    early_filter_passed: bool
    early_filter_result: Optional[VerificationResult] = None

    # Reasoning quality (for selection among passing candidates)
    reasoning_score: float = 0.0
    stated_confidence: float = 0.0

    # Hard Negative detection
    is_hard_negative: bool = False
    hard_negative_reason: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "candidate_id": self.candidate_id,
            "status": self.status.value,
            "early_filter_passed": self.early_filter_passed,
            "early_filter_result": self.early_filter_result.to_dict() if self.early_filter_result else None,
            "reasoning_score": self.reasoning_score,
            "stated_confidence": self.stated_confidence,
            "is_hard_negative": self.is_hard_negative,
            "hard_negative_reason": self.hard_negative_reason,
        }


@dataclass
class BestOfNResult:
    """Result of the Best-of-N tree search process."""

    challenge_id: str
    num_candidates: int
    candidates: list[CandidateResult]

    # Selection outcome
    selected_candidate: Optional[CandidateResult]
    selection_reason: str

    # Aggregated signals
    hard_negatives: list[CandidateResult]
    all_failed: bool

    # Timing
    total_time_ms: int

    def to_dict(self) -> dict:
        return {
            "challenge_id": self.challenge_id,
            "num_candidates": self.num_candidates,
            "candidates": [c.to_dict() for c in self.candidates],
            "selected_candidate_id": self.selected_candidate.candidate_id if self.selected_candidate else None,
            "selection_reason": self.selection_reason,
            "hard_negative_count": len(self.hard_negatives),
            "all_failed": self.all_failed,
            "total_time_ms": self.total_time_ms,
        }


@dataclass
class BestOfNConfig:
    """Configuration for Best-of-N tree search."""

    # Number of candidates to generate
    num_candidates: int = 3

    # Confidence threshold for "high confidence" (used in Hard Negative detection)
    high_confidence_threshold: float = 0.7

    # Reasoning score threshold for "correct reasoning" (used in Hard Negative detection)
    correct_reasoning_threshold: float = 0.6

    # Temperature for candidate diversity (higher = more diverse)
    candidate_temperature: float = 0.8

    # Whether to run early filters in parallel
    parallel_early_filter: bool = True

    # Whether to tag Hard Negatives for DPO priority
    tag_hard_negatives: bool = True


class PraxisRunner:
    """
    Orchestrates the Praxis Loop: Reasoning → Verification → Calibration.

    Usage:
        runner = PraxisRunner(model_id="my-model")
        result = await runner.run_challenge(challenge, phase_responses)

        if result.calibration.is_hallucination:
            print("Detected hallucination - high-value DPO rejected sample")
    """

    def __init__(
        self,
        model_id: str,
        output_dir: Optional[Path] = None,
        mcp_executor: Optional[MCPExecutor] = None,
        confidence_threshold: float = 0.8,  # Per spec: >0.8 is "high confidence"
        execution_threshold: float = 0.3,
        auto_init_mcp: bool = True,
        best_of_n_config: Optional[BestOfNConfig] = None,
        llm_client: Optional[Any] = None,  # LLM client for candidate generation
        # MLX Expert Mixture Adapter settings
        enable_adapter_switching: bool = True,
        adapter_config: Optional["AdapterConfig"] = None,
        mlx_client: Optional["MLXAdapterClient"] = None,
        # RAG settings
        enable_rag: bool = False,
        rag_persist_dir: Optional[Path] = None,
        rag_max_tokens: int = 2000,
    ):
        """
        Initialize Praxis Runner.

        Args:
            model_id: Identifier for the model being evaluated
            output_dir: Where to save results
            mcp_executor: Optional MCPExecutor instance (creates one if None)
            confidence_threshold: Confidence above this is considered "high"
            execution_threshold: Execution rate below this is considered "fail"
            auto_init_mcp: Automatically initialize MCP executor on first run
            best_of_n_config: Configuration for Best-of-N tree search
            llm_client: LLM client for generating candidate responses
            enable_adapter_switching: Enable automatic LoRA adapter switching (M3 Max)
            adapter_config: Configuration for Expert Mixture adapters
            mlx_client: Pre-configured MLX adapter client
            enable_rag: Enable RAG context augmentation for prompts
            rag_persist_dir: Directory for RAG vector store persistence
            rag_max_tokens: Maximum tokens for RAG context
        """
        self.model_id = model_id
        self.output_dir = output_dir or Path("praxis_output")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.mcp_executor = mcp_executor or MCPExecutor()
        self.confidence_threshold = confidence_threshold
        self.execution_threshold = execution_threshold
        self.auto_init_mcp = auto_init_mcp
        self._mcp_initialized = False

        # Best-of-N configuration
        self.best_of_n_config = best_of_n_config or BestOfNConfig()
        self.llm_client = llm_client

        # Expert Mixture Adapter configuration (M3 Max optimization)
        self.enable_adapter_switching = enable_adapter_switching and MLX_AVAILABLE
        self.adapter_config = adapter_config
        self.mlx_client = mlx_client
        self._current_adapter_pillar: Optional[Pillar] = None

        # Initialize MLX adapter client if enabled
        if self.enable_adapter_switching and MLX_AVAILABLE:
            if self.mlx_client is None and AdapterConfig is not None:
                self.adapter_config = adapter_config or AdapterConfig.from_env()
                # Lazy initialization - don't load model until first use
                logger.info(
                    "[Expert Mixture] Adapter switching enabled. "
                    "MLX client will be initialized on first challenge."
                )

        # RAG configuration
        self._rag_enabled = enable_rag and RAG_AVAILABLE
        self._rag_persist_dir = rag_persist_dir
        self._rag_max_tokens = rag_max_tokens
        self._rag_augmenter: Optional["RAGPromptAugmenter"] = None

        if self._rag_enabled:
            logger.info(
                "[RAG] RAG augmentation enabled. "
                "Augmenter will be initialized on first use."
            )

        # Underlying V2 grader
        self.grading_runner = GradingRunner(
            model_id=model_id,
            output_dir=output_dir,
            generate_dpo=False,  # We'll generate DPO ourselves with calibration
        )

        # Storage
        self.praxis_runs: list[PraxisRun] = []
        self.best_of_n_results: list[BestOfNResult] = []
        self.hard_negatives: list[CandidateResult] = []  # Priority DPO training queue
        self._adapter_switch_count = 0
        self._adapter_switch_time_ms = 0

    # -------------------------------------------------------------------------
    # Main Entry Point
    # -------------------------------------------------------------------------

    async def run_challenge(
        self,
        challenge: ChallengeV2,
        phase_responses: dict[PhaseID, str],
    ) -> PraxisRun:
        """
        Execute the full Praxis Loop for a challenge.

        1. Detect challenge pillar and load specialized adapter (M3 Max)
        2. Grade V2 reasoning phases
        3. Execute verification tasks via MCP
        4. Compute calibration
        5. Generate DPO signal
        """
        # Initialize MCP executor if needed
        if self.auto_init_mcp and not self._mcp_initialized:
            await self.mcp_executor.initialize()
            self._mcp_initialized = True
            logger.info(f"MCP Executor initialized: {self.mcp_executor.get_status()}")

        # =====================================================================
        # EXPERT MIXTURE: Auto-detect pillar and switch adapter
        # =====================================================================
        if self.enable_adapter_switching:
            await self._switch_adapter_for_challenge(challenge)

        # =====================================================================
        # RAG: Log RAG status for this challenge
        # =====================================================================
        if self._rag_enabled:
            logger.info(
                f"[RAG] Active for {challenge.id} (pillar={challenge.pillar.value})"
            )

        started_at = datetime.now()

        # Step 1: Grade V2 reasoning
        grading_run = self.grading_runner.grade_challenge(
            challenge=challenge,
            phase_responses=phase_responses,
            generate_synthetic_dpo=False,
        )

        # Step 2: Extract model's stated confidence
        stated_confidence = self._extract_confidence(phase_responses)

        # Step 3: Execute verification tasks
        verification_results = await self._execute_verification_tasks(
            challenge.verification_tasks
        )

        # Step 4: Compute calibration
        calibration = self._compute_calibration(
            reasoning_score=grading_run.total_score,
            stated_confidence=stated_confidence,
            verification_results=verification_results,
        )

        # Step 4b: Tag HALLUCINATION_EVENT in ReasoningChain metadata
        # Per spec: if confidence > 0.8 AND verification fails, tag as hallucination
        if calibration.is_hallucination:
            grading_run.reasoning_chain.metadata["HALLUCINATION_EVENT"] = True
            grading_run.reasoning_chain.metadata["hallucination_details"] = {
                "stated_confidence": calibration.stated_confidence,
                "execution_pass_rate": calibration.execution_pass_rate,
                "calibration_error": calibration.calibration_error,
                "category": calibration.category.value,
                "verification_failures": [
                    v.to_dict() for v in calibration.verification_results
                    if not v.passed
                ],
            }
            logger.warning(
                f"HALLUCINATION_EVENT tagged for {challenge.id}: "
                f"confidence={calibration.stated_confidence:.2f}, "
                f"pass_rate={calibration.execution_pass_rate:.2f}"
            )

        # Step 5: Generate DPO pair based on calibration
        dpo_pair = self._generate_praxis_dpo(
            challenge=challenge,
            phase_responses=phase_responses,
            calibration=calibration,
        )

        completed_at = datetime.now()

        praxis_run = PraxisRun(
            challenge_id=challenge.id,
            model_id=self.model_id,
            started_at=started_at,
            completed_at=completed_at,
            grading_run=grading_run,
            calibration=calibration,
            dpo_pair=dpo_pair,
        )

        self.praxis_runs.append(praxis_run)

        # Log calibration outcome
        self._log_calibration(praxis_run)

        return praxis_run

    async def generate_and_run_challenge(
        self,
        challenge: ChallengeV2,
        temperature: float = 0.7,
    ) -> PraxisRun:
        """
        Generate phase responses with RAG augmentation and run the Praxis loop.

        This is the primary method for end-to-end RAG-augmented evaluation.
        It generates LLM responses using RAG-enhanced prompts, then evaluates
        them with the full Praxis loop.

        Args:
            challenge: The challenge to evaluate
            temperature: Temperature for LLM generation

        Returns:
            PraxisRun with evaluation results

        Raises:
            ValueError: If no LLM client is configured
        """
        if not self.llm_client:
            raise ValueError(
                "LLM client required for generate_and_run_challenge(). "
                "Pass llm_client to PraxisRunner constructor."
            )

        # Log RAG status
        if self._rag_enabled:
            logger.info(
                f"[RAG] Generating responses with RAG augmentation for {challenge.id}"
            )
            augmenter = self._get_rag_augmenter()
            if augmenter:
                stats = augmenter.get_stats()
                logger.info(
                    f"[RAG] KBs available: {list(stats.get('collections', {}).keys())}, "
                    f"Total docs: {stats.get('total_documents', 0)}"
                )

        # Generate phase responses
        phase_responses = await self._generate_phase_responses(
            challenge=challenge,
            temperature=temperature,
        )

        # Run the Praxis loop
        return await self.run_challenge(
            challenge=challenge,
            phase_responses=phase_responses,
        )

    async def _generate_phase_responses(
        self,
        challenge: ChallengeV2,
        temperature: float = 0.7,
    ) -> dict[PhaseID, str]:
        """
        Generate responses for all phases using the LLM with RAG augmentation.

        Args:
            challenge: The challenge
            temperature: Generation temperature

        Returns:
            Dict mapping PhaseID to generated response
        """
        phase_responses: dict[PhaseID, str] = {}

        for i, phase in enumerate(challenge.phases):
            # Get RAG-augmented prompt
            prompt = self.get_augmented_prompt(challenge, phase_index=i)

            logger.debug(
                f"[Generate] Phase {phase.phase_id.value}: "
                f"prompt length={len(prompt)} chars"
            )

            # Generate response
            response = await self.llm_client.generate(
                prompt=prompt,
                temperature=temperature,
            )

            # Extract content from response
            if hasattr(response, 'content'):
                content = response.content
            elif hasattr(response, 'text'):
                content = response.text
            else:
                content = str(response)

            phase_responses[phase.phase_id] = content

        return phase_responses

    # -------------------------------------------------------------------------
    # BEST-OF-N TREE SEARCH
    # -------------------------------------------------------------------------

    async def run_challenge_best_of_n(
        self,
        challenge: ChallengeV2,
        generate_candidates_fn: Optional[Callable] = None,
    ) -> tuple[Optional[PraxisRun], BestOfNResult]:
        """
        Execute the Praxis Loop with Best-of-N tree search.

        This mitigates "tunnel vision" in 7B models by:
        1. Generating N independent candidate responses
        2. Running early filtering (first verification task only)
        3. Selecting the best candidate among those that pass
        4. Tagging "Hard Negatives" for priority DPO training

        Args:
            challenge: The challenge to evaluate
            generate_candidates_fn: Optional function to generate candidate responses.
                                   Signature: (challenge, num_candidates) -> list[dict[PhaseID, str]]
                                   If None, uses self.llm_client

        Returns:
            Tuple of (PraxisRun for selected candidate or None, BestOfNResult)
        """
        import asyncio
        import time

        start_time = time.time()
        config = self.best_of_n_config

        # Initialize MCP if needed
        if self.auto_init_mcp and not self._mcp_initialized:
            await self.mcp_executor.initialize()
            self._mcp_initialized = True
            logger.info(f"MCP Executor initialized for Best-of-N: {self.mcp_executor.get_status()}")

        # Validate challenge has verification tasks
        if not challenge.verification_tasks:
            raise ValueError(f"Challenge {challenge.id} has no verification tasks for early filtering")

        # =====================================================================
        # STEP 1: CANDIDATE GENERATION
        # =====================================================================
        logger.info(f"[Best-of-N] Generating {config.num_candidates} candidates for {challenge.id}")

        if generate_candidates_fn:
            candidate_responses = generate_candidates_fn(challenge, config.num_candidates)
        elif self.llm_client:
            candidate_responses = await self._generate_candidates_llm(
                challenge, config.num_candidates
            )
        else:
            raise ValueError("No candidate generation method available. Provide generate_candidates_fn or llm_client")

        # =====================================================================
        # STEP 2: EARLY FILTERING (First verification task only)
        # =====================================================================
        logger.info(f"[Best-of-N] Running early filter on {len(candidate_responses)} candidates")

        first_task = challenge.verification_tasks[0]
        candidates: list[CandidateResult] = []

        if config.parallel_early_filter:
            # Run early filters in parallel
            filter_tasks = [
                self._evaluate_candidate_early(
                    candidate_id=i,
                    phase_responses=responses,
                    first_task=first_task,
                    challenge=challenge,
                )
                for i, responses in enumerate(candidate_responses)
            ]
            candidates = await asyncio.gather(*filter_tasks)
        else:
            # Run sequentially
            for i, responses in enumerate(candidate_responses):
                candidate = await self._evaluate_candidate_early(
                    candidate_id=i,
                    phase_responses=responses,
                    first_task=first_task,
                    challenge=challenge,
                )
                candidates.append(candidate)

        # =====================================================================
        # STEP 3: SELECTION LOGIC
        # =====================================================================
        passing_candidates = [c for c in candidates if c.early_filter_passed]
        failing_candidates = [c for c in candidates if not c.early_filter_passed]

        logger.info(
            f"[Best-of-N] Early filter results: {len(passing_candidates)} passed, "
            f"{len(failing_candidates)} failed"
        )

        selected_candidate: Optional[CandidateResult] = None
        selection_reason: str = ""

        if not passing_candidates:
            # All candidates failed - select the one with highest reasoning score anyway
            # (for Hard Negative analysis)
            all_failed = True
            if candidates:
                selected_candidate = max(candidates, key=lambda c: c.reasoning_score)
                selected_candidate.status = CandidateStatus.SELECTED
                selection_reason = "all_failed_best_reasoning"
                logger.warning(
                    f"[Best-of-N] All candidates failed! Selecting best reasoning score: "
                    f"candidate_{selected_candidate.candidate_id} (score={selected_candidate.reasoning_score:.2f})"
                )
        else:
            all_failed = False
            # Select the candidate with highest reasoning score among passing
            selected_candidate = max(passing_candidates, key=lambda c: c.reasoning_score)
            selected_candidate.status = CandidateStatus.SELECTED
            selection_reason = "highest_reasoning_score"

            # Mark others as discarded
            for c in passing_candidates:
                if c != selected_candidate:
                    c.status = CandidateStatus.DISCARDED

            logger.info(
                f"[Best-of-N] Selected candidate_{selected_candidate.candidate_id} "
                f"(reasoning_score={selected_candidate.reasoning_score:.2f})"
            )

        # =====================================================================
        # STEP 4: HARD NEGATIVE DETECTION
        # =====================================================================
        hard_negatives = self._detect_hard_negatives(candidates, config)

        if hard_negatives:
            logger.info(
                f"[Best-of-N] Detected {len(hard_negatives)} Hard Negatives for priority DPO training"
            )
            if config.tag_hard_negatives:
                self.hard_negatives.extend(hard_negatives)

        # =====================================================================
        # STEP 5: RUN FULL PRAXIS ON SELECTED CANDIDATE
        # =====================================================================
        praxis_run: Optional[PraxisRun] = None

        if selected_candidate:
            logger.info(f"[Best-of-N] Running full Praxis on selected candidate_{selected_candidate.candidate_id}")
            praxis_run = await self.run_challenge(
                challenge=challenge,
                phase_responses=selected_candidate.phase_responses,
            )

            # Tag with Best-of-N metadata
            praxis_run.grading_run.reasoning_chain.metadata["best_of_n"] = {
                "num_candidates": config.num_candidates,
                "candidates_passed": len(passing_candidates),
                "selected_candidate_id": selected_candidate.candidate_id,
                "selection_reason": selection_reason,
                "hard_negatives_count": len(hard_negatives),
            }

        # Build result
        total_time_ms = int((time.time() - start_time) * 1000)

        best_of_n_result = BestOfNResult(
            challenge_id=challenge.id,
            num_candidates=config.num_candidates,
            candidates=candidates,
            selected_candidate=selected_candidate,
            selection_reason=selection_reason,
            hard_negatives=hard_negatives,
            all_failed=all_failed,
            total_time_ms=total_time_ms,
        )

        self.best_of_n_results.append(best_of_n_result)

        # Log summary
        self._log_best_of_n_result(best_of_n_result)

        return praxis_run, best_of_n_result

    async def _evaluate_candidate_early(
        self,
        candidate_id: int,
        phase_responses: dict[PhaseID, str],
        first_task: VerificationTask,
        challenge: ChallengeV2,
    ) -> CandidateResult:
        """
        Evaluate a single candidate with early filtering.

        Only executes the FIRST verification task to quickly prune bad candidates.
        """
        # Grade reasoning quality (quick evaluation)
        grading_run = self.grading_runner.grade_challenge(
            challenge=challenge,
            phase_responses=phase_responses,
            generate_synthetic_dpo=False,
        )
        reasoning_score = grading_run.total_score

        # Extract stated confidence
        stated_confidence = self._extract_confidence(phase_responses)

        # Execute ONLY the first verification task
        early_filter_result = await self._execute_single_task(first_task)
        early_filter_passed = early_filter_result.passed

        # Determine initial status
        status = (
            CandidateStatus.PASSED_EARLY_FILTER
            if early_filter_passed
            else CandidateStatus.FAILED_EARLY_FILTER
        )

        return CandidateResult(
            candidate_id=candidate_id,
            phase_responses=phase_responses,
            status=status,
            early_filter_passed=early_filter_passed,
            early_filter_result=early_filter_result,
            reasoning_score=reasoning_score,
            stated_confidence=stated_confidence,
        )

    def _detect_hard_negatives(
        self,
        candidates: list[CandidateResult],
        config: BestOfNConfig,
    ) -> list[CandidateResult]:
        """
        Detect Hard Negatives: candidates with high confidence + good reasoning but failed execution.

        These are the most valuable DPO training signals because the model was:
        - Confident (thought it was right)
        - Articulate (produced good-looking reasoning)
        - But WRONG (execution failed)

        This teaches the model that plausible-sounding reasoning can still be wrong.
        """
        hard_negatives = []

        for candidate in candidates:
            # Check for Hard Negative criteria
            is_high_confidence = candidate.stated_confidence >= config.high_confidence_threshold
            is_correct_reasoning = candidate.reasoning_score >= config.correct_reasoning_threshold
            failed_execution = not candidate.early_filter_passed

            if is_high_confidence and is_correct_reasoning and failed_execution:
                candidate.is_hard_negative = True
                candidate.hard_negative_reason = (
                    f"High confidence ({candidate.stated_confidence:.2f}) + "
                    f"Good reasoning ({candidate.reasoning_score:.2f}) + "
                    f"Failed execution"
                )

                hard_negatives.append(candidate)

                logger.warning(
                    f"[Hard Negative] candidate_{candidate.candidate_id}: "
                    f"conf={candidate.stated_confidence:.2f}, "
                    f"reasoning={candidate.reasoning_score:.2f}, "
                    f"exec=FAILED"
                )

        return hard_negatives

    async def _generate_candidates_llm(
        self,
        challenge: ChallengeV2,
        num_candidates: int,
    ) -> list[dict[PhaseID, str]]:
        """
        Generate candidate responses using the LLM client.

        Uses higher temperature for diversity among candidates.
        """
        if not self.llm_client:
            raise ValueError("No LLM client configured for candidate generation")

        candidates = []
        config = self.best_of_n_config

        # Generate prompt from challenge (with optional RAG augmentation)
        prompt = self.get_augmented_prompt(challenge, phase_index=0)

        for i in range(num_candidates):
            logger.debug(f"[Best-of-N] Generating candidate {i+1}/{num_candidates}")

            # Call LLM with diversity temperature
            response = await self.llm_client.generate(
                prompt=prompt,
                temperature=config.candidate_temperature,
                # Add seed variation for diversity
                seed=i * 12345 if hasattr(self.llm_client, 'generate') else None,
            )

            # Parse response into phase outputs
            # For now, assume single-phase challenges; extend as needed
            phase_responses = {
                challenge.phases[0].phase_id: response.content
                if hasattr(response, 'content') else str(response)
            }

            candidates.append(phase_responses)

        return candidates

    def _log_best_of_n_result(self, result: BestOfNResult) -> None:
        """Log Best-of-N search result summary."""
        status_counts = {}
        for c in result.candidates:
            status_counts[c.status.value] = status_counts.get(c.status.value, 0) + 1

        logger.info(
            f"[Best-of-N Summary] {result.challenge_id}: "
            f"candidates={result.num_candidates}, "
            f"passed={len([c for c in result.candidates if c.early_filter_passed])}, "
            f"hard_negatives={len(result.hard_negatives)}, "
            f"selected={'candidate_' + str(result.selected_candidate.candidate_id) if result.selected_candidate else 'None'}, "
            f"time={result.total_time_ms}ms"
        )

    def get_hard_negatives(self) -> list[CandidateResult]:
        """Get all collected Hard Negatives for priority DPO training."""
        return self.hard_negatives

    def get_hard_negative_dpo_pairs(self) -> list[DPOPair]:
        """
        Convert Hard Negatives to DPO pairs for priority training.

        Hard Negatives are the highest-value training signals because
        they represent articulate hallucinations.
        """
        import uuid
        pairs = []

        for candidate in self.hard_negatives:
            # Build the full response
            full_response = self._build_full_response(candidate.phase_responses)

            # Hard negatives become REJECTED samples
            pair = DPOPair(
                pair_id=f"hard_neg_{uuid.uuid4().hex[:8]}",
                challenge_id="unknown",  # Would need challenge context
                phase_id=PhaseID.ANALYZE,
                prompt="",  # Would need challenge prompt
                chosen="",  # Needs to be filled with correct response
                rejected=full_response,
                chosen_score=0.0,
                rejected_score=candidate.reasoning_score,
                margin=candidate.reasoning_score,  # High margin = valuable signal
                rejection_reasons=[
                    "hard_negative",
                    candidate.hard_negative_reason or "high_confidence_good_reasoning_failed_execution",
                ],
                chosen_source="praxis",
                rejected_source="best_of_n_hard_negative",
                signal_weight=1.5,  # Priority weight for Hard Negatives
                stated_confidence=candidate.stated_confidence,
                is_hallucination=True,
            )
            pairs.append(pair)

        return pairs

    # -------------------------------------------------------------------------
    # Verification Execution
    # -------------------------------------------------------------------------

    async def _execute_verification_tasks(
        self,
        tasks: list[VerificationTask],
    ) -> list[VerificationResult]:
        """Execute all verification tasks and collect results."""
        results = []

        for task in tasks:
            result = await self._execute_single_task(task)
            results.append(result)

        return results

    async def _execute_single_task(
        self,
        task: VerificationTask,
    ) -> VerificationResult:
        """Execute a single verification task via MCPExecutor."""
        import time
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

            # Validate output against task rules
            if tool_result.success:
                passed = self._validate_output(raw_output, task.validation_rule)
            else:
                passed = False

            error = tool_result.error

        except Exception as e:
            raw_output = None
            passed = False
            error = str(e)
            logger.exception(f"Error executing verification task: {task.instruction}")

        execution_time = int((time.time() - start_time) * 1000)

        return VerificationResult(
            task=task,
            tool_called=tool_name,
            tool_args=tool_args,
            raw_output=raw_output,
            passed=passed,
            execution_time_ms=execution_time,
            error=error,
        )

    def _validate_output(
        self,
        output: Any,
        validation_rule: dict,
    ) -> bool:
        """Validate execution output against the task's validation rule."""
        if not validation_rule:
            # No rule = just check for non-error output
            if isinstance(output, dict):
                return output.get("exit_code", -1) == 0 or "error" not in output
            return output is not None

        rule_type = validation_rule.get("type", "")

        if rule_type == "output_contains":
            expected = validation_rule.get("expected", "")
            output_str = str(output.get("stdout", output) if isinstance(output, dict) else output)
            return expected.lower() in output_str.lower()

        elif rule_type == "regex":
            pattern = validation_rule.get("pattern", "")
            output_str = str(output.get("stdout", output) if isinstance(output, dict) else output)
            return bool(re.search(pattern, output_str))

        elif rule_type == "exit_code":
            expected_code = validation_rule.get("expected", 0)
            if isinstance(output, dict):
                return output.get("exit_code") == expected_code
            return False

        elif rule_type == "json_path":
            # Validate a specific JSON path has expected value
            path = validation_rule.get("path", "")
            expected = validation_rule.get("expected")
            try:
                data = output if isinstance(output, dict) else json.loads(str(output))
                for key in path.split("."):
                    data = data[key]
                return data == expected
            except (KeyError, json.JSONDecodeError, TypeError):
                return False

        return False

    # -------------------------------------------------------------------------
    # Calibration
    # -------------------------------------------------------------------------

    def _compute_calibration(
        self,
        reasoning_score: float,
        stated_confidence: float,
        verification_results: list[VerificationResult],
    ) -> CalibrationResult:
        """Compute calibration metrics from reasoning and verification."""

        # Calculate execution pass rate
        if verification_results:
            passed_count = sum(1 for r in verification_results if r.passed)
            execution_pass_rate = passed_count / len(verification_results)
        else:
            execution_pass_rate = 0.0

        # Calibration error = gap between confidence and reality
        calibration_error = abs(stated_confidence - execution_pass_rate)

        # Categorize the outcome
        category = self._categorize_calibration(
            stated_confidence,
            execution_pass_rate,
        )

        # Check for hallucination
        is_hallucination = self.is_hallucination(
            stated_confidence=stated_confidence,
            execution_pass_rate=execution_pass_rate,
            reasoning_score=reasoning_score,
        )

        return CalibrationResult(
            reasoning_score=reasoning_score,
            stated_confidence=stated_confidence,
            execution_pass_rate=execution_pass_rate,
            calibration_error=calibration_error,
            category=category,
            is_hallucination=is_hallucination,
            verification_results=verification_results,
        )

    def _categorize_calibration(
        self,
        confidence: float,
        execution_rate: float,
    ) -> CalibrationCategory:
        """Categorize the calibration outcome."""
        high_conf = confidence >= self.confidence_threshold
        passed = execution_rate >= (1 - self.execution_threshold)

        if high_conf and passed:
            return CalibrationCategory.TRUE_UNDERSTANDING
        elif high_conf and not passed:
            return CalibrationCategory.HALLUCINATION
        elif not high_conf and passed:
            return CalibrationCategory.UNDER_CALIBRATED
        else:
            return CalibrationCategory.APPROPRIATE_UNCERTAINTY

    # -------------------------------------------------------------------------
    # SKELETON FOR USER TO TUNE
    # -------------------------------------------------------------------------

    def is_hallucination(
        self,
        stated_confidence: float,
        execution_pass_rate: float,
        reasoning_score: float,
    ) -> bool:
        """
        Determine if this response is a hallucination.

        A hallucination occurs when the model expresses high confidence
        but the verification tasks fail, indicating the model "sounds right"
        without actually being right.

        ┌─────────────────────────────────────────────────────────────────┐
        │  TODO: Tune these thresholds based on your training goals      │
        │                                                                 │
        │  STRICT (fewer flags, higher precision):                        │
        │    confidence > 0.85 AND execution_rate < 0.15                  │
        │                                                                 │
        │  MODERATE (balanced):                                           │
        │    confidence > 0.70 AND execution_rate < 0.30                  │
        │                                                                 │
        │  LOOSE (more flags, catches subtle overconfidence):             │
        │    confidence > 0.60 AND execution_rate < 0.40                  │
        │                                                                 │
        │  Consider also using reasoning_score:                           │
        │    - High reasoning + low execution = articulate hallucination  │
        │    - Low reasoning + low execution = general confusion          │
        └─────────────────────────────────────────────────────────────────┘

        Args:
            stated_confidence: Model's self-reported confidence (0.0-1.0)
            execution_pass_rate: Fraction of verification tasks that passed
            reasoning_score: V2 reasoning quality score (0.0-1.0)

        Returns:
            True if this appears to be a hallucination
        """
        # Current: MODERATE threshold
        # Adjust based on your training data quality needs

        confidence_is_high = stated_confidence > self.confidence_threshold  # default 0.7
        execution_failed = execution_pass_rate < self.execution_threshold   # default 0.3

        # Basic hallucination: confident but wrong
        basic_hallucination = confidence_is_high and execution_failed

        # Articulate hallucination: also scored well on reasoning (worse!)
        # This means the model produced plausible-sounding reasoning that's wrong
        # TODO: Weight articulate hallucinations more heavily in DPO
        _articulate_hallucination = (
            basic_hallucination and
            reasoning_score > 0.6
        )

        # For now, flag both types
        return basic_hallucination

    # -------------------------------------------------------------------------
    # DPO Generation
    # -------------------------------------------------------------------------

    def _generate_praxis_dpo(
        self,
        challenge: ChallengeV2,
        phase_responses: dict[PhaseID, str],
        calibration: CalibrationResult,
    ) -> Optional[DPOPair]:
        """Generate DPO pair based on Praxis calibration."""

        # Only generate for significant signals
        if calibration.dpo_signal_strength < 0.5:
            return None

        # Build the full response from phases
        full_response = self._build_full_response(phase_responses)

        import uuid

        # Build prompt from challenge (with RAG augmentation if enabled)
        prompt = self.get_augmented_prompt(challenge, phase_index=0)

        # Determine the primary phase for this DPO pair
        primary_phase = challenge.phases[0].phase_id if challenge.phases else PhaseID.OBSERVE

        if calibration.is_hallucination:
            # This is a REJECTED sample - the model was confidently wrong
            return DPOPair(
                pair_id=f"praxis_{uuid.uuid4().hex[:8]}",
                challenge_id=challenge.id,
                phase_id=primary_phase,
                prompt=prompt,
                chosen="",  # Will be filled by amplification with correct answer
                rejected=full_response,
                chosen_score=0.0,
                rejected_score=calibration.reasoning_score,
                margin=calibration.calibration_error,
                rejection_reasons=["hallucination", "high_confidence_wrong"],
                chosen_source="praxis",
                rejected_source="model",
                calibration_category=calibration.category.value,
                signal_weight=calibration.dpo_signal_strength,
                stated_confidence=calibration.stated_confidence,
                execution_pass_rate=calibration.execution_pass_rate,
                is_hallucination=True,
            )
        elif calibration.category == CalibrationCategory.TRUE_UNDERSTANDING:
            # This is a CHOSEN sample - the model was correctly confident
            return DPOPair(
                pair_id=f"praxis_{uuid.uuid4().hex[:8]}",
                challenge_id=challenge.id,
                phase_id=primary_phase,
                prompt=prompt,
                chosen=full_response,
                rejected="",  # Will be filled by amplification with incorrect answer
                chosen_score=calibration.reasoning_score,
                rejected_score=0.0,
                margin=1.0 - calibration.calibration_error,
                rejection_reasons=[],
                chosen_source="model",
                rejected_source="praxis",
                calibration_category=calibration.category.value,
                signal_weight=calibration.dpo_signal_strength,
                stated_confidence=calibration.stated_confidence,
                execution_pass_rate=calibration.execution_pass_rate,
                is_hallucination=False,
            )

        return None

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _extract_confidence(self, phase_responses: dict[PhaseID, str]) -> float:
        """Extract model's stated confidence from responses."""
        # Look for confidence statements in the responses
        confidence_patterns = [
            r"confidence[:\s]+(\d+(?:\.\d+)?)",
            r"(\d+(?:\.\d+)?)\s*%?\s*confident",
            r"certainty[:\s]+(\d+(?:\.\d+)?)",
        ]

        for response in phase_responses.values():
            for pattern in confidence_patterns:
                match = re.search(pattern, response.lower())
                if match:
                    value = float(match.group(1))
                    # Normalize to 0-1 if percentage
                    if value > 1:
                        value = value / 100
                    return min(1.0, max(0.0, value))

        # Default to moderate confidence if not stated
        return 0.5

    def _build_full_response(self, phase_responses: dict[PhaseID, str]) -> str:
        """Build full response string from phase outputs."""
        parts = []
        for phase_id in [PhaseID.OBSERVE, PhaseID.HYPOTHESIZE, PhaseID.TEST,
                         PhaseID.ANALYZE, PhaseID.SYNTHESIZE]:
            if phase_id in phase_responses:
                parts.append(f"## {phase_id.value.title()}\n{phase_responses[phase_id]}")
        return "\n\n".join(parts)

    # -------------------------------------------------------------------------
    # EXPERT MIXTURE ADAPTER SWITCHING
    # -------------------------------------------------------------------------

    async def _switch_adapter_for_challenge(self, challenge: ChallengeV2) -> bool:
        """
        Detect challenge pillar and switch to the specialized LoRA adapter.

        This leverages M3 Max's Unified Memory to keep the base model
        resident while only swapping the small LoRA weights (~100MB).

        Args:
            challenge: The challenge to analyze

        Returns:
            True if adapter was switched successfully
        """
        if not self.enable_adapter_switching:
            return False

        pillar = challenge.pillar

        # Skip if same adapter already active
        if self._current_adapter_pillar == pillar:
            logger.debug(f"[Expert Mixture] Adapter already active: {pillar.value}")
            return True

        # Lazy initialize MLX client on first use
        if self.mlx_client is None:
            if not self._initialize_mlx_client():
                logger.warning("[Expert Mixture] MLX client initialization failed")
                return False

        logger.info(
            f"[Expert Mixture] Switching adapter: {self._current_adapter_pillar} -> {pillar.value}"
        )

        import time
        start_time = time.time()

        try:
            if not self.mlx_client:
                 logger.warning("[Expert Mixture] MLX client not initialized")
                 return False

            success = self.mlx_client.switch_adapter(pillar)

            if success:
                switch_time_ms = int((time.time() - start_time) * 1000)
                self._adapter_switch_count += 1
                self._adapter_switch_time_ms += switch_time_ms
                self._current_adapter_pillar = pillar

                logger.info(
                    f"[Expert Mixture] Adapter switch complete: {pillar.value} "
                    f"({switch_time_ms}ms, avg: {self._adapter_switch_time_ms // max(1, self._adapter_switch_count)}ms)"
                )
                return True
            else:
                logger.warning(f"[Expert Mixture] Failed to switch to adapter: {pillar.value}")
                return False

        except Exception as e:
            logger.error(f"[Expert Mixture] Adapter switch error: {e}")
            return False

    def _initialize_mlx_client(self) -> bool:
        """
        Initialize the MLX adapter client (lazy initialization).

        This is expensive (loads base model) so we defer until first use.
        """
        if not MLX_AVAILABLE:
            logger.warning("[Expert Mixture] MLX not available (not on Apple Silicon?)")
            return False

        try:
            logger.info("[Expert Mixture] Initializing MLX client (loading base model)...")

            self.mlx_client = MLXAdapterClient(
                adapter_config=self.adapter_config,
                auto_load_base=True,
            )

            if self.mlx_client.is_ready():
                logger.info("[Expert Mixture] MLX client initialized successfully")
                return True
            else:
                logger.error("[Expert Mixture] MLX client failed to initialize")
                return False

        except Exception as e:
            logger.error(f"[Expert Mixture] MLX initialization error: {e}")
            return False

    def get_adapter_stats(self) -> dict:
        """Get Expert Mixture adapter statistics."""
        stats = {
            "enabled": self.enable_adapter_switching,
            "mlx_available": MLX_AVAILABLE,
            "current_adapter": self._current_adapter_pillar.value if self._current_adapter_pillar else None,
            "total_switches": self._adapter_switch_count,
            "avg_switch_time_ms": (
                self._adapter_switch_time_ms // max(1, self._adapter_switch_count)
            ),
        }

        if self.mlx_client:
            stats["mlx_client_stats"] = self.mlx_client.get_adapter_stats()

        return stats

    # -------------------------------------------------------------------------
    # RAG INTEGRATION
    # -------------------------------------------------------------------------

    def _get_rag_augmenter(self) -> Optional["RAGPromptAugmenter"]:
        """
        Get or initialize the RAG prompt augmenter (lazy initialization).

        Returns:
            RAGPromptAugmenter instance or None if RAG is disabled
        """
        if not self._rag_enabled:
            return None

        if self._rag_augmenter is None and RAG_AVAILABLE:
            logger.info("[RAG] Initializing RAG prompt augmenter...")
            self._rag_augmenter = RAGPromptAugmenter(
                persist_dir=self._rag_persist_dir,
                enabled=True,
                max_context_tokens=self._rag_max_tokens,
            )
            logger.info("[RAG] RAG prompt augmenter initialized")

        return self._rag_augmenter

    def set_rag_enabled(self, enabled: bool) -> bool:
        """
        Enable or disable RAG augmentation at runtime.

        Args:
            enabled: Whether to enable RAG

        Returns:
            True if RAG is now in the requested state
        """
        if enabled and not RAG_AVAILABLE:
            logger.warning("[RAG] Cannot enable RAG - module not available")
            return False

        self._rag_enabled = enabled
        if enabled:
            logger.info("[RAG] RAG augmentation enabled")
        else:
            logger.info("[RAG] RAG augmentation disabled")

        return True

    def get_augmented_prompt(
        self,
        challenge: ChallengeV2,
        phase_index: int = 0,
    ) -> str:
        """
        Get a challenge prompt augmented with RAG context.

        If RAG is disabled, returns the base prompt.

        Args:
            challenge: The challenge
            phase_index: Phase index for prompt generation

        Returns:
            Augmented prompt string
        """
        base_prompt = challenge.to_prompt(phase_index)

        augmenter = self._get_rag_augmenter()
        if augmenter is None:
            return base_prompt

        return augmenter.augment_challenge_prompt(
            challenge=challenge,
            phase_index=phase_index,
        )

    def get_rag_stats(self) -> dict:
        """Get RAG system statistics."""
        stats = {
            "enabled": self._rag_enabled,
            "rag_available": RAG_AVAILABLE,
            "max_context_tokens": self._rag_max_tokens,
        }

        augmenter = self._get_rag_augmenter()
        if augmenter:
            stats["augmenter_stats"] = augmenter.get_stats()

        return stats

    def _log_calibration(self, run: PraxisRun) -> None:
        """Log calibration outcome for monitoring."""
        cal = run.calibration

        emoji = {
            CalibrationCategory.TRUE_UNDERSTANDING: "✓",
            CalibrationCategory.HALLUCINATION: "⚠",
            CalibrationCategory.UNDER_CALIBRATED: "↓",
            CalibrationCategory.APPROPRIATE_UNCERTAINTY: "~",
        }[cal.category]

        logger.info(
            f"{emoji} [{run.challenge_id}] "
            f"Conf={cal.stated_confidence:.2f} "
            f"Exec={cal.execution_pass_rate:.2f} "
            f"CalErr={cal.calibration_error:.2f} "
            f"→ {cal.category.value}"
        )

        if cal.is_hallucination:
            logger.warning(
                f"  HALLUCINATION DETECTED: High confidence ({cal.stated_confidence:.2f}) "
                f"but execution failed ({cal.execution_pass_rate:.2f})"
            )

    # -------------------------------------------------------------------------
    # Export
    # -------------------------------------------------------------------------

    def export_results(self, filepath: Path) -> None:
        """Export all Praxis runs to JSON."""
        results = []
        for run in self.praxis_runs:
            results.append({
                "challenge_id": run.challenge_id,
                "model_id": run.model_id,
                "started_at": run.started_at.isoformat(),
                "completed_at": run.completed_at.isoformat(),
                "reasoning_score": run.grading_run.total_score,
                "calibration": run.calibration.to_dict(),
                "is_high_quality_signal": run.is_high_quality_signal,
            })

        with open(filepath, "w") as f:
            json.dump(results, f, indent=2)

        logger.info(f"Exported {len(results)} Praxis runs to {filepath}")

    def get_hallucination_rate(self) -> float:
        """Calculate overall hallucination rate."""
        if not self.praxis_runs:
            return 0.0
        hallucinations = sum(
            1 for r in self.praxis_runs
            if r.calibration.is_hallucination
        )
        return hallucinations / len(self.praxis_runs)



    def get_dpo_pairs(self) -> list[DPOPair]:
        """Get all generated DPO pairs from Praxis runs."""
        pairs = []
        for run in self.praxis_runs:
            if run.dpo_pair:
                pairs.append(run.dpo_pair)
        return pairs



    # -------------------------------------------------------------------------
    # MCP Integration
    # -------------------------------------------------------------------------

    async def shutdown(self) -> None:
        """Shutdown the Praxis Runner and its MCP executor."""
        if self._mcp_initialized:
            await self.mcp_executor.shutdown()
            self._mcp_initialized = False
            logger.info("Praxis Runner shutdown complete")

    def get_mcp_status(self) -> dict:
        """Get MCP executor status."""
        return {
            "initialized": self._mcp_initialized,
            "executor_status": self.mcp_executor.get_status(),
        }

    async def health_check(self) -> dict:
        """Run health check on MCP servers."""
        return await self.mcp_executor.health_check()

    def get_available_tools(self) -> list[str]:
        """Get list of available MCP tools."""
        return self.mcp_executor.get_available_tools()

    # -------------------------------------------------------------------------
    # Context Manager Support
    # -------------------------------------------------------------------------

    async def __aenter__(self) -> "PraxisRunner":
        """Async context manager entry."""
        await self.mcp_executor.initialize()
        self._mcp_initialized = True
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.shutdown()


# Convenience function for one-off challenge evaluation
async def evaluate_challenge(
    challenge: ChallengeV2,
    phase_responses: dict[PhaseID, str],
    model_id: str = "eval-model",
) -> PraxisRun:
    """
    Quick evaluation of a single challenge with Praxis loop.

    Usage:
        result = await evaluate_challenge(challenge, responses)
        if result.calibration.is_hallucination:
            print("Hallucination detected!")
    """
    async with PraxisRunner(model_id=model_id) as runner:
        return await runner.run_challenge(challenge, phase_responses)
