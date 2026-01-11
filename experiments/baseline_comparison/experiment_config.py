"""
Baseline Comparison Experiment Configuration

This experiment tests whether AgenticART's complexity is justified
by comparing against simpler baselines.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Optional


class ExperimentArm(Enum):
    """The 5 experimental conditions."""

    # Baseline: Frontier model with prompting only
    CLAUDE_PROMPTED = auto()

    # Baseline: 7B model, no fine-tuning
    QWEN_PROMPTED = auto()

    # Ablation: Single general-purpose LoRA
    QWEN_SINGLE_LORA = auto()

    # Ablation: Expert Mixture without Best-of-N
    QWEN_EXPERT_MIXTURE = auto()

    # Full treatment: Expert Mixture + Best-of-N + CoT
    AGENTIC_ART_FULL = auto()


class ChallengeTier(Enum):
    """Difficulty stratification for test challenges."""
    WHITE = "white"
    YELLOW = "yellow"
    GREEN = "green"
    BROWN = "brown"
    BLACK = "black"
    NOVEL = "novel"  # Unseen patterns for generalization testing


@dataclass
class ArmConfig:
    """Configuration for a single experimental arm."""

    arm: ExperimentArm
    model_id: str
    adapter_path: Optional[str] = None
    use_expert_mixture: bool = False
    best_of_n: int = 1
    enforce_cot: bool = False
    temperature: float = 0.7
    max_tokens: int = 4096

    # For Claude baseline
    api_provider: Optional[str] = None  # "anthropic" or None for local


# Arm configurations
ARM_CONFIGS = {
    ExperimentArm.CLAUDE_PROMPTED: ArmConfig(
        arm=ExperimentArm.CLAUDE_PROMPTED,
        model_id="claude-sonnet-4-20250514",
        api_provider="anthropic",
        temperature=0.7,
    ),

    ExperimentArm.QWEN_PROMPTED: ArmConfig(
        arm=ExperimentArm.QWEN_PROMPTED,
        model_id="models/qwen2.5-7b-instruct",
        temperature=0.7,
    ),

    ExperimentArm.QWEN_SINGLE_LORA: ArmConfig(
        arm=ExperimentArm.QWEN_SINGLE_LORA,
        model_id="models/qwen2.5-7b-instruct",
        adapter_path="adapters/qwen_general_lora",  # Single adapter for all pillars
        temperature=0.7,
    ),

    ExperimentArm.QWEN_EXPERT_MIXTURE: ArmConfig(
        arm=ExperimentArm.QWEN_EXPERT_MIXTURE,
        model_id="models/qwen2.5-7b-instruct",
        use_expert_mixture=True,  # Switches adapters per pillar
        temperature=0.7,
    ),

    ExperimentArm.AGENTIC_ART_FULL: ArmConfig(
        arm=ExperimentArm.AGENTIC_ART_FULL,
        model_id="models/qwen2.5-7b-instruct",
        use_expert_mixture=True,
        best_of_n=3,
        enforce_cot=True,
        temperature=0.7,
    ),
}


@dataclass
class ExperimentConfig:
    """Master configuration for the baseline comparison experiment."""

    # Experiment identification
    experiment_id: str = "baseline_v1"

    # Test set configuration
    test_set_path: Path = Path("experiments/baseline_comparison/test_challenges")
    challenges_per_tier: dict = field(default_factory=lambda: {
        ChallengeTier.WHITE: 20,
        ChallengeTier.YELLOW: 20,
        ChallengeTier.GREEN: 20,
        ChallengeTier.BROWN: 15,
        ChallengeTier.BLACK: 10,
        ChallengeTier.NOVEL: 15,
    })

    # Arms to run
    arms: list[ExperimentArm] = field(default_factory=lambda: list(ExperimentArm))

    # Execution settings
    max_retries: int = 2
    timeout_seconds: int = 300
    parallel_challenges: int = 1  # Serial for reproducibility

    # Randomization
    random_seed: int = 42
    shuffle_challenge_order: bool = True

    # Output
    results_dir: Path = Path("experiments/baseline_comparison/results")

    # Human evaluation settings
    human_eval_sample_size: int = 50  # Challenges to human-evaluate per arm
    require_dual_rating: bool = True  # Two raters for inter-rater reliability


@dataclass
class ChallengeResult:
    """Result from running a single challenge."""

    challenge_id: str
    arm: ExperimentArm
    tier: ChallengeTier
    pillar: str

    # Automated metrics
    execution_success: bool
    verification_passed: bool
    first_step_passed: bool
    time_seconds: float

    # Raw outputs
    model_response: str
    thinking_trace: Optional[str]
    verification_outputs: list[dict]

    # Error information
    error: Optional[str] = None

    # Human evaluation (filled later)
    human_reasoning_score: Optional[int] = None
    human_generalizability_score: Optional[int] = None
    human_actionability_score: Optional[int] = None
    human_false_confidence: Optional[bool] = None
    evaluator_id: Optional[str] = None


@dataclass
class ExperimentResults:
    """Aggregated results from the full experiment."""

    experiment_id: str
    config: ExperimentConfig

    # Per-challenge results
    challenge_results: list[ChallengeResult] = field(default_factory=list)

    # Computed after experiment
    summary_stats: Optional[dict] = None
    statistical_tests: Optional[dict] = None
