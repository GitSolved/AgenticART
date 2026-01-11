"""
Baseline Comparison Experiment

Validates whether AgenticART's complexity is justified by comparing:
- Full pipeline (7 adapters + Best-of-N + CoT)
- Expert Mixture only
- Single LoRA adapter
- Base model with prompting
- Claude with prompting

Usage:
    # Create holdout test set first (do this ONCE before training)
    python create_test_set.py

    # Run experiment
    python experiment_runner.py

    # Analyze results
    python statistical_analysis.py results/results_*.json
"""

from .experiment_config import (
    ARM_CONFIGS,
    ArmConfig,
    ChallengeTier,
    ExperimentArm,
    ExperimentConfig,
)

__all__ = [
    "ArmConfig",
    "ARM_CONFIGS",
    "ChallengeTier",
    "ExperimentArm",
    "ExperimentConfig",
]
