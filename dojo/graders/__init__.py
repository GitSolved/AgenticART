"""V2 Reasoning Graders for evaluating model responses to discovery challenges.

This module provides two runners:
- GradingRunner (Static): Grades reasoning quality only
- ActiveRunner (Live-Fire): Async runner with MCP execution and self-correction
"""

from dojo.graders.dpo_generator import DPOPair, DPOPairGenerator
from dojo.graders.metrics import CalibrationTracker, GradingMetrics
from dojo.graders.reasoning_grader import (
    HypothesisGrader,
    NegativeKnowledgeGrader,
    ObservationGrader,
    PhaseGrader,
    ReasoningGrader,
    RootCauseGrader,
    VerificationGrader,
)
from dojo.graders.runner import (
    ActiveRun,
    ActiveRunner,
    CalibrationCategory,
    CalibrationScore,
    GradingRun,
    GradingRunner,
    SelfCorrectionAttempt,
    VerificationResult,
)

__all__ = [
    # Static grading
    "ReasoningGrader",
    "PhaseGrader",
    "ObservationGrader",
    "HypothesisGrader",
    "RootCauseGrader",
    "NegativeKnowledgeGrader",
    "VerificationGrader",
    "GradingRunner",
    "GradingRun",
    # Active grading (async with MCP)
    "ActiveRunner",
    "ActiveRun",
    "CalibrationCategory",
    "CalibrationScore",
    "VerificationResult",
    "SelfCorrectionAttempt",
    # DPO generation
    "DPOPairGenerator",
    "DPOPair",
    # Metrics
    "GradingMetrics",
    "CalibrationTracker",
]
