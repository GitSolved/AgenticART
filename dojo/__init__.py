"""
AgenticART Dojo Framework

A training system for security LLMs using structured challenges,
automated grading, and continuous improvement through fine-tuning.
"""

from dojo.models import (
    Belt,
    Grade,
    ScriptType,
    Challenge,
    ChallengeInput,
    ChallengeResult,
    ExpectedOutput,
    ScoringRubric,
    SenseiAssessment,
    TrainingExample,
    ModelProgress,
)
from dojo.config import DojoConfig
from dojo.exceptions import (
    DojoError,
    ChallengeNotFoundError,
    InvalidBeltError,
    GradingError,
    ExportError,
    ExecutionError,
    ValidationError,
    CurriculumError,
)

# Curriculum imports (Phase 2)
from dojo.curriculum import (
    ChallengeLoader,
    Executor,
    ExecutionResult,
    ErrorExtractor,
    ErrorContext,
    ContextInjector,
    Challenger,
    AttemptRecord,
    ChallengeSession,
)

# Sensei imports (Phase 3)
from dojo.sensei import (
    Sensei,
    TrainingCycleResult,
    Grader,
    GradingCriteria,
    GradingResult,
    TrainingExtractor,
    ExtractionConfig,
    TrainingDataExporter,
    ExportFormat,
    DPOPair,
    ProgressTracker,
)

# Fine-tuning imports (Phase 4)
from dojo.finetune import (
    TrainingPackager,
    FinetuneConfig,
)

__version__ = "0.3.0"
__all__ = [
    # Models
    "Belt",
    "Grade",
    "ScriptType",
    "Challenge",
    "ChallengeInput",
    "ChallengeResult",
    "ExpectedOutput",
    "ScoringRubric",
    "SenseiAssessment",
    "TrainingExample",
    "ModelProgress",
    # Config
    "DojoConfig",
    # Exceptions
    "DojoError",
    "ChallengeNotFoundError",
    "InvalidBeltError",
    "GradingError",
    "ExportError",
    "ExecutionError",
    "ValidationError",
    "CurriculumError",
    # Curriculum (Phase 2)
    "ChallengeLoader",
    "Executor",
    "ExecutionResult",
    "ErrorExtractor",
    "ErrorContext",
    "ContextInjector",
    "Challenger",
    "AttemptRecord",
    "ChallengeSession",
    # Sensei (Phase 3)
    "Sensei",
    "TrainingCycleResult",
    "Grader",
    "GradingCriteria",
    "GradingResult",
    "TrainingExtractor",
    "ExtractionConfig",
    "TrainingDataExporter",
    "ExportFormat",
    "DPOPair",
    "ProgressTracker",
    # Fine-tuning (Phase 4)
    "TrainingPackager",
    "FinetuneConfig",
]
