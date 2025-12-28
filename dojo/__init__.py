"""
AgenticART Dojo Framework

A training system for security LLMs using structured challenges,
automated grading, and continuous improvement through fine-tuning.
"""

from dojo.config import DojoConfig

# Curriculum imports (Phase 2)
from dojo.curriculum import (
    AttemptRecord,
    ChallengeLoader,
    Challenger,
    ChallengeSession,
    ContextInjector,
    ErrorContext,
    ErrorExtractor,
    ExecutionResult,
    Executor,
)
from dojo.exceptions import (
    ChallengeNotFoundError,
    CurriculumError,
    DojoError,
    ExecutionError,
    ExportError,
    GradingError,
    InvalidBeltError,
    ValidationError,
)

# Fine-tuning imports (Phase 4)
from dojo.finetune import (
    FinetuneConfig,
    TrainingPackager,
)
from dojo.models import (
    Belt,
    Challenge,
    ChallengeInput,
    ChallengeResult,
    EnvMetadata,
    EvalLabel,
    ExpectedOutput,
    Grade,
    GraderStatus,
    LiveFeedEntry,
    ModelProgress,
    ScoringRubric,
    ScriptType,
    SenseiAssessment,
    TrainingExample,
)

# Sensei imports (Phase 3)
from dojo.sensei import (
    DPOPair,
    EventLogger,
    EventRecord,
    ExportFormat,
    ExtractionConfig,
    generate_config_hash,
    Grader,
    GradingCriteria,
    GradingResult,
    ProgressTracker,
    Sensei,
    TrainingCycleResult,
    TrainingDataExporter,
    TrainingExtractor,
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
    # Live Feed (new)
    "LiveFeedEntry",
    "EvalLabel",
    "GraderStatus",
    "EnvMetadata",
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
    # Event Logging
    "EventLogger",
    "EventRecord",
    "generate_config_hash",
    # Fine-tuning (Phase 4)
    "TrainingPackager",
    "FinetuneConfig",
]
