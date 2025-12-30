"""
Dojo Sensei Module - Phase 3

Grading, training data extraction, and export functionality.
"""

from dojo.sensei.event_logger import (
    EventLogger,
    EventRecord,
    generate_config_hash,
    get_schema_documentation,
)
from dojo.sensei.exploitation_validator import (
    ExploitationConfig,
    ExploitationResult,
    ExploitationType,
    ExploitationValidator,
)
from dojo.sensei.exporter import DPOPair, ExportFormat, TrainingDataExporter
from dojo.sensei.grader import Grader, GradingCriteria, GradingResult
from dojo.sensei.progress_tracker import ProgressTracker
from dojo.sensei.sensei import Sensei, TrainingCycleResult
from dojo.sensei.training_extractor import ExtractionConfig, TrainingExtractor

__all__ = [
    # Core orchestrator
    "Sensei",
    "TrainingCycleResult",
    # Grading
    "Grader",
    "GradingCriteria",
    "GradingResult",
    # Exploitation Validation
    "ExploitationValidator",
    "ExploitationResult",
    "ExploitationType",
    "ExploitationConfig",
    # Extraction
    "TrainingExtractor",
    "ExtractionConfig",
    # Export
    "TrainingDataExporter",
    "ExportFormat",
    "DPOPair",
    # Progress
    "ProgressTracker",
    # Event Logging
    "EventLogger",
    "EventRecord",
    "generate_config_hash",
    "get_schema_documentation",
]
