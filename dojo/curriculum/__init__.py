"""
Dojo Curriculum Module

Handles challenge loading, execution, error extraction, and the feedback loop.
"""

from dojo.curriculum.challenger import AttemptRecord, Challenger, ChallengeSession
from dojo.curriculum.context_injector import (
    BlockType,
    ContextBlock,
    ContextInjector,
    extract_error_metadata,
    parse_blocks,
    validate_prompt_structure,
)
from dojo.curriculum.error_extractor import ErrorContext, ErrorExtractor
from dojo.curriculum.executor import ExecutionResult, Executor
from dojo.curriculum.loader import ChallengeLoader

__all__ = [
    # Loader
    "ChallengeLoader",
    # Executor
    "Executor",
    "ExecutionResult",
    # Error handling
    "ErrorExtractor",
    "ErrorContext",
    # Context injection (structured blocks)
    "ContextInjector",
    "BlockType",
    "ContextBlock",
    "parse_blocks",
    "validate_prompt_structure",
    "extract_error_metadata",
    # Orchestration
    "Challenger",
    "AttemptRecord",
    "ChallengeSession",
]
