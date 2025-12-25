"""
Dojo Curriculum Module

Handles challenge loading, execution, error extraction, and the feedback loop.
"""

from dojo.curriculum.loader import ChallengeLoader
from dojo.curriculum.executor import Executor, ExecutionResult
from dojo.curriculum.error_extractor import ErrorExtractor, ErrorContext
from dojo.curriculum.context_injector import ContextInjector
from dojo.curriculum.challenger import Challenger, AttemptRecord, ChallengeSession

__all__ = [
    # Loader
    "ChallengeLoader",
    # Executor
    "Executor",
    "ExecutionResult",
    # Error handling
    "ErrorExtractor",
    "ErrorContext",
    # Context injection
    "ContextInjector",
    # Orchestration
    "Challenger",
    "AttemptRecord",
    "ChallengeSession",
]
