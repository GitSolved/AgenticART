"""
Dojo Curriculum Module

Handles challenge loading, execution, error extraction, and the feedback loop.
"""

from dojo.curriculum.challenger import AttemptRecord, Challenger, ChallengeSession
from dojo.curriculum.context_injector import ContextInjector
from dojo.curriculum.error_extractor import ErrorContext, ErrorExtractor
from dojo.curriculum.executor import (
    ExecutionResult,
    ExecutionTier,
    Executor,
    OnDeviceToolExecutor,
)
from dojo.curriculum.loader import ChallengeLoader

__all__ = [
    # Loader
    "ChallengeLoader",
    # Executor
    "Executor",
    "ExecutionResult",
    "ExecutionTier",
    "OnDeviceToolExecutor",
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
