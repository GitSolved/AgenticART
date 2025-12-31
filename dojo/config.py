"""Dojo configuration management."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class DojoConfig:
    """Configuration for the Dojo framework."""

    # Paths
    dojo_root: Path = field(default_factory=lambda: Path(__file__).parent)
    curriculum_dir: Optional[Path] = None
    training_output_dir: Optional[Path] = None

    # Grading thresholds
    passing_score: int = 70
    promotion_score: int = 80

    # Retry settings
    max_retries: int = 3
    retry_with_context: bool = True

    # Belt promotion requirements (challenges needed per belt)
    challenges_for_promotion: dict = field(
        default_factory=lambda: {
            "white": 5,
            "yellow": 8,
            "orange": 10,
            "green": 12,
            "blue": 15,
            "purple": 15,
            "brown": 20,
            "black": 25,
        }
    )

    # Score requirements for promotion (percentage)
    score_for_promotion: dict = field(
        default_factory=lambda: {
            "white": 70,
            "yellow": 75,
            "orange": 75,
            "green": 80,
            "blue": 80,
            "purple": 85,
            "brown": 85,
            "black": 90,
        }
    )

    # LLM settings (inherit from main config if not set)
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    llm_timeout: int = 300

    # Export settings
    default_export_format: str = "alpaca"

    def __post_init__(self) -> None:
        """Initialize derived paths."""
        if self.curriculum_dir is None:
            self.curriculum_dir = self.dojo_root / "curriculum"

        if self.training_output_dir is None:
            # Go up from dojo/ to project root, then to output/training
            project_root = self.dojo_root.parent
            self.training_output_dir = project_root / "output" / "training"

    def ensure_directories(self) -> None:
        """Create required directories if they don't exist."""
        if self.curriculum_dir:
            self.curriculum_dir.mkdir(parents=True, exist_ok=True)
        if self.training_output_dir:
            self.training_output_dir.mkdir(parents=True, exist_ok=True)

    def get_belt_requirements(self, belt: str) -> dict:
        """Get promotion requirements for a specific belt."""
        return {
            "challenges_required": self.challenges_for_promotion.get(belt, 10),
            "score_required": self.score_for_promotion.get(belt, 80),
        }

    @classmethod
    def from_env(cls) -> DojoConfig:
        """Load configuration from environment variables."""
        config = cls(
            passing_score=int(os.getenv("DOJO_PASSING_SCORE", "70")),
            promotion_score=int(os.getenv("DOJO_PROMOTION_SCORE", "80")),
            max_retries=int(os.getenv("DOJO_MAX_RETRIES", "3")),
            retry_with_context=os.getenv("DOJO_RETRY_WITH_CONTEXT", "true").lower() == "true",
            llm_provider=os.getenv("LLM_PROVIDER"),
            llm_model=os.getenv("OLLAMA_MODEL"),
            llm_timeout=int(os.getenv("DOJO_LLM_TIMEOUT", "300")),
            default_export_format=os.getenv("DOJO_EXPORT_FORMAT", "alpaca"),
        )

        # Override paths if specified in environment
        if env_curriculum := os.getenv("DOJO_CURRICULUM_DIR"):
            config.curriculum_dir = Path(env_curriculum)

        if env_training := os.getenv("DOJO_TRAINING_OUTPUT"):
            config.training_output_dir = Path(env_training)

        return config

    def to_dict(self) -> dict:
        """Convert configuration to dictionary."""
        return {
            "paths": {
                "dojo_root": str(self.dojo_root),
                "curriculum_dir": str(self.curriculum_dir) if self.curriculum_dir else None,
                "training_output_dir": str(self.training_output_dir) if self.training_output_dir else None,
            },
            "grading": {
                "passing_score": self.passing_score,
                "promotion_score": self.promotion_score,
            },
            "retry": {
                "max_retries": self.max_retries,
                "retry_with_context": self.retry_with_context,
            },
            "promotion": {
                "challenges_for_promotion": self.challenges_for_promotion,
                "score_for_promotion": self.score_for_promotion,
            },
            "llm": {
                "provider": self.llm_provider,
                "model": self.llm_model,
                "timeout": self.llm_timeout,
            },
            "export": {
                "default_format": self.default_export_format,
            },
        }


# Global default configuration
_default_config: Optional[DojoConfig] = None


def get_config() -> DojoConfig:
    """Get the global configuration, creating from environment if needed."""
    global _default_config
    if _default_config is None:
        _default_config = DojoConfig.from_env()
    return _default_config


def set_config(config: DojoConfig) -> None:
    """Set the global configuration."""
    global _default_config
    _default_config = config
