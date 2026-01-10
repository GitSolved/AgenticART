# Phase 4: Fine-Tuning Module
# Export training data and scripts for fine-tuning on GPU-enabled machines
#
# Includes:
# - TrainingPackager: Export training data for remote GPU training
# - ActiveLearningLoop: Real-time MLX LoRA fine-tuning on Apple Silicon

from .config import FinetuneConfig
from .packager import TrainingPackager

# MLX Active Learning (Apple Silicon)
try:
    from .active_correction import (
        ActiveLearningLoop,
        DPOTrainingPair,
        LoRAConfig,
        MLXLoRATrainer,
        check_mlx_available,
    )
    MLX_AVAILABLE = check_mlx_available()
except ImportError:
    MLX_AVAILABLE = False
    ActiveLearningLoop = None
    MLXLoRATrainer = None
    DPOTrainingPair = None
    LoRAConfig = None

__all__ = [
    # Training data export
    "TrainingPackager",
    "FinetuneConfig",
    # MLX Active Learning
    "ActiveLearningLoop",
    "MLXLoRATrainer",
    "DPOTrainingPair",
    "LoRAConfig",
    "MLX_AVAILABLE",
]
