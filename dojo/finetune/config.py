"""Fine-tuning configuration for AgenticART Dojo."""

from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path


@dataclass
class FinetuneConfig:
    """Configuration for fine-tuning WhiteRabbitNeo or similar models."""

    # Model settings
    base_model: str = "hf.co/bartowski/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B-GGUF"
    huggingface_model: str = "WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B"
    output_name: str = "WhiteRabbitNeo-ADB-Dojo"

    # LoRA settings
    lora_r: int = 16
    lora_alpha: int = 32
    lora_dropout: float = 0.05
    target_modules: list = field(default_factory=lambda: [
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj"
    ])

    # Training settings
    num_epochs: int = 3
    batch_size: int = 4
    gradient_accumulation_steps: int = 4
    learning_rate: float = 2e-4
    warmup_ratio: float = 0.03
    max_seq_length: int = 2048

    # Hardware settings
    use_4bit: bool = True  # QLoRA
    use_gradient_checkpointing: bool = True

    # Paths
    training_data_path: Optional[Path] = None
    output_dir: Path = Path("./dojo_finetuned")

    def to_dict(self) -> dict:
        """Convert config to dictionary."""
        return {
            "base_model": self.base_model,
            "huggingface_model": self.huggingface_model,
            "output_name": self.output_name,
            "lora_r": self.lora_r,
            "lora_alpha": self.lora_alpha,
            "lora_dropout": self.lora_dropout,
            "target_modules": self.target_modules,
            "num_epochs": self.num_epochs,
            "batch_size": self.batch_size,
            "gradient_accumulation_steps": self.gradient_accumulation_steps,
            "learning_rate": self.learning_rate,
            "warmup_ratio": self.warmup_ratio,
            "max_seq_length": self.max_seq_length,
            "use_4bit": self.use_4bit,
            "use_gradient_checkpointing": self.use_gradient_checkpointing,
            "training_data_path": str(self.training_data_path) if self.training_data_path else None,
            "output_dir": str(self.output_dir),
        }
