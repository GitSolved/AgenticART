"""
Package training data and scripts for fine-tuning on GPU machines.

"""

from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional

from .config import FinetuneConfig


class TrainingPackager:
    """Packages training data and scripts for portable fine-tuning."""

    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = Path(output_dir or "./dojo_finetune_package")

    def create_package(
        self,
        training_data_path: Path,
        dpo_data_path: Optional[Path] = None,
        config: Optional[FinetuneConfig] = None,
    ) -> Path:
        """Create a portable fine-tuning package."""
        config = config or FinetuneConfig()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        package_dir = self.output_dir / f"finetune_package_{timestamp}"
        package_dir.mkdir(parents=True, exist_ok=True)

        data_dir = package_dir / "data"
        data_dir.mkdir(exist_ok=True)
        shutil.copy(training_data_path, data_dir / "training_data.json")
        config.training_data_path = Path("data/training_data.json")

        if dpo_data_path and dpo_data_path.exists():
            shutil.copy(dpo_data_path, data_dir / "dpo_data.jsonl")
            config.dpo_data_path = Path("data/dpo_data.jsonl")

        with open(package_dir / "config.json", "w") as f:
            json.dump(config.to_dict(), f, indent=2)

        self._create_training_script(package_dir, config)
        self._create_mlx_script(package_dir, config)
        self._create_requirements(package_dir)
        self._create_readme(package_dir, config)

        print(f"Package created at: {package_dir}")
        return package_dir

    def _create_training_script(self, package_dir: Path, config: FinetuneConfig):
        """Create the main training script optimized for Apple Silicon (M3 Max)."""
        script = """import argparse, json, os, torch
from pathlib import Path
from datasets import Dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    TrainingArguments
)
from trl import SFTTrainer, DPOTrainer
from peft import LoraConfig, get_peft_model

def main():
    with open("config.json") as f: config = json.load(f)
    model_id = config["huggingface_model"]

    print(f"Loading model for M3 Max GPU (Metal)...")

    # 1. Tokenizer
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    tokenizer.pad_token = tokenizer.eos_token

    # 2. Load Model in BF16 (Native for M3 Max)
    # Note: We avoid bitsandbytes as it doesn't support MPS yet.
    # 64GB RAM is enough to load Qwen 32B in BF16 for LoRA training.
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        torch_dtype=torch.bfloat16,
        device_map="auto",
        trust_remote_code=True
    )

    # 3. LoRA Setup (Targets only necessary weights to save memory)
    peft_config = LoraConfig(
        r=16,
        lora_alpha=32,
        target_modules=["q_proj", "v_proj"], # Optimized for memory
        lora_dropout=0.05,
        bias="none",
        task_type="CAUSAL_LM"
    )
    model = get_peft_model(model, peft_config)
    model.print_trainable_parameters()

    # 4. Data Setup
    with open(config["training_data_path"]) as f: sft_data = json.load(f)
    sft_ds = Dataset.from_list(sft_data).map(lambda x: {"text": f"### Instruction:\n{x['instruction']}\n\n### Response:\n{x['output']}"})

    # 5. SFT Training
    print("Starting High-Speed SFT on Metal GPU...")
    SFTTrainer(
        model=model,
        processing_class=tokenizer,
        train_dataset=sft_ds,
        dataset_text_field="text",
        max_seq_length=2048,
        args=TrainingArguments(
            output_dir="./sft",
            num_train_epochs=3,
            learning_rate=2e-4,
            per_device_train_batch_size=1,
            gradient_accumulation_steps=4,
            bf16=True, # Use BFloat16 for stability and speed
            logging_steps=1,
            report_to="none"
        )
    ).train()

    if config.get("dpo_data_path"):
        print("Starting DPO Reinforcement...")
        dpo_data = []
        with open(config["dpo_data_path"]) as f:
            for line in f: dpo_data.append(json.loads(line))
        DPOTrainer(
            model=model,
            ref_model=None,
            processing_class=tokenizer,
            beta=0.1,
            train_dataset=Dataset.from_list(dpo_data),
            args=TrainingArguments(
                output_dir="./dpo",
                num_train_epochs=1,
                learning_rate=5e-5,
                bf16=True,
                report_to="none"
            )
        ).train()

    print("Saving optimized LoRA adapter...")
    model.save_pretrained("./final_model")
    tokenizer.save_pretrained("./final_model")

if __name__ == "__main__": main()
"""
        with open(package_dir / "train.py", "w") as f:
            f.write(script)

    def _create_mlx_script(self, package_dir: Path, config: FinetuneConfig):
        """Create the MLX-specific training script for Apple Silicon."""
        script = """import json, os

def main():
    model_path = "WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B"
    dataset_path = "data"
    output_adapter = "mlx_adapters"

    os.makedirs(dataset_path, exist_ok=True)
    os.makedirs(output_adapter, exist_ok=True)

    # Format for MLX with Validation split
    with open("data/training_data.json", "r") as f:
        sft_data = json.load(f)

    split_idx = int(len(sft_data) * 0.9)
    train_data = sft_data[:split_idx]
    valid_data = sft_data[split_idx:] or [sft_data[-1]]

    def write_jsonl(data, filename):
        with open(os.path.join(dataset_path, filename), "w") as f:
            for item in data:
                f.write(json.dumps({"prompt": f"### Instruction:\\n{item['instruction']}\\n\\n### Response:", "completion": item['output']}) + "\\n")

    write_jsonl(train_data, "train.jsonl")
    write_jsonl(valid_data, "valid.jsonl")

    print("🚀 IGNITING 40-CORE GPU via MLX CLI...")
    command = (
        f"python3 -m mlx_lm lora "
        f"--model {model_path} "
        f"--train "
        f"--data {dataset_path} "
        f"--iters 500 "
        f"--batch-size 4 "
        f"--num-layers -1 "
        f"--adapter-path {output_adapter}"
    )
    os.system(command)

if __name__ == "__main__": main()
"""
        with open(package_dir / "mlx_train.py", "w") as f:
            f.write(script)

    def _create_requirements(self, package_dir: Path):
        """Create requirements.txt."""
        reqs = "torch\ntransformers\ndatasets\naccelerate\ntrl\npeft\nbitsandbytes\nsentencepiece\nprotobuf\nmlx-lm\nmlx\n"
        with open(package_dir / "requirements.txt", "w") as f:
            f.write(reqs)

    def _create_readme(self, package_dir: Path, config: FinetuneConfig):
        """Create README."""
        readme = "# Fine-Tuning Engine\n\nRun fine-tuning on GPU.\n"
        with open(package_dir / "README.md", "w") as f:
            f.write(readme)
