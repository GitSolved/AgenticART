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
        self._create_requirements(package_dir)
        self._create_readme(package_dir, config)

        print(f"Package created at: {package_dir}")
        return package_dir

    def _create_training_script(self, package_dir: Path, config: FinetuneConfig):
        """Create the main training script."""
        script = """import argparse, json, os, torch
from pathlib import Path
from datasets import Dataset
from transformers import TrainingArguments
from trl import SFTTrainer, DPOTrainer
from unsloth import FastLanguageModel

def main():
    with open("config.json") as f: config = json.load(f)
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=config["huggingface_model"], max_seq_length=2048, load_in_4bit=True)
    model = FastLanguageModel.get_peft_model(model, r=16, target_modules=["q_proj", "k_proj", "v_proj", "o_proj"])

    with open(config["training_data_path"]) as f: sft_data = json.load(f)
    sft_ds = Dataset.from_list(sft_data).map(lambda x: {"text": f"### Instruction:\\n{x['instruction']}\\n\\n### Response:\\n{x['output']}"})

    SFTTrainer(model=model, tokenizer=tokenizer, train_dataset=sft_ds, dataset_text_field="text", max_seq_length=2048,
               args=TrainingArguments(output_dir="./sft", num_train_epochs=3, learning_rate=2e-4, fp16=True)).train()

    if config.get("dpo_data_path"):
        dpo_data = []
        with open(config["dpo_data_path"]) as f:
            for line in f: dpo_data.append(json.loads(line))
        DPOTrainer(model=model, ref_model=None, tokenizer=tokenizer, beta=0.1, train_dataset=Dataset.from_list(dpo_data),
                   args=TrainingArguments(output_dir="./dpo", num_train_epochs=1, learning_rate=5e-5, fp16=True)).train()

    model.save_pretrained_gguf("./final_model", tokenizer)

if __name__ == "__main__": main()
"""
        with open(package_dir / "train.py", "w") as f:
            f.write(script)

    def _create_requirements(self, package_dir: Path):
        """Create requirements.txt."""
        reqs = "torch\ntransformers\ndatasets\naccelerate\ntrl\npeft\nbitsandbytes\nunsloth\n"
        with open(package_dir / "requirements.txt", "w") as f:
            f.write(reqs)

    def _create_readme(self, package_dir: Path, config: FinetuneConfig):
        """Create README."""
        readme = "# Fine-Tuning Engine\n\nRun fine-tuning on GPU.\n"
        with open(package_dir / "README.md", "w") as f:
            f.write(readme)
