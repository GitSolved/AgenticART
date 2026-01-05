"""Package training data and scripts for fine-tuning on GPU machines."""

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
        config: Optional[FinetuneConfig] = None,
    ) -> Path:
        """
        Create a portable fine-tuning package.

        Args:
            training_data_path: Path to combined training data (Alpaca JSON)
            config: Fine-tuning configuration

        Returns:
            Path to the created package directory
        """
        config = config or FinetuneConfig()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        package_dir = self.output_dir / f"finetune_package_{timestamp}"
        package_dir.mkdir(parents=True, exist_ok=True)

        # Copy training data
        data_dir = package_dir / "data"
        data_dir.mkdir(exist_ok=True)
        shutil.copy(training_data_path, data_dir / "training_data.json")

        # Save config
        config.training_data_path = Path("data/training_data.json")
        with open(package_dir / "config.json", "w") as f:
            json.dump(config.to_dict(), f, indent=2)

        # Create training script
        self._create_training_script(package_dir, config)

        # Create Colab notebook
        self._create_colab_notebook(package_dir, config)

        # Create requirements.txt
        self._create_requirements(package_dir)

        # Create README
        self._create_readme(package_dir, config)

        # Create Ollama Modelfile (lightweight alternative)
        self._create_ollama_modelfile(package_dir, training_data_path)

        print(f"Package created at: {package_dir}")
        return package_dir

    def _create_training_script(self, package_dir: Path, config: FinetuneConfig):
        """Create the main training script (MLX Optimized)."""
        script = '''#!/usr/bin/env python3
"""
Fine-tune WhiteRabbitNeo on ADB Dojo training data using MLX (Apple Silicon).

Requirements:
- Apple Silicon Mac (M1/M2/M3) with macOS 13.3+
- Python 3.10+
- See requirements.txt for dependencies

Usage:
    python train.py
    python train.py --iters 600 --batch-size 4
"""

import argparse
import json
import os
import sys
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Fine-tune WhiteRabbitNeo on ADB data (MLX)")
    parser.add_argument("--iters", type=int, default=600, help="Number of training iterations")
    parser.add_argument("--batch-size", type=int, default=4, help="Batch size")
    parser.add_argument("--learning-rate", type=float, default=1e-5, help="Learning rate")
    parser.add_argument("--adapter-path", type=str, default="mlx_adapters", help="Output adapter path")
    parser.add_argument("--data-dir", type=str, default="data", help="Data directory")
    args = parser.parse_args()

    # Load config
    with open("config.json") as f:
        config = json.load(f)

    model_path = config.get("huggingface_model", "WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B")
    
    print("=" * 60)
    print("AgenticART Dojo - Fine-Tuning (MLX / Apple Silicon)")
    print("=" * 60)
    print(f"Model: {model_path}")
    print(f"Iterations: {args.iters}")
    print(f"Batch Size: {args.batch_size}")
    print(f"Adapter Path: {args.adapter_path}")
    print("=" * 60)

    # Prepare Data for MLX (JSONL format)
    print(f"Preparing data in {args.data_dir}...")
    with open(config["training_data_path"]) as f:
        raw_data = json.load(f)

    # Split data (90/10)
    split_idx = int(len(raw_data) * 0.9)
    train_data = raw_data[:split_idx]
    valid_data = raw_data[split_idx:] or [raw_data[-1]]

    def write_jsonl(data, filename):
        path = Path(args.data_dir) / filename
        with open(path, "w") as f:
            for item in data:
                # Format: ### Instruction: ... ### Input: ... ### Response: ...
                prompt = f"### Instruction:\\n{item['instruction']}\\n\\n### Input:\\n{item.get('input', '')}\\n\\n### Response:"
                completion = item['output']
                # MLX LoRA 'text' format
                entry = {"text": f"{prompt} {completion}"}
                f.write(json.dumps(entry) + "\\n")
    
    write_jsonl(train_data, "train.jsonl")
    write_jsonl(valid_data, "valid.jsonl")
    
    print(f"Data prepared. Starting MLX training...")
    print("🚀 IGNITING 40-CORE GPU via MLX CLI...")
    
    # Construct MLX CLI command
    cmd = (
        f"python3 -m mlx_lm.lora "
        f"--model {model_path} "
        f"--train "
        f"--data {args.data_dir} "
        f"--iters {args.iters} "
        f"--batch-size {args.batch_size} "
        f"--adapter-path {args.adapter_path} "
        f"--learning-rate {args.learning_rate} "
        f"--num-layers 16 "
        f"--seed 42"
    )
    
    exit_code = os.system(cmd)
    
    if exit_code == 0:
        print("=" * 60)
        print("Training complete!")
        print(f"Adapters saved to: {args.adapter_path}")
        print("To test:")
        print(f"python -m dojo.test_end_to_end --mode mlx --adapter {args.adapter_path}")
        print("=" * 60)
    else:
        print("Training failed.")
        sys.exit(exit_code)

if __name__ == "__main__":
    main()
'''
        with open(package_dir / "train.py", "w") as f:
            f.write(script)

    def _create_colab_notebook(self, package_dir: Path, config: FinetuneConfig):
        """Create a Google Colab notebook for cloud training."""
        notebook = {
            "nbformat": 4,
            "nbformat_minor": 0,
            "metadata": {
                "colab": {
                    "provenance": [],
                    "gpuType": "T4"
                },
                "kernelspec": {
                    "name": "python3",
                    "display_name": "Python 3"
                },
                "accelerator": "GPU"
            },
            "cells": [
                {
                    "cell_type": "markdown",
                    "metadata": {},
                    "source": [
                        "# AgenticART Dojo - Fine-Tune WhiteRabbitNeo\\n",
                        "\\n",
                        "This notebook fine-tunes WhiteRabbitNeo on ADB command data collected from the Dojo.\\n",
                        "\\n",
                        "**Requirements:** T4 GPU (free tier) or better"
                    ]
                },
                {
                    "cell_type": "code",
                    "metadata": {},
                    "source": [
                        "# Install dependencies\\n",
                        "!pip install -q unsloth\\n",
                        "!pip install -q --no-deps trl peft accelerate bitsandbytes"
                    ],
                    "execution_count": None,
                    "outputs": []
                },
                {
                    "cell_type": "code",
                    "metadata": {},
                    "source": [
                        "# Upload your training data\\n",
                        "from google.colab import files\\n",
                        "uploaded = files.upload()  # Upload training_data.json"
                    ],
                    "execution_count": None,
                    "outputs": []
                },
                {
                    "cell_type": "code",
                    "metadata": {},
                    "source": [
                        "import json\\n",
                        "from datasets import Dataset\\n",
                        "from unsloth import FastLanguageModel\\n",
                        "from trl import SFTTrainer\\n",
                        "from transformers import TrainingArguments\\n",
                        "\\n",
                        "# Load training data\\n",
                        "with open('training_data.json') as f:\\n",
                        "    training_data = json.load(f)\\n",
                        "print(f'Loaded {len(training_data)} examples')"
                    ],
                    "execution_count": None,
                    "outputs": []
                },
                {
                    "cell_type": "code",
                    "metadata": {},
                    "source": [
                        "# Format data\\n",
                        "def format_alpaca(example):\\n",
                        "    if example.get('input'):\\n",
                        "        text = f\\\"\\\"\\\"### Instruction:\\n",
                        "{example['instruction']}\\n",
                        "\\n",
                        "### Input:\\n",
                        "{example['input']}\\n",
                        "\\n",
                        "### Response:\\n",
                        "{example['output']}\\\"\\\"\\\"\\n",
                        "    else:\\n",
                        "        text = f\\\"\\\"\\\"### Instruction:\\n",
                        "{example['instruction']}\\n",
                        "\\n",
                        "### Response:\\n",
                        "{example['output']}\\\"\\\"\\\"\\n",
                        "    return {'text': text}\\n",
                        "\\n",
                        "dataset = Dataset.from_list(training_data)\\n",
                        "dataset = dataset.map(format_alpaca)\\n",
                        "print(f'Formatted {len(dataset)} examples')"
                    ],
                    "execution_count": None,
                    "outputs": []
                },
                {
                    "cell_type": "code",
                    "metadata": {},
                    "source": [
                        "# Load model\\n",
                        "model, tokenizer = FastLanguageModel.from_pretrained(\\n",
                        f"    model_name='{config.huggingface_model}',\\n",
                        f"    max_seq_length={config.max_seq_length},\\n",
                        "    load_in_4bit=True,\\n",
                        ")\\n",
                        "\\n",
                        "# Add LoRA\\n",
                        "model = FastLanguageModel.get_peft_model(\\n",
                        "    model,\\n",
                        f"    r={config.lora_r},\\n",
                        f"    lora_alpha={config.lora_alpha},\\n",
                        f"    lora_dropout={config.lora_dropout},\\n",
                        f"    target_modules={config.target_modules},\\n",
                        "    use_gradient_checkpointing='unsloth',\\n",
                        ")"
                    ],
                    "execution_count": None,
                    "outputs": []
                },
                {
                    "cell_type": "code",
                    "metadata": {},
                    "source": [
                        "# Training\\n",
                        "trainer = SFTTrainer(\\n",
                        "    model=model,\\n",
                        "    tokenizer=tokenizer,\\n",
                        "    train_dataset=dataset,\\n",
                        "    args=TrainingArguments(\\n",
                        "        output_dir='./output',\\n",
                        f"        num_train_epochs={config.num_epochs},\\n",
                        f"        per_device_train_batch_size={config.batch_size},\\n",
                        f"        gradient_accumulation_steps={config.gradient_accumulation_steps},\\n",
                        f"        learning_rate={config.learning_rate},\\n",
                        f"        warmup_ratio={config.warmup_ratio},\\n",
                        "        fp16=True,\\n",
                        "        logging_steps=10,\\n",
                        "        optim='adamw_8bit',\\n",
                        "    ),\\n",
                        "    dataset_text_field='text',\\n",
                        f"    max_seq_length={config.max_seq_length},\\n",
                        "    packing=True,\\n",
                        ")\\n",
                        "\\n",
                        "trainer.train()"
                    ],
                    "execution_count": None,
                    "outputs": []
                },
                {
                    "cell_type": "code",
                    "metadata": {},
                    "source": [
                        "# Save as GGUF for Ollama\\n",
                        "model.save_pretrained_gguf(\\n",
                        "    'WhiteRabbitNeo-ADB-Dojo',\\n",
                        "    tokenizer,\\n",
                        "    quantization_method='q4_k_m',\\n",
                        ")\\n",
                        "\\n",
                        "# Download the model\\n",
                        "from google.colab import files\\n",
                        "files.download('WhiteRabbitNeo-ADB-Dojo-unsloth.Q4_K_M.gguf')"
                    ],
                    "execution_count": None,
                    "outputs": []
                },
                {
                    "cell_type": "markdown",
                    "metadata": {},
                    "source": [
                        "## Import to Ollama\\n",
                        "\\n",
                        "After downloading, create a Modelfile:\\n",
                        "```\\n",
                        "FROM ./WhiteRabbitNeo-ADB-Dojo-unsloth.Q4_K_M.gguf\\n",
                        "```\\n",
                        "\\n",
                        "Then run:\\n",
                        "```bash\\n",
                        "ollama create whiterabbit-adb-dojo -f Modelfile\\n",
                        "```"
                    ]
                }
            ]
        }

        with open(package_dir / "finetune_colab.ipynb", "w") as f:
            json.dump(notebook, f, indent=2)

    def _create_requirements(self, package_dir: Path):
        """Create requirements.txt."""
        requirements = """# Fine-tuning requirements
# Install with: pip install -r requirements.txt

# MLX (Apple Silicon)
mlx>=0.6.0
mlx-lm>=0.1.0

# Core
torch>=2.0.0
transformers>=4.36.0
datasets>=2.14.0

# Utilities
sentencepiece
protobuf
"""
        with open(package_dir / "requirements.txt", "w") as f:
            f.write(requirements)

    def _create_readme(self, package_dir: Path, config: FinetuneConfig):
        """Create README with instructions (MLX Optimized)."""
        readme = f"""# AgenticART Dojo - Fine-Tuning Package (MLX Edition)

This package contains everything needed to fine-tune WhiteRabbitNeo on ADB command data using **Apple Silicon (MLX)**.

## Contents

- `data/training_data.json` - Training data in Alpaca format
- `train.py` - Main training script (uses `mlx_lm.lora`)
- `config.json` - Training configuration
- `requirements.txt` - Python dependencies (MLX)
- `Modelfile` - Ollama Modelfile (lightweight alternative)

## Requirements

- **Hardware:** Apple Silicon Mac (M1/M2/M3)
- **OS:** macOS 13.3+
- **Python:** 3.10+
- **RAM:** 16GB+ recommended

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run Training

This will use the Neural Engine / GPU on your Mac.

```bash
# Standard run (default settings)
python train.py

# Custom settings
python train.py --iters 1000 --batch-size 8 --learning-rate 1e-5
```

### 3. Test Your Model

After training, adapters are saved to `mlx_adapters/`. Test them in the Dojo:

```bash
cd ../..
python -m dojo.test_end_to_end --mode mlx --adapter dojo_finetune_package/finetune_package_<timestamp>/mlx_adapters
```

## Configuration

Default settings in `config.json`:

| Setting | Value |
|---------|-------|
| Base Model | {config.huggingface_model} |
| LoRA Rank | {config.lora_r} |
| LoRA Alpha | {config.lora_alpha} |
| Epochs/Iters | {config.num_epochs} (converted to iters) |
| Batch Size | {config.batch_size} |

## Alternative: Ollama

If you prefer to run the base model in Ollama without fine-tuning:

```bash
ollama create whiterabbit-adb-dojo -f Modelfile
ollama run whiterabbit-adb-dojo
```
"""
        with open(package_dir / "README.md", "w") as f:
            f.write(readme)

    def _create_ollama_modelfile(self, package_dir: Path, training_data_path: Path):
        """Create an Ollama Modelfile with system prompt as a lightweight alternative."""
        # Load some examples for the system prompt
        with open(training_data_path) as f:
            examples = json.load(f)

        # Select a few good examples
        sample_examples = []
        for ex in examples[:10]:
            if len(ex.get("output", "")) < 100:  # Short, clear examples
                sample_examples.append(ex)
                if len(sample_examples) >= 5:
                    break

        examples_text = ""
        for ex in sample_examples:
            examples_text += f"Task: {ex['instruction'].split(chr(10))[0]}\n"
            examples_text += f"Command: {ex['output']}\n\n"

        modelfile = f'''# Ollama Modelfile for WhiteRabbitNeo with ADB expertise
# This is a lightweight alternative that adds a system prompt without fine-tuning
#
# Usage:
#   ollama create whiterabbit-adb-dojo -f Modelfile
#   ollama run whiterabbit-adb-dojo

FROM hf.co/bartowski/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B-GGUF:Q4_K_M

PARAMETER temperature 0.3
PARAMETER top_p 0.9
PARAMETER num_ctx 4096

SYSTEM """You are an expert Android security researcher specializing in ADB (Android Debug Bridge) commands.

When asked to write ADB commands:
1. Use the correct prefix: 'shell' for on-device commands, direct commands for host operations
2. Common patterns:
   - Device info: shell getprop ro.build.version.release
   - Package list: shell pm list packages
   - Start activity: shell am start -n <package>/<activity>
   - Logcat: shell logcat -d <tag>:<level> *:S
   - Process list: shell ps
   - Permissions: shell dumpsys package <pkg> | grep permission
   - Network: shell ip addr
   - Screenshot: shell screencap -p /sdcard/screenshot.png
   - Port forward: forward tcp:<port> tcp:<port>

3. Avoid common mistakes:
   - Don't use backticks around commands
   - Don't add unnecessary quotes around simple arguments
   - Use -d flag with logcat to dump and exit
   - For grep filters, use: | grep pattern (not quoted)

Examples of correct commands:
{examples_text}

Respond with only the ADB command, no explanation unless asked."""
'''
        with open(package_dir / "Modelfile", "w") as f:
            f.write(modelfile)
