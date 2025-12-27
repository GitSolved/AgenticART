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
        """Create the main training script."""
        script = '''#!/usr/bin/env python3
"""
Fine-tune WhiteRabbitNeo on ADB Dojo training data using Unsloth.

Requirements:
- NVIDIA GPU with 16GB+ VRAM (or 8GB with aggressive quantization)
- Python 3.10+
- See requirements.txt for dependencies

Usage:
    python train.py
    python train.py --epochs 5 --batch-size 2
"""

import argparse
import json
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="Fine-tune WhiteRabbitNeo on ADB data")
    parser.add_argument("--epochs", type=int, default=3, help="Number of training epochs")
    parser.add_argument("--batch-size", type=int, default=4, help="Batch size")
    parser.add_argument("--learning-rate", type=float, default=2e-4, help="Learning rate")
    parser.add_argument("--max-seq-length", type=int, default=2048, help="Max sequence length")
    parser.add_argument("--output-dir", type=str, default="./output", help="Output directory")
    args = parser.parse_args()

    # Load config
    with open("config.json") as f:
        config = json.load(f)

    # Override with CLI args
    config["num_epochs"] = args.epochs
    config["batch_size"] = args.batch_size
    config["learning_rate"] = args.learning_rate
    config["max_seq_length"] = args.max_seq_length
    config["output_dir"] = args.output_dir

    print("=" * 60)
    print("AgenticART Dojo - Fine-Tuning")
    print("=" * 60)
    print(f"Model: {config['huggingface_model']}")
    print(f"Epochs: {config['num_epochs']}")
    print(f"Batch Size: {config['batch_size']}")
    print(f"Learning Rate: {config['learning_rate']}")
    print()

    try:
        from unsloth import FastLanguageModel
        from unsloth import is_bfloat16_supported
        USE_UNSLOTH = True
        print("Using Unsloth for optimized training")
    except ImportError:
        USE_UNSLOTH = False
        print("Unsloth not available, using standard transformers")

    from datasets import Dataset
    from transformers import TrainingArguments
    from trl import SFTTrainer

    # Load training data
    print("\\nLoading training data...")
    with open(config["training_data_path"]) as f:
        training_data = json.load(f)
    print(f"Loaded {len(training_data)} examples")

    # Format for training
    def format_alpaca(example):
        if example.get("input"):
            text = f"""### Instruction:
{example["instruction"]}

### Input:
{example["input"]}

### Response:
{example["output"]}"""
        else:
            text = f"""### Instruction:
{example["instruction"]}

### Response:
{example["output"]}"""
        return {"text": text}

    dataset = Dataset.from_list(training_data)
    dataset = dataset.map(format_alpaca)
    print(f"Formatted {len(dataset)} training examples")

    # Load model
    print(f"\\nLoading model: {config['huggingface_model']}...")

    if USE_UNSLOTH:
        model, tokenizer = FastLanguageModel.from_pretrained(
            model_name=config["huggingface_model"],
            max_seq_length=config["max_seq_length"],
            dtype=None,  # Auto-detect
            load_in_4bit=config["use_4bit"],
        )

        # Add LoRA adapters
        model = FastLanguageModel.get_peft_model(
            model,
            r=config["lora_r"],
            target_modules=config["target_modules"],
            lora_alpha=config["lora_alpha"],
            lora_dropout=config["lora_dropout"],
            bias="none",
            use_gradient_checkpointing="unsloth",
            random_state=42,
        )
    else:
        from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
        import torch

        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
        )

        model = AutoModelForCausalLM.from_pretrained(
            config["huggingface_model"],
            quantization_config=bnb_config,
            device_map="auto",
            trust_remote_code=True,
        )
        tokenizer = AutoTokenizer.from_pretrained(
            config["huggingface_model"],
            trust_remote_code=True,
        )

        model = prepare_model_for_kbit_training(model)

        lora_config = LoraConfig(
            r=config["lora_r"],
            lora_alpha=config["lora_alpha"],
            target_modules=config["target_modules"],
            lora_dropout=config["lora_dropout"],
            bias="none",
            task_type="CAUSAL_LM",
        )
        model = get_peft_model(model, lora_config)

    # Ensure pad token
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # Training arguments
    training_args = TrainingArguments(
        output_dir=config["output_dir"],
        num_train_epochs=config["num_epochs"],
        per_device_train_batch_size=config["batch_size"],
        gradient_accumulation_steps=config["gradient_accumulation_steps"],
        learning_rate=config["learning_rate"],
        warmup_ratio=config["warmup_ratio"],
        logging_steps=10,
        save_steps=100,
        save_total_limit=3,
        fp16=not (USE_UNSLOTH and is_bfloat16_supported()),
        bf16=USE_UNSLOTH and is_bfloat16_supported(),
        optim="adamw_8bit",
        weight_decay=0.01,
        lr_scheduler_type="cosine",
        seed=42,
        report_to="none",
    )

    # Create trainer
    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        args=training_args,
        dataset_text_field="text",
        max_seq_length=config["max_seq_length"],
        packing=True,
    )

    # Train
    print("\\nStarting training...")
    print("-" * 60)
    trainer.train()

    # Save model
    print("\\nSaving model...")
    output_path = Path(config["output_dir"]) / config["output_name"]

    if USE_UNSLOTH:
        # Save in multiple formats
        model.save_pretrained_merged(
            str(output_path) + "_merged",
            tokenizer,
            save_method="merged_16bit",
        )
        # Save GGUF for Ollama
        model.save_pretrained_gguf(
            str(output_path) + "_gguf",
            tokenizer,
            quantization_method="q4_k_m",
        )
    else:
        model.save_pretrained(str(output_path) + "_lora")
        tokenizer.save_pretrained(str(output_path) + "_lora")

    print("=" * 60)
    print("Training complete!")
    print(f"Model saved to: {output_path}")
    print("=" * 60)


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

# Core
torch>=2.0.0
transformers>=4.36.0
datasets>=2.14.0
accelerate>=0.25.0

# Fine-tuning
trl>=0.7.0
peft>=0.7.0
bitsandbytes>=0.41.0

# Optimized training (recommended)
unsloth>=2024.1

# Utilities
sentencepiece
protobuf
"""
        with open(package_dir / "requirements.txt", "w") as f:
            f.write(requirements)

    def _create_readme(self, package_dir: Path, config: FinetuneConfig):
        """Create README with instructions."""
        readme = f"""# AgenticART Dojo - Fine-Tuning Package

This package contains everything needed to fine-tune WhiteRabbitNeo on ADB command data.

## Contents

- `data/training_data.json` - Training data in Alpaca format (60 examples)
- `train.py` - Main training script
- `finetune_colab.ipynb` - Google Colab notebook (free GPU)
- `config.json` - Training configuration
- `requirements.txt` - Python dependencies
- `Modelfile` - Ollama Modelfile (lightweight alternative)

## Requirements

- **GPU:** NVIDIA with 16GB+ VRAM (or 8GB with aggressive settings)
- **RAM:** 32GB recommended
- **Python:** 3.10+

## Quick Start

### Option 1: Local Training (GPU required)

```bash
# Install dependencies
pip install -r requirements.txt

# Run training
python train.py

# Or with custom settings
python train.py --epochs 5 --batch-size 2
```

### Option 2: Google Colab (Free GPU)

1. Open `finetune_colab.ipynb` in Google Colab
2. Upload `data/training_data.json`
3. Run all cells
4. Download the GGUF model

### Option 3: Ollama Modelfile (No fine-tuning)

For a quick boost without GPU training:

```bash
ollama create whiterabbit-adb-dojo -f Modelfile
ollama run whiterabbit-adb-dojo
```

## Configuration

Default settings in `config.json`:

| Setting | Value |
|---------|-------|
| Base Model | {config.huggingface_model} |
| LoRA Rank | {config.lora_r} |
| LoRA Alpha | {config.lora_alpha} |
| Epochs | {config.num_epochs} |
| Batch Size | {config.batch_size} |
| Learning Rate | {config.learning_rate} |
| Max Seq Length | {config.max_seq_length} |

## After Training

### Import to Ollama

```bash
# Create Modelfile pointing to your GGUF
echo 'FROM ./WhiteRabbitNeo-ADB-Dojo.gguf' > Modelfile

# Create the model
ollama create whiterabbit-adb-dojo -f Modelfile

# Test it
ollama run whiterabbit-adb-dojo "Write an ADB command to list installed packages"
```

### Test in Dojo

```bash
cd AgenticART
python -m dojo.test_end_to_end --mode live --belt white
```

## Training Data Statistics

- **Total Examples:** 60
- **Belts Covered:** White, Yellow, Orange
- **Example Types:**
  - Positive (successful): 15
  - Negative (with corrections): 28
  - Error recovery: 23
  - Kata (reference): 45

## Expected Results

After fine-tuning, the model should improve on:
- Correct ADB command syntax
- Proper use of `shell` prefix vs `adb` prefix
- Pipe and grep operations
- Android-specific commands (dumpsys, am, pm)

Target: 80%+ pass rate on white/yellow belt challenges.
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

PARAMETER temperature 0.1
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
