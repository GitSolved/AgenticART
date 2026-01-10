#!/usr/bin/env python3
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
                prompt = f"### Instruction:\n{item['instruction']}\n\n### Input:\n{item.get('input', '')}\n\n### Response:"
                completion = item['output']
                # MLX LoRA 'text' format
                entry = {"text": f"{prompt} {completion}"}
                f.write(json.dumps(entry) + "\n")

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
