#!/usr/bin/env python3
"""
DPO Training Script for AgenticART Security Analysis Model.

This script fine-tunes using Direct Preference Optimization on the
generated chosen/rejected pairs.

Requirements:
- Python 3.10+
- PyTorch with MPS/CUDA support
- TRL library

Usage:
    python train_dpo.py
    python train_dpo.py --model Qwen/Qwen2.5-Coder-7B-Instruct --epochs 2
"""

import argparse
import json
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description="DPO Training")
    parser.add_argument("--model", type=str, default="gpt2", help="Base model")
    parser.add_argument("--epochs", type=int, default=1, help="Training epochs")
    parser.add_argument("--batch-size", type=int, default=2, help="Batch size")
    parser.add_argument("--lr", type=float, default=5e-5, help="Learning rate")
    parser.add_argument("--output-dir", type=str, default="./dpo_output", help="Output directory")
    args = parser.parse_args()

    print("=" * 60)
    print("DPO TRAINING - AgenticART Security Model")
    print("=" * 60)

    # Import dependencies
    print("
📦 Loading dependencies...")
    import torch
    from datasets import load_dataset
    from transformers import AutoModelForCausalLM, AutoTokenizer
    from trl import DPOConfig, DPOTrainer

    device = "mps" if torch.backends.mps.is_available() else "cuda" if torch.cuda.is_available() else "cpu"
    print(f"   Device: {device}")

    # Load training data
    print("
📂 Loading training data...")
    dataset = load_dataset("json", data_files="data/dpo_pairs.jsonl", split="train")
    print(f"   Loaded {len(dataset)} DPO pairs")

    # Split
    split = dataset.train_test_split(test_size=0.1, seed=42)
    train_dataset = split["train"]
    eval_dataset = split["test"]
    print(f"   Train: {len(train_dataset)}, Eval: {len(eval_dataset)}")

    # Load model
    print(f"
🤖 Loading model: {args.model}...")
    tokenizer = AutoTokenizer.from_pretrained(args.model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(args.model)
    print(f"   Parameters: {model.num_parameters() / 1e6:.1f}M")

    # Configure DPO
    training_args = DPOConfig(
        output_dir=args.output_dir,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        max_length=1024,
        max_prompt_length=512,
        num_train_epochs=args.epochs,
        learning_rate=args.lr,
        logging_steps=10,
        eval_strategy="steps",
        eval_steps=100,
        save_strategy="epoch",
        report_to="none",
    )

    trainer = DPOTrainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        processing_class=tokenizer,
    )

    # Train
    print("
🚀 Starting DPO training...")
    trainer.train()

    # Save
    print(f"
💾 Saving to {args.output_dir}...")
    trainer.save_model()
    tokenizer.save_pretrained(args.output_dir)

    print("
✅ Training complete!")
    print(f"Model saved to: {args.output_dir}")

if __name__ == "__main__":
    main()
