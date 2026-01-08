#!/usr/bin/env python3
"""
Test DPO training with the generated training data.

This script validates that the training data works with TRL's DPOTrainer
using a small model for quick testing.

Usage:
    python test_dpo_training.py [--dry-run] [--samples N]
"""

import argparse
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Test DPO training")
    parser.add_argument("--dry-run", action="store_true", help="Only validate, don't train")
    parser.add_argument("--samples", type=int, default=100, help="Number of samples to use")
    parser.add_argument("--model", type=str, default="gpt2", help="Model to fine-tune")
    args = parser.parse_args()

    print("=" * 60)
    print("DPO TRAINING TEST")
    print("=" * 60)

    # Import dependencies
    print("\n📦 Loading dependencies...")
    try:
        import torch
        from datasets import load_dataset
        from transformers import AutoModelForCausalLM, AutoTokenizer
        from trl import DPOConfig, DPOTrainer
        print(f"   ✅ PyTorch: {torch.__version__}")
        print(f"   ✅ TRL loaded")
        print(f"   ✅ Device: {'mps' if torch.backends.mps.is_available() else 'cuda' if torch.cuda.is_available() else 'cpu'}")
    except ImportError as e:
        print(f"   ❌ Missing dependency: {e}")
        print("   Install with: pip install trl transformers datasets torch")
        return

    # Load training data
    print("\n📂 Loading training data...")
    training_dir = Path(__file__).parent
    jsonl_files = list(training_dir.glob("dpo_amplified_*.jsonl"))

    if not jsonl_files:
        print("   ❌ No training data found!")
        return

    training_file = jsonl_files[0]
    dataset = load_dataset("json", data_files=str(training_file), split="train")
    print(f"   ✅ Loaded {len(dataset)} examples from {training_file.name}")

    # Subsample for testing
    if args.samples < len(dataset):
        dataset = dataset.shuffle(seed=42).select(range(args.samples))
        print(f"   📉 Using {args.samples} samples for testing")

    # Split into train/eval
    split = dataset.train_test_split(test_size=0.1, seed=42)
    train_dataset = split["train"]
    eval_dataset = split["test"]
    print(f"   📊 Train: {len(train_dataset)}, Eval: {len(eval_dataset)}")

    if args.dry_run:
        print("\n✅ Dry run complete - data is valid!")
        print("\nTo run actual training:")
        print(f"   python {Path(__file__).name} --samples 100 --model gpt2")
        return

    # Load model and tokenizer
    print(f"\n🤖 Loading model: {args.model}...")
    tokenizer = AutoTokenizer.from_pretrained(args.model)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(args.model)
    print(f"   ✅ Model loaded: {model.num_parameters() / 1e6:.1f}M parameters")

    # Configure DPO training
    print("\n⚙️  Configuring DPO trainer...")
    training_args = DPOConfig(
        output_dir="./dpo_test_output",
        per_device_train_batch_size=2,
        per_device_eval_batch_size=2,
        max_length=1024,
        max_prompt_length=512,
        num_train_epochs=1,
        learning_rate=5e-5,
        logging_steps=10,
        eval_strategy="steps",
        eval_steps=50,
        save_strategy="no",  # Don't save for testing
        report_to="none",  # Don't report to wandb etc
        remove_unused_columns=False,
    )

    # Create trainer
    trainer = DPOTrainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        processing_class=tokenizer,
    )
    print("   ✅ DPOTrainer configured")

    # Train
    print("\n🚀 Starting training...")
    try:
        trainer.train()
        print("\n✅ Training completed successfully!")

        # Evaluate
        print("\n📊 Final evaluation...")
        metrics = trainer.evaluate()
        for key, value in metrics.items():
            print(f"   {key}: {value:.4f}")

    except Exception as e:
        print(f"\n❌ Training error: {e}")
        import traceback
        traceback.print_exc()

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
