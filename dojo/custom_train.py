from __future__ import annotations

import json
import os
import subprocess


def main():
    # Configuration
    model_path = "models/whiterabbit-7b-dojo-4bit"
    data_source = (
        "dojo_output/training_data/llama3.1-70b-20251228_071557_20251228_071557_alpaca.json"
    )
    dataset_dir = "models/adapter-data"
    adapter_output = "models/whiterabbit-7b-adapters"

    print("🔧 Configuring training...")
    print(f"  Model: {model_path}")
    print(f"  Data: {data_source}")

    os.makedirs(dataset_dir, exist_ok=True)
    os.makedirs(adapter_output, exist_ok=True)

    # 1. Load Data
    with open(data_source, "r") as f:
        data = json.load(f)

    print(f"  Loaded {len(data)} examples.")

    # 2. Format for MLX (including Input field)
    # Simple split: 90% train, 10% valid (at least 1 for valid)
    split_idx = max(1, int(len(data) * 0.9))
    train_data = data[:split_idx]
    valid_data = data[split_idx:]

    # If valid is empty (e.g. only 1 example), copy the last one
    if not valid_data:
        valid_data = [data[-1]]

    def write_jsonl(items, filename):
        path = os.path.join(dataset_dir, filename)
        with open(path, "w") as f:
            for item in items:
                # Construct prompt with input if present
                instruction = item.get("instruction", "")
                inp = item.get("input", "")

                if inp:
                    prompt = (
                        f"### Instruction:\n{instruction}\n\n### Input:\n{inp}\n\n### Response:"
                    )
                else:
                    prompt = f"### Instruction:\n{instruction}\n\n### Response:"

                entry = {"prompt": prompt, "completion": item["output"]}
                f.write(json.dumps(entry) + "\n")
        print(f"  Wrote {len(items)} items to {path}")

    write_jsonl(train_data, "train.jsonl")
    write_jsonl(valid_data, "valid.jsonl")

    # 3. Run MLX LoRA Training
    # We use the subprocess to run the module
    print("\n🚀 IGNITING MLX LoRA FINE-TUNING (500 iters)...")

    # Adjust learning rate or rank if needed, but defaults are usually fine for a start.
    # We point to our prepared data directory.
    cmd = [
        "python3", "-m", "mlx_lm.lora",
        "--model", model_path,
        "--train",
        "--data", dataset_dir,
        "--iters", "500",
        "--batch-size", "1",
        "--adapter-path", adapter_output,
        "--learning-rate", "1e-5",
        "--steps-per-eval", "50",
        "--save-every", "100",
    ]

    print(f"  Command: {' '.join(cmd)}")
    subprocess.run(cmd, check=False)

    print("\n✅ Fine-tuning complete.")
    print(f"  Adapters saved to: {adapter_output}")


if __name__ == "__main__":
    main()
