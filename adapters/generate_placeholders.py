#!/usr/bin/env python3
"""
Generate placeholder LoRA adapter weights for testing.

These are NOT trained weights - just random tensors in the correct format
to verify the adapter loading infrastructure works.

For real adapters, use the dojo training pipeline:
    python -m dojo.train_adapter --pillar static_analysis
"""

import json
from pathlib import Path

# Check for safetensors availability
try:
    import numpy as np
    from safetensors.numpy import save_file
    HAS_SAFETENSORS = True
except ImportError:
    HAS_SAFETENSORS = False
    print("Warning: safetensors not installed. Run: pip install safetensors numpy")


ADAPTER_DIRS = [
    "qwen_static_lora",
    "qwen_negative_lora",
    "qwen_rootcause_lora",
    "qwen_transfer_lora",
    "qwen_methodology_lora",
    "qwen_taxonomy_lora",
    "qwen_patch_lora",
]

# LoRA config matching Qwen 2.5 7B architecture
LORA_CONFIG = {
    "rank": 64,
    "alpha": 128,
    "hidden_size": 3584,  # Qwen 2.5 7B
    "num_layers": 28,     # Qwen 2.5 7B
    "target_modules": ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
}


def generate_placeholder_weights(adapter_dir: Path, rank: int = 64) -> dict:
    """
    Generate placeholder LoRA weights.

    LoRA decomposes weight updates as: W' = W + BA
    where B is (hidden_size x rank) and A is (rank x hidden_size)
    """
    if not HAS_SAFETENSORS:
        print(f"Skipping {adapter_dir.name} - safetensors not available")
        return {}

    tensors = {}
    hidden_size = LORA_CONFIG["hidden_size"]

    # Generate placeholder weights for each layer and target module
    for layer_idx in range(LORA_CONFIG["num_layers"]):
        for module in LORA_CONFIG["target_modules"]:
            # LoRA A matrix (rank x hidden_size) - initialized small
            key_a = f"model.layers.{layer_idx}.self_attn.{module}.lora_A.weight"
            tensors[key_a] = (np.random.randn(rank, hidden_size) * 0.01).astype(np.float16)

            # LoRA B matrix (hidden_size x rank) - initialized to zero
            key_b = f"model.layers.{layer_idx}.self_attn.{module}.lora_B.weight"
            tensors[key_b] = np.zeros((hidden_size, rank), dtype=np.float16)

    return tensors


def create_adapter_placeholder(adapter_name: str) -> None:
    """Create a complete placeholder adapter directory."""
    adapter_dir = Path(__file__).parent / adapter_name
    adapter_dir.mkdir(exist_ok=True)

    # Generate and save placeholder weights
    if HAS_SAFETENSORS:
        weights = generate_placeholder_weights(adapter_dir)
        weights_path = adapter_dir / "adapters.safetensors"
        save_file(weights, str(weights_path))
        print(f"Created: {weights_path} ({weights_path.stat().st_size / 1024 / 1024:.1f} MB)")

    # Create training metadata placeholder
    metadata = {
        "adapter_name": adapter_name,
        "status": "placeholder",
        "note": "These are random weights for testing. Train real adapters with dojo.train_adapter",
        "lora_config": LORA_CONFIG,
    }

    metadata_path = adapter_dir / "training_metadata.json"
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"Created: {metadata_path}")


def main():
    """Generate placeholders for all adapters."""
    print("=" * 60)
    print("Generating Placeholder LoRA Adapters")
    print("=" * 60)
    print()
    print("NOTE: These are NOT trained weights!")
    print("Use dojo.train_adapter to create real adapters.")
    print()

    for adapter_name in ADAPTER_DIRS:
        print(f"\nProcessing: {adapter_name}")
        create_adapter_placeholder(adapter_name)

    print()
    print("=" * 60)
    print("Placeholder generation complete!")
    print()
    print("To train real adapters:")
    print("  python -m dojo.train_adapter --pillar <pillar_name>")
    print()
    print("To fine-tune with MLX:")
    print("  mlx_lm.lora --model models/qwen2.5-7b-instruct \\")
    print("              --train --data training_data.jsonl \\")
    print("              --adapter-path adapters/<adapter_name>")
    print("=" * 60)


if __name__ == "__main__":
    main()
