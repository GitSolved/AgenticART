from __future__ import annotations

import sys
from pathlib import Path

# Add project root to path before local imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Local imports
from dojo.finetune.config import FinetuneConfig
from dojo.finetune.packager import TrainingPackager


def main():
    # 1. Setup paths
    master_dir = project_root / "master_dataset"
    alpaca_path = master_dir / "master_alpaca.json"
    dpo_path = master_dir / "master_dpo.jsonl"

    if not alpaca_path.exists():
        print(f"Error: SFT data not found at {alpaca_path}")
        return

    # 2. Configure for WhiteRabbitNeo 7B (Optimized for Security & High Plasticity)
    config = FinetuneConfig(
        huggingface_model="WhiteRabbitNeo/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B",
        output_name="WhiteRabbitNeo-7B-ADB-Dojo",
        num_epochs=5,  # More epochs for 7B to ensure learning
        batch_size=4,  # 7B can handle larger batches
        gradient_accumulation_steps=1,
        use_4bit=True,
    )

    # 3. Create Package
    packager = TrainingPackager(output_dir=project_root / "dojo_finetune_package")
    package_path = packager.create_package(
        training_data_path=alpaca_path,
        dpo_data_path=dpo_path if dpo_path.exists() else None,
        config=config,
    )

    print("\nSuccessfully prepared fine-tuning package for 7B model!")
    print(f"Location: {package_path}")
    print("\nTo start training on a GPU machine:")
    print(f"  cd {package_path}")
    print("  pip install -r requirements.txt")
    print("  python mlx_train.py")


if __name__ == "__main__":
    main()