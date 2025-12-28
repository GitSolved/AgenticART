import os
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

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

    # 2. Configure for Qwen 2.5 Coder 32B (Non-gated, better for ADB)
    config = FinetuneConfig(
        huggingface_model="Qwen/Qwen2.5-Coder-32B-Instruct",
        output_name="Qwen2.5-Coder-32B-ADB-Dojo",
        num_epochs=3,
        batch_size=1, 
        gradient_accumulation_steps=4, # 32B can use smaller accumulation than 70B
        use_4bit=True
    )

    # 3. Create Package
    packager = TrainingPackager(output_dir=project_root / "dojo_finetune_package")
    package_path = packager.create_package(
        training_data_path=alpaca_path,
        dpo_data_path=dpo_path if dpo_path.exists() else None,
        config=config
    )

    print(f"\nSuccessfully prepared fine-tuning package for 70B model!")
    print(f"Location: {package_path}")
    print("\nTo start training on a GPU machine:")
    print(f"  cd {package_path}")
    print("  pip install -r requirements.txt")
    print("  python train.py")

if __name__ == "__main__":
    main()
