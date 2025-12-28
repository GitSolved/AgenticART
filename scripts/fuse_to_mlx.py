
import os
import json
from mlx_lm import load
from mlx_lm.utils import save_model

def main():
    model_path = "mlx-community/Qwen2.5-Coder-32B-Instruct-4bit"
    adapter_path = "dojo_finetune_package/finetune_package_20251228_003337/mlx_adapters"
    output_path = "models/qwen2.5-32b-dojo-final"
    
    print(f"🧠 Loading Base Model + Adapters...")
    model, tokenizer = load(model_path, adapter_path=adapter_path)
    
    print(f"💾 Saving Fused Model to {output_path}...")
    save_model(output_path, model)
    
    print(f"✅ Fusion complete! Your fine-tuned model is ready at: {output_path}")

if __name__ == "__main__":
    main()
