
import mlx.core as mx
from mlx_lm import load
from mlx_lm.utils import export_gguf

def main():
    # Use the 62GB Fused model as the source
    model_path = "models/qwen2.5-32b-dojo-final-v2"
    gguf_path = "models/qwen2.5-32b-dojo.gguf"
    
    print(f"🧠 Loading Fused Brain from {model_path}...")
    # Load into CPU to avoid Metal OOM during export
    model, tokenizer = load(model_path, model_config={"device": "cpu"})
    
    print(f"🚀 Exporting to GGUF (this will quantize to 4-bit automatically)...")
    export_gguf(model_path, gguf_path)
    
    print(f"✅ Export complete: {gguf_path}")

if __name__ == "__main__":
    main()
