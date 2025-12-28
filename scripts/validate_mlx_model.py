import os
from mlx_lm import load, generate

def main():
    model_path = "models/qwen2.5-32b-dojo-final-v2-4bit"
    
    print(f"🧠 Loading OPTIMIZED FINAL BRAIN (64 Layers, 4-bit): {model_path}...")
    model, tokenizer = load(model_path)
    
    # FORCE SPEAK: Provide the first character of 'shell' to break the EOS loop
    prompt = "### Instruction:\nWrite an ADB shell command that outputs the Android version of the connected device.\nThe output should be just the version number (e.g., \"7.0\" or \"11\").\n\n### Response: s"
    
    print(f"\n--- Testing OPTIMIZED FINAL BRAIN ---")
    response = generate(model, tokenizer, prompt=prompt, max_tokens=100)
    print(f"COMMAND OUTPUT: |{response}|")

if __name__ == "__main__":
    main()