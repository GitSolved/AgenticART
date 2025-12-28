import os
from mlx_lm import load, generate

def main():
    model_path = "models/whiterabbit-7b-dojo-4bit"
    
    print(f"🧠 Loading Native MLX Brain: {model_path}...")
    # Properly unpack based on MLX version (2 or 3 values)
    results = load(model_path)
    model = results[0]
    tokenizer = results[1]
    
    # FORMAT LOCK: Use the exact format from train.jsonl
    prompt = "### Instruction:\nWrite an ADB shell command that identifies the current WiFi IP address of the device.\n\n### Response: shell "
    
    print(f"\n--- Testing NATIVE MLX BRAIN ---")
    # Correct call to generate (no 'temp' keyword if using defaults or check version)
    # Most MLX versions use 'temp' but let's stick to basics to ensure success
    response = generate(model, tokenizer, prompt=prompt, max_tokens=100)
    print(f"COMMAND OUTPUT: |shell {response.strip()}|")

if __name__ == "__main__":
    main()