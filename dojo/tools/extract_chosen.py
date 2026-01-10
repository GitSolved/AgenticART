import json
import sys
import random
from pathlib import Path

def extract_chosen_sft(input_path: str, output_dir: str):
    """
    Extract the 'chosen' field from DPO JSONL and format it for MLX SFT (chat).
    Input: {"prompt": "SYSTEM: ... USER: ...", "chosen": "RESPONSE", "rejected": "..."}
    Output: {"messages": [{"role": "system", "content": "..."}, {"role": "user", "content": "..."}, {"role": "assistant", "content": "..."}]}
    """
    input_file = Path(input_path)
    output_path_train = Path(output_dir) / "train.jsonl"
    output_path_valid = Path(output_dir) / "valid.jsonl"
    
    print(f"Extracting Chosen SFT from {input_file} -> {output_dir}...")
    
    all_data = []
    
    with open(input_file, 'r') as infile:
        for line in infile:
            if not line.strip(): continue
            try:
                data = json.loads(line)
                
                # Parse Prompt
                prompt_text = data.get("prompt", "")
                # Split SYSTEM / USER
                system_content = "You are a helpful assistant."
                user_content = prompt_text
                
                if "SYSTEM:" in prompt_text and "USER:" in prompt_text:
                    parts = prompt_text.split("USER:")
                    system_part = parts[0].replace("SYSTEM:", "").strip()
                    user_part = parts[1].strip()
                    system_content = system_part
                    user_content = user_part
                
                assistant_content = data.get("chosen", "")
                
                # Build Chat Object
                chat_obj = {
                    "messages": [
                        {"role": "system", "content": system_content},
                        {"role": "user", "content": user_content},
                        {"role": "assistant", "content": assistant_content}
                    ]
                }
                all_data.append(chat_obj)
            except Exception as e:
                print(f"Skipping bad line: {e}")
                
    # Shuffle and Split (80/20)
    random.shuffle(all_data)
    split_idx = int(len(all_data) * 0.8)
    train_data = all_data[:split_idx]
    valid_data = all_data[split_idx:]
    
    with open(output_path_train, 'w') as f:
        for item in train_data:
            f.write(json.dumps(item) + "\n")
            
    with open(output_path_valid, 'w') as f:
        for item in valid_data:
            f.write(json.dumps(item) + "\n")
            
    print(f"Total: {len(all_data)}")
    print(f"Train: {len(train_data)} saved to {output_path_train}")
    print(f"Valid: {len(valid_data)} saved to {output_path_valid}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 extract_chosen.py <input.jsonl> <output_dir>")
        sys.exit(1)
    
    extract_chosen_sft(sys.argv[1], sys.argv[2])
