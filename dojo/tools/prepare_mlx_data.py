import json
import random
import sys
from pathlib import Path


def convert_to_mlx_chat(input_path: str, output_dir: str):
    """
    Convert Alpaca-style JSONL to MLX Chat format (OpenAI messages) and split into train/valid.
    """
    input_file = Path(input_path)
    output_path_train = Path(output_dir) / "train.jsonl"
    output_path_valid = Path(output_dir) / "valid.jsonl"

    print(f"Converting {input_file} -> {output_dir}...")

    all_data = []

    # Read all data
    with open(input_file, 'r') as infile:
        for line in infile:
            if not line.strip(): continue
            try:
                data = json.loads(line)

                # Extract fields
                system = data.get("system", "You are a helpful assistant.")
                user_msg = data.get("instruction", "")
                if data.get("input"):
                    user_msg += "\n\n" + data["input"]
                assistant_msg = data.get("output", "")

                # Build Chat Object
                chat_obj = {
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user_msg},
                        {"role": "assistant", "content": assistant_msg}
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

    # Save Train
    with open(output_path_train, 'w') as f:
        for item in train_data:
            f.write(json.dumps(item) + "\n")

    # Save Valid
    with open(output_path_valid, 'w') as f:
        for item in valid_data:
            f.write(json.dumps(item) + "\n")

    print(f"Total: {len(all_data)}")
    print(f"Train: {len(train_data)} saved to {output_path_train}")
    print(f"Valid: {len(valid_data)} saved to {output_path_valid}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 prepare_mlx_data.py <input.jsonl> <output_dir>")
        sys.exit(1)

    convert_to_mlx_chat(sys.argv[1], sys.argv[2])
