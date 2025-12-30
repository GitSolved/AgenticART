#!/usr/bin/env python3
from pathlib import Path

from huggingface_hub import snapshot_download

model_id = "mlx-community/Qwen2.5-72B-Instruct-4bit"
local_dir = Path("models/Qwen2.5-72B-Instruct-4bit")

print(f"Downloading {model_id} to {local_dir}...")
snapshot_download(repo_id=model_id, local_dir=local_dir)
print("Download complete.")
