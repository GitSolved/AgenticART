#!/bin/bash
# =============================================================================
# Expert Mixture LoRA Adapter Training Script
# =============================================================================
#
# Usage:
#   ./train_adapter.sh <pillar_name> [--epochs N] [--rank R]
#
# Examples:
#   ./train_adapter.sh static_analysis
#   ./train_adapter.sh root_cause --epochs 500 --rank 32
#
# Prerequisites:
#   - MLX-LM installed: pip install mlx-lm
#   - Base model downloaded: models/qwen2.5-7b-instruct
#   - Training data generated: python -m dojo.export_training_data
# =============================================================================

set -e

# Default configuration
PILLAR="${1:-static_analysis}"
EPOCHS=1000
RANK=64
BATCH_SIZE=4
LEARNING_RATE="1e-4"
BASE_MODEL="models/qwen2.5-7b-instruct"

# Parse optional arguments
shift || true
while [[ $# -gt 0 ]]; do
    case $1 in
        --epochs) EPOCHS="$2"; shift 2 ;;
        --rank) RANK="$2"; shift 2 ;;
        --batch) BATCH_SIZE="$2"; shift 2 ;;
        --lr) LEARNING_RATE="$2"; shift 2 ;;
        --model) BASE_MODEL="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Map pillar name to adapter directory
case $PILLAR in
    static_analysis|static)   ADAPTER_DIR="qwen_static_lora" ;;
    negative_knowledge|negative) ADAPTER_DIR="qwen_negative_lora" ;;
    root_cause|rootcause)     ADAPTER_DIR="qwen_rootcause_lora" ;;
    pattern_transfer|transfer) ADAPTER_DIR="qwen_transfer_lora" ;;
    methodology)              ADAPTER_DIR="qwen_methodology_lora" ;;
    taxonomy)                 ADAPTER_DIR="qwen_taxonomy_lora" ;;
    patch_analysis|patch)     ADAPTER_DIR="qwen_patch_lora" ;;
    *)
        echo "Unknown pillar: $PILLAR"
        echo "Valid pillars: static_analysis, negative_knowledge, root_cause,"
        echo "               pattern_transfer, methodology, taxonomy, patch_analysis"
        exit 1
        ;;
esac

ADAPTER_PATH="adapters/${ADAPTER_DIR}"
TRAINING_DATA="${ADAPTER_PATH}/training_data.jsonl"

echo "============================================================"
echo "Training Expert Mixture Adapter"
echo "============================================================"
echo "Pillar:        $PILLAR"
echo "Adapter:       $ADAPTER_DIR"
echo "Base Model:    $BASE_MODEL"
echo "Epochs:        $EPOCHS"
echo "LoRA Rank:     $RANK"
echo "Batch Size:    $BATCH_SIZE"
echo "Learning Rate: $LEARNING_RATE"
echo "============================================================"

# Check prerequisites
if [ ! -d "$BASE_MODEL" ]; then
    echo "Error: Base model not found at $BASE_MODEL"
    echo "Download with: mlx_lm.convert --hf-path Qwen/Qwen2.5-7B-Instruct"
    exit 1
fi

if [ ! -f "$TRAINING_DATA" ]; then
    echo "Warning: Training data not found at $TRAINING_DATA"
    echo "Generating from dojo training runs..."
    python -m dojo.export_training_data --pillar "$PILLAR" --output "$TRAINING_DATA"
fi

# Create adapter directory if needed
mkdir -p "$ADAPTER_PATH"

# Run MLX LoRA fine-tuning
echo ""
echo "Starting MLX LoRA fine-tuning..."
echo ""

mlx_lm.lora \
    --model "$BASE_MODEL" \
    --train \
    --data "$TRAINING_DATA" \
    --adapter-path "$ADAPTER_PATH" \
    --iters "$EPOCHS" \
    --batch-size "$BATCH_SIZE" \
    --learning-rate "$LEARNING_RATE" \
    --lora-rank "$RANK" \
    --lora-layers 28

# Update adapter config with training metadata
python3 << EOF
import json
from datetime import datetime
from pathlib import Path

config_path = Path("$ADAPTER_PATH/adapter_config.json")
if config_path.exists():
    with open(config_path) as f:
        config = json.load(f)
else:
    config = {}

config["training"] = {
    "status": "trained",
    "epochs": $EPOCHS,
    "rank": $RANK,
    "batch_size": $BATCH_SIZE,
    "learning_rate": "$LEARNING_RATE",
    "trained_at": datetime.now().isoformat(),
    "base_model": "$BASE_MODEL",
}

with open(config_path, "w") as f:
    json.dump(config, f, indent=2)

print(f"Updated: {config_path}")
EOF

echo ""
echo "============================================================"
echo "Training complete!"
echo "Adapter saved to: $ADAPTER_PATH"
echo ""
echo "To use this adapter:"
echo "  from agent.mlx_adapter_client import MLXAdapterClient"
echo "  client = MLXAdapterClient()"
echo "  client.switch_adapter(Pillar.$PILLAR)"
echo "============================================================"
