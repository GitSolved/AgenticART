#!/bin/bash
# Yellow Belt Training Launcher (Curriculum Learning)
set -e

# Configuration
# WE TRAIN ON TOP OF THE WHITE BELT MODEL
MODEL_NAME="models/AgenticART-7B-White"
DATA_DIR="Projects/AgenticART/dojo/training_data/mlx"
OUTPUT_ADAPTER="adapters/yellow_belt_v1"

echo "=================================================="
echo "   🟡 AGENTIC ART DOJO: YELLOW BELT TRAINING     "
echo "=================================================="
echo "Base Model: $MODEL_NAME (Previous Graduate)"
echo "Data:       $DATA_DIR (1000 Trajectories)"
echo "--------------------------------------------------"

if [ ! -d "$MODEL_NAME" ]; then
    echo "❌ Error: Base model not found at $MODEL_NAME"
    echo "   Did you brand the White Belt model yet?"
    exit 1
fi

echo "🚀 Starting Curriculum Fine-Tuning..."

# MLX LoRA Command
python3 -m mlx_lm.lora \
    --model "$MODEL_NAME" \
    --train \
    --data "$DATA_DIR" \
    --iters 1000 \
    --batch-size 4 \
    --num-layers 16 \
    --adapter-path "$OUTPUT_ADAPTER" \
    --save-every 200

echo ""
echo "✅ Training Complete!"
echo "   Adapter saved to: $OUTPUT_ADAPTER"
