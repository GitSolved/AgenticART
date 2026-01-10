#!/bin/bash
# White Belt Training Launcher (MLX) - FIXED V5 (Reliable Base)
set -e

# Configuration
# WhiteRabbitNeo is 404ing even with token. Reverting to the solid base.
# We will build our own security model on top of Qwen.
MODEL_NAME="Qwen/Qwen2.5-7B-Instruct"
DATA_DIR="Projects/AgenticART/dojo/training_data/mlx"
OUTPUT_ADAPTER="adapters/white_belt_v1"

echo "=================================================="
echo "   🥋 AGENTIC ART DOJO: WHITE BELT TRAINING      "
echo "=================================================="
echo "Model: $MODEL_NAME (Public Base)"
echo "Data:  $DATA_DIR"
echo "--------------------------------------------------"

# Ensure MLX is installed
if ! python3 -c "import mlx_lm" &> /dev/null; then
    echo "❌ Error: mlx-lm python package not found. Please run: pip install mlx-lm"
    exit 1
fi

echo "🚀 Starting QLoRA Fine-Tuning..."
echo "   (Check training.log for progress)"

# MLX LoRA Command
python3 -m mlx_lm.lora \
    --model "$MODEL_NAME" \
    --train \
    --data "$DATA_DIR" \
    --iters 600 \
    --batch-size 4 \
    --num-layers 16 \
    --adapter-path "$OUTPUT_ADAPTER" \
    --save-every 100

echo ""
echo "✅ Training Complete!"
echo "   Adapter saved to: $OUTPUT_ADAPTER"
echo ""
echo "To test the trained model, run:"
echo "python3 -m mlx_lm.generate --model $MODEL_NAME --adapter-path $OUTPUT_ADAPTER --prompt 'Analyze com.example...'"