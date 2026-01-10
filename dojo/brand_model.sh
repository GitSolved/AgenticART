#!/bin/bash
# AgenticART Branding Script (v2.1 - Portable)
set -e

BELT_COLOR=$1
BASE_MODEL=$2

if [ -z "$BELT_COLOR" ] || [ -z "$BASE_MODEL" ]; then
    echo "Usage: ./brand_model.sh <BeltColor> <BaseModelPath>"
    exit 1
fi

# Manual lowercase for older bash/macOS
COLOR_LOWER=$(echo "$BELT_COLOR" | tr '[:upper:]' '[:lower:]')
ADAPTER_PATH="adapters/${COLOR_LOWER}_belt_v1"
OUTPUT_NAME="models/AgenticART-7B-$BELT_COLOR"

echo "=================================================="
echo "   🏷️  AGENTIC ART: BRANDING & FUSION ($BELT_COLOR)"
echo "=================================================="
echo "Base:    $BASE_MODEL"
echo "Adapter: $ADAPTER_PATH"
echo "Target:  $OUTPUT_NAME"
echo "--------------------------------------------------"

if [ ! -d "$ADAPTER_PATH" ]; then
    echo "❌ Error: Adapter not found at $ADAPTER_PATH"
    exit 1
fi

echo "🚀 Fusing Model..."
python3 -m mlx_lm.fuse \
    --model "$BASE_MODEL" \
    --adapter-path "$ADAPTER_PATH" \
    --save-path "$OUTPUT_NAME"

echo ""
echo "✅ Fusion Complete! Target: $OUTPUT_NAME"

