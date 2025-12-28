import mlx.core as mx
from mlx_lm import convert


def main():
    # Force CPU for quantization to avoid Metal timeout
    mx.set_default_device(mx.cpu)

    hf_path = "models/whiterabbit-7b-dojo-fused"
    mlx_path = "models/whiterabbit-7b-dojo-4bit"

    print("🚀 Quantizing Fused 7B Brain (15GB -> ~4.7GB)...")
    convert(hf_path=hf_path, mlx_path=mlx_path, quantize=True, q_bits=4)
    print(f"✅ Quantization complete: {mlx_path}")


if __name__ == "__main__":
    main()
