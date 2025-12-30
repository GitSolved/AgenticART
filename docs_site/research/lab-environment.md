# Lab Environment

Technical specifications for reproducing AgenticART experiments.

## Hardware

| Component | Specification |
|-----------|---------------|
| Machine | MacBook Pro (Mac15,9) |
| Processor | Apple M3 Max (16-core CPU) |
| GPU | 40-core (Metal Performance Shaders) |
| Architecture | ARM64 (Apple Silicon) |
| Peak Memory | ~5.87 GB during training |

## Software Stack

| Component | Version |
|-----------|---------|
| Python | 3.11.9 |
| MLX-LM | 0.30.0 |
| ADB | 1.0.41 |
| Ollama | Latest |

## Models

### Student Model (Edge Agent)

- **Name:** WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B
- **Parameters:** 7.62 Billion
- **Format:** MLX 4-bit quantized
- **Specialization:** Cybersecurity, exploit generation

### Teacher Model (Oracle)

- **Name:** Llama-3.1-70B
- **Parameters:** 70 Billion
- **Provider:** Meta AI via Ollama
- **Role:** Gold trajectory generation

## Training Configuration

| Parameter | Value |
|-----------|-------|
| Method | LoRA (Low-Rank Adaptation) |
| Dataset | 10 gold trajectories |
| Iterations | 500 |
| Batch size | 1 |
| Learning rate | 1e-5 |
| Trainable params | 11.534M (0.151% of base) |
| Loss | 3.198 → 0.091 |

## Target Environment

| Parameter | Value |
|-----------|-------|
| Device | Android Emulator |
| API Level | 30 (Android 11) |
| Security | SELinux Enforcing |
| Root | No (non-rooted) |

## Reproducing Results

1. Set up environment per [Installation Guide](../getting-started/installation.md)
2. Run white belt with 70B teacher to generate traces
3. Package training data
4. Fine-tune 7B model with LoRA
5. Evaluate fine-tuned model on same challenges
