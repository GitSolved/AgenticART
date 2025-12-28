# AgenticART Research Lab: Technical Specifications

**Milestone:** Android 11 Recursive Distillation
**Date:** 2025-12-28
**Lead Investigator:** AgenticART Dojo Framework

---

## 1. Hardware Infrastructure
The experiment was conducted on a high-density local workstation to prove capability compression on consumer-grade hardware.

*   **Machine:** MacBook Pro (Mac15,9)
*   **Processor:** Apple M3 Max (16-core CPU)
*   **Graphics:** 40-core GPU (Metal Performance Shaders enabled)
*   **Architecture:** ARM64 (Apple Silicon)
*   **Memory Type:** Unified Memory Architecture (UMA)
*   **Peak Memory Usage during Training:** ~5.87 GB (Training 7B model)

---

## 2. Software Stack
A fully local, air-gapped-compatible stack was utilized to ensure data privacy and grounded execution.

*   **Operating System:** macOS (Darwin ARM64)
*   **Core Framework:** AgenticART Dojo (Recursive SFT/DPO Engine)
*   **Runtime:** Python 3.11.9
*   **Fine-Tuning Engine:** MLX-LM (Version 0.30.0)
*   **Local Inference:** Ollama (Teacher orchestration)
*   **Android Interface:** ADB (Android Debug Bridge version 1.0.41)
*   **Quantization:** 4-bit NormalFloat (NF4) via MLX

---

## 3. Model Specifications

### Student Model (The "Edge" Agent)
*   **Name:** WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B
*   **Parameters:** 7.62 Billion
*   **Base:** Qwen 2.5 Coder
*   **Format:** MLX 4-bit (Locally Quantized)
*   **Specialization:** Cyber-security, Exploit Generation, Code Analysis.

### Teacher Model (The "Oracle")
*   **Name:** Llama-3.1-70B
*   **Parameters:** 70 Billion
*   **Provider:** Meta AI (Hosted locally via Ollama)
*   **Role:** Trajectory Synthesis & Gold-standard command generation.

---

## 4. Distillation Methodology (LoRA)
The transition from 20% to 100% success was achieved via targeted Low-Rank Adaptation.

*   **Training Type:** Supervised Fine-Tuning (SFT)
*   **Dataset:** 10 Gold Trajectories (High-Signal)
*   **Iterations:** 500
*   **Batch Size:** 1 (Small dataset optimization)
*   **Learning Rate:** 1e-5
*   **Adapter Path:** `models/whiterabbit-7b-adapters`
*   **Trainable Parameters:** 11.534M (0.151% of base model)
*   **Loss Convergence:** 3.198 (Initial) -> 0.091 (Final)

---

## 5. Execution Environment (The Target)
*   **Target Device:** 127.0.0.1:6562 (Android Emulator)
*   **API Level:** 30 (Android 11)
*   **Security Context:** SELinux Enforcing, No Root (Initially), Foundational ADB interfaces.

---

## 6. Critical Operational Insights for Paper
1.  **Capability Parity:** We achieved **100% parity** with the 70B teacher model (improving from a 20% baseline) while reducing parameter count by **90%**.
2.  **Prompt Engineering:** The "Inference Muzzle" (Manual Stop Tokens) was the critical software fix that allowed the 7B model to reliably execute commands without EOS leakage.
3.  **Efficiency Density:** Success was achieved with <15 training samples, proving that domain-specific alignment requires **depth of trajectory**, not breadth of data.
