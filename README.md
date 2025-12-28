# AgenticART: Recursive Hardware-Grounded Alignment for Autonomous Android Vulnerability Research

**Abstract:** AgenticART is a research framework designed to bridge the gap between general-purpose Large Language Models (LLMs) and the specialized requirements of Android security engineering. By implementing a recursive "Feedback Loopback" architecture, the system performs autonomous trajectory synthesis, hardware-level verification via a live Android environment, and subsequent model alignment using Supervised Fine-Tuning (SFT) and Direct Preference Optimization (DPO).

---

## 🔬 Core Methodology: Hardware-Grounded RLHF

The framework operates on the hypothesis that security-specific model intelligence is a function of verified execution history rather than static pre-training.

### 1. Trajectory Synthesis & Execution Feed
The system generates candidate exploit trajectories across three primary execution domains:
*   **CLI/ADB Layer:** Shell-level reconnaissance and intent manipulation logic.
*   **Dynamic Instrumentation (Frida):** Runtime memory inspection and API hooking.
*   **Kernel Interface (C/Native):** Low-level interaction with system drivers and the Linux kernel.

### 2. Automated Data Provenance (The Refinery)
AgenticART utilizes an automated grading engine to classify raw execution logs:
*   **NVD-Driven Curriculum:** Ingests live CVE data from the NIST National Vulnerability Database.
*   **Semantic Classification:** CVEs are categorized into a tiered "Belt System" using a multi-factor heuristic involving CVSS 3.1 scores, attack vectors, and keyword-based complexity analysis (e.g., UAF vs. Info Leak).
*   **Verification Gate:** Only trajectories achieving a verified terminal state (objective met) are promoted to the "Gold" training set.

### 3. Alignment & Reinforcement (DPO Phase)
Model refinement is achieved through Direct Preference Optimization:
*   **Chosen Trajectories ($y_w$):** Verified successful executions.
*   **Rejected Trajectories ($y_l$):** Failed attempts exhibiting common security-specific failure modes (e.g., syntax errors, permission denied states, or kernel panics).
*   **Reward Modeling:** This phase encodes "security intuition" by mathematically penalizing trajectories that lead to failed states.

---

## 🍱 Tiered Proficiency Infrastructure (Curriculum)
The research environment is partitioned into discrete belts to measure model generalization:
*   **L1 (White/Yellow):** Foundational reconnaissance and environment fingerprinting.
*   **L2 (Orange/Green):** Inter-Process Communication (IPC) logic and dynamic instrumentation.
*   **L3 (Blue/Purple):** Native memory corruption and privilege escalation.
*   **L4 (Brown/Black):** Autonomous Vulnerability Research (AVR) and kernel-level zero-day discovery.

---

## 🏎 Performance Architecture: MLX & Apple Silicon
To facilitate high-throughput local experimentation, the framework implements a native **MLX-LM** training path optimized for Apple's M-series Unified Memory:
*   **Quantization:** 4-bit NormalFloat (NF4) quantization for high-parameter models (32B+).
*   **LoRA Integration:** Low-Rank Adaptation targeting the $W_q$ and $y_v$ projections to minimize memory overhead while maintaining alignment stability.
*   **Compute:** Direct utilization of the 40-core GPU via Metal Performance Shaders (MPS), achieving an order of magnitude increase in tokens-per-second during alignment phases.

---

## 🛠 Implementation & Reproduction

### Prerequisites
*   Android SDK / Platform Tools (ADB)
*   Ollama (Local Inference Engine)
*   MLX / MLX-LM (M-series Optimization)

### Execution Pipeline
1.  **Curriculum Generation:** `python3 scripts/generate_nvd_challenges.py`
2.  **Trajectory Mining:** `python3 dojo/test_end_to_end.py --mode live --model [base_model] --belt [target]`
3.  **Model Alignment:** `python3 scripts/package_finetune.py` followed by `python3 mlx_train.py`

---

## 📊 Evaluation & Metrics
Progress is tracked via the **Dojo Benchmarking Dashboard**, which evaluates:
*   **Domain Mastery:** Success rates across specific vulnerability classes.
*   **Execution Reliability:** The ratio of syntax-correct outputs to total attempts.
*   **Cross-Device Generalization:** (TODO) Performance delta across varying Android API levels and security patch sets.