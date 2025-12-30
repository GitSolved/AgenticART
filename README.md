# AgenticART: A Dojo Framework for Recursive Security LLM Training

**Abstract:** AgenticART is a research framework for studying how Large Language Models (LLMs) can be aligned to Android security tasks. It implements a recursive "feedback loopback" architecture that (i) synthesizes candidate exploit trajectories, (ii) executes them on a live Android environment, and (iii) uses the resulting execution traces to refine models via Supervised Fine-Tuning (SFT) and Direct Preference Optimization (DPO). The current implementation targets shell/ADB, Frida-based dynamic instrumentation, and native interfaces as primary execution domains.

---

## 🚀 Proof of Impact: The Android 11 Milestone

We have successfully demonstrated the "Dojo Flywheel" by distilling data-center class intelligence into a local, specialized agent.

*   **Student:** WhiteRabbitNeo 2.5 7B (MLX 4-bit)
*   **Teacher:** Llama 3.1 70B
*   **Target:** Android 11 (API 30)
*   **Result:** The student model's pass rate on foundational security tasks increased from **20% to 100%** (+80 percentage points) after 500 iterations of LoRA fine-tuning on teacher-generated "Gold" trajectories.

---

## 🛡️ Why AgenticART?

This framework solves the "Security AI Paradox" by providing:

1.  **Capability Compression (Distillation):** High-end reasoning from 70B+ models is compressed into 7B models that run natively on local workstations/laptops.
2.  **Air-Gapped Privacy:** 100% offline execution. No exploit trajectories are ever sent to cloud APIs, making it safe for sensitive vulnerability research.
3.  **Execution-Verified Truth:** Unlike general LLMs that hallucinate code, AgenticART models are trained on **verified execution traces** from Android devices or emulators. They know what *actually* works.
4.  **Automated Specialization:** The framework acts as a "factory" for security brains. Point it at a new Android version or device, and it autonomously trains a specialized agent for that specific target.

---

## 🔬 Research Significance: AI Alignment for Security

For AI Security researchers, AgenticART provides a novel environment for studying **Hardware-Grounded Alignment**:

1.  **Physical Verification Gates vs. "Vibe Checks":** Most RLHF depends on human preference ("vibe checks"). AgenticART replaces human graders with a physical Android kernel. The reward signal is binary and objective: *Does the code execute and achieve the goal on real hardware?*
2.  **Quantified Capability Compression:** We have empirically demonstrated a **10:1 Intelligence Density** ratio, proving that specialized 7B models can achieve 100% parity with 70B models when distilled through hardware-verified trajectories.
3.  **Failure Mode Archeology:** By capturing and grading thousands of failed attempts, the Dojo builds a unique dataset of **AI Security Hallucinations**. This allows researchers to study the cognitive limits of LLMs in high-stakes, adversarial environments.
4.  **Recursive Alignment Loop:** The Dojo acts as a "Specialization Factory." It solves the problem of model decay against new security patches by autonomously synthesized new "Gold" data for every new Android OS release.

---

## 🎯 High-Level Overview

At a high level, AgenticART runs an LLM as an "agent" that proposes actions (e.g., ADB commands, Frida scripts, native code), executes them on an Android device or emulator, and logs what happened. Verified-successful sequences are treated as positive training examples; failed or unsafe sequences become negative examples. Over time, these examples can be used to train or adapt models that better handle Android vulnerability research workflows. This repository focuses on the orchestration, data pipeline, and alignment scripts needed to explore that loop.

---

## 🔬 Core Methodology: Execution-Verified RLHF

The framework operates on the hypothesis that security-specific capabilities depend on verified execution history, not only on static pre-training. This repository provides tooling to test that hypothesis; full empirical evaluation is ongoing.

### 1. Trajectory Synthesis & Execution Feed

The system generates candidate exploit trajectories across three primary execution domains:

* **CLI/ADB Layer:** Shell-level reconnaissance and intent manipulation logic.
* **Dynamic Instrumentation (Frida):** Runtime memory inspection and API hooking.
* **Kernel Interface (C/Native):** Low-level interaction with system drivers and the Linux kernel. *(Currently syntax-validation only; on-device execution requires NDK integration.)*

### 2. Automated Data Provenance (The Refinery)

AgenticART includes an automated grading component that attempts to classify raw execution logs:

* **NVD-Driven Curriculum:** Ingests live CVE data from the NIST National Vulnerability Database.
* **Semantic Classification:** CVEs are categorized into a tiered "Belt System" using a multi-factor heuristic involving CVSS 3.1 scores, attack vectors, and keyword-based complexity analysis (e.g., UAF vs. Info Leak).
* **Verification Gate:** Only trajectories that reach a clearly defined objective (e.g., specific file access, privilege boundary crossing) are promoted to the "Gold" training set; this promotion logic is configurable and still under active refinement.

### 3. Alignment & Reinforcement (DPO Phase)

Model refinement is achieved through Direct Preference Optimization:

* **Chosen Trajectories ($y_w$):** Verified successful executions.
* **Rejected Trajectories ($y_l$):** Failed attempts exhibiting common security-specific failure modes (e.g., syntax errors, permission denied states, or execution crashes).
* **Reward Modeling:** This phase is intended to encode security-relevant preferences by penalizing trajectories that consistently lead to failed or unsafe states (e.g., repeated permission errors, crashes). We have not yet quantified how much this improves real-world exploit performance; that is future work.

---

## 🍱 Tiered Proficiency Infrastructure (Curriculum)

The research environment is partitioned into discrete belts to measure model generalization:

* **L1 (White/Yellow):** Foundational reconnaissance and environment fingerprinting.
* **L2 (Orange/Green):** Inter-Process Communication (IPC) logic and dynamic instrumentation.
* **L3 (Blue/Purple):** Native memory corruption and privilege escalation.
* **L4 (Brown/Black):** Autonomous Vulnerability Research (AVR) targeting kernel-level behavior and complex exploitation chains. In the current codebase, L4 is a conceptual target tier; systematic zero-day discovery is an aspirational goal rather than a demonstrated capability.

---

## 🏎 Performance Architecture: MLX & Apple Silicon

To facilitate high-throughput local experimentation, the framework implements a native **MLX-LM** training path optimized for Apple's M-series Unified Memory:

* **Quantization:** 4-bit NormalFloat (NF4) quantization for high-parameter models (32B+).
* **LoRA Integration:** Low-Rank Adaptation targeting the $W_q$ and $W_v$ projections to minimize memory overhead while maintaining alignment stability.
* **Compute:** Direct utilization of the 40-core GPU via Metal Performance Shaders (MPS). In local testing on M-series hardware, this configuration has provided substantial speedups in tokens-per-second during alignment experiments, compared to unoptimized baselines.

---

## 🛠 Implementation & Reproduction

### Prerequisites

* Python 3.10+
* Android SDK / Platform Tools (ADB)
* Ollama (Local Inference Engine)
* MLX / MLX-LM (M-series Optimization, optional)

### Installation

```bash
# Clone and install dependencies
git clone https://github.com/GitSolved/AgenticART.git
cd AgenticART
pip install -r requirements.txt

# Install as editable package (optional, for development)
pip install -e .
```

### Execution Pipeline

1. **Curriculum Generation:** `python3 scripts/generate_nvd_challenges.py`
2. **Trajectory Mining:** `python3 dojo/test_end_to_end.py --mode live --model [base_model] --belt [target]`
3. **Model Alignment:** `python3 scripts/package_finetune.py` followed by `python3 mlx_train.py`

Each step is modular; researchers can swap in different base models, challenge sets, or training backends while keeping the same orchestration flow.

---

## 📊 Evaluation & Metrics

Progress is tracked via the **Dojo Benchmarking Dashboard**, which evaluates:

* **Domain Mastery:** Success rates across specific vulnerability classes.
* **Execution Reliability:** The ratio of syntax-correct outputs to total attempts.
* **Cross-Device Generalization:** Performance delta across varying Android API levels and security patch sets.

---

## 🧠 Framework Evolution: The ReAct Challenger

Recent research within the Dojo has proven that while the "Basic Challenger" is efficient for foundational tasks, higher-belt challenges (Yellow and above) require **ReAct (Reason + Act)** prompting to achieve reliability.

### 🔬 Proof of ReAct Effectiveness: Multi-Step Discovery
We conducted a controlled experiment on a **Dynamic Package Discovery** task: *"Find the versionName of the package containing 'telephony'."*

*   **Basic Challenger (FAIL):** Attempts to solve the problem in a single turn using complex, brittle one-liners. It cannot adapt when a command fails or when intermediate data is needed.
*   **ReAct Challenger (SUCCESS):** Demonstrates "System 2" thinking by breaking the task into logical steps:
    1.  **Reconnaissance:** Enumerates packages to find the exact target string.
    2.  **Analysis:** Uses the discovered package name to query the system for the version.
    3.  **Validation:** Confirms the output matches the goal and signals completion.

### 🗝️ Key Integration Insight
ReAct is the **essential bridge** between simple command generation and autonomous vulnerability research. It enables the model to recover from "Permission Denied" errors, pivot to alternative tools (e.g., switching from `pm` to `dumpsys`), and maintain a stateful context of the target device's internal state.

---

## 🚧 Status and Limitations

### Currently implemented:

*   **[VERIFIED]** End-to-end distillation loop: 70B Teacher → 7B Student via MLX LoRA.
*   **[VERIFIED]** +80 percentage point improvement on Android 11 foundational benchmarks (20% → 100%, reaching parity with teacher).
*   End-to-end orchestration for generating Android security challenges from NVD data.
*   Initial grading and curriculum logic (belt tiers) based on CVSS and heuristic classification.

### Experimental / in progress:

* Robust automated verification criteria for "success" across diverse vulnerability classes.
* Evaluation of how much aligned models improve over base models on fixed Android security benchmarks.
* Generalization tests across multiple device profiles and API levels.

### Known limitations and risks:

* This framework is a research prototype and should not be treated as a production-ready pentesting tool.
* Automated exploit generation and execution can cause instability (e.g., crashes, data loss) on test devices; use only in controlled environments you own and have permission to test.
* The system does not guarantee discovery of new vulnerabilities; its primary purpose is to study agentic workflows and alignment in Android security contexts.

Note: upcoming research paper proving effectiveness of this framework will be posted to my cybersecurity portfolio website: [secureyourgear.com](https://secureyourgear.com). Comments & questions are always appreciated! 
