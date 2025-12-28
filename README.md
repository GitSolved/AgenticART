# AgenticART: Recursive Hardware-Grounded Alignment for Autonomous Android Vulnerability Research

**Abstract:** AgenticART is a research framework for studying how Large Language Models (LLMs) can be aligned to Android security tasks. It implements a recursive "feedback loopback" architecture that (i) synthesizes candidate exploit trajectories, (ii) executes them on a live Android environment, and (iii) uses the resulting execution traces to refine models via Supervised Fine-Tuning (SFT) and Direct Preference Optimization (DPO). The current implementation targets shell/ADB, Frida-based dynamic instrumentation, and native interfaces as primary execution domains.

---

## 🎯 High-Level Overview

At a high level, AgenticART runs an LLM as an "agent" that proposes actions (e.g., ADB commands, Frida scripts, native code), executes them on an Android device or emulator, and logs what happened. Verified-successful sequences are treated as positive training examples; failed or unsafe sequences become negative examples. Over time, these examples can be used to train or adapt models that better handle Android vulnerability research workflows. This repository focuses on the orchestration, data pipeline, and alignment scripts needed to explore that loop.

---

## 🔬 Core Methodology: Hardware-Grounded RLHF

The framework operates on the hypothesis that security-specific capabilities depend on verified execution history, not only on static pre-training. This repository provides tooling to test that hypothesis; full empirical evaluation is ongoing.

### 1. Trajectory Synthesis & Execution Feed

The system generates candidate exploit trajectories across three primary execution domains:

* **CLI/ADB Layer:** Shell-level reconnaissance and intent manipulation logic.
* **Dynamic Instrumentation (Frida):** Runtime memory inspection and API hooking.
* **Kernel Interface (C/Native):** Low-level interaction with system drivers and the Linux kernel.

### 2. Automated Data Provenance (The Refinery)

AgenticART includes an automated grading component that attempts to classify raw execution logs:

* **NVD-Driven Curriculum:** Ingests live CVE data from the NIST National Vulnerability Database.
* **Semantic Classification:** CVEs are categorized into a tiered "Belt System" using a multi-factor heuristic involving CVSS 3.1 scores, attack vectors, and keyword-based complexity analysis (e.g., UAF vs. Info Leak).
* **Verification Gate:** Only trajectories that reach a clearly defined objective (e.g., specific file access, privilege boundary crossing) are promoted to the "Gold" training set; this promotion logic is configurable and still under active refinement.

### 3. Alignment & Reinforcement (DPO Phase)

Model refinement is achieved through Direct Preference Optimization:

* **Chosen Trajectories ($y_w$):** Verified successful executions.
* **Rejected Trajectories ($y_l$):** Failed attempts exhibiting common security-specific failure modes (e.g., syntax errors, permission denied states, or kernel panics).
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
* **LoRA Integration:** Low-Rank Adaptation targeting the $W_q$ and $y_v$ projections to minimize memory overhead while maintaining alignment stability.
* **Compute:** Direct utilization of the 40-core GPU via Metal Performance Shaders (MPS). In local testing on M-series hardware, this configuration has provided substantial speedups in tokens-per-second during alignment experiments, compared to unoptimized baselines.

---

## 🛠 Implementation & Reproduction

### Prerequisites

* Android SDK / Platform Tools (ADB)
* Ollama (Local Inference Engine)
* MLX / MLX-LM (M-series Optimization)

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
* **Cross-Device Generalization:** (TODO) Performance delta across varying Android API levels and security patch sets.

---

## 🚧 Status and Limitations

### Currently implemented:

* End-to-end orchestration for generating Android security challenges from NVD data, running live trajectories against an Android device/emulator, and collecting execution logs.
* Initial grading and curriculum logic (belt tiers) based on CVSS and heuristic classification.
* SFT/DPO training scripts targeting MLX/Apple Silicon with NF4 quantization and LoRA adapters.

### Experimental / in progress:

* Robust automated verification criteria for "success" across diverse vulnerability classes.
* Evaluation of how much aligned models improve over base models on fixed Android security benchmarks.
* Generalization tests across multiple device profiles and API levels.

### Known limitations and risks:

* This framework is a research prototype and should not be treated as a production-ready pentesting tool.
* Automated exploit generation and execution can cause instability (e.g., crashes, data loss) on test devices; use only in controlled environments you own and have permission to test.
* The system does not guarantee discovery of new vulnerabilities; its primary purpose is to study agentic workflows and alignment in Android security contexts.

---

## 📄 License

MIT

---

## 🙏 Acknowledgments

This research was developed with assistance from Claude (Anthropic) for code review, documentation, and experiment design.
