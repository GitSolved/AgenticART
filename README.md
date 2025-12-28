# 🥋 AgenticART: The Android Security Training Dojo

**A Self-Improving "Data Flywheel" Engine for Autonomous Vulnerability Research (AVR) and hardware-grounded model refinement.**

AgenticART turns generic LLMs into specialized security agents by recursively mining verified security trajectories from a live Android environment. It uses the **National Vulnerability Database (NVD)** as an automated training factory, translating real-world CVEs into executable Dojo challenges.

---

## 🏗 The Architecture: "The Feedback Loopback"

AgenticART operates as a continuous four-stage loop that aligns LLM reasoning with the physical reality of the Android operating system.

### 1. The Execution Feed (Hardware Grounding)
The system executes and verifies security payloads across three primary domains:
*   **ADB Commands:** Fundamentals, recon, and intent manipulation.
*   **Frida Scripts (JS):** Dynamic instrumentation and runtime analysis.
*   **Kernel Exploits (C):** Privilege escalation and memory corruption logic.

### 2. Automated Curation (The Refinery)
Raw logs are processed via a logic-aware refinery to ensure maximum data quality:
*   **NVD Integration:** Automatically fetches recent CVEs and classifies them into the Belt System based on CVSS and semantic complexity (UAF, Intent Redirection, etc.).
*   **Success-Only Filter:** Strictly blocks failed attempts from entering the Supervised Learning (SFT) set.

### 3. The Playbook (Verified Successes)
A persistent library of verified "Gold Standard" exploits.
*   **Knowledge Foundation:** Focuses on "Structural Vulnerabilities"—bugs that represent entire classes of security failure.
*   **Survival of the Fittest:** Automatically upgrades records when a more efficient solution is discovered.

### 4. Reinforcement Learning (DPO)
The final alignment stage where the model develops "Security Intuition" by studying **Direct Preference Optimization (DPO)** pairs: *"Incorrect command caused a syntax error; the Corrected command achieved root."*

---

## 🍱 The Belt System (Curriculum)
*   ⚪ **White/Yellow:** Reconnaissance & Fundamentals (`dumpsys`, `getprop`).
*   🟠 **Orange/Green:** Interaction & Dynamic Analysis (`Intents`, `Frida Hooks`).
*   🔵 **Blue/Purple:** Exploitation & IPC (`Native code`, `Binder LPE`).
*   🟫 **Brown/Black:** Critical & Kernel (`UAF`, `Zero-days`, `AVR`).

---

## 🚀 Apple Silicon "Turbo" Optimization
Optimized specifically for **M3 Max** hardware using Apple's native **MLX** framework:
*   **MLX Training:** Native GPU-accelerated fine-tuning using 4-bit quantization.
*   **Unified Memory Utilization:** Efficiently loads 32B+ models for high-speed local learning.
*   **10x-50x Speedup:** Bypasses CPU bottlenecks to "ignite" the 40-core GPU.

---

## 🛠 Getting Started

### 1. Requirements
*   **Ollama:** For local LLM inference.
*   **MLX:** For high-performance Mac training.
*   **Android SDK:** A running emulator (AVD) or physical device connected via ADB.

### 2. Automate the Curriculum
```bash
# Generate 50 new challenges from the NVD API
python3 scripts/generate_nvd_challenges.py

# Build the structural knowledge foundation
python3 scripts/generate_foundation_curriculum.py
```

### 3. Initiate the Loopback
```bash
# Run the 70B model through the curriculum to generate "Gold" data
python3 dojo/test_end_to_end.py --mode live --model llama3.1:70b-instruct-q4_K_M --belt orange
```

### 4. Ignite the GPU (Training)
```bash
# Package data and run the MLX optimized trainer
python3 scripts/package_finetune.py
cd dojo_finetune_package/latest_package
python3 mlx_train.py
```

---

## ⚖️ The Unique Value
AgenticART creates a **"Data Moat."** By running this engine, you manufacture the intelligence required to automate vulnerability research at scale. You are building the world's most precise model for Android exploitation, grounded in real-world hardware execution.