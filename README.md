# 🥋 AgenticART: The Android Security Training Dojo

**A multi-modal "Feedback Loopback" Data Engine for Autonomous Vulnerability Research (AVR) and hardware-grounded model refinement.**

AgenticART implements a recursive training architecture that uses a live Android environment to observe, correct, and warehouse high-precision security trajectories. It is designed to turn generic LLMs into specialized security agents capable of navigating the complex boundaries of the Android kernel and discovering undocumented vulnerabilities.

---

## 🏗 The Architecture: "The Feedback Loopback"

AgenticART operates as a continuous four-stage loop that aligns LLM reasoning with the physical reality of the Android operating system.

### 1. The Multi-Modal Mine (Hardware Grounding)
The system mines high-fidelity security data across three primary domains:
*   **ADB Commands:** Fundamentals, recon, and intent manipulation.
*   **Frida Scripts (JS):** Dynamic instrumentation and runtime analysis.
*   **Kernel Exploits (C):** Privilege escalation and memory corruption logic.

### 2. The High-Fidelity Refinery (Automated Curation)
Raw logs are processed via a logic-aware refinery to ensure maximum data quality:
*   **Smart Grader:** Language-specific validation that eliminates false syntax errors in complex JS/C code.
*   **API Bridge:** Uses the Ollama HTTP API to capture clean, uncorrupted model output.
*   **Success-Only Filter:** Strictly blocks failed attempts from entering the Supervised Learning (SFT) set.

### 3. The Intelligence Warehouse (Discovery Hub)
A persistent library of verified "Gold Standard" exploits.
*   **Survival of the Fittest:** Automatically upgrades records when a more efficient solution is discovered.
*   **AVR Log:** Captures every successful bypass and unique failure mode across all models.

### 4. DPO Boundary Learning (Security Intuition)
The final alignment stage where the model develops "Security Intuition" by studying the **Boundary**: *"Path X leads to a Kernel Panic; therefore, the only logical trajectory is Path Y."*

---

## ⚫ The Black Belt: Autonomous Vulnerability Research (AVR)
AgenticART is built for the "Long Game" of zero-day discovery. Using the new **Exploration Mode**, the system acts as an automated bug-hunter:
1.  **Enumerate** undocumented system services and exported interfaces.
2.  **Recursively Probe** targets using the Feedback Loopback to fix and refine payloads.
3.  **Identify Anomalies** (crashes, memory leaks, logic flaws) that mark potential zero-day vulnerabilities or high-value bug bounty targets.

---

## 🍱 The Belt System (Curriculum)
*   ⚪ **White:** Fundamentals (`getprop`, `pm list`).
*   🟡 **Yellow:** Reconnaissance (`dumpsys`, `am start`).
*   🟠 **Orange:** Pre-Exploitation (SUID Probing, Payload Staging).
*   🔵 **Blue:** Exploitation & Rooting (`C-exploits`, `kernel triggers`).
*   🟢 **Green:** Dynamic Analysis (`Frida instrumentation`).
*   ⚫ **Black:** Autonomous Vulnerability Research (AVR).

---

## 🛠 Getting Started

### 1. Requirements
*   **Ollama:** For local LLM inference.
*   **Android SDK:** A running emulator (AVD) or physical device connected via ADB.
*   **Python 3.10+**

### 2. Initiate the Loopback
```bash
# Standard Challenge Mode
python3 -m dojo.test_end_to_end --mode live --model qwen2.5-coder:32b --belt orange

# Autonomous Exploration Mode (AVR Foundation)
python3 -c "from dojo.curriculum.challenger import Challenger; challenger.run_exploration(target='com.android.systemui')"
```

---

## ⚖️ The Unique Value
AgenticART creates a **"Data Moat."** By running this engine, you generate a proprietary dataset of hardware-verified Android exploits. You are not just using AI; you are **manufacturing the intelligence** required to automate vulnerability research at scale.
