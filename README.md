# 🥋 AgenticART: The Android Security Training Dojo

**An automated, hardware-grounded feedback loop for turning generic LLMs into specialized Android Security Agents.**

Traditional LLMs (like Llama 3 or GPT-4) frequently fail at niche technical tasks like Android Penetration Testing because of high-sensitivity syntax and complex privilege models. **AgenticART** solves the "Cold Start" problem by using a real Android environment to "teach" models through failure.

## 🚀 The Core Value
This is not a "hacking tool"—it is a **Training Data Factory**. It automates the process of:
1. **Testing** an LLM against real Android hardware (ADB).
2. **Extracting** specific failure reasons (Permission Denied, Syntax Error, etc.).
3. **Coaching** the model with automated hints to force self-correction.
4. **Refining** the output through strict prefix normalization and success-only filtering.
5. **Exporting** the resulting logs into high-quality **Fine-tuning datasets (Alpaca, ShareGPT & DPO)**.

---

## 🔄 The "Sensei" Feedback Loop
The framework treats the LLM like a student in a martial arts dojo:

1. **The Challenge:** The Sensei (Framework) gives the Student (LLM) a security task (e.g., "Extract the contacts database").
2. **The Attempt:** The Student generates an ADB command.
3. **The Execution:** The `Executor` runs the command on a live Android Emulator.
4. **The Lesson:** If it fails, the `ErrorExtractor` analyzes the `stderr` and feeds a hint back to the LLM.
5. **The Kata:** Once the model succeeds (verified via Regex), the entire multi-turn interaction is saved as a training example.

---

## 🍱 Project Structure (The Belt System)
The curriculum is divided into "Belts," allowing you to measure an LLM's progression:

*   ⚪ **White Belt:** Basic recon and device info gathering (`getprop`, `pm list`).
*   🟡 **Yellow Belt:** Intermediate diagnostics and intent manipulation (`dumpsys`, `am start`).
*   🟠 **Orange Belt:** Advanced exploitation and root-level access (`run-as`, `sqlite3`, `content query`).

---

## 🛠 Getting Started

### 1. Requirements
*   **Ollama:** For local LLM inference.
*   **Android SDK:** A running emulator (AVD) or physical device connected via ADB.
*   **Python 3.10+**

### 2. Run a Training Session
Generate a dataset by running a model through the White Belt:
```bash
python3 -m dojo.test_end_to_end --mode live --model llama3.1:8b --belt white
```

### 3. Export Data
After the run, your specialized training data is waiting in `dojo_output/`:
*   `training_data_alpaca.json`: Filtered, success-only data for Supervised Fine-Tuning (SFT).
*   `training_data_sharegpt.jsonl`: Multi-turn conversational data for "Reasoning" training.
*   `training_data_dpo.jsonl`: **Direct Preference Optimization** pairs (the "Wrong" vs "Right" paths).

---

## 📊 Performance Benchmark (Yellow Belt)
Current findings show that the Dojo framework significantly improves model accuracy by providing hardware-grounded context and strict formatting rules.

| Model Configuration | Pass Rate | Attempt 1 Success |
| :--- | :--- | :--- |
| **Llama 3.1 8B (Baseline)** | 30% | <10% |
| **WhiteRabbitNeo 7B (Baseline)** | 30% | <10% |
| **Refined Dojo (Ours)** | **50% - 80%** | **40% - 60%** |

---

## ⚖️ Why this Project Matters
Manual data collection for cybersecurity is slow and dangerous. **AgenticART** creates a safe, automated "Sandboxed Sandbox" where models can try and fail thousands of times until they master the art of Android security—resulting in a model that is hardware-verified, not just "smart-sounding."