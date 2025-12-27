# 🥋 AgenticART: The Android Security Training Dojo

**An automated, hardware-grounded Data Engine for turning generic LLMs into specialized Android Security Agents.**

Most AI security projects fail because they train models on "noisy" data (failures mixed with successes). **AgenticART** implements a "Self-Correcting Gold Mine" architecture that uses real Android hardware to filter, refine, and warehouse only the highest-quality training trajectories.

---

## 🏗 The Data Engine Architecture: "The Gold Mine"

AgenticART operates as a four-stage engine that turns raw LLM attempts into hardware-verified intelligence.

### 1. The Mine (Hardware Grounding)
The model attempts security challenges against a **live Android device (ADB)**. 
*   **Judge:** The Android Kernel. If a command fails, the system captures the objective error (e.g., `Permission Denied`).
*   **Result:** Raw data that is grounded in reality, not internet theory.

### 2. The Refinery (Automated Filtration)
Raw logs are "poisonous." Our refinery automatically cleans them:
*   **Success-Only Filter:** Strictly blocks failed attempts from entering the Supervised Learning (SFT) set.
*   **Prefix Normalization:** Strips redundant syntax (e.g., `adb shell`) to ensure 100% consistent command structure.
*   **Multi-Turn Logic:** Converts "Failure → Hint → Success" sequences into conversational data that teaches the model *how* to debug.

### 3. The Warehouse (Master Dataset)
A persistent, ever-growing library of the "Best Hits" recorded across all models.
*   **Deduplication:** Ignores redundant data to keep training sets lean.
*   **Quality Upgrades:** If a new run finds a **Grade A** (Perfect) command for a task where we only had a **Grade B**, the Warehouse automatically **overwrites** the old data with the better version.

### 4. The Intelligence (DPO Boundary Learning)
The final stage where raw data is transformed into "Security Intuition."
*   **Boundary Mapping:** The system pairs the **Warehouse Success (Chosen)** against the **New Failure Modes (Rejected)** for the same task.
*   **The Lesson:** During training, the model doesn't just learn "This is the answer." It learns the **Boundary**: *"Doing X results in a Permission Error; therefore, the only logical path is Y."*

---

## 📈 Why this makes Models Smarter (The Flywheel)

| Stage | Traditional Method | AgenticART Data Engine |
| :--- | :--- | :--- |
| **Data Quality** | "Poisoned" with failures | **100% Hardware-Verified Successes** |
| **Consistency** | Confused by mixed prefixes | **Strictly Normalized Syntax** |
| **Learning** | Rote Memorization | **Agentic Reasoning (Logic of the Fix)** |
| **Over Time** | Model regresses/gets worse | **Model "Levels Up" via the Warehouse** |

---

## 🍱 The Belt System (Curriculum)
The curriculum is divided into "Belts" to measure progression:
*   ⚪ **White Belt:** Fundamentals (`getprop`, `pm list`).
*   🟡 **Yellow Belt:** Reconnaissance (`dumpsys`, `am start`).
*   🟠 **Orange Belt:** Exploitation (`run-as`, `sqlite3`, `content query`).
*   ⚫ **Black Belt:** (In Research) Novel zero-day pattern generation.

---

## 🛠 Getting Started

### 1. Requirements
*   **Ollama:** For local LLM inference.
*   **Android SDK:** A running emulator (AVD) or physical device via ADB.
*   **Python 3.10+**

### 2. Run a Training Session
```bash
python3 -m dojo.test_end_to_end --mode live --model llama3.1:8b --belt yellow
```

### 3. Access the Warehouse
Your "Gold Standard" training data is automatically maintained in:
*   `master_dataset/master_alpaca.json`: The best successes for SFT.
*   `master_dataset/master_dpo.jsonl`: Preference pairs for DPO.

---

## ⚖️ The Unique Value
AgenticART creates a **"Data Moat."** By running this engine, you generate a proprietary dataset of hardware-verified Android exploits that doesn't exist anywhere else. You aren't just using AI; you are **manufacturing the intelligence** required to find the next generation of zero-day vulnerabilities.