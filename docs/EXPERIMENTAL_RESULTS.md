# AgenticART Dojo: Experimental Results

## Abstract

This document presents experimental results from evaluating the AgenticART Dojo framework for improving LLM-generated ADB commands through execution feedback. We compare three configurations: (1) base model, (2) system prompt enhancement (Modelfile), and (3) fine-tuned model with 60 training examples collected via the Dojo feedback loop.

## Experimental Setup

### Hardware
- **Data Collection Machine**: Windows 11, 16GB RAM, no GPU (Ollama CPU inference)
- **Fine-tuning Machine**: Linux, NVIDIA GPU (details TBD)
- **Android Emulator**: Android 7.0 (API 24), x86 emulator via Android Studio AVD

### Models
- **Base Model**: WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B-GGUF (Q4_K_M quantization)
- **Modelfile**: Base model + structured system prompt with ADB command patterns
- **Fine-tuned**: Base model fine-tuned with 60 Alpaca-format examples (3 epochs, LoRA r=16)

### Evaluation Metrics
- **Pass Rate**: Percentage of challenges where the generated command produces expected output
- **Attempts**: Number of retries needed (max 3) before success or failure
- **Grade**: A-F scale based on syntax correctness, API validity, execution success, and objective achievement

### Challenge Sets
| Belt | Challenges | Focus |
|------|------------|-------|
| White | 5 | Basic ADB commands (getprop, pm list, ps) |
| Yellow | 10 | Intermediate (dumpsys, am start, logcat, screencap) |
| Orange | 15 | Advanced (run-as, sqlite3, content providers, port forwarding) |

---

## Results

### Summary Table

| Model | White Belt | Yellow Belt | Orange Belt | Overall |
|-------|------------|-------------|-------------|---------|
| **Base WhiteRabbitNeo** | 80% (4/5) | 30% (3/10) | 33% (5/15) | 40% (12/30) |
| **Modelfile (System Prompt)** | 80% (4/5) | 60% (6/10) | 33% (5/15) | 50% (15/30) |
| **Fine-tuned (60 examples)** | 60% (3/5) | 50% (5/10) | 27% (4/15) | 40% (12/30) |

### Detailed Results by Challenge

#### White Belt (Fundamentals)

| Challenge | Base | Modelfile | Fine-tuned |
|-----------|------|-----------|------------|
| white_001: Android Version | PASS | PASS (2 att) | FAIL |
| white_002: Package Listing | PASS | PASS | PASS |
| white_003: Device Model | PASS | PASS | PASS |
| white_004: Process Enumeration | PASS | PASS | PASS |
| white_005: Protected File Access | FAIL | FAIL | FAIL |

**Key Finding**: Base model and Modelfile both achieve 80%. Fine-tuned model regressed to 60% due to learning incorrect `adb shell` prefix pattern.

#### Yellow Belt (Intermediate)

| Challenge | Base | Modelfile | Fine-tuned |
|-----------|------|-----------|------------|
| yellow_001: App Permission Extraction | FAIL | PASS | FAIL |
| yellow_002: Launch Activity via Intent | PASS | PASS | PASS |
| yellow_003: Network Configuration | FAIL | PASS (2 att) | PASS (2 att) |
| yellow_004: Log Analysis with Filters | FAIL | PASS (2 att) | PASS |
| yellow_005: Running Services Enumeration | FAIL | FAIL | FAIL |
| yellow_006: APK Path Discovery | PASS | PASS (2 att) | PASS |
| yellow_007: Send Broadcast Intent | FAIL | FAIL | FAIL |
| yellow_008: Device Screenshot | FAIL | FAIL | FAIL |
| yellow_009: Simulate Text Input | FAIL | FAIL | FAIL |
| yellow_010: CPU Architecture Info | PASS | PASS | PASS |

**Key Finding**: Modelfile doubled yellow belt performance (30% → 60%) through explicit command patterns in system prompt.

#### Orange Belt (Advanced)

| Challenge | Base | Modelfile | Fine-tuned |
|-----------|------|-----------|------------|
| orange_001: App Data Directory | FAIL | FAIL | FAIL |
| orange_002: SQLite Database | FAIL | FAIL | FAIL |
| orange_003: Active Network Connections | PASS | PASS (2 att) | PASS |
| orange_004: Content Provider Enumeration | FAIL | FAIL | FAIL |
| orange_005: Process Memory Mapping | FAIL | FAIL | FAIL |
| orange_006: Package Component Listing | FAIL | FAIL | FAIL |
| orange_007: Security Properties | PASS | PASS (2 att) | FAIL |
| orange_008: Application Force Stop | PASS | FAIL | FAIL |
| orange_009: Hardware Key Simulation | FAIL | FAIL | FAIL |
| orange_010: Port Forward Configuration | FAIL | FAIL | FAIL |
| orange_011: Application Data Backup | FAIL | FAIL | FAIL |
| orange_012: UI Hierarchy Extraction | PASS | PASS | PASS |
| orange_013: Storage Space Analysis | PASS | PASS | PASS |
| orange_014: Modify System Setting | FAIL | FAIL | FAIL |
| orange_015: Shell Environment Dump | FAIL | PASS | PASS |

**Key Finding**: Orange belt performance plateaued across all configurations (~33%), indicating complex command synthesis requires more sophisticated training approaches.

---

## Analysis

### Why Did the Modelfile Outperform Fine-tuning?

1. **Training Data Quality Issues**
   - 60 examples included many failed attempts (negative examples)
   - Model may have learned patterns from incorrect commands
   - Format mismatch: training data included `adb shell` prefix while challenges expect just `shell`

2. **Observed Failure Patterns in Fine-tuned Model**
   - Generated `adb shell ...` instead of `shell ...`
   - Added unnecessary complexity (grep patterns, flags like `-A`)
   - Syntax errors from improper quoting

3. **System Prompt Advantages**
   - Direct, unambiguous command patterns
   - No conflicting examples
   - Explicit format rules ("Output ONLY the ADB command")

### Training Data Statistics

| Metric | Value |
|--------|-------|
| Total unique examples | 169 |
| Alpaca format (positive/kata) | 52 |
| DPO pairs | 23 |
| Examples by belt | White: 33, Yellow: 64, Orange: 72 |
| Examples by type | Positive: 22, Negative: 63, Error Recovery: 54, Kata: 30 |

**Issue Identified**: High ratio of negative examples (63) to positive examples (22) may have biased the model toward failure patterns.

---

## Key Findings

### 1. Execution Feedback Loop Works for Data Collection
The Dojo successfully collected 169 unique training examples across 10+ live test runs, demonstrating the viability of automated training data generation through execution feedback.

### 2. System Prompt Engineering > Naive Fine-tuning
For this task, a well-crafted system prompt (Modelfile) with explicit command patterns outperformed fine-tuning with 60 examples:
- Modelfile: +25% improvement on yellow belt
- Fine-tuned: -10% regression on white belt

### 3. Training Data Curation is Critical
The raw output of the Dojo feedback loop requires curation before fine-tuning:
- Filter out negative examples or use them only for DPO
- Ensure format consistency (remove `adb` prefix)
- Balance example types (more positive, fewer negative)

### 4. Orange Belt Represents a Complexity Ceiling
All three configurations performed similarly on orange belt (~33%), suggesting:
- Complex ADB commands (sqlite3, content providers, port forwarding) require specialized training
- May need domain-specific pre-training or larger training sets
- Some challenges may be inherently difficult due to device permissions

---

## Recommendations for Future Work

1. **Curated Training Set**: Fine-tune with only positive and kata examples (exclude negative/error_recovery)

2. **Format Normalization**: Pre-process training data to ensure consistent `shell` prefix (not `adb shell`)

3. **Larger Training Set**: Collect 500+ examples with better positive/negative balance

4. **DPO Training**: Use DPO pairs for preference learning rather than SFT

5. **Multi-turn Training**: Include retry sequences as multi-turn conversations to teach error recovery

---

## Reproducibility

### Running the Experiments

```bash
# Clone repository
git clone https://github.com/GitSolved/AgenticART.git
cd AgenticART

# Install dependencies
pip install -r dojo/requirements.txt

# Pull base model
ollama pull hf.co/bartowski/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B-GGUF:Q4_K_M

# Start Android emulator
emulator -avd <your_avd_name>

# Run evaluations
python -m dojo.test_end_to_end --mode live --belt white
python -m dojo.test_end_to_end --mode live --belt yellow
python -m dojo.test_end_to_end --mode live --belt orange
```

### Creating the Modelfile

```bash
cd dojo_output/finetune_package_*/
ollama create whiterabbit-adb-dojo -f Modelfile
python -m dojo.test_end_to_end --mode live --belt white --model whiterabbit-adb-dojo
```

---

## Appendix: Modelfile Configuration

```
FROM hf.co/bartowski/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B-GGUF:Q4_K_M

PARAMETER temperature 0.1
PARAMETER top_p 0.9
PARAMETER num_ctx 4096

SYSTEM """You are an expert Android security researcher specializing in ADB commands.

CRITICAL RULES:
1. Output ONLY the ADB command - no explanations, no markdown, no backticks
2. Use 'shell' prefix for on-device commands (not 'adb shell')
3. Use direct commands for host operations: forward, backup, install, push, pull
4. Never wrap commands in quotes or backticks

== WHITE BELT - Basic Commands (Priority) ==
Task: Get Android version
Command: shell getprop ro.build.version.release

Task: List installed packages
Command: shell pm list packages

Task: List running processes
Command: shell ps
...
"""
```

---

## Conclusion

The AgenticART Dojo demonstrates a viable approach to collecting execution-grounded training data for security LLMs. However, our experiments reveal that naive fine-tuning on raw feedback loop data can underperform simple system prompt engineering. The key insight is that **execution feedback generates valuable data, but curation is required before training**. Future work should focus on automated filtering of training examples and more sophisticated training approaches like DPO.

---

*Experimental data collected: December 24-25, 2025*
*Framework version: Dojo v0.3.0*
