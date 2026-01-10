# AgenticART Dojo Framework

**Transform AgenticART from a tool into a training ground for security LLMs**

---

## Philosophy

A **dojo** is not just a place where techniques are practiced—it's a system that:
- Provides structured progression (belt levels)
- Offers immediate feedback (sensei corrections)
- Captures successful patterns (kata)
- Measures mastery (grading)
- Enables continuous improvement (deliberate practice)

AgenticART already captures exploitation trajectories. The Dojo Framework formalizes this into a **self-improving training loop**.

---

## Architecture Overview

```
+-------------------------------------------------------------------------+
|                          DOJO FRAMEWORK                                 |
+-------------------------------------------------------------------------+
|                                                                         |
|  +------------------+    +------------------+    +------------------+   |
|  |    CURRICULUM    |    |     SPARRING     |    |     GRADING      |   |
|  |   (Challenge     |--->|   (Execution     |--->|    (Quality      |   |
|  |    Progression)  |    |    Against AVD)  |    |    Assessment)   |   |
|  +------------------+    +------------------+    +------------------+   |
|          |                       |                       |              |
|          |                       v                       |              |
|          |              +------------------+             |              |
|          |              |      SENSEI      |             |              |
|          |              |   (Feedback &    |<------------+              |
|          |              |    Correction)   |                            |
|          |              +------------------+                            |
|          |                       |                                      |
|          v                       v                                      |
|  +------------------------------------------------------------------+  |
|  |                    TRAINING DATA PIPELINE                         |  |
|  |  +--------------+  +--------------+  +--------------+             |  |
|  |  |   Positive   |  |   Negative   |  |    Error     |             |  |
|  |  |   Examples   |  |   Examples   |  |   Recovery   |             |  |
|  |  +--------------+  +--------------+  +--------------+             |  |
|  +------------------------------------------------------------------+  |
|                              |                                          |
|                              v                                          |
|                    +------------------+                                 |
|                    |   FINE-TUNING    |                                 |
|                    |    (LoRA/MLX)    |                                 |
|                    +------------------+                                 |
|                                                                         |
+-------------------------------------------------------------------------+
```

---

## Directory Structure

```
dojo/
|-- __init__.py              # Package exports
|-- config.py                # DojoConfig settings
|-- models.py                # Core data models (Belt, Grade, Challenge, etc.)
|-- exceptions.py            # Custom exceptions
|
|-- curriculum/              # Challenge system
|   |-- __init__.py
|   |-- challenger.py        # Orchestrates attempts with feedback loop
|   |-- loader.py            # Loads challenges from YAML
|   |-- executor.py          # Executes commands against device
|   |-- context_injector.py  # Injects error context for retries
|   |-- error_extractor.py   # Extracts actionable error information
|   |
|   |-- white_belt/          # Fundamentals
|   |   +-- challenges.yaml
|   |-- yellow_belt/         # Reconnaissance
|   |   +-- challenges.yaml
|   +-- orange_belt/         # Vulnerability mapping
|       +-- challenges.yaml
|
|-- sensei/                  # Grading and training data
|   |-- __init__.py
|   |-- sensei.py            # Main orchestrator
|   |-- grader.py            # Evaluates challenge sessions
|   |-- exporter.py          # Exports to Alpaca/ShareGPT/DPO formats
|   |-- progress_tracker.py  # Tracks model progress across sessions
|   +-- training_extractor.py # Extracts training examples from sessions
|
|-- finetune/                # Model training utilities
|   |-- __init__.py
|   |-- config.py            # FinetuneConfig
|   +-- packager.py          # Packages data for GPU training
|
|-- test_end_to_end.py       # Integration test
|-- test_phase2.py           # Curriculum tests
+-- test_phase3.py           # Sensei tests
```

---

## 1. Belt Progression System

### Belt Levels

| Belt | Name | Challenge Type | Success Criteria |
|------|------|----------------|------------------|
| ⬜ White | Fundamentals | ADB command syntax, device enumeration | Valid commands, correct output parsing |
| 🟨 Yellow | Reconnaissance | Package listing, permission analysis | Complete device profile extraction |
| 🟧 Orange | Vulnerability Mapping | CVE matching, version fingerprinting | Accurate CVE-to-device correlation |
| 🟩 Green | Scripting | Python/Bash exploit scaffolding | Syntactically correct, executable scripts |
| 🟦 Blue | Exploitation | Known CVE reproduction | Successful privilege escalation |
| 🟪 Purple | Evasion | SELinux bypass, detection avoidance | Undetected execution |
| 🟫 Brown | Chaining | Multi-phase attack orchestration | Complete chain from recon to verify |
| ⬛ Black | Novel Exploit | Zero-day pattern generation | Working exploit for unpatched vuln |

> **Current Implementation:** White, Yellow, and Orange belt challenges are implemented. Higher belts are planned.

### Challenge YAML Format

```yaml
# dojo/curriculum/white_belt/challenges.yaml
challenges:
  - id: white_001
    name: "Device Android Version"
    description: |
      Write an ADB shell command that outputs the Android version.
      The output should be just the version number (e.g., "11").
    belt: white
    difficulty: 1
    script_type: adb

    inputs:
      device_id: "emulator-5554"
      device_context:
        connection: "adb"
        task: "retrieve Android version"

    validation:
      type: regex_match
      pattern: "^\\d+(\\.\\d+)*"

    hints:
      - "Use 'adb shell getprop' to read system properties"
      - "Android version is stored in ro.build.version.release"

    kata_solution: "shell getprop ro.build.version.release"

    tags:
      - fundamentals
      - device-info
```

---

## 2. Core Components

### ChallengeLoader

Loads and validates challenges from YAML files.

```python
from dojo.curriculum import ChallengeLoader

loader = ChallengeLoader()
challenge = loader.load("white_001")
all_white = loader.load_belt(Belt.WHITE)
```

### Challenger

Orchestrates challenge attempts with the feedback loop.

```python
from dojo.curriculum import Challenger, ChallengeSession

challenger = Challenger(
    loader=loader,
    executor=executor,
    llm_client=llm_client,
    max_attempts=3,
)

session: ChallengeSession = challenger.run_challenge("white_001")
print(f"Success: {session.final_success}")
print(f"Attempts: {len(session.attempts)}")
```

### Executor

Executes commands against the Android device with tier tracking.

```python
from dojo.curriculum import Executor, ExecutionResult

executor = Executor(adb_path="/usr/bin/adb", device_id="emulator-5554")
result: ExecutionResult = executor.execute("shell getprop ro.build.version.release")

print(f"Success: {result.success}")
print(f"Output: {result.stdout}")
print(f"Tier: {result.tier_used}")  # 1=ADB, 2=ON_DEVICE
```

### ErrorExtractor & ContextInjector

Extracts error information and injects it into retry prompts.

```python
from dojo.curriculum import ErrorExtractor, ContextInjector

extractor = ErrorExtractor()
error_context = extractor.extract(result)

injector = ContextInjector()
retry_prompt = injector.inject(original_prompt, error_context)
```

---

## 3. Sensei Module (Grading & Training Data)

### Sensei

The main orchestrator that connects grading, extraction, and export.

```python
from dojo.sensei import Sensei

sensei = Sensei(output_dir=Path("./dojo_output"))

# Evaluate a single session
assessment, examples = sensei.evaluate_session(session, model_id="qwen-v1")

# Evaluate multiple sessions and run full cycle
result = sensei.run_training_cycle(
    sessions=sessions,
    model_id="qwen-v1",
    export_formats=[ExportFormat.ALPACA, ExportFormat.DPO],
)
print(result.summary())
```

### Grader

Evaluates challenge sessions and produces assessments.

```python
from dojo.sensei import Grader, GradingResult

grader = Grader()
assessment: SenseiAssessment = grader.grade_session(session)

print(f"Grade: {assessment.grade}")  # Grade.PERFECT, GOOD, ACCEPTABLE, POOR, FAIL
print(f"Score: {assessment.score}")  # 0-100
print(f"Syntax Issues: {assessment.syntax_issues}")
print(f"API Errors: {assessment.api_errors}")
```

### Grade Enum

```python
from dojo.models import Grade

class Grade(Enum):
    PERFECT = "A"      # No corrections needed -> positive example
    GOOD = "B"         # Minor issues -> positive with notes
    ACCEPTABLE = "C"   # Functional but needs improvement
    POOR = "D"         # Major issues -> negative example with correction
    FAIL = "F"         # Non-functional -> negative example
```

### TrainingExtractor

Extracts training examples from graded sessions.

```python
from dojo.sensei import TrainingExtractor

extractor = TrainingExtractor()
examples: list[TrainingExample] = extractor.extract_from_session(session, assessment)

# Examples include:
# - Positive examples (Grade A/B)
# - Negative examples (Grade D/F)
# - Error recovery pairs (failed -> fixed)
```

### TrainingDataExporter

Exports training data in multiple formats.

```python
from dojo.sensei import TrainingDataExporter, ExportFormat

exporter = TrainingDataExporter(output_dir=Path("./training_data"))

# Export in Alpaca format (instruction/input/output)
path = exporter.export(examples, ExportFormat.ALPACA)

# Export in DPO format (chosen/rejected pairs)
path = exporter.export(examples, ExportFormat.DPO)

# Export in ShareGPT format (conversations)
path = exporter.export(examples, ExportFormat.SHAREGPT)
```

### ProgressTracker

Tracks model progress across training sessions.

```python
from dojo.sensei import ProgressTracker

tracker = ProgressTracker(storage_path=Path("./progress"))
tracker.record_assessment(model_id, assessment)

progress = tracker.get_progress(model_id)
print(f"Belt: {progress.current_belt}")
print(f"Pass Rate: {progress.pass_rate}%")
print(f"Ready for Promotion: {progress.ready_for_promotion}")
```

---

## 4. Execution Tier System

### Overview

The Dojo uses a tiered execution model that prioritizes resource efficiency.

| Tier | Name | Description | When to Use |
|------|------|-------------|-------------|
| **1** | ADB | Pure shell commands via ADB | Always try first |
| **2** | On-Device | Tools on Android (sqlite3, toybox) | When ADB insufficient |
| **3** | External | Kali tools (nmap, metasploit) | **Preprocessing ONLY** |

### Tier Exhaustion Strategy

1. **Try Tier 1 first**: Can this be done with pure ADB commands?
2. **Escalate to Tier 2**: If ADB is insufficient, use on-device tools
3. **Tier 3 is preprocessing only**: Kali tools embed results in challenge metadata

### ExecutionResult Metadata

```python
@dataclass
class ExecutionResult:
    success: bool
    exit_code: int
    stdout: str
    stderr: str
    duration: float
    command: str
    tier_used: ExecutionTier  # SHELL, ON_DEVICE, EXTERNAL
    tools_used: list[str]
```

---

## 5. Fine-tuning Pipeline

### TrainingPackager

Creates portable packages for GPU training.

```python
from dojo.finetune import TrainingPackager, FinetuneConfig

packager = TrainingPackager(output_dir=Path("./packages"))

config = FinetuneConfig(
    base_model="Qwen/Qwen2.5-Coder-7B",
    adapter_type="lora",
    lora_rank=16,
    learning_rate=1e-4,
    epochs=3,
)

package_path = packager.create_package(
    training_data_path=Path("./training_data/combined.json"),
    config=config,
)
```

### Package Contents

```
finetune_package_20250104_120000/
|-- data/
|   +-- training_data.json    # Alpaca format
|-- config.json               # FinetuneConfig
|-- train.py                  # Training script
|-- train_mlx.py              # MLX training (Apple Silicon)
+-- README.md                 # Instructions
```

---

## 6. Data Models

### Core Models (dojo/models.py)

```python
from dojo.models import (
    Belt,              # WHITE, YELLOW, ORANGE, GREEN, BLUE, PURPLE, BROWN, BLACK
    Grade,             # PERFECT, GOOD, ACCEPTABLE, POOR, FAIL
    ScriptType,        # ADB, PYTHON, FRIDA, BASH
    Challenge,         # Challenge definition
    ChallengeInput,    # Input context for challenge
    ExpectedOutput,    # Expected output specification
    ScoringRubric,     # Scoring weights
    SenseiAssessment,  # Grading result
    TrainingExample,   # Extracted training sample
    ModelProgress,     # Model's progress tracking
)
```

### Belt Model

```python
class Belt(Enum):
    WHITE = "white"
    YELLOW = "yellow"
    ORANGE = "orange"
    GREEN = "green"
    BLUE = "blue"
    PURPLE = "purple"
    BROWN = "brown"
    BLACK = "black"

    @property
    def display(self) -> str:
        """Belt with color emoji."""
        icons = {"white": "⬜", "yellow": "🟨", ...}
        return f"{icons[self.value]} {self.value.title()}"

    def next_belt(self) -> Optional[Belt]:
        """Get the next belt in progression."""
        ...
```

---

## 7. Running the Dojo

### End-to-End Test

```bash
# Run the complete dojo pipeline
python -m dojo.test_end_to_end

# This will:
# 1. Load white belt challenges
# 2. Run model against challenges
# 3. Grade outputs with Sensei
# 4. Extract training examples
# 5. Export to Alpaca format
```

### Programmatic Usage

```python
from dojo import (
    ChallengeLoader,
    Challenger,
    Executor,
    Sensei,
)
from agent.llm_client import OllamaClient

# Setup
loader = ChallengeLoader()
executor = Executor(device_id="emulator-5554")
llm = OllamaClient(model="qwen2.5-coder:7b")

challenger = Challenger(
    loader=loader,
    executor=executor,
    llm_client=llm,
    max_attempts=3,
)

sensei = Sensei()

# Run challenges
sessions = []
for challenge_id in ["white_001", "white_002", "white_003"]:
    session = challenger.run_challenge(challenge_id)
    sessions.append(session)

# Grade and export
result = sensei.run_training_cycle(
    sessions=sessions,
    model_id="qwen-v1",
    export_formats=[ExportFormat.ALPACA],
)

print(result.summary())
```

---

## 8. Integration with AgenticART

### Existing Components -> Dojo

| Existing Component | Dojo Integration |
|-------------------|------------------|
| `agent/llm_client.py` | LLM provider for Challenger |
| `agent/script_generator.py` | Can use Sensei for grading |
| `core/exploitation/` | Executor wraps these modules |

### Dojo Outputs -> Fine-tuning

```
dojo_output/
|-- training_data/
|   |-- alpaca_20250104_120000.json
|   |-- dpo_20250104_120000.json
|   +-- sharegpt_20250104_120000.json
|-- progress/
|   +-- model_progress.json
+-- packages/
    +-- finetune_package_20250104_120000/
```

---

## 9. Continuous Improvement Workflow

### The Dojo Loop

```
+---------------------------------------------------------------------+
|                        TRAINING CYCLE                               |
+---------------------------------------------------------------------+
|                                                                     |
|  1. Challenge Session                                               |
|  +---------------------------------------------------------------+  |
|  | Load challenges -> Run model -> Execute -> Collect attempts   |  |
|  +---------------------------------------------------------------+  |
|                              |                                      |
|                              v                                      |
|  2. Grading                                                         |
|  +---------------------------------------------------------------+  |
|  | Sensei grades -> Extract examples -> Update progress          |  |
|  +---------------------------------------------------------------+  |
|                              |                                      |
|                              v                                      |
|  3. Export                                                          |
|  +---------------------------------------------------------------+  |
|  | Export Alpaca/DPO -> Package for training                     |  |
|  +---------------------------------------------------------------+  |
|                              |                                      |
|                              v                                      |
|  4. Fine-tune (External)                                            |
|  +---------------------------------------------------------------+  |
|  | Run LoRA training -> Evaluate -> Deploy improved model        |  |
|  +---------------------------------------------------------------+  |
|                              |                                      |
|                              v                                      |
|  5. Belt Evaluation                                                 |
|  +---------------------------------------------------------------+  |
|  | Run belt suite -> Check promotion -> Unlock next belt         |  |
|  +---------------------------------------------------------------+  |
|                                                                     |
+---------------------------------------------------------------------+
```

---

## 10. Metrics

### TrainingCycleResult

```python
@dataclass
class TrainingCycleResult:
    assessments: list[SenseiAssessment]
    examples: list[TrainingExample]
    exports: dict[ExportFormat, Path]
    progress: ModelProgress
    promotion: Optional[Belt] = None
    stats: dict = field(default_factory=dict)

    def summary(self) -> str:
        """Human-readable summary."""
        return f"""
=== Training Cycle Complete ===
Sessions graded: {len(self.assessments)}
Examples extracted: {len(self.examples)}
Files exported: {len(self.exports)}

Model: {self.progress.model_id}
Belt: {self.progress.current_belt.display}
Pass Rate: {self.progress.pass_rate:.1f}%
"""
```

### ModelProgress

```python
@dataclass
class ModelProgress:
    model_id: str
    current_belt: Belt
    challenges_attempted: int
    challenges_passed: int
    total_score: int
    assessment_count: int

    @property
    def pass_rate(self) -> float:
        if self.challenges_attempted == 0:
            return 0.0
        return (self.challenges_passed / self.challenges_attempted) * 100

    @property
    def average_score(self) -> float:
        if self.assessment_count == 0:
            return 0.0
        return self.total_score / self.assessment_count
```

---

## Next Steps

1. **Implement Green+ belt challenges** - Extend curriculum beyond Orange
2. **Add CLI interface** - `python -m dojo train`, `python -m dojo export`
3. **Build metrics dashboard** - Streamlit visualization of progress
4. **Integrate with webapp** - Add Dojo tab to existing Streamlit app
5. **Automate training loop** - Scheduled daily challenge runs

---

*"A black belt is a white belt who never quit."*
