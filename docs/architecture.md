# AgenticART Architecture: Praxis (V2)

## Executive Summary

The AgenticART architecture trains models to **reason about vulnerabilities** through structured cognitive phases, using tool execution as binary ground truth.

### Key Components

| Component | Status | Description |
|-----------|--------|-------------|
| **Praxis Loop** | ✅ Implemented | Reasoning → Verification → Calibration cycle |
| **MCP Integration** | ✅ Implemented | Model Context Protocol for Android security tools |
| **RAG System** | ✅ Implemented | Retrieval-Augmented Generation for context |
| **V2 Curriculum** | ✅ Implemented | 7 pillars, multi-phase challenges |
| **DPO Training** | ✅ Implemented | Preference pair extraction |
| **Belt Progression** | 🔄 In Progress | White through Black belt challenges |

---

## Core Paradigm

### Reasoning Chain
Input: APK + manifest + decompiled code
1. **OBSERVE**: Identify security-relevant artifacts.
2. **HYPOTHESIZE**: Identify attack surface and potential vulnerabilities.
3. **TEST**: Design and execute MCP verification tasks.
4. **CALIBRATE**: Compare confidence to execution pass rate.
5. **CORRECT**: If execution fails, revise hypothesis.
6. **TRAIN**: Capture high-quality DPO chosen/rejected pairs.

---

## New Challenge Types

### Type 1: OBSERVATION Challenge
**Purpose**: Train the model to identify security-relevant artifacts
**Input**: Code, manifest, binary properties, runtime traces
**Output**: Structured list of observations with security relevance scores
**Evaluation**: Completeness, accuracy, relevance ranking

### Type 2: HYPOTHESIS Challenge
**Purpose**: Train the model to form testable security hypotheses
**Input**: Observations + context
**Output**: Ranked hypotheses with confidence and test plans
**Evaluation**: Hypothesis validity, testability, reasoning quality

### Type 3: VERIFICATION Challenge
**Purpose**: Train the model to design and execute tests
**Input**: Hypothesis + available tools
**Output**: Test plan + execution + result interpretation
**Evaluation**: Test coverage, methodology soundness, interpretation accuracy

### Type 4: ROOT CAUSE Challenge
**Purpose**: Train deep understanding of WHY vulnerabilities exist
**Input**: Verified vulnerability + code
**Output**: Root cause analysis with vulnerability taxonomy mapping
**Evaluation**: Depth of understanding, correct classification, generalization

### Type 5: NEGATIVE Challenge
**Purpose**: Train recognition of SECURE patterns
**Input**: Secure code implementation
**Output**: Security analysis explaining why it's NOT vulnerable
**Evaluation**: Accuracy of security property identification, attack resistance analysis

### Type 6: TRANSFER Challenge
**Purpose**: Train pattern recognition across contexts
**Input**: Multiple code samples with same vulnerability class
**Output**: Pattern abstraction + application to new code
**Evaluation**: Pattern generalization quality, correct application

### Type 7: SYNTHESIS Challenge (Black Belt)
**Purpose**: Train end-to-end discovery on novel targets
**Input**: Previously unseen APK
**Output**: Complete vulnerability report with all phases documented
**Evaluation**: Discovery of planted vulnerability OR novel finding

---

## New Data Structures

### Challenge Schema V2

```yaml
challenge:
  id: string
  name: string
  version: 2

  # Challenge classification
  type: observation | hypothesis | verification | root_cause | negative | transfer | synthesis
  pillar: static_analysis | negative_knowledge | root_cause | pattern_transfer | methodology | taxonomy | patch_analysis
  belt: white | yellow | orange | green | blue | purple | brown | black
  difficulty: 1-10

  # Input artifacts (what the model receives)
  artifacts:
    - type: decompiled_code | manifest | binary_properties | runtime_trace | network_capture | previous_output
      content: string | file_reference
      context: string  # What this artifact represents

  # Phase-specific configuration
  phases:
    - phase_id: observe | hypothesize | test | analyze | synthesize
      instruction: string  # What to do in this phase
      expected_output_schema: object  # Structure of expected output
      evaluation_criteria: list[string]  # How to grade this phase
      max_tokens: int  # Token limit for this phase response

  # Ground truth for evaluation
  ground_truth:
    vulnerability_present: bool
    vulnerability_type: string | null
    cwe_id: string | null
    root_cause: string | null
    secure_properties: list[string]  # For negative challenges
    key_observations: list[string]  # Must-find items
    valid_hypotheses: list[object]
    valid_tests: list[object]

  # Training metadata
  training:
    reasoning_chain_required: bool
    dpo_pairs_available: bool
    negative_examples: list[string]  # What NOT to conclude
    common_mistakes: list[string]  # Frequent errors to train against

  # Relationships
  prerequisites: list[challenge_id]
  unlocks: list[challenge_id]
  pattern_family: string  # For transfer learning grouping
```

### Reasoning Chain Schema

```yaml
reasoning_chain:
  challenge_id: string
  model_id: string
  timestamp: datetime

  phases:
    - phase_id: string
      input_provided: string
      model_output: string
      output_parsed: object  # Structured extraction

      evaluation:
        score: float  # 0.0 - 1.0
        criteria_scores: dict[string, float]
        feedback: string
        hallucinations_detected: list[string]

      reasoning_quality:
        completeness: float
        accuracy: float
        depth: float
        transferability: float

  overall:
    success: bool
    total_score: float
    grade: A | B | C | D | F
    discovery_made: bool
    novel_finding: bool
```

---

## Training Data Generation

### Per-Phase Training Examples

Each phase generates its own training data:

```python
# OBSERVATION phase training example
{
  "instruction": "Analyze the following Android code and identify all security-relevant observations.",
  "input": "<decompiled Java code>",
  "output": {
    "observations": [
      {"artifact": "WebView.addJavascriptInterface", "relevance": "high", "reasoning": "..."},
      {"artifact": "Intent.getStringExtra without validation", "relevance": "medium", "reasoning": "..."}
    ],
    "security_context": "...",
    "recommended_next_steps": ["..."]
  }
}

# HYPOTHESIS phase training example
{
  "instruction": "Based on these observations, form testable security hypotheses.",
  "input": "<observations from previous phase>",
  "output": {
    "hypotheses": [
      {
        "statement": "The JavaScript interface exposes methods that can be called from untrusted web content",
        "confidence": 0.8,
        "testable": true,
        "test_plan": "Hook addJavascriptInterface, enumerate exposed methods, test from malicious URL",
        "cwe_mapping": "CWE-749"
      }
    ]
  }
}

# ROOT_CAUSE phase training example
{
  "instruction": "Explain WHY this vulnerability exists at a fundamental level.",
  "input": "<verified vulnerability details>",
  "output": {
    "surface_cause": "User input reaches addJavascriptInterface without validation",
    "root_cause": "Trust boundary violation - web content treated as trusted",
    "fundamental_principle": "Confused deputy problem - privileged component (native code) controlled by unprivileged input (JavaScript)",
    "similar_patterns": ["AIDL without caller verification", "ContentProvider without permission checks"],
    "taxonomy": {
      "cwe": "CWE-749",
      "parent_cwe": "CWE-668",
      "owasp_mobile": "M7"
    }
  }
}
```

### DPO Pair Generation

For each phase, generate preference pairs:

```python
{
  "prompt": "<observation phase prompt>",
  "chosen": "<complete, accurate observations with correct relevance ranking>",
  "rejected": "<incomplete observations OR incorrect relevance OR hallucinated findings>",
  "rejection_reasons": ["missed_critical_finding", "hallucinated_api", "incorrect_relevance"]
}
```

---

## Evaluation Rubrics

### Observation Phase Rubric
| Criterion | Weight | Description |
|-----------|--------|-------------|
| Completeness | 30% | Did it find all key artifacts? |
| Accuracy | 30% | Are observations factually correct? |
| Relevance | 20% | Is security relevance correctly assessed? |
| No Hallucination | 20% | No made-up APIs/paths/methods? |

### Hypothesis Phase Rubric
| Criterion | Weight | Description |
|-----------|--------|-------------|
| Validity | 25% | Is the hypothesis logically sound? |
| Testability | 25% | Can it be verified/falsified? |
| Specificity | 20% | Is it precise enough to act on? |
| Coverage | 15% | Does it address key observations? |
| CWE Mapping | 15% | Correct vulnerability classification? |

### Root Cause Phase Rubric
| Criterion | Weight | Description |
|-----------|--------|-------------|
| Depth | 30% | Goes beyond surface to fundamental cause? |
| Accuracy | 25% | Correctly identifies the real cause? |
| Generalization | 25% | Identifies transferable patterns? |
| Taxonomy | 20% | Correct CWE/OWASP mapping? |

### Negative Challenge Rubric
| Criterion | Weight | Description |
|-----------|--------|-------------|
| Correct Classification | 40% | Correctly identifies as NOT vulnerable? |
| Security Property ID | 30% | Identifies what MAKES it secure? |
| Attack Resistance | 20% | Explains why attacks would fail? |
| No False Positives | 10% | Doesn't hallucinate vulnerabilities? |

---

## Belt Progression Model

```
WHITE BELT: Foundation
├── Focus: Basic observation skills
├── Challenge Types: OBSERVATION only
├── Artifacts: Simple code snippets, basic manifests
├── Success Criteria: 70% observation accuracy
└── Challenges: 50

YELLOW BELT: Classification
├── Focus: Vulnerability taxonomy
├── Challenge Types: OBSERVATION + taxonomy mapping
├── Artifacts: Code with known vulnerability types
├── Success Criteria: 80% CWE classification accuracy
└── Challenges: 75

ORANGE BELT: Pattern Recognition
├── Focus: Recognizing vulnerability patterns
├── Challenge Types: OBSERVATION + HYPOTHESIS
├── Artifacts: Multiple code samples per pattern family
├── Success Criteria: Identify pattern in 3/5 new samples
└── Challenges: 100

GREEN BELT: Hypothesis Formation
├── Focus: Forming testable hypotheses
├── Challenge Types: Full OBSERVATION → HYPOTHESIS → TEST
├── Artifacts: APKs, Frida available
├── Success Criteria: 70% hypothesis verification rate
└── Challenges: 125

BLUE BELT: Root Cause Analysis
├── Focus: Deep understanding of WHY
├── Challenge Types: Add ROOT_CAUSE phase
├── Artifacts: Verified vulnerabilities for analysis
├── Success Criteria: Root cause matches expert analysis
└── Challenges: 150

PURPLE BELT: Negative Knowledge
├── Focus: Recognizing secure code
├── Challenge Types: NEGATIVE + comparative analysis
├── Artifacts: Secure implementations to analyze
├── Success Criteria: <5% false positive rate
└── Challenges: 175

BROWN BELT: Transfer Learning
├── Focus: Applying patterns to new contexts
├── Challenge Types: TRANSFER challenges across apps
├── Artifacts: Multiple APKs, pattern families
├── Success Criteria: Find same vuln class in new app
└── Challenges: 200

BLACK BELT: Discovery
├── Focus: Novel vulnerability discovery
├── Challenge Types: SYNTHESIS on unknown targets
├── Artifacts: Previously unseen APKs
├── Success Criteria: Discover planted OR novel vulnerability
└── Challenges: 180
```

---

## RAG System

The RAG (Retrieval-Augmented Generation) system provides contextual knowledge to reduce hallucinations:

```
Challenge Input
      │
      ▼
┌─────────────────┐     ┌──────────────────────────────────┐
│  Query Router   │────▶│  Knowledge Bases (ChromaDB)      │
│  (Pillar-aware) │     │  ┌──────────┐ ┌──────────┐      │
└─────────────────┘     │  │ vuln_db  │ │ examples │      │
      │                 │  └──────────┘ └──────────┘      │
      ▼                 │  ┌──────────┐ ┌──────────┐      │
┌─────────────────┐     │  │android_api│ │tool_docs │      │
│ RAG Context     │◀────│  └──────────┘ └──────────┘      │
│ Builder         │     └──────────────────────────────────┘
└─────────────────┘
      │
      ▼
 LLM (Qwen 32B / MLX)
```

**Knowledge Bases:**
- `vuln_db`: CWE definitions, OWASP Mobile Top 10
- `examples`: Analysis examples from curriculum
- `android_api`: API docs, permissions, deprecations
- `tool_docs`: ADB, Frida, jadx commands

**See:** [RAG_SYSTEM.md](RAG_SYSTEM.md) for detailed documentation.

---

## MCP Integration

The MCP (Model Context Protocol) provides standardized tool execution for verification:

```
┌─────────────────────────────────────────────────────────────────────┐
│                       Praxis Verification Layer                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  PraxisRunner                                                        │
│       │                                                              │
│       ▼                                                              │
│  ┌─────────────┐                                                     │
│  │MCPExecutor  │──────┬──────────┬──────────┬──────────┐            │
│  └─────────────┘      │          │          │          │            │
│                       ▼          ▼          ▼          ▼            │
│                 ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐    │
│                 │  JADX   │ │Apktool  │ │  ADB    │ │ Frida   │    │
│                 │ Server  │ │ Server  │ │ Server  │ │ Server  │    │
│                 └─────────┘ └─────────┘ └─────────┘ └─────────┘    │
│                       │          │          │          │            │
│                       ▼          ▼          ▼          ▼            │
│                 ┌─────────────────────────────────────────────┐     │
│                 │              Tool Results                    │     │
│                 │  (Binary ground truth for calibration)       │     │
│                 └─────────────────────────────────────────────┘     │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

**MCP Servers:**
- `jadx`: Java decompilation, code search, security patterns
- `apktool`: APK decoding, manifest extraction, smali analysis
- `adb`: Device interaction, package info
- `frida`: Dynamic instrumentation (planned)

**See:** [MCP_INTEGRATION.md](MCP_INTEGRATION.md) for detailed documentation.

---

## Implementation Phases

### Phase 1: Foundation (New Models) ✅ COMPLETE
1. Create `ChallengeV2` model with multi-phase support
2. Create `ReasoningChain` model for capturing full traces
3. Create `PhaseEvaluation` model for per-phase grading
4. Update loader to support V2 challenges while maintaining V1 compatibility

### Phase 2: Evaluation (New Grader) ✅ COMPLETE
1. Create `ReasoningGrader` with per-phase rubrics
2. Implement hallucination detection for reasoning (not just commands)
3. Create `TransferEvaluator` for pattern recognition assessment
4. Implement negative example evaluation

### Phase 3: Execution (New Executors) ✅ COMPLETE
1. Implement Frida script executor
2. Implement static analysis tooling (jadx output parsing) → MCP servers
3. Create multi-phase executor that chains phases → PraxisRunner
4. Add artifact extraction utilities

### Phase 4: Training Data (New Extractor) ✅ COMPLETE
1. Create `ReasoningExtractor` for full chain capture
2. Implement per-phase DPO pair generation
3. Create negative example extraction
4. Implement pattern family clustering

### Phase 5: Curriculum (Challenge Creation) 🔄 IN PROGRESS
1. Write 50 WHITE belt observation challenges ✅
2. Write 75 YELLOW belt taxonomy challenges ✅
3. Continue through all belts with ~1000 total challenges
4. Integrate existing vulnerable APKs

### Phase 6: RAG System ✅ COMPLETE
1. Implement ChromaDB-based knowledge bases
2. Create embedding pipeline (sentence-transformers)
3. Implement pillar-aware query routing
4. Create context builder with token budgeting
5. Integrate with PraxisRunner

### Phase 7: MCP Integration ✅ COMPLETE
1. Create MCPExecutor for tool routing
2. Implement JADX MCP server
3. Implement Apktool MCP server
4. Integrate with Praxis verification loop

---

## Directory Structure

```
AgenticART/
├── agent/                           # Agent components
│   ├── memory/                      # Vector store, conversation memory
│   ├── prompts/                     # Prompt templates
│   └── chains/                      # LangChain-style chains
├── core/                            # Core security modules
│   ├── traffic/                     # Network traffic analysis
│   ├── exploitation/                # Exploitation techniques
│   ├── scanning/                    # Vulnerability scanning
│   ├── verification/                # Result verification
│   └── reconnaissance/              # Recon modules
├── dojo/                            # Training & curriculum
│   ├── curriculum/
│   │   └── v2/                      # V2 curriculum
│   │       ├── schema.yaml          # Challenge schema
│   │       └── pillars/             # 7 pillar challenges
│   │           ├── static_analysis/
│   │           ├── negative_knowledge/
│   │           ├── root_cause/
│   │           ├── pattern_transfer/
│   │           ├── methodology/
│   │           ├── taxonomy/
│   │           └── patch_analysis/
│   ├── graders/                     # Challenge grading
│   │   └── praxis_runner.py         # Main Praxis loop
│   ├── sensei/                      # Training components
│   │   ├── reasoning_grader.py
│   │   └── reasoning_extractor.py
│   ├── evaluation/                  # Evaluation results
│   ├── finetune/                    # Fine-tuning scripts
│   ├── mcp/                         # MCP Integration
│   │   ├── executor.py              # MCPExecutor, ToolResult
│   │   ├── server.py                # Base server utilities
│   │   ├── config/                  # Server configurations
│   │   └── servers/                 # MCP server implementations
│   │       ├── jadx_server.py
│   │       └── apktool_server.py
│   ├── rag/                         # RAG System
│   │   ├── config.py                # RAGConfig, pillar weights
│   │   ├── embeddings.py            # EmbeddingPipeline
│   │   ├── chunking.py              # Text/code chunking
│   │   ├── retriever.py             # RAGRetriever, QueryRouter
│   │   ├── context_builder.py       # RAGContextBuilder
│   │   ├── knowledge_bases/         # KB implementations
│   │   │   ├── vuln_db.py
│   │   │   ├── examples.py
│   │   │   ├── android_api.py
│   │   │   └── tool_docs.py
│   │   └── loaders/                 # Data loaders
│   │       ├── owasp_loader.py
│   │       ├── cwe_loader.py
│   │       └── curriculum_loader.py
│   ├── targets/                     # Target APKs
│   │   └── vulnerable_apks/
│   └── training_data/               # Generated training data
│       ├── dpo/                     # DPO pairs
│       └── mlx/                     # MLX format
├── webapp/                          # Streamlit web interface
├── tests/                           # Test suite
├── docs/                            # Documentation
├── scripts/                         # Utility scripts
├── experiments/                     # Experiment tracking
└── docker/                          # Docker configurations
```

---

## Migration Strategy

1. V1 challenges remain functional (backward compatible)
2. V2 challenges use new loader with `version: 2` detection
3. Models can progress through V1 → V2 curriculum
4. Training data from both versions can be combined
5. Gradual migration: write new challenges as V2, optionally convert high-value V1

---

## Success Metrics

### Model Capability Metrics
- **Observation Accuracy**: % of key artifacts correctly identified
- **Hypothesis Validity**: % of hypotheses that are testable and relevant
- **Verification Rate**: % of hypotheses correctly verified/falsified
- **Root Cause Depth**: Expert rating of analysis depth (1-5)
- **False Positive Rate**: % of secure code incorrectly flagged
- **Transfer Success**: % of patterns recognized in new contexts
- **Discovery Rate**: % of synthesis challenges with correct findings

### Training Data Quality Metrics
- **Reasoning Chain Completeness**: % of chains with all phases captured
- **DPO Pair Quality**: Expert rating of chosen/rejected contrast
- **Negative Example Coverage**: % of vulnerability types with negative examples
- **Pattern Family Coverage**: # of distinct patterns with 5+ instances

### Curriculum Coverage Metrics
- **CWE Coverage**: % of Android-relevant CWEs with challenges
- **OWASP Coverage**: % of Mobile Top 10 with challenges
- **Tool Coverage**: % of standard tools (Frida, ADB, etc.) exercised
- **Difficulty Distribution**: Even spread across 1-10 difficulty scale
