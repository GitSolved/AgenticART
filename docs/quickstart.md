# Quick Start

Get AgenticART running in 5 minutes.

## Prerequisites

- Python 3.10+
- Android emulator (Genymotion or AVD)
- [Ollama](https://ollama.ai) for local LLM inference

## Installation

### 1. Clone and Install

```bash
git clone https://github.com/GitSolved/AgenticART.git
cd AgenticART

# Install Core & Dojo dependencies
pip install -r requirements.txt
pip install -r dojo/requirements.txt

# For M3 Max (Fine-tuning support)
pip install mlx-lm
```

### 2. Start Android Emulator

```bash
# For Android Studio AVD (Rooted recommended)
emulator -avd <your_avd_name>
```

### 3. Start Ollama

```bash
ollama serve

# Recommended (32B Coder) - Requires 24GB+ RAM
ollama pull qwen2.5-coder:32b

# Fast Alternative (7B Coder) - Requires 8GB RAM
ollama pull qwen2.5-coder:7b
```

### 4. Initialize RAG System (Optional but Recommended)

The RAG system provides contextual knowledge to reduce hallucinations:

```bash
# Install RAG dependencies
pip install sentence-transformers chromadb

# Populate knowledge bases with OWASP/CWE data
python scripts/populate_rag.py
```

This loads:
- OWASP Mobile Top 10 2024 vulnerability data
- CWE definitions relevant to Android security
- Curriculum examples from completed challenges

## Run Challenges

### Basic Test Run

```bash
# Run white belt challenges using Ollama
python -m dojo.test_end_to_end --mode live --belt white --model qwen2.5-coder:32b
```

This will:

1. Load **White Belt (Observation)** challenges.
2. Send artifacts (APK/Manifest) to the LLM.
3. Use the **Praxis Loop** to verify reasoning against the emulator.
4. Grade the results and capture **DPO Training Data**.

### Execution Modes

| Mode | Flag | Description |
|------|------|-------------|
| Live | `--mode live` | Real-time execution via Ollama |
| MLX | `--mode mlx` | Native Apple Silicon execution (Fastest) |
| Mock | `--mode mock` | CI/CD testing without a real LLM |

### Belt Progression

```bash
# Progress through belts as the model improves
python -m dojo.test_end_to_end --mode live --belt white
python -m dojo.test_end_to_end --mode live --belt yellow
python -m dojo.test_end_to_end --mode live --belt orange
```

## Package Training Data

After running challenges, package the data for fine-tuning:

```bash
python -m dojo.finetune.packager
```

This creates training datasets from:

- ✅ Working scripts
- ✅ Error→fix pairs
- ✅ Graded trajectories

## Web Interface

Launch the Streamlit dashboard:

```bash
streamlit run webapp/app.py
```

Access at [http://localhost:8501](http://localhost:8501)

## Next Steps

- [Installation Guide](SETUP.md) - Detailed setup instructions
- [Dojo Framework](DOJO_FRAMEWORK.md) - Training methodology and V2 architecture
- [Architecture](architecture.md) - System design overview
- [RAG System](RAG_SYSTEM.md) - Knowledge retrieval for context augmentation
- [MCP Integration](MCP_INTEGRATION.md) - Tool execution protocol for verification
- [Docker Sandbox](DOCKER_SANDBOX.md) - Isolated execution setup
