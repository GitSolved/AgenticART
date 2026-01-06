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
pip install -r dojo/requirements.txt
```

### 2. Start Android Emulator

```bash
# For Android Studio AVD
emulator -avd <your_avd_name>

# For Genymotion
# Start via Genymotion Desktop application
```

### 3. Start Ollama

```bash
ollama serve
ollama pull llama3.2
```

## Run Challenges

### Basic Test Run

```bash
# Run white belt challenges (safest)
python -m dojo.test_end_to_end --mode live --belt white
```

This will:

1. Load white belt challenges
2. Send each challenge to your LLM
3. Execute generated commands on the emulator
4. Grade the results
5. Save trajectories for training

### Execution Modes

| Mode | Command | Description |
|------|---------|-------------|
| Dry Run | `--mode dry_run` | Validate only, no execution |
| Docker | `--mode docker` | Isolated container execution (recommended) |
| Live | `--mode live` | Direct execution on host |

!!! warning "Docker Mode Setup"
    For Docker mode, first build the sandbox image:
    ```bash
    docker-compose build sandbox
    docker network create --internal agentic-sandbox-net
    ```

### Belt Progression

```bash
# Start with white belt
python -m dojo.test_end_to_end --mode docker --belt white

# Progress through belts
python -m dojo.test_end_to_end --mode docker --belt yellow
python -m dojo.test_end_to_end --mode docker --belt orange
# ... and so on
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
- [Dojo Framework](DOJO_FRAMEWORK.md) - Training methodology
- [Docker Sandbox](DOCKER_SANDBOX.md) - Isolated execution setup
- [Architecture](architecture.md) - System design overview
