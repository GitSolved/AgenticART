"""
AgenticART Agent Layer

Hybrid architecture combining:
- HackSynth's Planner/Summarizer dual-module pattern
- PentAGI's memory subsystem
- PentestGPT's prompt engineering approach
"""

from pathlib import Path

from dotenv import load_dotenv

from .llm_client import LLMClient
from .planner import Planner
from .script_generator import ScriptGenerator
from .summarizer import Summarizer

# Auto-load .env from config/ directory
_config_dir = Path(__file__).parent.parent / "config"
_env_file = _config_dir / ".env"
if _env_file.exists():
    load_dotenv(_env_file)
else:
    # Fall back to .env.example for defaults
    _env_example = _config_dir / ".env.example"
    if _env_example.exists():
        load_dotenv(_env_example)

__all__ = ["LLMClient", "Planner", "Summarizer", "ScriptGenerator"]
