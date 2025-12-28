
import logging
import subprocess

logger = logging.getLogger(__name__)

def check_model_available(model_name: str) -> bool:
    """Check if a model is available in Ollama."""
    try:
        result = subprocess.run(["ollama", "list"], capture_output=True, text=True)
        return model_name in result.stdout
    except Exception as e:
        logger.error(f"Error checking Ollama models: {e}")
        return False

def pull_model(model_name: str):
    """Attempt to pull a model from Ollama."""
    print(f"Pulling model {model_name}...")
    subprocess.run(["ollama", "pull", model_name])

if __name__ == "__main__":
    target = "llama3.1:70b-instruct-q4_K_M"
    if check_model_available(target):
        print(f"Model {target} is ready for inference/evaluation.")
    else:
        print(f"Model {target} not found locally.")
