"""
Unified LLM Client

Provides a consistent interface across multiple LLM providers:
- OpenAI (GPT-4, GPT-4-turbo)
- Anthropic (Claude)
- Local (Ollama, LM Studio)

Inspired by PentestGPT's multi-provider support in legacy/
"""

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Generator, Optional


class LLMProvider(Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    LOCAL = "local"  # Alias for ollama
    MOCK = "mock"


@dataclass
class LLMResponse:
    """Standardized response from any LLM provider."""
    content: str
    model: str
    provider: LLMProvider
    tokens_used: int
    finish_reason: str


class BaseLLMClient(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    def complete(self, prompt: str, system: Optional[str] = None) -> LLMResponse:
        """Generate a completion for the given prompt."""
        pass

    @abstractmethod
    def stream(self, prompt: str, system: Optional[str] = None) -> Generator[str, None, None]:
        """Stream a completion for the given prompt."""
        pass


class OpenAIClient(BaseLLMClient):
    """OpenAI API client."""

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4-turbo-preview") -> None:
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = model
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            from openai import OpenAI
            self._client = OpenAI(api_key=self.api_key)  # type: ignore
        return self._client

    def complete(self, prompt: str, system: Optional[str] = None) -> LLMResponse:
        client = self._get_client()
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        response = client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=float(os.getenv("OPENAI_TEMPERATURE", "0.7")),
            max_tokens=int(os.getenv("OPENAI_MAX_TOKENS", "4096")),
        )

        return LLMResponse(
            content=response.choices[0].message.content,
            model=self.model,
            provider=LLMProvider.OPENAI,
            tokens_used=response.usage.total_tokens,
            finish_reason=response.choices[0].finish_reason,
        )

    def stream(self, prompt: str, system: Optional[str] = None) -> Generator[str, None, None]:
        client = self._get_client()
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        stream = client.chat.completions.create(
            model=self.model,
            messages=messages,
            stream=True,
        )

        for chunk in stream:
            if chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content


class AnthropicClient(BaseLLMClient):
    """Anthropic Claude client."""

    def __init__(self, api_key: Optional[str] = None, model: str = "claude-sonnet-4-20250514") -> None:
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.model = model
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            from anthropic import Anthropic
            self._client = Anthropic(api_key=self.api_key)  # type: ignore
        return self._client

    def complete(self, prompt: str, system: Optional[str] = None) -> LLMResponse:
        client = self._get_client()

        response = client.messages.create(
            model=self.model,
            max_tokens=4096,
            system=system or "",
            messages=[{"role": "user", "content": prompt}],
        )

        return LLMResponse(
            content=response.content[0].text,
            model=self.model,
            provider=LLMProvider.ANTHROPIC,
            tokens_used=response.usage.input_tokens + response.usage.output_tokens,
            finish_reason=response.stop_reason,
        )

    def stream(self, prompt: str, system: Optional[str] = None) -> Generator[str, None, None]:
        client = self._get_client()

        with client.messages.stream(
            model=self.model,
            max_tokens=4096,
            system=system or "",
            messages=[{"role": "user", "content": prompt}],
        ) as stream:
            for text in stream.text_stream:
                yield text


class OllamaClient(BaseLLMClient):
    """
    Ollama client with full chat API support.

    Supports model discovery, health checks, and proper conversation format.
    """

    def __init__(
        self,
        endpoint: Optional[str] = None,
        model: Optional[str] = None,
        temperature: float = 0.7,
        context_length: int = 8192,
    ) -> None:
        self.endpoint = endpoint or os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.model = model or os.getenv("OLLAMA_MODEL", "qwen2.5:72b")
        self.temperature = float(os.getenv("OLLAMA_TEMPERATURE", str(temperature)))
        self.context_length = int(os.getenv("OLLAMA_CONTEXT_LENGTH", str(context_length)))

    def is_available(self) -> bool:
        """Check if Ollama server is running."""
        import requests
        try:
            response = requests.get(f"{self.endpoint}/api/tags", timeout=5)
            return response.status_code == 200
        except requests.RequestException:
            return False

    def list_models(self) -> list[dict]:
        """List all available models on the Ollama server."""
        import requests
        try:
            response = requests.get(f"{self.endpoint}/api/tags", timeout=10)
            if response.status_code == 200:
                return response.json().get("models", [])
        except requests.RequestException:
            pass
        return []

    def get_model_info(self, model_name: Optional[str] = None) -> Optional[dict]:
        """Get information about a specific model."""
        import requests
        model = model_name or self.model
        try:
            response = requests.post(
                f"{self.endpoint}/api/show",
                json={"name": model},
                timeout=10,
            )
            if response.status_code == 200:
                return response.json()
        except requests.RequestException:
            pass
        return None

    def pull_model(self, model_name: str) -> bool:
        """Pull a model from Ollama registry."""
        import requests
        try:
            response = requests.post(
                f"{self.endpoint}/api/pull",
                json={"name": model_name, "stream": False},
                timeout=600,  # Models can take a while to download
            )
            return response.status_code == 200
        except requests.RequestException:
            return False

    def complete(self, prompt: str, system: Optional[str] = None) -> LLMResponse:
        import requests

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        response = requests.post(
            f"{self.endpoint}/api/chat",
            json={
                "model": self.model,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": self.temperature,
                    "num_ctx": self.context_length,
                },
            },
            timeout=300,
        )

        if response.status_code != 200:
            raise RuntimeError(f"Ollama error: {response.text}")

        data = response.json()

        return LLMResponse(
            content=data["message"]["content"],
            model=self.model or "unknown",
            provider=LLMProvider.LOCAL,
            tokens_used=data.get("eval_count", 0) + data.get("prompt_eval_count", 0),
            finish_reason=data.get("done_reason", "stop"),
        )

    def stream(self, prompt: str, system: Optional[str] = None) -> Generator[str, None, None]:
        import json

        import requests

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        response = requests.post(
            f"{self.endpoint}/api/chat",
            json={
                "model": self.model,
                "messages": messages,
                "stream": True,
                "options": {
                    "temperature": self.temperature,
                    "num_ctx": self.context_length,
                },
            },
            stream=True,
            timeout=300,
        )

        for line in response.iter_lines():
            if line:
                data = json.loads(line)
                if "message" in data and "content" in data["message"]:
                    yield data["message"]["content"]


class MockClient(BaseLLMClient):
    """Mock client for testing."""

    def complete(self, prompt: str, system: Optional[str] = None) -> LLMResponse:
        # Include part of prompt to make response unique for different calls
        content = f"Mock response for: {prompt[:20]}"
        if "RESULT:" in prompt or "Analyze" in prompt:
            content = "RESULT: success\nKEY_FINDINGS:\n- Mock finding\nVULNERABILITIES:\n- None\nNEXT_STEPS:\n- Continue"
        elif "PLAN:" in prompt or "Create a comprehensive" in prompt:
            content = "1. Reconnaissance\nACTION: Recon\nCOMMAND: adb shell id\n2. Scanning\n3. Exploitation\n4. Privilege Escalation\n5. Verification"
        elif "Generate a" in prompt or "```" in prompt:
            content = "```python\nprint('Mock script')\n```"

        return LLMResponse(
            content=content,
            model="mock",
            provider=LLMProvider.MOCK,
            tokens_used=0,
            finish_reason="stop",
        )

    def stream(self, prompt: str, system: Optional[str] = None) -> Generator[str, None, None]:
        yield "Mock "
        yield "stream"


# Backwards compatibility alias
LocalLLMClient = OllamaClient


class LLMClient:
    """
    Factory class that returns the appropriate LLM client based on configuration.

    Usage:
        client = LLMClient.create()  # Uses LLM_PROVIDER env var
        client = LLMClient.create(provider="openai")
        response = client.complete("What vulnerabilities exist in Android 14?")
    """

    @staticmethod
    def create(provider: Optional[str] = None) -> BaseLLMClient:
        provider = provider or os.getenv("LLM_PROVIDER", "ollama")

        if provider == "openai":
            return OpenAIClient(
                model=os.getenv("OPENAI_MODEL", "gpt-4-turbo-preview")
            )
        elif provider == "anthropic":
            return AnthropicClient(
                model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
            )
        elif provider in ("ollama", "local"):
            return OllamaClient(
                model=os.getenv("OLLAMA_MODEL", os.getenv("LOCAL_LLM_MODEL", "qwen2.5:72b"))
            )
        elif provider == "mock":
            return MockClient()
        else:
            raise ValueError(f"Unknown LLM provider: {provider}")

    @staticmethod
    def list_ollama_models() -> list[dict]:
        """Convenience method to list available Ollama models."""
        client = OllamaClient()
        return client.list_models()

    @staticmethod
    def check_ollama() -> tuple[bool, str]:
        """Check if Ollama is available and return status message."""
        client = OllamaClient()
        if client.is_available():
            models = client.list_models()
            model_names = [m.get("name", "unknown") for m in models]
            return True, f"Ollama running with {len(models)} models: {', '.join(model_names[:5])}"
        return False, "Ollama not available at " + (client.endpoint or "unknown")
