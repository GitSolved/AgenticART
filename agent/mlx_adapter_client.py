"""
MLX Expert Mixture Adapter Client

Dynamic LoRA adapter switching for specialized security analysis.

Takes advantage of Apple Silicon's Unified Memory to keep the base model
resident while hot-swapping specialized LoRA adapters for different
security pillars (static analysis, root cause, taxonomy, etc.).

Architecture:
    ┌─────────────────────────────────────────────────────────────────┐
    │                    M3 Max Unified Memory                        │
    │  ┌─────────────────────────────────────────────────────────┐   │
    │  │         Base Model (Qwen 2.5 7B) - RESIDENT              │   │
    │  │                    ~14GB                                  │   │
    │  └─────────────────────────────────────────────────────────┘   │
    │                           │                                     │
    │                    LoRA Merge Layer                             │
    │                           │                                     │
    │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐        │
    │  │Static│ │Root  │ │Patch │ │Taxon │ │Method│ │Trans │        │
    │  │~100MB│ │~100MB│ │~100MB│ │~100MB│ │~100MB│ │~100MB│        │
    │  └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘        │
    │     ↑ HOT-SWAP (near-instant, only loads delta weights)        │
    └─────────────────────────────────────────────────────────────────┘

Usage:
    client = MLXAdapterClient(
        model_path="models/qwen2.5-7b-instruct",
        adapter_config=AdapterConfig.default(),
    )

    # Automatic adapter selection based on challenge pillar
    response = client.complete_with_adapter(
        prompt="Analyze this code for vulnerabilities...",
        pillar=Pillar.STATIC_ANALYSIS,
    )

    # Manual adapter control
    client.load_adapter(Pillar.ROOT_CAUSE)
    response = client.complete(prompt)
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Generator, Optional

from dojo.models_v2 import Pillar

logger = logging.getLogger(__name__)


# =============================================================================
# ADAPTER CONFIGURATION
# =============================================================================

@dataclass
class AdapterMapping:
    """Mapping of a security pillar to its specialized LoRA adapter."""

    pillar: Pillar
    adapter_path: str
    description: str
    rank: int = 64  # LoRA rank
    alpha: float = 128.0  # LoRA alpha scaling
    target_modules: list[str] = field(default_factory=lambda: [
        "q_proj", "k_proj", "v_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj"
    ])

    @property
    def adapter_name(self) -> str:
        """Get the adapter name from path."""
        return Path(self.adapter_path).stem


@dataclass
class AdapterConfig:
    """Configuration for the Expert Mixture Adapter system."""

    # Base model configuration
    base_model_path: str = "models/qwen2.5-7b-instruct"
    adapter_base_dir: str = "adapters"

    # Pillar-to-adapter mappings
    mappings: dict[Pillar, AdapterMapping] = field(default_factory=dict)

    # Performance settings
    keep_base_in_memory: bool = True  # Critical for fast swapping
    lazy_load_adapters: bool = True  # Load adapters on first use
    cache_adapters: bool = True  # Keep recently used adapters in memory
    adapter_cache_size: int = 3  # Number of adapters to keep cached

    # Generation defaults
    default_temperature: float = 0.7
    default_max_tokens: int = 4096

    @classmethod
    def default(cls) -> "AdapterConfig":
        """Create default configuration with standard adapter mappings."""
        config = cls()
        config.mappings = {
            Pillar.STATIC_ANALYSIS: AdapterMapping(
                pillar=Pillar.STATIC_ANALYSIS,
                adapter_path="adapters/qwen_static_lora",
                description="Specialized for decompiled code analysis, API pattern recognition",
                rank=64,
            ),
            Pillar.NEGATIVE_KNOWLEDGE: AdapterMapping(
                pillar=Pillar.NEGATIVE_KNOWLEDGE,
                adapter_path="adapters/qwen_negative_lora",
                description="Trained to recognize secure patterns and avoid false positives",
                rank=64,
            ),
            Pillar.ROOT_CAUSE: AdapterMapping(
                pillar=Pillar.ROOT_CAUSE,
                adapter_path="adapters/qwen_rootcause_lora",
                description="Deep analysis of WHY vulnerabilities exist",
                rank=64,
            ),
            Pillar.PATTERN_TRANSFER: AdapterMapping(
                pillar=Pillar.PATTERN_TRANSFER,
                adapter_path="adapters/qwen_transfer_lora",
                description="Cross-context pattern recognition and application",
                rank=64,
            ),
            Pillar.METHODOLOGY: AdapterMapping(
                pillar=Pillar.METHODOLOGY,
                adapter_path="adapters/qwen_methodology_lora",
                description="Systematic vulnerability discovery methodology",
                rank=64,
            ),
            Pillar.TAXONOMY: AdapterMapping(
                pillar=Pillar.TAXONOMY,
                adapter_path="adapters/qwen_taxonomy_lora",
                description="CWE/OWASP classification and hierarchy understanding",
                rank=64,
            ),
            Pillar.PATCH_ANALYSIS: AdapterMapping(
                pillar=Pillar.PATCH_ANALYSIS,
                adapter_path="adapters/qwen_patch_lora",
                description="Analyzing security patches for completeness and bypasses",
                rank=64,
            ),
        }
        return config

    @classmethod
    def from_env(cls) -> "AdapterConfig":
        """Create configuration from environment variables."""
        config = cls.default()
        config.base_model_path = os.getenv(
            "MLX_BASE_MODEL",
            config.base_model_path
        )
        config.adapter_base_dir = os.getenv(
            "MLX_ADAPTER_DIR",
            config.adapter_base_dir
        )
        return config

    def get_adapter_path(self, pillar: Pillar) -> Optional[str]:
        """Get the full adapter path for a pillar."""
        mapping = self.mappings.get(pillar)
        if mapping:
            return str(Path(self.adapter_base_dir) / mapping.adapter_path)
        return None


# =============================================================================
# ADAPTER MANAGER
# =============================================================================

class AdapterState(Enum):
    """State of an adapter in the manager."""
    NOT_LOADED = "not_loaded"
    LOADING = "loading"
    LOADED = "loaded"
    ACTIVE = "active"  # Currently merged with base model
    CACHED = "cached"  # Loaded but not active


@dataclass
class AdapterInfo:
    """Runtime information about a loaded adapter."""
    pillar: Pillar
    path: str
    state: AdapterState
    load_time_ms: int = 0
    last_used: float = 0.0
    use_count: int = 0

    def to_dict(self) -> dict:
        return {
            "pillar": self.pillar.value,
            "path": self.path,
            "state": self.state.value,
            "load_time_ms": self.load_time_ms,
            "use_count": self.use_count,
        }


class AdapterManager:
    """
    Manages LoRA adapter lifecycle for the Expert Mixture system.

    Handles loading, caching, and swapping of specialized adapters
    while keeping the base model resident in Unified Memory.
    """

    def __init__(self, config: AdapterConfig):
        self.config = config
        self._adapters: dict[Pillar, AdapterInfo] = {}
        self._active_adapter: Optional[Pillar] = None
        self._adapter_cache: list[Pillar] = []  # LRU cache order

        # MLX model reference (set by client)
        self._mlx_model: Optional[Any] = None
        self._mlx_tokenizer: Optional[Any] = None

        # Statistics
        self._total_swaps = 0
        self._total_swap_time_ms = 0

    def set_model(self, model: Any, tokenizer: Any) -> None:
        """Set the MLX model and tokenizer references."""
        self._mlx_model = model
        self._mlx_tokenizer = tokenizer

    @property
    def active_adapter(self) -> Optional[Pillar]:
        """Get the currently active adapter pillar."""
        return self._active_adapter

    @property
    def available_adapters(self) -> list[Pillar]:
        """Get list of configured adapters."""
        return list(self.config.mappings.keys())

    def get_adapter_info(self, pillar: Pillar) -> Optional[AdapterInfo]:
        """Get information about a specific adapter."""
        return self._adapters.get(pillar)

    def load_adapter(self, pillar: Pillar) -> bool:
        """
        Load a LoRA adapter for the specified pillar.

        Uses MLX's model.load_adapter() to efficiently load only the
        delta weights without reloading the base model.

        Args:
            pillar: The security pillar to load adapter for

        Returns:
            True if adapter was loaded successfully
        """
        if self._mlx_model is None:
            raise RuntimeError("MLX model not initialized. Call set_model() first.")

        mapping = self.config.mappings.get(pillar)
        if not mapping:
            logger.warning(f"No adapter mapping found for pillar: {pillar.value}")
            return False

        adapter_path = self.config.get_adapter_path(pillar)
        if not adapter_path or not Path(adapter_path).exists():
            logger.warning(f"Adapter path not found: {adapter_path}")
            return False

        # Check if already loaded
        if pillar in self._adapters and self._adapters[pillar].state in (
            AdapterState.LOADED, AdapterState.ACTIVE, AdapterState.CACHED
        ):
            logger.debug(f"Adapter already loaded: {pillar.value}")
            return True

        logger.info(f"Loading adapter for {pillar.value} from {adapter_path}")
        start_time = time.time()

        try:
            # Use MLX-LM's load_adapter function
            # This loads ONLY the LoRA weights, not the full model
            self._mlx_model.load_adapter(adapter_path)

            load_time_ms = int((time.time() - start_time) * 1000)

            self._adapters[pillar] = AdapterInfo(
                pillar=pillar,
                path=adapter_path,
                state=AdapterState.LOADED,
                load_time_ms=load_time_ms,
                last_used=time.time(),
            )

            logger.info(f"Adapter loaded in {load_time_ms}ms: {pillar.value}")
            return True

        except Exception as e:
            logger.error(f"Failed to load adapter {pillar.value}: {e}")
            return False

    def activate_adapter(self, pillar: Pillar) -> bool:
        """
        Activate an adapter by merging it with the base model.

        This is the "hot-swap" operation that changes which expert
        is active for inference.

        Args:
            pillar: The pillar whose adapter to activate

        Returns:
            True if adapter was activated successfully
        """
        if self._mlx_model is None:
            raise RuntimeError("MLX model not initialized")

        # Same adapter already active - no-op
        if self._active_adapter == pillar:
            logger.debug(f"Adapter already active: {pillar.value}")
            self._update_usage(pillar)
            return True

        # Load if not already loaded
        if pillar not in self._adapters or self._adapters[pillar].state == AdapterState.NOT_LOADED:
            if not self.load_adapter(pillar):
                return False

        logger.info(f"Activating adapter: {pillar.value} (previous: {self._active_adapter})")
        start_time = time.time()

        try:
            adapter_path = self.config.get_adapter_path(pillar)

            # Deactivate current adapter if any
            if self._active_adapter and self._active_adapter in self._adapters:
                self._adapters[self._active_adapter].state = AdapterState.CACHED

            # Activate the new adapter via MLX
            # The model.load_adapter() function handles merging
            self._mlx_model.load_adapter(adapter_path)

            swap_time_ms = int((time.time() - start_time) * 1000)
            self._total_swaps += 1
            self._total_swap_time_ms += swap_time_ms

            # Update state
            self._adapters[pillar].state = AdapterState.ACTIVE
            self._active_adapter = pillar
            self._update_usage(pillar)
            self._update_cache(pillar)

            logger.info(
                f"Adapter swap completed in {swap_time_ms}ms: {pillar.value} "
                f"(avg: {self._total_swap_time_ms // max(1, self._total_swaps)}ms)"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to activate adapter {pillar.value}: {e}")
            return False

    def unload_adapter(self, pillar: Pillar) -> bool:
        """Unload an adapter from memory."""
        if pillar not in self._adapters:
            return True

        if self._active_adapter == pillar:
            logger.warning(f"Cannot unload active adapter: {pillar.value}")
            return False

        # Remove from cache
        if pillar in self._adapter_cache:
            self._adapter_cache.remove(pillar)

        del self._adapters[pillar]
        logger.info(f"Adapter unloaded: {pillar.value}")
        return True

    def _update_usage(self, pillar: Pillar) -> None:
        """Update usage statistics for an adapter."""
        if pillar in self._adapters:
            self._adapters[pillar].last_used = time.time()
            self._adapters[pillar].use_count += 1

    def _update_cache(self, pillar: Pillar) -> None:
        """Update LRU cache order."""
        if pillar in self._adapter_cache:
            self._adapter_cache.remove(pillar)
        self._adapter_cache.append(pillar)

        # Evict oldest if cache is full
        while len(self._adapter_cache) > self.config.adapter_cache_size:
            evict_pillar = self._adapter_cache.pop(0)
            if evict_pillar != self._active_adapter:
                self.unload_adapter(evict_pillar)

    def get_stats(self) -> dict:
        """Get adapter manager statistics."""
        return {
            "active_adapter": self._active_adapter.value if self._active_adapter else None,
            "loaded_adapters": [p.value for p in self._adapters.keys()],
            "cached_adapters": [p.value for p in self._adapter_cache],
            "total_swaps": self._total_swaps,
            "avg_swap_time_ms": (
                self._total_swap_time_ms // max(1, self._total_swaps)
            ),
            "adapters": {
                p.value: info.to_dict()
                for p, info in self._adapters.items()
            },
        }


# =============================================================================
# MLX ADAPTER CLIENT
# =============================================================================

class MLXAdapterClient:
    """
    MLX-based LLM client with dynamic LoRA adapter switching.

    Keeps the base Qwen 2.5 7B model resident in Unified Memory while
    hot-swapping specialized LoRA adapters for different security pillars.

    Usage:
        client = MLXAdapterClient()

        # Auto-select adapter based on pillar
        response = client.complete_with_adapter(
            prompt="Analyze this code...",
            pillar=Pillar.STATIC_ANALYSIS,
        )

        # Manual control
        client.switch_adapter(Pillar.ROOT_CAUSE)
        response = client.complete(prompt)
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        adapter_config: Optional[AdapterConfig] = None,
        auto_load_base: bool = True,
    ):
        """
        Initialize the MLX Adapter Client.

        Args:
            model_path: Path to base model (overrides config)
            adapter_config: Adapter configuration
            auto_load_base: Automatically load base model on init
        """
        self.config = adapter_config or AdapterConfig.from_env()
        if model_path:
            self.config.base_model_path = model_path

        self.adapter_manager = AdapterManager(self.config)

        # MLX model state
        self._model: Optional[Any] = None
        self._tokenizer: Optional[Any] = None
        self._model_loaded = False

        # Generation config
        self.temperature = self.config.default_temperature
        self.max_tokens = self.config.default_max_tokens

        if auto_load_base:
            self.load_base_model()

    def load_base_model(self) -> bool:
        """
        Load the base model into Unified Memory.

        This is the expensive operation that should only happen once.
        The model remains resident while adapters are swapped.

        Returns:
            True if model was loaded successfully
        """
        if self._model_loaded:
            logger.debug("Base model already loaded")
            return True

        logger.info(f"Loading base model: {self.config.base_model_path}")
        start_time = time.time()

        try:
            # Import MLX-LM
            from mlx_lm import load

            # Load model and tokenizer
            self._model, self._tokenizer = load(self.config.base_model_path)

            # Set model reference in adapter manager
            self.adapter_manager.set_model(self._model, self._tokenizer)

            load_time = time.time() - start_time
            self._model_loaded = True

            logger.info(f"Base model loaded in {load_time:.2f}s")
            return True

        except ImportError:
            logger.error("mlx-lm not installed. Install with: pip install mlx-lm")
            return False
        except Exception as e:
            logger.error(f"Failed to load base model: {e}")
            return False

    def switch_adapter(self, pillar: Pillar) -> bool:
        """
        Switch to the adapter for the specified pillar.

        This is a fast operation (~50-200ms) since only LoRA weights
        are swapped, not the full model.

        Args:
            pillar: The security pillar to switch to

        Returns:
            True if adapter was switched successfully
        """
        if not self._model_loaded:
            logger.error("Base model not loaded. Call load_base_model() first.")
            return False

        return self.adapter_manager.activate_adapter(pillar)

    def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> str:
        """
        Generate a completion using the currently active adapter.

        Args:
            prompt: The input prompt
            system: Optional system prompt
            temperature: Generation temperature (default from config)
            max_tokens: Max tokens to generate (default from config)

        Returns:
            Generated text
        """
        if not self._model_loaded:
            raise RuntimeError("Base model not loaded")

        from mlx_lm import generate

        # Build full prompt with system message
        if system:
            full_prompt = f"<|im_start|>system\n{system}<|im_end|>\n<|im_start|>user\n{prompt}<|im_end|>\n<|im_start|>assistant\n"
        else:
            full_prompt = f"<|im_start|>user\n{prompt}<|im_end|>\n<|im_start|>assistant\n"

        response = generate(
            self._model,
            self._tokenizer,
            prompt=full_prompt,
            temp=temperature or self.temperature,
            max_tokens=max_tokens or self.max_tokens,
        )

        return response

    def complete_with_adapter(
        self,
        prompt: str,
        pillar: Pillar,
        system: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> str:
        """
        Generate a completion with automatic adapter switching.

        Switches to the appropriate adapter for the pillar before
        generating the completion.

        Args:
            prompt: The input prompt
            pillar: Security pillar (determines which adapter to use)
            system: Optional system prompt
            temperature: Generation temperature
            max_tokens: Max tokens to generate

        Returns:
            Generated text
        """
        # Switch adapter if needed
        if self.adapter_manager.active_adapter != pillar:
            if not self.switch_adapter(pillar):
                logger.warning(
                    f"Failed to switch to {pillar.value} adapter, "
                    f"using current: {self.adapter_manager.active_adapter}"
                )

        return self.complete(
            prompt=prompt,
            system=system,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    async def generate(
        self,
        prompt: str,
        temperature: Optional[float] = None,
        seed: Optional[int] = None,
    ) -> "MLXResponse":
        """
        Async generate method for compatibility with PraxisRunner.

        Args:
            prompt: The input prompt
            temperature: Generation temperature
            seed: Random seed (for reproducibility in Best-of-N)

        Returns:
            MLXResponse with generated content
        """
        # MLX doesn't have native async, so we just call sync
        content = self.complete(
            prompt=prompt,
            temperature=temperature or self.temperature,
        )
        return MLXResponse(content=content)

    def stream(
        self,
        prompt: str,
        system: Optional[str] = None,
    ) -> Generator[str, None, None]:
        """
        Stream a completion token by token.

        Args:
            prompt: The input prompt
            system: Optional system prompt

        Yields:
            Generated tokens
        """
        if not self._model_loaded:
            raise RuntimeError("Base model not loaded")

        from mlx_lm import stream_generate

        if system:
            full_prompt = f"<|im_start|>system\n{system}<|im_end|>\n<|im_start|>user\n{prompt}<|im_end|>\n<|im_start|>assistant\n"
        else:
            full_prompt = f"<|im_start|>user\n{prompt}<|im_end|>\n<|im_start|>assistant\n"

        for token in stream_generate(
            self._model,
            self._tokenizer,
            prompt=full_prompt,
            temp=self.temperature,
            max_tokens=self.max_tokens,
        ):
            yield token

    def get_active_adapter(self) -> Optional[Pillar]:
        """Get the currently active adapter pillar."""
        return self.adapter_manager.active_adapter

    def get_adapter_stats(self) -> dict:
        """Get adapter manager statistics."""
        return self.adapter_manager.get_stats()

    def is_ready(self) -> bool:
        """Check if client is ready for inference."""
        return self._model_loaded


@dataclass
class MLXResponse:
    """Response object for MLX client compatibility."""
    content: str


# =============================================================================
# FACTORY FUNCTION
# =============================================================================

def create_mlx_client(
    model_path: Optional[str] = None,
    adapter_config: Optional[AdapterConfig] = None,
) -> MLXAdapterClient:
    """
    Factory function to create an MLX Adapter Client.

    Usage:
        client = create_mlx_client()
        response = client.complete_with_adapter(
            prompt="Analyze...",
            pillar=Pillar.STATIC_ANALYSIS,
        )
    """
    return MLXAdapterClient(
        model_path=model_path,
        adapter_config=adapter_config,
    )
