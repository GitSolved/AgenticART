#!/usr/bin/env python3
"""
MLX-Powered Active Learning: Real-Time Hallucination Correction

This module implements an active learning loop that:
1. Detects high-confidence hallucinations via PraxisRunner
2. Generates DPO pairs (chosen: corrected reasoning, rejected: hallucination)
3. Triggers MLX LoRA fine-tuning on Apple Silicon (M3 Max 40-core GPU)
4. Updates the model in real-time to learn from mechanical mistakes

Architecture:
    M3 Max 40-core GPU → MLX LoRA training
    64GB Unified Memory → Full model + LoRA adapters in memory
    Real-time feedback → Model improves during evaluation

Usage:
    from dojo.finetune.active_correction import ActiveLearningLoop

    loop = ActiveLearningLoop(
        base_model="mlx-community/Qwen2.5-Coder-7B-Instruct-4bit",
        lora_rank=8,
    )

    # Run challenge and auto-correct on hallucination
    result = await loop.run_and_learn(challenge, phase_responses)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# MLX Integration (Apple Silicon Optimized)
# ─────────────────────────────────────────────────────────────────────────────

def check_mlx_available() -> bool:
    """Check if MLX is available on this system."""
    try:
        import mlx.core  # noqa: F401
        return True
    except ImportError:
        return False


def get_mlx_device_info() -> dict:
    """Get MLX device information."""
    try:
        import mlx.core as mx
        return {
            "backend": "mlx",
            "metal_available": True,
            "default_device": str(mx.default_device()),
        }
    except ImportError:
        return {"backend": "none", "metal_available": False}


@dataclass
class LoRAConfig:
    """Configuration for LoRA fine-tuning."""

    rank: int = 8
    alpha: float = 16.0
    dropout: float = 0.0
    target_modules: list[str] = field(default_factory=lambda: [
        "q_proj", "v_proj", "k_proj", "o_proj",
        "gate_proj", "up_proj", "down_proj",
    ])
    learning_rate: float = 1e-4
    batch_size: int = 1
    gradient_accumulation_steps: int = 4
    max_seq_length: int = 2048
    warmup_steps: int = 10
    save_every: int = 100


@dataclass
class DPOTrainingPair:
    """A single DPO training pair for hallucination correction."""

    prompt: str
    chosen: str  # Corrected reasoning
    rejected: str  # Hallucination
    challenge_id: str
    confidence: float
    execution_pass_rate: float
    calibration_error: float
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: dict = field(default_factory=dict)

    def to_training_format(self) -> dict:
        """Convert to MLX training format."""
        return {
            "prompt": self.prompt,
            "chosen": self.chosen,
            "rejected": self.rejected,
            "metadata": {
                "challenge_id": self.challenge_id,
                "confidence": self.confidence,
                "execution_pass_rate": self.execution_pass_rate,
                "calibration_error": self.calibration_error,
                "timestamp": self.timestamp.isoformat(),
                **self.metadata,
            }
        }


# ─────────────────────────────────────────────────────────────────────────────
# MLX LoRA Trainer
# ─────────────────────────────────────────────────────────────────────────────

class MLXLoRATrainer:
    """
    MLX-based LoRA trainer for Apple Silicon.

    Uses mlx-lm library for efficient fine-tuning on M3 Max.
    """

    def __init__(
        self,
        base_model: str,
        lora_config: Optional[LoRAConfig] = None,
        output_dir: Optional[Path] = None,
        adapter_path: Optional[Path] = None,
    ):
        """
        Initialize MLX LoRA trainer.

        Args:
            base_model: HuggingFace model ID or local path
            lora_config: LoRA configuration
            output_dir: Where to save adapters
            adapter_path: Path to existing adapter to continue training
        """
        self.base_model = base_model
        self.lora_config = lora_config or LoRAConfig()
        self.output_dir = output_dir or Path("mlx_lora_output")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.adapter_path = adapter_path

        self._model = None
        self._tokenizer = None
        self._initialized = False

        # Training state
        self.training_pairs: list[DPOTrainingPair] = []
        self.total_updates = 0
        self.hallucinations_corrected = 0

    def initialize(self) -> bool:
        """Initialize model and tokenizer."""
        if self._initialized:
            return True

        if not check_mlx_available():
            logger.error("MLX not available. Install with: pip install mlx mlx-lm")
            return False

        try:
            from mlx_lm import load

            logger.info(f"Loading model: {self.base_model}")

            # Load model with existing adapter if provided
            if self.adapter_path and self.adapter_path.exists():
                logger.info(f"Loading existing adapter: {self.adapter_path}")
                loaded = load(
                    self.base_model,
                    adapter_path=str(self.adapter_path),
                )
                self._model = loaded[0]
                self._tokenizer = loaded[1]
            else:
                loaded = load(self.base_model)
                self._model = loaded[0]
                self._tokenizer = loaded[1]

            self._initialized = True
            logger.info(f"Model loaded. Device: {get_mlx_device_info()}")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize MLX model: {e}")
            return False

    def train_on_pair(self, pair: DPOTrainingPair) -> dict:
        """
        Perform a single LoRA update on a DPO pair.

        This is the core of real-time active learning:
        - Model sees its mistake (rejected)
        - Model learns the correction (chosen)
        - LoRA adapters are updated immediately
        """
        if not self._initialized:
            if not self.initialize():
                return {"success": False, "error": "Failed to initialize model"}

        self.training_pairs.append(pair)

        try:
            # Create temporary training file
            with tempfile.NamedTemporaryFile(
                mode='w', suffix='.jsonl', delete=False
            ) as f:
                f.write(json.dumps(pair.to_training_format()) + '\n')
                train_file = f.name

            # Run LoRA training via mlx_lm
            result = self._run_lora_update(train_file, pair)

            # Cleanup
            os.unlink(train_file)

            self.total_updates += 1
            if result.get("success"):
                self.hallucinations_corrected += 1

            return result

        except Exception as e:
            logger.exception("LoRA update failed")
            return {"success": False, "error": str(e)}

    def _run_lora_update(self, train_file: str, pair: DPOTrainingPair) -> dict:
        """Run a single LoRA update using mlx_lm."""
        try:
            # Configure LoRA training
            adapter_dir = self.output_dir / "adapters" / f"update_{self.total_updates}"
            adapter_dir.mkdir(parents=True, exist_ok=True)

            # Create training config
            train_config = {
                "model": self.base_model,
                "train": train_file,
                "adapter_path": str(adapter_dir),
                "lora_rank": self.lora_config.rank,
                "lora_layers": self.lora_config.target_modules,
                "learning_rate": self.lora_config.learning_rate,
                "batch_size": self.lora_config.batch_size,
                "iters": 1,  # Single update for real-time learning
                "seed": 42,
            }

            # Write config
            config_path = adapter_dir / "train_config.json"
            with open(config_path, 'w') as f:
                json.dump(train_config, f, indent=2)

            # Run training
            # Note: In production, use lora.train() directly
            # For now, we use subprocess for cleaner isolation
            import subprocess
            result = subprocess.run(
                [
                    "python3", "-m", "mlx_lm.lora",
                    "--model", self.base_model,
                    "--train",
                    "--data", train_file,
                    "--adapter-path", str(adapter_dir),
                    "--lora-rank", str(self.lora_config.rank),
                    "--learning-rate", str(self.lora_config.learning_rate),
                    "--batch-size", str(self.lora_config.batch_size),
                    "--iters", "1",
                ],
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode == 0:
                # Update adapter path for future training
                self.adapter_path = adapter_dir
                return {
                    "success": True,
                    "adapter_path": str(adapter_dir),
                    "challenge_id": pair.challenge_id,
                    "update_number": self.total_updates,
                }
            else:
                return {
                    "success": False,
                    "error": result.stderr,
                    "stdout": result.stdout,
                }

        except Exception as e:
            return {"success": False, "error": str(e)}

    def train_batch(self, pairs: list[DPOTrainingPair]) -> dict:
        """Train on a batch of DPO pairs."""
        if not pairs:
            return {"success": True, "updates": 0}

        if not self._initialized:
            if not self.initialize():
                return {"success": False, "error": "Failed to initialize model"}

        try:
            # Create batch training file
            with tempfile.NamedTemporaryFile(
                mode='w', suffix='.jsonl', delete=False
            ) as f:
                for pair in pairs:
                    f.write(json.dumps(pair.to_training_format()) + '\n')
                train_file = f.name

            # Configure batch training
            adapter_dir = self.output_dir / "adapters" / f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            adapter_dir.mkdir(parents=True, exist_ok=True)

            import subprocess
            result = subprocess.run(
                [
                    "python3", "-m", "mlx_lm.lora",
                    "--model", self.base_model,
                    "--train",
                    "--data", train_file,
                    "--adapter-path", str(adapter_dir),
                    "--lora-rank", str(self.lora_config.rank),
                    "--learning-rate", str(self.lora_config.learning_rate),
                    "--batch-size", str(min(self.lora_config.batch_size, len(pairs))),
                    "--iters", str(len(pairs)),
                ],
                capture_output=True,
                text=True,
                timeout=600,
            )

            os.unlink(train_file)

            if result.returncode == 0:
                self.adapter_path = adapter_dir
                self.total_updates += len(pairs)
                self.hallucinations_corrected += len(pairs)
                self.training_pairs.extend(pairs)
                return {
                    "success": True,
                    "adapter_path": str(adapter_dir),
                    "updates": len(pairs),
                }
            else:
                return {"success": False, "error": result.stderr}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate text using the current model + LoRA adapters."""
        if not self._initialized:
            if not self.initialize():
                raise RuntimeError("Failed to initialize model")

        try:
            from mlx_lm import generate

            full_prompt = prompt
            if system_prompt:
                full_prompt = f"<|system|>\n{system_prompt}\n<|user|>\n{prompt}\n<|assistant|>\n"

            response = generate(
                self._model,
                self._tokenizer,
                prompt=full_prompt,
                max_tokens=2048,
                temp=0.7,
            )

            return response

        except Exception as e:
            logger.error(f"Generation failed: {e}")
            return f"Error: {e}"

    def save_checkpoint(self, name: Optional[str] = None) -> Path:
        """Save current LoRA adapter checkpoint."""
        name = name or f"checkpoint_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        checkpoint_dir = self.output_dir / "checkpoints" / name
        checkpoint_dir.mkdir(parents=True, exist_ok=True)

        if self.adapter_path and self.adapter_path.exists():
            # Copy adapter files
            for f in self.adapter_path.iterdir():
                shutil.copy2(f, checkpoint_dir / f.name)

        # Save training history
        history = {
            "total_updates": self.total_updates,
            "hallucinations_corrected": self.hallucinations_corrected,
            "training_pairs": [p.to_training_format() for p in self.training_pairs],
            "base_model": self.base_model,
            "lora_config": {
                "rank": self.lora_config.rank,
                "alpha": self.lora_config.alpha,
                "target_modules": self.lora_config.target_modules,
            },
        }
        with open(checkpoint_dir / "training_history.json", 'w') as f:
            json.dump(history, f, indent=2)

        logger.info(f"Checkpoint saved: {checkpoint_dir}")
        return checkpoint_dir

    def get_stats(self) -> dict:
        """Get training statistics."""
        return {
            "total_updates": self.total_updates,
            "hallucinations_corrected": self.hallucinations_corrected,
            "training_pairs_count": len(self.training_pairs),
            "current_adapter": str(self.adapter_path) if self.adapter_path else None,
            "model": self.base_model,
            "device_info": get_mlx_device_info(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Active Learning Loop
# ─────────────────────────────────────────────────────────────────────────────

class ActiveLearningLoop:
    """
    Complete active learning loop with MLX LoRA fine-tuning.

    Workflow:
    1. Run challenge via ActiveRunner
    2. If hallucination detected → generate DPO pair
    3. Trigger MLX LoRA update
    4. Model improves in real-time
    """

    def __init__(
        self,
        base_model: str = "mlx-community/Qwen2.5-Coder-32B-Instruct-4bit",
        lora_rank: int = 8,
        output_dir: Optional[Path] = None,
        auto_train: bool = True,
        train_batch_size: int = 1,
        min_calibration_error: float = 0.3,
        max_retries: int = 30,  # Increased to 30 for "Superhuman Persistence"
    ):
        """
        Initialize active learning loop.

        Args:
            base_model: MLX model to fine-tune
            lora_rank: LoRA rank (higher = more capacity)
            output_dir: Where to save outputs
            auto_train: Automatically train on hallucinations
            train_batch_size: Batch training pairs before update
            min_calibration_error: Minimum error to trigger training
            max_retries: Maximum self-correction attempts (Inference-Time Compute)
        """
        self.output_dir = output_dir or Path("active_learning_output")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.auto_train = auto_train
        self.train_batch_size = train_batch_size
        self.min_calibration_error = min_calibration_error

        # Initialize MLX trainer
        self.trainer = MLXLoRATrainer(
            base_model=base_model,
            lora_config=LoRAConfig(rank=lora_rank),
            output_dir=self.output_dir / "lora",
        )

        # Initialize ActiveRunner (uses trainer for LLM calls)
        from dojo.graders.runner import ActiveRunner
        self.runner = ActiveRunner(
            model_id=base_model,
            llm_client=self.trainer,  # Trainer implements generate()
            output_dir=self.output_dir / "runs",
            max_self_corrections=max_retries,
        )

        # Pending training pairs (for batch training)
        self.pending_pairs: list[DPOTrainingPair] = []

        # Statistics
        self.challenges_run = 0
        self.hallucinations_detected = 0
        self.corrections_applied = 0

    async def run_and_learn(
        self,
        challenge: Any,  # ChallengeV2
        phase_responses: dict,
    ) -> dict:
        """
        Run a challenge and learn from any hallucinations.

        Returns:
            Dict with run results and learning outcomes
        """
        from dojo.graders.runner import ActiveRun

        self.challenges_run += 1

        # Run the challenge with self-correction
        active_run: ActiveRun = await self.runner.run_challenge(
            challenge=challenge,
            phase_responses=phase_responses,
        )

        result = {
            "challenge_id": challenge.id,
            "reasoning_score": active_run.total_score,
            "is_hallucination": active_run.is_hallucination,
            "calibration": active_run.calibration.to_dict(),
            "self_corrections": len(active_run.self_corrections),
            "training_triggered": False,
        }

        # Check for hallucination
        if active_run.is_hallucination:
            self.hallucinations_detected += 1
            logger.warning(
                f"Hallucination detected in {challenge.id}: "
                f"confidence={active_run.calibration.stated_confidence:.2f}, "
                f"pass_rate={active_run.calibration.execution_pass_rate:.2f}"
            )

            # Generate DPO pair
            dpo_pair = self._create_dpo_pair(
                challenge=challenge,
                active_run=active_run,
                phase_responses=phase_responses,
            )

            if dpo_pair:
                self.pending_pairs.append(dpo_pair)
                result["dpo_pair_generated"] = True

                # Auto-train if enabled
                if self.auto_train:
                    if len(self.pending_pairs) >= self.train_batch_size:
                        train_result = await self._train_pending()
                        result["training_triggered"] = True
                        result["training_result"] = train_result

        return result

    def _create_dpo_pair(
        self,
        challenge: Any,
        active_run: Any,
        phase_responses: dict,
    ) -> Optional[DPOTrainingPair]:
        """Create a DPO pair from a hallucination detection."""
        calibration = active_run.calibration

        # Only train on significant calibration errors
        if calibration.calibration_error < self.min_calibration_error:
            return None

        # Build prompt from challenge
        prompt = f"""Challenge: {challenge.name}

Description: {challenge.description}

Artifacts:
"""
        for artifact in challenge.artifacts[:2]:  # Limit artifacts
            prompt += f"\n{artifact.context}:\n{artifact.content[:500]}...\n"

        # Get rejected response (the hallucination)
        from dojo.models_v2 import PhaseID
        rejected = phase_responses.get(PhaseID.HYPOTHESIZE, "")
        if not rejected:
            rejected = phase_responses.get(PhaseID.ANALYZE, "")

        # Get chosen response (corrected reasoning from self-correction)
        chosen = None
        if active_run.self_corrections:
            # Use the final revised hypothesis
            chosen = active_run.self_corrections[-1].revised_hypothesis
        else:
            # Generate a correction template
            chosen = self._generate_correction_template(
                challenge=challenge,
                rejected=rejected,
                calibration=calibration,
            )

        if not chosen or not rejected:
            return None

        return DPOTrainingPair(
            prompt=prompt,
            chosen=chosen,
            rejected=rejected,
            challenge_id=challenge.id,
            confidence=calibration.stated_confidence,
            execution_pass_rate=calibration.execution_pass_rate,
            calibration_error=calibration.calibration_error,
            metadata={
                "verification_failures": [
                    v.to_dict() for v in calibration.verification_results
                    if not v.passed
                ],
                "self_correction_attempts": len(active_run.self_corrections),
            },
        )

    def _generate_correction_template(
        self,
        challenge: Any,
        rejected: str,
        calibration: Any,
    ) -> str:
        """Generate a correction template when no self-correction exists."""
        # Extract what failed
        failures = [v for v in calibration.verification_results if not v.passed]
        failure_summary = "\n".join([
            f"- {v.task.instruction}: {v.error or 'validation failed'}"
            for v in failures[:3]
        ])

        return f"""Based on the verification results, my initial hypothesis was incorrect.

The following verifications failed:
{failure_summary}

I should have:
1. Been more cautious about claiming high confidence without empirical verification
2. Checked my assumptions against the actual execution environment
3. Considered alternative explanations for the observed behavior

Revised hypothesis with appropriate uncertainty:
[The model should learn to express lower confidence when lacking verification]
"""

    async def _train_pending(self) -> dict:
        """Train on pending DPO pairs."""
        if not self.pending_pairs:
            return {"success": True, "updates": 0}

        pairs_to_train = self.pending_pairs.copy()
        self.pending_pairs.clear()

        if len(pairs_to_train) == 1:
            result = self.trainer.train_on_pair(pairs_to_train[0])
        else:
            result = self.trainer.train_batch(pairs_to_train)

        if result.get("success"):
            self.corrections_applied += len(pairs_to_train)
            logger.info(
                f"LoRA update complete: {len(pairs_to_train)} corrections applied. "
                f"Total corrections: {self.corrections_applied}"
            )

        return result

    async def run_curriculum(
        self,
        challenges: list,
        phase_response_generator: Callable,
    ) -> dict:
        """
        Run a full curriculum with active learning.

        Args:
            challenges: List of ChallengeV2 objects
            phase_response_generator: Async function that generates responses
                                     for a challenge

        Returns:
            Curriculum run summary
        """
        results = []

        for i, challenge in enumerate(challenges):
            logger.info(f"Running challenge {i+1}/{len(challenges)}: {challenge.id}")

            # Generate responses using the current model
            phase_responses = await phase_response_generator(challenge)

            # Run and learn
            result = await self.run_and_learn(challenge, phase_responses)
            results.append(result)

            # Progress logging
            if (i + 1) % 10 == 0:
                logger.info(
                    f"Progress: {i+1}/{len(challenges)} | "
                    f"Hallucinations: {self.hallucinations_detected} | "
                    f"Corrections: {self.corrections_applied}"
                )

        # Final training on remaining pairs
        if self.pending_pairs:
            await self._train_pending()

        # Save checkpoint
        self.trainer.save_checkpoint(f"curriculum_complete_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

        return {
            "challenges_run": self.challenges_run,
            "hallucinations_detected": self.hallucinations_detected,
            "corrections_applied": self.corrections_applied,
            "hallucination_rate": self.hallucinations_detected / max(1, self.challenges_run),
            "results": results,
            "trainer_stats": self.trainer.get_stats(),
        }

    def get_stats(self) -> dict:
        """Get current statistics."""
        return {
            "challenges_run": self.challenges_run,
            "hallucinations_detected": self.hallucinations_detected,
            "corrections_applied": self.corrections_applied,
            "pending_pairs": len(self.pending_pairs),
            "hallucination_rate": (
                self.hallucinations_detected / max(1, self.challenges_run)
            ),
            "trainer": self.trainer.get_stats(),
        }

    async def shutdown(self) -> None:
        """Shutdown the active learning loop."""
        # Train any remaining pairs
        if self.pending_pairs:
            await self._train_pending()

        # Save final checkpoint
        self.trainer.save_checkpoint("final")

        # Shutdown runner
        await self.runner.shutdown()


# ─────────────────────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────────────────────

async def main():
    """Demo of the active learning loop."""
    import argparse

    parser = argparse.ArgumentParser(description="MLX Active Learning Loop")
    parser.add_argument(
        "--model",
        default="mlx-community/Qwen2.5-Coder-32B-Instruct-4bit",
        help="MLX model to fine-tune",
    )
    parser.add_argument(
        "--lora-rank",
        type=int,
        default=8,
        help="LoRA rank",
    )
    parser.add_argument(
        "--challenge",
        default="method_observe_white_001",
        help="Challenge ID to run",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=30,
        help="Max self-correction retries",
    )
    args = parser.parse_args()

    print("=" * 60)
    print("MLX-Powered Active Learning Loop")
    print("=" * 60)
    print(f"Model: {args.model}")
    print(f"LoRA Rank: {args.lora_rank}")
    print(f"Max Retries: {args.retries}")
    print(f"MLX Available: {check_mlx_available()}")
    print(f"Device Info: {get_mlx_device_info()}")
    print("=" * 60)

    # Check MLX availability
    if not check_mlx_available():
        print("\nERROR: MLX not available.")
        print("Install with: pip install mlx mlx-lm")
        return

    # Initialize loop
    loop = ActiveLearningLoop(
        base_model=args.model,
        lora_rank=args.lora_rank,
        auto_train=True,
        max_retries=args.retries,
    )

    # Load challenge
    from dojo.curriculum.loader import ChallengeLoader
    from dojo.models_v2 import PhaseID

    loader = ChallengeLoader()
    challenge = loader.load_challenge(args.challenge)

    print(f"\nLoaded challenge: {challenge.name}")
    print(f"Verification tasks: {len(challenge.verification_tasks)}")

    # Generate mock responses (in production, use actual model)
    mock_responses = {
        PhaseID.OBSERVE: """
## Observations

Looking at the AndroidManifest.xml, I observe:
1. Multiple dangerous permissions requested (CAMERA, CONTACTS, LOCATION)
2. The DeepLinkActivity is exported=true
3. cleartext traffic is enabled
4. The ContactsProvider is exported with grantUriPermissions

Confidence: 90%
""",
        PhaseID.HYPOTHESIZE: """
## Hypothesis

Based on my observations, I hypothesize:
1. The exported DeepLinkActivity could be vulnerable to intent injection
2. The exported ContentProvider could leak contact data
3. Cleartext traffic enables MITM attacks

Confidence: 85%
""",
    }

    print("\nRunning challenge with active learning...")
    result = await loop.run_and_learn(challenge, mock_responses)

    print("\n" + "=" * 60)
    print("Results")
    print("=" * 60)
    print(f"Reasoning Score: {result['reasoning_score']:.2%}")
    print(f"Is Hallucination: {result['is_hallucination']}")
    print(f"Self-Corrections: {result['self_corrections']}")
    print(f"Training Triggered: {result['training_triggered']}")
    print("\nCalibration:")
    print(f"  Stated Confidence: {result['calibration']['stated_confidence']:.2%}")
    print(f"  Execution Pass Rate: {result['calibration']['execution_pass_rate']:.2%}")
    print(f"  Category: {result['calibration']['category']}")

    print("\n" + "=" * 60)
    print("Active Learning Stats")
    print("=" * 60)
    stats = loop.get_stats()
    for key, value in stats.items():
        if key != "trainer":
            print(f"  {key}: {value}")

    await loop.shutdown()
    print("\nActive learning loop complete.")


if __name__ == "__main__":
    asyncio.run(main())
