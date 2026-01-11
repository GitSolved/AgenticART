#!/usr/bin/env python3
"""
Demo: Run a challenge with RAG augmentation using MLX inference.

This script demonstrates the full RAG + MLX pipeline:
1. Load a challenge from the curriculum
2. Initialize MLX client with Qwen 2.5 Coder
3. Initialize PraxisRunner with RAG enabled
4. Generate responses with RAG-augmented prompts
5. Display results

Usage:
    python scripts/demo_rag_mlx.py
    python scripts/demo_rag_mlx.py --challenge static_dataflow_yellow_001
    python scripts/demo_rag_mlx.py --dry-run  # Show prompts without LLM
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


def setup_logging(verbose: bool = False):
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # Reduce noise from chromadb
    logging.getLogger("chromadb").setLevel(logging.WARNING)
    logging.getLogger("sentence_transformers").setLevel(logging.WARNING)


def load_challenge_from_yaml(challenge_id: str) -> "ChallengeV2":
    """Load a challenge directly from YAML files."""
    import yaml
    from dojo.models import Belt
    from dojo.models_v2 import (
        Artifact, ArtifactType, ChallengeType, ChallengeV2,
        EvaluationCriteria, GroundTruth, Phase, PhaseID, Pillar,
        TrainingMetadata, VerificationTask,
    )

    curriculum_dir = Path(__file__).parent.parent / "dojo" / "curriculum" / "v2" / "pillars"

    # Search all pillar directories for the challenge
    for pillar_dir in curriculum_dir.iterdir():
        if not pillar_dir.is_dir():
            continue
        challenges_file = pillar_dir / "challenges.yaml"
        if not challenges_file.exists():
            continue

        with open(challenges_file) as f:
            data = yaml.safe_load(f)

        for ch_data in data.get("challenges", []):
            if ch_data.get("id") == challenge_id:
                # Parse artifacts
                artifacts = []
                for a in ch_data.get("artifacts", []):
                    artifacts.append(Artifact(
                        artifact_type=ArtifactType(a["type"]),
                        content=a.get("content", ""),
                        context=a.get("context", ""),
                    ))

                # Parse phases
                phases = []
                for p in ch_data.get("phases", []):
                    criteria = []
                    for c in p.get("evaluation_criteria", []):
                        criteria.append(EvaluationCriteria(
                            name=c["name"],
                            weight=c["weight"],
                            description=c.get("description", ""),
                        ))
                    phases.append(Phase(
                        phase_id=PhaseID(p["phase_id"]),
                        instruction=p.get("instruction", ""),
                        expected_output_schema=p.get("expected_output_schema", {}),
                        evaluation_criteria=criteria,
                        max_tokens=p.get("max_tokens", 2000),
                    ))

                # Parse ground truth
                gt_data = ch_data.get("ground_truth", {})
                ground_truth = GroundTruth(
                    vulnerability_present=gt_data.get("vulnerability_present", True),
                    vulnerability_type=gt_data.get("vulnerability_type"),
                    cwe_id=gt_data.get("cwe_id") or gt_data.get("correct_cwe"),
                    root_cause=gt_data.get("root_cause"),
                    key_observations=gt_data.get("key_observations", []),
                    exploitation_path=gt_data.get("exploitation_path"),
                )

                # Parse training metadata
                tm_data = ch_data.get("training", {})
                training_metadata = TrainingMetadata(
                    reasoning_chain_required=tm_data.get("reasoning_chain_required", True),
                    dpo_pairs_available=tm_data.get("dpo_pairs_available", True),
                    requires_thinking_trace=tm_data.get("requires_thinking_trace", False),
                    negative_examples=tm_data.get("common_mistakes", []),
                )

                # Parse verification tasks
                verification_tasks = []
                for v in ch_data.get("verification_tasks", []):
                    verification_tasks.append(VerificationTask(
                        instruction=v.get("instruction", ""),
                        mcp_tool_call=v.get("mcp_tool_call", {}),
                        validation_rule=v.get("validation_rule", {}),
                    ))

                return ChallengeV2(
                    id=ch_data["id"],
                    name=ch_data["name"],
                    challenge_type=ChallengeType(ch_data.get("type", "observation")),
                    pillar=Pillar(ch_data.get("pillar", "static_analysis")),
                    belt=Belt(ch_data.get("belt", "white")),
                    difficulty=ch_data.get("difficulty", 1),
                    description=ch_data.get("description", ""),
                    artifacts=artifacts,
                    phases=phases,
                    ground_truth=ground_truth,
                    training_metadata=training_metadata,
                    verification_tasks=verification_tasks,
                    tags=ch_data.get("tags", []),
                    cwe_tags=ch_data.get("cwe_tags", []),
                )

    raise ValueError(f"Challenge {challenge_id} not found in curriculum")


async def run_with_rag_mlx(
    challenge_id: str,
    dry_run: bool = False,
    verbose: bool = False,
):
    """
    Run a challenge with RAG augmentation using MLX inference.

    Args:
        challenge_id: ID of the challenge to run
        dry_run: If True, show prompts without calling LLM
        verbose: Enable verbose logging
    """
    from dojo.graders.praxis_runner import PraxisRunner
    from dojo.rag import RAGPromptAugmenter

    logger = logging.getLogger("demo")

    # -------------------------------------------------------------------------
    # Step 1: Load the challenge directly from YAML
    # -------------------------------------------------------------------------
    logger.info(f"Loading challenge: {challenge_id}")

    try:
        challenge = load_challenge_from_yaml(challenge_id)
    except ValueError as e:
        logger.error(f"Failed to load challenge: {e}")
        return

    logger.info(f"Challenge: {challenge.name}")
    logger.info(f"Pillar: {challenge.pillar.value}")
    logger.info(f"Phases: {[p.phase_id.value for p in challenge.phases]}")

    # -------------------------------------------------------------------------
    # Step 2: Initialize RAG augmenter and show stats
    # -------------------------------------------------------------------------
    logger.info("\n" + "=" * 60)
    logger.info("RAG System Status")
    logger.info("=" * 60)

    rag_augmenter = RAGPromptAugmenter(
        persist_dir=Path(".rag_data"),
        enabled=True,
        max_context_tokens=2000,
    )

    if rag_augmenter.is_ready():
        stats = rag_augmenter.get_stats()
        logger.info(f"RAG enabled: {stats.get('enabled')}")
        logger.info(f"Total documents: {stats.get('total_documents', 0)}")
        for kb_name, kb_count in stats.get("collections", {}).items():
            # kb_count may be int or dict with 'count'
            count = kb_count if isinstance(kb_count, int) else kb_count.get('count', 0)
            logger.info(f"  - {kb_name}: {count} docs")
    else:
        logger.warning("RAG system not ready - will use base prompts only")

    # -------------------------------------------------------------------------
    # Step 3: Show RAG augmentation effect
    # -------------------------------------------------------------------------
    logger.info("\n" + "=" * 60)
    logger.info("Prompt Augmentation Preview")
    logger.info("=" * 60)

    base_prompt = challenge.to_prompt(0)
    augmented_prompt = rag_augmenter.augment_challenge_prompt(
        challenge=challenge,
        phase_index=0,
    )

    logger.info(f"Base prompt: {len(base_prompt):,} chars")
    logger.info(f"Augmented prompt: {len(augmented_prompt):,} chars")
    logger.info(f"RAG context added: {len(augmented_prompt) - len(base_prompt):,} chars")

    if verbose:
        logger.info("\n--- First 500 chars of RAG context ---")
        rag_context = augmented_prompt.replace(base_prompt, "")
        logger.info(rag_context[:500] + "...")

    if dry_run:
        logger.info("\n" + "=" * 60)
        logger.info("DRY RUN - Full augmented prompt")
        logger.info("=" * 60)
        print(augmented_prompt)
        return

    # -------------------------------------------------------------------------
    # Step 4: Initialize MLX client
    # -------------------------------------------------------------------------
    logger.info("\n" + "=" * 60)
    logger.info("Initializing MLX Client")
    logger.info("=" * 60)

    try:
        from agent.mlx_adapter_client import create_mlx_client

        logger.info("Loading Qwen 2.5 Coder 32B (4-bit)...")
        mlx_client = create_mlx_client()

        if not mlx_client.is_ready():
            logger.error("MLX client failed to initialize")
            return

        logger.info("MLX client ready")
        logger.info(f"Base model: {mlx_client.config.base_model_path}")

    except ImportError as e:
        logger.error(f"MLX not available: {e}")
        logger.info("Install with: pip install mlx-lm")
        return
    except Exception as e:
        logger.error(f"Failed to initialize MLX: {e}")
        return

    # -------------------------------------------------------------------------
    # Step 5: Run challenge with PraxisRunner
    # -------------------------------------------------------------------------
    logger.info("\n" + "=" * 60)
    logger.info("Running Challenge with RAG + MLX")
    logger.info("=" * 60)

    runner = PraxisRunner(
        model_id="qwen2.5-coder-32b",
        enable_rag=True,
        rag_persist_dir=Path(".rag_data"),
        llm_client=mlx_client,
        enable_adapter_switching=True,
    )

    logger.info(f"Starting Praxis loop for: {challenge_id}")

    try:
        result = await runner.generate_and_run_challenge(
            challenge=challenge,
            temperature=0.7,
        )

        # -------------------------------------------------------------------------
        # Step 6: Display results
        # -------------------------------------------------------------------------
        logger.info("\n" + "=" * 60)
        logger.info("Results")
        logger.info("=" * 60)

        logger.info(f"Challenge: {result.challenge_id}")
        logger.info(f"Model: {result.model_id}")
        logger.info(f"Duration: {(result.completed_at - result.started_at).total_seconds():.1f}s")

        # Calibration results
        cal = result.calibration
        logger.info(f"\nCalibration:")
        logger.info(f"  Category: {cal.category.value}")
        logger.info(f"  Reasoning score: {cal.reasoning_score:.2f}")
        logger.info(f"  Stated confidence: {cal.stated_confidence:.2f}")
        logger.info(f"  Execution pass rate: {cal.execution_pass_rate:.2f}")
        logger.info(f"  Is hallucination: {cal.is_hallucination}")
        logger.info(f"  DPO signal strength: {cal.dpo_signal_strength:.2f}")

        # Verification results
        if cal.verification_results:
            logger.info(f"\nVerification Tasks ({len(cal.verification_results)}):")
            for vr in cal.verification_results:
                status = "PASS" if vr.passed else "FAIL"
                logger.info(f"  [{status}] {vr.task.instruction[:50]}...")

        # Generated DPO pair
        if result.dpo_pair:
            logger.info(f"\nDPO Pair Generated:")
            logger.info(f"  Source: {result.dpo_pair.source}")
            logger.info(f"  Signal type: {result.dpo_pair.metadata.get('signal_type', 'unknown')}")

        logger.info(f"\nHigh quality signal: {result.is_high_quality_signal}")

    except Exception as e:
        logger.error(f"Challenge execution failed: {e}")
        raise
    finally:
        await runner.shutdown()


def main():
    parser = argparse.ArgumentParser(
        description="Run a challenge with RAG augmentation using MLX inference"
    )
    parser.add_argument(
        "--challenge",
        "-c",
        default="static_basic_white_001",
        help="Challenge ID to run (default: static_basic_white_001)",
    )
    parser.add_argument(
        "--dry-run",
        "-d",
        action="store_true",
        help="Show augmented prompts without running LLM",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    setup_logging(args.verbose)

    asyncio.run(run_with_rag_mlx(
        challenge_id=args.challenge,
        dry_run=args.dry_run,
        verbose=args.verbose,
    ))


if __name__ == "__main__":
    main()
