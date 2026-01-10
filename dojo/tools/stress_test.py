"""
Stress Test Tool: Quantify Model Stability (Flakiness).

Runs a specific challenge N times to measure variance in reasoning quality and success rate.
Generates 'stress_test_results.json' for the Research Dashboard.
"""

import argparse
import json
import random
import time

# Mocking imports since we are simulating for the dashboard
# In production, this would import GradingRunner and real models
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import numpy as np


@dataclass
class StressRun:
    run_id: int
    score: float
    success: bool
    hallucinations: int
    confidence: float

def run_stress_test(model_id: str, challenge_id: str, iterations: int, output_dir: Path):
    """
    Execute N iterations of a challenge (Simulated).
    """
    print(f"🔬 Starting Stress Test: {model_id} on {challenge_id} (n={iterations})")

    results = []

    # Simulation parameters (representing a "good but slightly flaky" model)
    base_score = 85.0
    score_std = 5.0  # Variance
    success_rate = 0.8

    for i in range(iterations):
        # Simulate variability
        score = min(100, max(0, random.normalvariate(base_score, score_std)))
        is_success = random.random() < success_rate

        # Correlation: successes usually have higher scores
        if is_success:
            score = max(score, 80)
        else:
            score = min(score, 75)

        results.append(StressRun(
            run_id=i+1,
            score=score,
            success=is_success,
            hallucinations=random.choice([0, 0, 0, 1, 2]),
            confidence=min(1.0, score/100 + random.uniform(-0.05, 0.05))
        ))

        print(f"  Run {i+1}/{iterations}: Score={score:.1f}, Success={is_success}")
        time.sleep(0.1) # Simulate work

    # Calculate Statistics
    scores = [r.score for r in results]
    successes = [r.success for r in results]

    stats = {
        "model_id": model_id,
        "challenge_id": challenge_id,
        "iterations": iterations,
        "timestamp": datetime.now().isoformat(),
        "mean_score": np.mean(scores),
        "std_dev_score": np.std(scores),
        "min_score": np.min(scores),
        "max_score": np.max(scores),
        "pass_rate": np.mean(successes),
        "stability_score": 1.0 - (np.std(scores) / 100.0), # Normalized stability
        "runs": [
            {
                "id": r.run_id,
                "score": r.score,
                "success": r.success,
                "hallucinations": r.hallucinations,
                "confidence": r.confidence
            }
            for r in results
        ]
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    outfile = output_dir / f"stress_test_{model_id}_{int(time.time())}.json"

    with open(outfile, 'w') as f:
        json.dump(stats, f, indent=2)

    print(f"\n✅ Stress Test Complete. Saved to {outfile}")
    print(f"   Stability Score: {stats['stability_score']:.2f}")
    print(f"   Pass Rate: {stats['pass_rate']:.1%}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run AgenticART Stress Test")
    parser.add_argument("--model", default="AgenticART-7B-Yellow", help="Model ID")
    parser.add_argument("--challenge", default="ch001_vulnbank_auth_bypass", help="Challenge ID")
    parser.add_argument("-n", "--iterations", type=int, default=20, help="Number of runs")
    parser.add_argument("--out", default="dojo_output/grading_output", help="Output directory")

    args = parser.parse_args()

    run_stress_test(args.model, args.challenge, args.iterations, Path(args.out))
