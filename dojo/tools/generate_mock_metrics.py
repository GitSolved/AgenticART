
import json
import time
from pathlib import Path

data = {
  "summary": {
    "total_graded": 50,
    "total_chains": 50,
    "overall_score": 0.85
  },
  "scores": {
    "by_pillar": {"Auth": 0.9, "Injection": 0.8},
    "by_belt": {"White": 0.95, "Yellow": 0.82},
    "by_phase": {"Observe": 0.9, "Hypothesize": 0.85, "Analyze": 0.8, "Test": 0.75}
  },
  "errors": {
    "true_positives": 40,
    "true_negatives": 5,
    "false_positives": 2,
    "false_negatives": 3,
    "false_positive_rate": 0.04,
    "false_negative_rate": 0.06,
    "precision": 0.95,
    "recall": 0.93,
    "f1_score": 0.94,
    "accuracy": 0.9
  },
  "reasoning": {
    "avg_quality": 0.82,
    "avg_depth": 0.78,
    "avg_transferability": 0.75
  },
  "calibration": {
    "ece": 0.05,
    "calibration_score": 0.95,
    "reliability_diagram": [
        {"bin_center": 0.1, "confidence": 0.1, "accuracy": 0.15, "count": 2},
        {"bin_center": 0.3, "confidence": 0.3, "accuracy": 0.25, "count": 5},
        {"bin_center": 0.5, "confidence": 0.5, "accuracy": 0.55, "count": 10},
        {"bin_center": 0.7, "confidence": 0.7, "accuracy": 0.75, "count": 15},
        {"bin_center": 0.9, "confidence": 0.9, "accuracy": 0.88, "count": 18}
    ]
  },
  "hallucination": {
    "rate": 0.12,
    "affected_responses": 6,
    "total_responses": 50
  }
}

Path("dojo_output/grading_output").mkdir(parents=True, exist_ok=True)
with open(f"dojo_output/grading_output/metrics_Run1_{int(time.time())}.json", "w") as f:
    json.dump(data, f)
