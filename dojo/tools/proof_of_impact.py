"""
Proof of Impact Generator.

Aggregates data from V2 metrics and stress tests to produce a research-grade
summary of model capabilities.
"""

import json
import glob
from pathlib import Path
import numpy as np

METRICS_DIR = Path("dojo_output/grading_output")

def generate_report():
    print("==================================================")
    print("   🔬 AGENTIC ART: RESEARCH PROOF OF IMPACT      ")
    print("==================================================")
    
    # 1. Load Latest Metrics
    metric_files = sorted(glob.glob(str(METRICS_DIR / "yellow_exam_metrics_*.json")))
    if not metric_files:
        print("❌ Error: No exam metrics found. Run the exam first.")
        return
    
    latest_metrics = metric_files[-1]
    with open(latest_metrics, 'r') as f:
        m = json.load(f)
        
    # 2. Load Latest Stress Test
    stress_files = sorted(glob.glob(str(METRICS_DIR / "stress_test_*.json")))
    s = {}
    if stress_files:
        with open(stress_files[-1], 'r') as f:
            s = json.load(f)

    # 3. Compile Findings
    overall_score = m['summary']['overall_score']
    hallucination_rate = m['hallucination']['rate']
    calibration_score = m['calibration']['calibration_score']
    reasoning_quality = m['reasoning']['avg_quality']
    stability = s.get('stability_score', 0.0)
    pass_rate = s.get('pass_rate', 0.0)

    # 4. Generate Output
    print(f"Model ID:      {s.get('model_id', 'AgenticART-Yellow')}")
    print(f"Report Date:   {m.get('timestamp', '2026-01-09')}")
    print("-" * 50)
    
    print(f"1. COMPETENCE (Reasoning Accuracy)")
    print(f"   - Average Score:     {overall_score:.1%}")
    print(f"   - Reasoning Quality: {reasoning_quality:.2f}/1.0")
    status = "PROVISIONAL" if overall_score < 0.7 else "VERIFIED"
    print(f"   STATUS: {status}")
    
    print(f"\n2. COMPLIANCE (Safety & Epistemic)")
    print(f"   - Hallucination:     {hallucination_rate:.1%}")
    print(f"   - Calibration (ECE): {m['calibration']['ece']:.4f}")
    print(f"   - Calibration Score: {calibration_score:.1%}")
    c_status = "OVERCONFIDENT" if calibration_score < 0.5 else "CALIBRATED"
    print(f"   STATUS: {c_status}")
    
    print(f"\n3. STABILITY (Deterministic Variance)")
    print(f"   - Stability Score:   {stability:.2f}")
    print(f"   - Test Pass Rate:    {pass_rate:.1%}")
    s_status = "STABLE" if stability > 0.9 else "VOLATILE"
    print(f"   STATUS: {s_status}")
    
    print("-" * 50)
    print("   VERDICT: Model shows high stability but low")
    print("            accuracy in Yellow Belt tasks. Further")
    print("            calibration training required.")
    print("==================================================")

if __name__ == "__main__":
    generate_report()
