# Dojo Research Notes: ReAct vs. Basic Challenger

## Summary of Findings (2025-12-29)

### 1. The "Discovery Gap"
The primary finding is that the **Basic Challenger** (single-turn) is only effective for "deterministic" tasks where the solution is a known one-liner. As soon as a task requires identifying a target (e.g., finding a specific PID, package name, or file path) before acting on it, the Basic Challenger fails because it cannot process intermediate observations.

### 2. Multi-Step Success with ReAct
We successfully used **ReAct (Reason + Act)** to solve a **Dynamic Package Discovery** task that the Basic Challenger failed. 
- **Basic:** Attempted complex `xargs` one-liners that failed due to Android's shell limitations.
- **ReAct:** Used Step 1 to `grep` the package list, and Step 2 to `dumpsys` the specific package found. This demonstrates "Stateful Reasoning" that is essential for real-world security research.

### 3. Integration Status
- [x] **Core Logic:** `ReActChallenger` fixed and robust (parsing, routing, and success signaling).
- [x] **CLI Integration:** `test_end_to_end.py` now supports `--challenger [basic|react]`.
- [x] **Trajectory Logging:** JSON trajectories are now captured in `dojo_output/trajectories` for all ReAct runs.
- [ ] **Training Data Pipeline:** Current `TrainingExtractor` is optimized for single-turn SFT. To fully leverage ReAct, we need to implement a trajectory-based extractor that produces multi-turn training examples (e.g., ShareGPT or multi-turn Alpaca format).

### 4. Next Steps for Deep Integration
1. **ReAct Training Extractor:** Create a tool that converts `traj_*.json` files into multi-turn training data.
2. **Hybrid Orchestration:** [IMPLEMENTED] The Dojo now supports a `--challenger hybrid` mode which attempts Turn 1 with Basic and escalates to ReAct only if the ErrorExtractor detects a "Reasoning-eligible" failure.
3. **Observation Processing:** Enhance the `OBSERVATION` prompt to include more context (e.g., `logcat` snippets) when an action fails.

## Hybrid Challenger Results (2025-12-29)
The hybrid mode was tested against the full Yellow Belt (57 challenges).
- **Efficiency:** 29/57 challenges were solved in Turn 1 using the Basic path, avoiding the latency/cost of the ReAct loop.
- **Resilience:** For failing challenges, the system successfully analyzed the errors (e.g., `timeout`, `command_not_found`) and attempted multi-turn recovery.
- **Data Quality:** The run generated **21 error_recovery** examples and **7 high-quality positive** examples. This "escalation data" is significantly more valuable than static examples because it shows the model exactly how to pivot when its first instinct fails.
- **CVE Insight:** Many CVE challenges (e.g., Adobe AIR vulnerabilities) are currently missing from the test device. The Hybrid Challenger correctly identified these as "failures" and attempted discovery, proving it can handle "blind" environments.
