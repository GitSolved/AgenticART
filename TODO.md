# AgenticART Metrics Enhancement Roadmap

Track progress on quantifying AgenticART's impact through comprehensive metrics.

---

## Feature 1: Enhanced Metrics System (Priority 1)

**Goal:** Quantify hallucination reduction and training efficiency

- [ ] **Hallucination Tracking**
  - [ ] Add `hallucination_count` and `hallucination_types` to `GradingCriteria`
  - [ ] Implement `_detect_hallucinations()` in `Grader` class
  - [ ] Detect: fake APIs, invalid ADB commands, placeholder paths
  - [ ] Location: `dojo/sensei/grader.py`, `dojo/models.py`

- [ ] **Temporal Metrics**
  - [ ] Add `attempt_timestamps` to `ChallengeSession`
  - [ ] Implement `time_to_success` property
  - [ ] Implement `avg_attempt_interval` property
  - [ ] Location: `dojo/curriculum/challenger.py`

- [ ] **Aggregate ModelProgress**
  - [ ] Add `total_hallucinations`, `total_attempts`, `total_time_seconds`
  - [ ] Add `scores_history` for trend calculation
  - [ ] Implement `hallucination_rate`, `avg_iterations`, `avg_time_to_success`
  - [ ] Implement `improvement_trend` property
  - [ ] Location: `dojo/models.py`

---

## Feature 2: Baseline Comparison Framework (Priority 2)

**Goal:** Enable side-by-side model evaluation

- [ ] Create `dojo/benchmarks/baseline.py`
- [ ] Implement `BaselineComparison` class
- [ ] Run same challenges against multiple models
- [ ] Output comparative metrics table:
  - Model ID
  - Pass rate
  - Avg score
  - Hallucination rate
  - Avg iterations
- [ ] Support: base Llama, GPT-4, tuned variants

---

## Feature 3: Metrics Export (Priority 3)

**Goal:** Export metrics for external dashboards

- [ ] Create `dojo/metrics/exporter.py`
- [ ] Implement `MetricsExporter` class
- [ ] Support formats:
  - [ ] JSON (for APIs)
  - [ ] CSV (for spreadsheets)
  - [ ] Prometheus format (for Grafana)
- [ ] Export session-level and aggregate metrics
- [ ] Include timestamps for time-series analysis

---

## Feature 4: Aggregate Dashboard (Priority 4)

**Goal:** Rollup views and trend analysis

- [ ] Create `dojo/metrics/aggregator.py`
- [ ] Implement `AggregateMetrics` dataclass:
  ```python
  @dataclass
  class AggregateMetrics:
      total_challenges: int
      overall_pass_rate: float
      avg_score: float
      hallucination_rate: float
      avg_iterations: float
      avg_time_to_success: float
      belt_distribution: dict[Belt, int]
      improvement_trend: float
  ```
- [ ] Aggregate across all sessions
- [ ] Support filtering by:
  - [ ] Model ID
  - [ ] Belt level
  - [ ] Date range
- [ ] Generate summary reports

---

## Impact Measurement Formula

```
Impact Score = (ΔSuccess × Coverage × Efficiency) / Cost

Where:
  ΔSuccess   = Pass rate improvement (%)
  Coverage   = Techniques × Android versions supported
  Efficiency = 1 / Avg iterations needed
  Cost       = GPU hours + Human hours
```

---

## References

- Inspired by metrics from "LLM-Powered Android Exploitation" (arXiv:2509.07933)
- Existing grading system: `dojo/sensei/grader.py`
- Current models: `dojo/models.py`
