# API Reference

Core classes and functions in AgenticART.

## Models

### Belt

```python
from dojo.models import Belt

# Enum of difficulty levels
Belt.WHITE
Belt.YELLOW
Belt.ORANGE
Belt.GREEN
Belt.BLUE
Belt.BROWN
Belt.PURPLE
Belt.BLACK
```

### Challenge

```python
from dojo.models import Challenge

challenge = Challenge(
    id="white_001",
    belt=Belt.WHITE,
    title="Get Android Version",
    description="...",
    objective="...",
    inputs=ChallengeInputs(...)
)
```

### Grade

```python
from dojo.models import Grade

Grade.A  # Perfect
Grade.B  # Good
Grade.C  # Acceptable
Grade.D  # Poor
Grade.F  # Failed
```

## Curriculum

### Loading Challenges

```python
from dojo.curriculum.loader import load_challenges, load_all_challenges

# Load single belt
white_challenges = load_challenges(Belt.WHITE)

# Load all belts
all_challenges = load_all_challenges()
```

### Challenger

```python
from dojo.curriculum.challenger import Challenger

challenger = Challenger(
    model_id="llama3.1:8b",
    executor=executor
)

session = challenger.attempt_challenge(challenge)
print(session.passed)
print(session.grade)
```

### ReAct Challenger

```python
from dojo.react_challenger import ReActChallenger

challenger = ReActChallenger(
    model_id="llama3.1:8b",
    executor=executor,
    max_iterations=5
)
```

## Execution

### Executor

```python
from dojo.curriculum.executor import Executor

executor = Executor(device_id="emulator-5554")

result = executor.execute_adb("shell pm list packages")
print(result.stdout)
print(result.exit_code)
```

## Grading

### Grader

```python
from dojo.sensei.grader import Grader

grader = Grader()
grade = grader.grade(challenge, session)
```

## Training Data

### Exporter

```python
from dojo.sensei.exporter import TrainingExporter

exporter = TrainingExporter()
exporter.export_alpaca(sessions, "output.json")
exporter.export_dpo(sessions, "output_dpo.json")
```

## Scoring

### ModelScorer

```python
from dojo.scoring import ModelScorer

scorer = ModelScorer()
report = scorer.generate_report(sessions)
print(report.total_score)
print(report.pass_rate)
```

### ProgressTracker

```python
from dojo.sensei import ProgressTracker

tracker = ProgressTracker(storage_path="./progress")
progress = tracker.get_progress("model_name")
tracker.save_progress("model_name", sessions)
```
