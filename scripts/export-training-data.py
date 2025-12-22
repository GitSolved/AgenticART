#!/usr/bin/env python3
"""
Training Data Exporter

Converts attack chain logs into high-quality training datasets for fine-tuning.
Supports Alpaca (Instruction/Input/Output) and OpenAI (Messages) formats.
"""

import argparse
import json
from pathlib import Path


def parse_attack_chain(file_path):
    """Parse a single attack chain JSON file."""
    with open(file_path, "r") as f:
        return json.load(f)


def to_alpaca(data):
    """Convert to Alpaca format."""
    objective = data.get("objective", "Perform Android penetration testing")
    target = data.get("target", "Unknown Device")

    # We create a trajectory instruction
    instruction = f"Plan and execute an Android penetration test for the following objective on target: {target}"
    input_text = objective

    # The output is the successful sequence of phases
    phases_text = []
    for phase in data.get("phases", []):
        status = "Success" if phase.get("success") else "Failed"
        phases_text.append(f"- Phase {phase.get('phase')}: {status}")
        if phase.get("error"):
            phases_text.append(f"  Error: {phase.get('error')}")

    output = "\n".join(phases_text)
    if data.get("root_achieved"):
        output += "\n\nResult: Root access achieved successfully."

    return {"instruction": instruction, "input": input_text, "output": output}


def to_sharegpt(data):
    """Convert to ShareGPT/OpenAI messages format."""
    objective = data.get("objective", "Perform Android penetration testing")
    target = data.get("target", "Unknown Device")

    messages = [
        {"from": "human", "value": f"Target: {target}\nObjective: {objective}"},
    ]

    # Simulate assistant explaining the outcome
    response = "I have executed the attack chain. Here is the summary of events:\n\n"
    for phase in data.get("phases", []):
        response += f"Phase {phase.get('phase')}: {'SUCCESS' if phase.get('success') else 'FAILED'}\n"

    if data.get("root_achieved"):
        response += "\nExploitation Status: ROOT ACHIEVED"
    else:
        response += "\nExploitation Status: ACCESS LIMITED"

    messages.append({"from": "gpt", "value": response})

    return {"conversations": messages}


def main():
    parser = argparse.ArgumentParser(description="Export attack logs to training data")
    parser.add_argument(
        "--input-dir", default="output/attack_chains", help="Directory containing JSON logs"
    )
    parser.add_argument("--output", default="output/training_data.jsonl", help="Output file path")
    parser.add_argument(
        "--format", choices=["alpaca", "sharegpt"], default="alpaca", help="Dataset format"
    )

    args = parser.parse_args()

    input_path = Path(args.input_dir)
    if not input_path.exists():
        print(f"Error: Input directory {args.input_dir} does not exist.")
        return

    output_file = Path(args.output)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    dataset = []
    log_files = list(input_path.glob("*.json"))

    print(f"Processing {len(log_files)} log files...")

    for log_file in log_files:
        try:
            data = parse_attack_chain(log_file)
            if args.format == "alpaca":
                dataset.append(to_alpaca(data))
            else:
                dataset.append(to_sharegpt(data))
        except Exception as e:
            print(f"Skipping {log_file.name}: {e}")

    with open(output_file, "w") as f:
        if args.output.endswith(".jsonl"):
            for entry in dataset:
                f.write(json.dumps(entry) + "\n")
        else:
            json.dump(dataset, f, indent=2)

    print(f"Successfully exported {len(dataset)} entries to {args.output}")


if __name__ == "__main__":
    main()
