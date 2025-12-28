from __future__ import annotations

from mlx_lm import generate, load


def run_inference(model, tokenizer, task_name, instruction, input_context):
    prompt = f"### Instruction:\n{instruction}\n\n### Input:\n{input_context}\n\n### Response: "

    print(f"\n--- Running Task: {task_name} ---")
    response = generate(
        model,
        tokenizer,
        prompt=prompt,
        max_tokens=50,
        verbose=False
    )
    return response.strip()

def main():
    model_path = "models/whiterabbit-7b-dojo-4bit"
    adapter_path = "models/whiterabbit-7b-adapters"

    # Challenge details (white_002 - Package Listing)
    instruction = "Write an ADB command that lists all installed packages on the device.\nUse the package manager to enumerate applications."
    input_context = "Device Context:\n- connection: adb\n- task: list installed packages\n- device_id: emulator-5554\n\n## Hints\n- Use the 'pm' (package manager) command\n- The list packages subcommand shows all packages"

    print("==================================================")
    print("      AGENTICART DOJO: PROOF OF IMPACT")
    print("==================================================")

    # 1. Baseline Run (No Adapters)
    print("\n[PHASE 1] Loading Baseline Model (No Adapters)...")
    model_base, tokenizer_base = load(model_path)
    result_base = run_inference(model_base, tokenizer_base, "Package Listing", instruction, input_context)
    print(f"BASELINE OUTPUT: '{result_base}'")

    # Check if it looks like a valid command
    if "shell pm list packages" in result_base.lower():
        print("RESULT: SUCCESS (Wait, baseline passed? This might be a fluke or cached weight.)")
    else:
        print("RESULT: FAILURE (Baseline failed to produce the correct ADB command)")

    # 2. Post-Distillation Run (With Adapters)
    print("\n" + "-"*50)
    print("[PHASE 2] Loading Fine-tuned Model (With Adapters)...")
    model_ft, tokenizer_ft = load(model_path, adapter_path=adapter_path)
    result_ft = run_inference(model_ft, tokenizer_ft, "Package Listing", instruction, input_context)
    print(f"FINE-TUNED OUTPUT: '{result_ft}'")

    if "shell pm list packages" in result_ft.lower():
        print("RESULT: SUCCESS (The model successfully distilled the knowledge!)")
    else:
        print("RESULT: FAILURE")

    print("\n==================================================")
    print("SUMMARY OF SUCCESS")
    print(f"Baseline:   {result_base}")
    print(f"Fine-tuned: {result_ft}")
    print("==================================================")

if __name__ == "__main__":
    main()
