from __future__ import annotations

from mlx_lm import generate, load


def main():
    model_path = "models/whiterabbit-7b-dojo-4bit"
    adapter_path = "models/whiterabbit-7b-adapters"

    print(f"Loading model: {model_path}")
    print(f"Loading adapter: {adapter_path}")

    model, tokenizer = load(model_path, adapter_path=adapter_path)

    prompt = """### Instruction:
Write an ADB shell command that outputs the Android version of the connected device.
The output should be just the version number (e.g., "7.0" or "11").

### Input:
Device Context:
- connection: adb
- task: retrieve Android version
- device_id: emulator-5554

## Hints
- Use 'adb shell getprop' to read system properties
- Android version is stored in ro.build.version.release

## Output Format
Provide only the adb command/script. No explanations or markdown.

### Response:"""

    # Test 1: Simple Hello
    print("Test 1: 'hello'")
    response = generate(model, tokenizer, prompt="hello", max_tokens=10, verbose=True)
    print(f"Result: {response}")

    # Test 2: Prompt with space
    prompt_space = prompt + " "
    print("\nTest 2: Prompt with space")
    response = generate(
        model,
        tokenizer,
        prompt=prompt_space,
        max_tokens=100,
        verbose=True
    )
    if response:
        print(f"Raw Response: '{response}'")
    else:
        print("Response was None")

if __name__ == "__main__":
    main()

