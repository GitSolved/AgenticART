import json

from mlx_lm.utils import load


def convert_to_mlx_format(input_file, output_file, model_path):
    _, tokenizer = load(model_path)

    with open(input_file, "r") as f_in, open(output_file, "w") as f_out:
        for line in f_in:
            data = json.loads(line)
            # Convert ShareGPT to Messages
            messages = []
            for msg in data["conversations"]:
                role = "user" if msg["from"] == "human" else msg["from"]
                messages.append({"role": role, "content": msg["value"]})

            # Apply Template to create raw text
            text = tokenizer.apply_chat_template(messages, tokenize=False)
            f_out.write(json.dumps({"text": text}) + "\n")


model_path = "models/whiterabbit-7b-dojo-4bit"
convert_to_mlx_format("data/train.jsonl", "data/train_final.jsonl", model_path)
convert_to_mlx_format("data/valid.jsonl", "data/valid_final.jsonl", model_path)
