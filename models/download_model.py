from transformers import AutoModelForCausalLM, AutoTokenizer

MODEL_NAME = "Qwen/Qwen2.5-0.5B-Instruct"

SAVE_PATH = "./models/qwen_0_5b"

print("Downloading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

print("Downloading model...")
model = AutoModelForCausalLM.from_pretrained(MODEL_NAME)

print("Saving locally...")
tokenizer.save_pretrained(SAVE_PATH)
model.save_pretrained(SAVE_PATH)

print("Done!")