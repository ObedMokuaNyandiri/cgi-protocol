import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel
import time
import sys
import logging
try:
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
except ImportError:
    print("Please install torch and transformers: pip install torch transformers")
    sys.exit(1)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("qwen-isolated-server")

app = FastAPI(title="Isolated Qwen Server (OpenAI Compatible)")

# ── Load Model ─────────────────────────────────────────────────────────────
MODEL_PATH = "./models/models/qwen_0_5b"
logger.info(f"Loading isolated model from {MODEL_PATH}...")
try:
    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
    model = AutoModelForCausalLM.from_pretrained(MODEL_PATH, torch_dtype=torch.float32)
except Exception as e:
    logger.error(f"Failed to load model: {e}")
    sys.exit(1)
logger.info("Model loaded successfully.")

# ── OpenAI Compatible Endpoints ───────────────────────────────────────────
class ChatMessage(BaseModel):
    role: str
    content: str

class ChatCompletionRequest(BaseModel):
    model: str
    messages: list[ChatMessage]
    max_tokens: int = 100
    temperature: float = 0.7
    seed: int | None = None

@app.post("/v1/chat/completions")
async def chat_completions(req: ChatCompletionRequest):
    logger.info(f"Received inference request for {req.model}")
    
    # Combine messages into a single prompt
    prompt = "\n".join(f"{msg.role}: {msg.content}" for msg in req.messages)
    prompt += "\nassistant:"

    if req.seed is not None:
        torch.manual_seed(req.seed)

    inputs = tokenizer(prompt, return_tensors="pt")
    
    t0 = time.time()
    outputs = model.generate(
        **inputs,
        max_new_tokens=req.max_tokens,
        temperature=req.temperature,
        do_sample=(req.temperature > 0.0),
        pad_token_id=tokenizer.eos_token_id
    )
    t1 = time.time()

    # Extract only the generated text
    input_length = inputs.input_ids.shape[1]
    generated_tokens = outputs[0][input_length:]
    generated_text = tokenizer.decode(generated_tokens, skip_special_tokens=True).strip()

    logger.info(f"Generated {len(generated_tokens)} tokens in {t1-t0:.2f}s")

    # Format as OpenAI response
    return {
        "id": "chatcmpl-isolated-qwen",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": req.model,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": generated_text
            },
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": input_length,
            "completion_tokens": len(generated_tokens),
            "total_tokens": input_length + len(generated_tokens)
        }
    }

@app.get("/v1/models")
async def list_models():
    return {
        "object": "list",
        "data": [{"id": "qwen_0_5b", "object": "model", "created": int(time.time()), "owned_by": "isolated-test"}]
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8001)
