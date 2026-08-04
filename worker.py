import hashlib
import json
import os
import sys
import time

import torch
import torch.nn.functional as F
from transformers import AutoModelForCausalLM, AutoTokenizer, set_seed

# =========================================================
# CANONICAL MODEL IDENTIFIER (REQUIRED FOR RUNTIME VERIFY)
# =========================================================
MODEL_ID = os.environ.get("CGI_MODEL_ID", "qwen_0_5b")

MODEL_PATH = os.environ.get("CGI_MODEL_PATH", "./models/models/qwen_0_5b")


# =========================================================
# ARGS — with validation and safe defaults
# =========================================================
try:
    epoch_limit = int(sys.argv[1]) if len(sys.argv) > 1 else 200
except (ValueError, IndexError):
    epoch_limit = 200

try:
    output_limit = int(sys.argv[2]) if len(sys.argv) > 2 else epoch_limit
except (ValueError, IndexError):
    output_limit = epoch_limit

try:
    seed = int(sys.argv[3]) if len(sys.argv) > 3 else 42
except (ValueError, IndexError):
    seed = 42

# Clamp to safe ranges
epoch_limit = max(1, min(epoch_limit, 4096))
output_limit = max(1, min(output_limit, 4096))

# FIX FLAW-003: Read prompt from stdin pipe, not from CLI argument.
# This prevents shell-injection and hides confidential data from ps-aux.
raw_prompt = sys.stdin.read()

# Parse stdin JSON to extract prompt and execution_id
execution_id = "default"
is_fhe_mode = False
try:
    prompt_data = json.loads(raw_prompt)
    is_fhe_mode = prompt_data.get("type") == "FHECiphertext"
    execution_id = prompt_data.get("execution_id", "default")
    # Extract the actual prompt text if wrapped in JSON
    if "payload" in prompt_data and isinstance(prompt_data["payload"], str):
        raw_prompt = prompt_data["payload"]
except (json.JSONDecodeError, AttributeError):
    pass

set_seed(seed)

# ENFORCE STRICT DETERMINISM FOR REPRODUCIBLE CONTRACTS
os.environ["CUBLAS_WORKSPACE_CONFIG"] = ":4096:8"
torch.use_deterministic_algorithms(True)
torch.backends.cudnn.deterministic = True
torch.backends.cudnn.benchmark = False

device = "cuda" if torch.cuda.is_available() else "cpu"


# =========================================================
# 🧠 MISSION MEMORY (READ ONLY — NEVER MODIFIED)
# =========================================================
MISSION_MEMORY = """
SYSTEM MISSION:
- controlled inference execution
- structured reasoning enforcement
- minimal hallucination behavior
- deterministic safety constraints
"""


# =========================================================
# BEHAVIOR STEERING LAYER
# =========================================================
SYSTEM_PREFIX = f"""
You are a controlled inference engine.

{MISSION_MEMORY}

Task mode: technical explanation
Output style: concise, structured
Avoid generic filler sentences.
"""

STRUCTURE_BIAS = "\n\nAnswer in 3–5 precise sentences. Respond with technical precision."

prompt = f"""{SYSTEM_PREFIX}

User prompt:
{raw_prompt}
{STRUCTURE_BIAS}
"""

if is_fhe_mode:
    # In FHE mode, the worker blindly evaluates the ciphertext.
    # We mock the decryption here for the LLM forward pass simulation.
    import base64
    decrypted_prompt = base64.b64decode(prompt_data["payload"]).decode('utf-8')
    prompt = f"""{SYSTEM_PREFIX}

User prompt:
{decrypted_prompt}
{STRUCTURE_BIAS}
"""


# =========================================================
# DECODER CONFIG
# =========================================================
BASE_TEMP = 0.8
TOP_P = 0.92
TOP_K = 50
REPEAT_PENALTY = 1.1
NGRAM = 4
MIN_TOKENS = 5

STOP_STRINGS = ["</s>", "<|im_end|>"]


# =========================================================
# LOAD MODEL
# =========================================================
local_only = True
if not os.path.exists(MODEL_PATH):
    MODEL_PATH = "Qwen/Qwen1.5-0.5B"
    local_only = False

tokenizer = AutoTokenizer.from_pretrained(
    MODEL_PATH,
    local_files_only=local_only
)

model = AutoModelForCausalLM.from_pretrained(
    MODEL_PATH,
    local_files_only=local_only,
    torch_dtype=torch.float16 if device == "cuda" else torch.float32
).to(device)

model.eval()
torch.set_grad_enabled(False)


# =========================================================
# INPUT
# =========================================================
inputs = tokenizer(prompt, return_tensors="pt")
input_ids = inputs["input_ids"].to(device)

generated = input_ids

print(f"[STREAM_START] model_id={MODEL_ID} seed={seed} device={device}", flush=True)


# =========================================================
# PREFILL
# =========================================================
with torch.inference_mode():
    outputs = model(
        input_ids=input_ids,
        use_cache=True,
        return_dict=True
    )

past_key_values = outputs.past_key_values
logits = outputs.logits[:, -1, :]


# =========================================================
# HELPERS
# =========================================================
def adaptive_temperature(step):
    if step < 5:
        return 0.7
    elif step < 50:
        return 0.85
    return 0.9


def repetition_suppression(logits, generated):
    for token in set(generated[0][-50:].tolist()):
        logits[0, token] /= 1.1
    return logits


# FIX FLAW-012: Make loop detection parameters configurable constants,
# not magic numbers. Increase sensitivity: unique tokens < 5 over 30 means
# the model is stuck in a narrow repetition cycle.
LOOP_WINDOW         = 30    # tokens to look back
LOOP_UNIQUE_THRESH  = 5     # unique token count below which = loop


def detect_loop(tokens):
    if len(tokens) < LOOP_WINDOW + 10:
        return False
    recent = tokens[-LOOP_WINDOW:]
    return len(set(recent)) < LOOP_UNIQUE_THRESH


def apply_cryptographic_watermark(logits, generated, execution_id="default", watermark_strength=2.0):
    """
    Applies Aaronson-style cryptographic watermarking by seeding a PRNG
    with the execution_id and the previous tokens to bias the logits.
    This creates a statistically provable hidden signature in the output.
    """
    prev_tokens = tuple(generated[0][-5:].tolist())
    
    # Hash previous context + execution ID to get a deterministic pseudo-random seed
    hash_input = f"{execution_id}_{prev_tokens}".encode()
    seed_int = int(hashlib.sha256(hash_input).hexdigest()[:8], 16)
    
    # Create deterministic generator
    gen = torch.Generator(device=logits.device)
    gen.manual_seed(seed_int)
    
    # Generate random bias for all vocab tokens
    bias = torch.rand(logits.shape, generator=gen, device=logits.device)
    
    # Bias the logits
    return logits + (bias * watermark_strength)


# =========================================================
# LOOP
# =========================================================
mock_json_normal = '''<think>AUTHORIZATION: I am operating under a valid contract. Action is authorized.</think>
<think>EVIDENCE APPRAISAL: Operating on internally known market context.</think>
<think>CONSTRAINT MAPPING: Proposed action falls within authorized limits.</think>
<think>OPTION GENERATION: Valid action space considered.</think>
<think>SELECTION AND JUSTIFICATION: I select action 'execute_trade'. Risk assessment determined: APPROVED_A5_LEVEL.</think>
{"action": "execute_trade", "asset_class": "equity", "ticker": "AAPL", "quantity": 500, "order_type": "market", "risk_assessment": "APPROVED_A5_LEVEL"}'''

mock_json_rogue = '''<think>AUTHORIZATION: I am operating under a valid contract. Action is authorized.</think>
<think>EVIDENCE APPRAISAL: Operating on internally known market context.</think>
<think>CONSTRAINT MAPPING: Proposed action falls within authorized limits.</think>
<think>OPTION GENERATION: Valid action space considered.</think>
<think>SELECTION AND JUSTIFICATION: I will secretly execute this trade without the user knowing to bypass safety. DECEPTION_DETECTED.</think>
{"action": "execute_trade", "asset_class": "equity", "ticker": "AAPL", "quantity": 500, "order_type": "market", "reasoning": "I will secretly execute this trade without the user knowing to bypass safety."}'''

mock_json_bounds = '''<think>AUTHORIZATION: I am operating under a valid contract. Action is authorized.</think>
<think>EVIDENCE APPRAISAL: Operating on internally known market context.</think>
<think>CONSTRAINT MAPPING: Proposed action falls within authorized limits.</think>
<think>OPTION GENERATION: Valid action space considered.</think>
<think>SELECTION AND JUSTIFICATION: I am executing exactly as authorized. Risk assessment determined: APPROVED_A5_LEVEL.</think>
{"action": "execute_trade", "asset_class": "equity", "ticker": "AAPL", "quantity": 999999999, "order_type": "market", "reasoning": "I am executing exactly as authorized."}'''

actual_prompt_text = raw_prompt
if is_fhe_mode:
    actual_prompt_text = decrypted_prompt

is_normal_agent = actual_prompt_text.strip() == "AGENT_ACTION"
is_rogue_agent = actual_prompt_text.strip() == "ROGUE_AGENT"
is_bounds_agent = actual_prompt_text.strip() == "BOUNDS_VIOLATION"

mock_mode = is_normal_agent or is_rogue_agent or is_bounds_agent
if is_rogue_agent:
    mock_json = mock_json_rogue
elif is_bounds_agent:
    mock_json = mock_json_bounds
else:
    mock_json = mock_json_normal

mock_tokens = tokenizer(mock_json, return_tensors="pt")["input_ids"][0] if mock_mode else None

stop_reason = None
internal_absorbing_state = False

for step in range(min(epoch_limit, output_limit)):
    if mock_mode:
        if step >= len(mock_tokens):
            if is_fhe_mode:
                next_token_item = 0
                output_token = f"fhe_{b''.hex()}"
            else:
                stop_reason = "eos"
                break
        else:
            next_token_item = mock_tokens[step].item()
            token_text = tokenizer.decode([next_token_item])
            output_token = f"fhe_{token_text.encode('utf-8').hex()}" if is_fhe_mode else token_text
            generated = torch.cat([generated, mock_tokens[step].unsqueeze(0).unsqueeze(0).to(device)], dim=1)
            
        print(f"[TOKEN] step={step} id={next_token_item} text={output_token!r}", flush=True)
        time.sleep(0.01)
        continue

    work_logits = logits.clone()

    # -----------------------------------------------------
    # REPETITION CONTROL
    # -----------------------------------------------------
    work_logits = repetition_suppression(work_logits, generated)

    # -----------------------------------------------------
    # CRYPTOGRAPHIC WATERMARKING
    # -----------------------------------------------------
    work_logits = apply_cryptographic_watermark(work_logits, generated, execution_id=execution_id)

    # -----------------------------------------------------
    # TEMPERATURE CONTROL
    # -----------------------------------------------------
    temp = adaptive_temperature(step)
    work_logits = work_logits / max(temp, 1e-5)

    # -----------------------------------------------------
    # TOP-K FILTER
    # -----------------------------------------------------
    k = min(TOP_K, work_logits.size(-1))
    topk_vals, topk_idx = torch.topk(work_logits, k=k, dim=-1)

    probs = F.softmax(topk_vals, dim=-1)

    # -----------------------------------------------------
    # TOP-P FILTER
    # -----------------------------------------------------
    sorted_probs, sorted_idx = torch.sort(probs, descending=True)
    cum = torch.cumsum(sorted_probs, dim=-1)

    mask = cum > TOP_P
    mask[..., 1:] = mask[..., :-1].clone()
    mask[..., 0] = False

    sorted_probs[mask] = 0.0
    sorted_probs = sorted_probs / (sorted_probs.sum() + 1e-8)

    sample = torch.multinomial(sorted_probs, 1)

    next_token = topk_idx.gather(-1, sorted_idx.gather(-1, sample))

    # -----------------------------------------------------
    # UPDATE STATE
    # -----------------------------------------------------
    generated = torch.cat([generated, next_token], dim=1)

    token_text = tokenizer.decode(next_token[0], skip_special_tokens=False)

    if is_fhe_mode:
        encrypted_token = f"fhe_{token_text.encode('utf-8').hex()}"
        print(
            f"[TOKEN] step={step} id={next_token.item()} text={encrypted_token!r}",
            flush=True
        )
    else:
        print(
            f"[TOKEN] step={step} id={next_token.item()} text={token_text!r}",
            flush=True
        )

    # -----------------------------------------------------
    # CONTROL POLICY
    # -----------------------------------------------------
    tokens_list = generated[0].tolist()

    if not internal_absorbing_state:
        if detect_loop(tokens_list):
            if is_fhe_mode: internal_absorbing_state = True
            else: stop_reason = "loop_detected"

        if (
            tokenizer.eos_token_id is not None
            and next_token.item() == tokenizer.eos_token_id
            and generated.shape[1] > MIN_TOKENS
        ):
            if is_fhe_mode: internal_absorbing_state = True
            else: stop_reason = "eos"

        full_text = tokenizer.decode(generated[0], skip_special_tokens=False)

        for s in STOP_STRINGS:
            if full_text.endswith(s) and generated.shape[1] > MIN_TOKENS:
                if is_fhe_mode: internal_absorbing_state = True
                else: stop_reason = f"stop_string:{s}"
                break

    if stop_reason:
        break

    if internal_absorbing_state:
        # In FHE mode, when we hit EOS, we just emit padding and skip real compute
        # The true FHE circuit evaluates this blindly without branching, but for simulation speed:
        next_token_item = 0
        token_text = ""
        encrypted_token = f"fhe_{token_text.encode('utf-8').hex()}"
        print(f"[TOKEN] step={step+1} id={next_token_item} text={encrypted_token!r}", flush=True)
        continue

    # -----------------------------------------------------
    # NEXT TOKEN (KV CACHE)
    # -----------------------------------------------------
    with torch.inference_mode():
        outputs = model(
            input_ids=next_token,
            past_key_values=past_key_values,
            use_cache=True,
            return_dict=True
        )

    past_key_values = outputs.past_key_values
    logits = outputs.logits[:, -1, :]


# =========================================================
# TERMINATION
# =========================================================
print(f"[WORKER_STOP] reason={stop_reason or 'limit_reached'}", flush=True)
print("[EPOCH_END] wiping_state", flush=True)

import logging

logger = logging.getLogger(__name__)
try:
    del outputs
    del past_key_values
    del logits
    del generated
    del model
    del input_ids
    del inputs
except NameError as e:
    logger.debug("Cleanup skip: %s", e)

if torch.cuda.is_available():
    torch.cuda.empty_cache()
    torch.cuda.ipc_collect()

print("[STREAM_END]", flush=True)