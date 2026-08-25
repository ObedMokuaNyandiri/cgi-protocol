# CGI Protocol — AI Model Integration Guide

CGI Protocol

1. [Deploying a Local Model with vLLM](#deploying-a-local-model-with-vllm)
2. [Using Remote Cloud APIs](#using-remote-cloud-apis)
3. [Operations & Maintenance](#operations--maintenance)

## Operations & Maintenance

### Secret Management
By default, the CGI-Protocol generates and stores a governance ECDSA private key as a PEM file on disk (`auth/private_key.pem`). 
In production (e.g., Kubernetes), bake the application into a Docker container and provide the private key via the `CGI_PRIVATE_KEY` environment variable (using Vault or Docker Secrets). The system will automatically prioritize the environment variable over disk files.

### Multi-Worker Deployments
Because the CGI-Protocol utilizes SQLite with Write-Ahead Logging (WAL) and has migrated stateful rate limits to the database, the API gateway is safe to run with multiple workers.
By default, `API_WORKERS` is configured to `os.cpu_count() - 1`. If you run behind a load balancer with multiple containers, note that the rate limit and replay cache are currently bound to the local SQLite file. For distributed deployments, you should mount the SQLite volume (`data/audit_ledger.db`) via an NFS/EFS share or refactor `ledger.py` to use PostgreSQL.

### Database Backups (Zero-Downtime)
The SQLite ledger serves as your immutable audit trail. Do not rely on file-system backups while the server is running, as it may corrupt the WAL state.
Instead, use the included online backup script which leverages the SQLite backup API:
```bash
python script/backup_ledger.py
```
Run this on a cron schedule. It will safely copy the database to `data/backups/audit_ledger_backup_YYYYMMDD_HHMMSS.db` without locking the API gateway.

---

CGI Protocol wraps any AI model with cryptographic governance: signed attestations, audit trails, constraint violation detection, and blockchain anchoring — regardless of which model or cloud provider you use.

## Quick-Start: Choose Your Backend

| I want to use... | Set `AI_BACKEND_TYPE` | Also need |
|------------------|-----------------------|-----------|
| Google Gemini | `gemini_native` | `AI_API_KEY=` (Google AI Studio) |
| OpenAI GPT-4o | `openai_compatible` | `AI_API_KEY=sk-...`, `AI_ENDPOINT_URL=https://api.openai.com/v1` |
| Anthropic Claude | `anthropic` | `AI_API_KEY=sk-ant-...` |
| Azure OpenAI | `azure_openai` | `AI_API_KEY=`, `AZURE_OPENAI_RESOURCE=`, `AZURE_OPENAI_DEPLOYMENT=` |
| Groq (fast Llama) | `groq` | `AI_API_KEY=gsk_...` |
| Mistral AI | `mistral` | `AI_API_KEY=` |
| Together AI | `together_ai` | `AI_API_KEY=` |
| HuggingFace API | `huggingface_api` | `AI_API_KEY=hf_...`, `MODEL_ID=mistralai/...` |

| Cohere Command R | `cohere` | `AI_API_KEY=` |
| Ollama (local) | `ollama_local` | Ollama running (`ollama serve`) |
| vLLM server | `vllm_local` | vLLM running on port 8000 |
| llama.cpp server | `llamacpp_server` | llama-server running on port 8080 |
| HuggingFace local | `huggingface_local` | `MODEL_PATH=`, `torch` installed |

---

## Cloud API Providers

### Google Gemini

```env
AI_BACKEND_TYPE=gemini_native
AI_API_KEY=your_gemini_api_key_here
MODEL_ID=gemini-2.5-flash
```

Get your key: https://aistudio.google.com/app/apikey

Available models:
- `gemini-2.5-flash` — fastest, cheapest
- `gemini-2.5-pro` — most capable
- `gemini-1.5-pro-latest` — large context window
- `gemini-1.5-flash-latest` — balanced

---

### OpenAI

```env
AI_BACKEND_TYPE=openai_compatible
AI_ENDPOINT_URL=https://api.openai.com/v1
AI_API_KEY=sk-proj-...
MODEL_ID=gpt-4o-mini
```

Get your key: https://platform.openai.com/api-keys

Available models: `gpt-4o`, `gpt-4o-mini`, `gpt-4-turbo`, `gpt-3.5-turbo`, `o1-mini`, `o3-mini`

---

### Anthropic Claude

```env
AI_BACKEND_TYPE=anthropic
AI_API_KEY=sk-ant-api03-...
MODEL_ID=claude-sonnet-4-5
```

Get your key: https://console.anthropic.com/

Available models:
- `claude-opus-4-5` — most capable
- `claude-sonnet-4-5` — balanced (recommended)
- `claude-haiku-3-5` — fastest, cheapest
- `claude-3-5-sonnet-20241022` — strong coding/analysis

---

### Azure OpenAI Service

```env
AI_BACKEND_TYPE=azure_openai
AI_API_KEY=your_azure_key_from_portal
AZURE_OPENAI_RESOURCE=my-company-openai
AZURE_OPENAI_DEPLOYMENT=gpt-4o-deployment
AZURE_API_VERSION=2024-02-01
MODEL_ID=gpt-4o
```

> **Note**: The `MODEL_ID` is informational for Azure — the actual model is determined by your deployment name.

Find your resource and key: Azure Portal → OpenAI Service → Keys and Endpoint

---

### Groq (Ultra-Fast Inference)

Groq provides sub-second inference for Llama and Mixtral models.

```env
AI_BACKEND_TYPE=groq
AI_API_KEY=gsk_...
MODEL_ID=llama-3.3-70b-versatile
```

Get your key: https://console.groq.com/

Available models:
- `llama-3.3-70b-versatile` — recommended general purpose
- `llama-3.1-8b-instant` — fastest
- `mixtral-8x7b-32768` — large context
- `gemma2-9b-it` — Google Gemma

---

### Mistral AI

```env
AI_BACKEND_TYPE=mistral
AI_API_KEY=your_mistral_key
MODEL_ID=mistral-large-latest
```

Get your key: https://console.mistral.ai/

Available models: `mistral-large-latest`, `mistral-medium-latest`, `mistral-small-latest`, `codestral-latest`, `open-mistral-7b`

---

### Together AI

```env
AI_BACKEND_TYPE=together_ai
AI_API_KEY=your_together_key
MODEL_ID=meta-llama/Llama-3.3-70B-Instruct-Turbo
```

Get your key: https://api.together.ai/

Popular models:
- `meta-llama/Llama-3.3-70B-Instruct-Turbo`
- `meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo`
- `mistralai/Mixtral-8x7B-Instruct-v0.1`
- `Qwen/Qwen2.5-72B-Instruct-Turbo`
- `deepseek-ai/DeepSeek-V3`

---

### HuggingFace Inference API

```env
AI_BACKEND_TYPE=huggingface_api
AI_API_KEY=hf_...
MODEL_ID=mistralai/Mistral-7B-Instruct-v0.2
```

Get your token: https://huggingface.co/settings/tokens

For **dedicated/private endpoints**:
```env
AI_ENDPOINT_URL=https://your-endpoint.endpoints.huggingface.cloud/v1/chat/completions
```

> **Note**: Free serverless API returns 503 while the model loads (first request takes ~30s).

---



### Cohere Command R

```env
AI_BACKEND_TYPE=cohere
AI_API_KEY=your_cohere_key
MODEL_ID=command-r-plus-08-2024
```

Get your key: https://dashboard.cohere.com/api-keys

Available models: `command-r-plus-08-2024`, `command-r-08-2024`, `command-light`, `command`

---

## Local / Self-Hosted Providers

### Ollama (Recommended for Local)

Ollama is the easiest way to run open-source models locally.

**1. Install Ollama**
```bash
# macOS/Linux
curl -fsSL https://ollama.ai/install.sh | sh

# Windows: download from https://ollama.ai
```

**2. Pull a model**
```bash
ollama pull llama3.2          # 2GB — good general purpose
ollama pull qwen2.5:7b        # Qwen2.5 7B
ollama pull deepseek-r1:7b    # DeepSeek R1 reasoning
ollama pull phi3              # Microsoft Phi-3 (small, fast)
```

**3. Configure CGI Protocol**
```env
AI_BACKEND_TYPE=ollama_local
AI_ENDPOINT_URL=http://localhost:11434
MODEL_ID=llama3.2
```

Ollama runs automatically in the background after installation.
List available models: `ollama list`

---

### vLLM (High-Throughput Local Server)

vLLM is the fastest open-source inference server, ideal for production local deployments.

**1. Install and start vLLM**
```bash
pip install vllm
vllm serve meta-llama/Llama-3.2-3B-Instruct \
    --port 8000 \
    --api-key no-key-needed
```

**2. Configure CGI Protocol**
```env
AI_BACKEND_TYPE=vllm_local
AI_ENDPOINT_URL=http://localhost:8000/v1
MODEL_ID=meta-llama/Llama-3.2-3B-Instruct
```

> **Note**: vLLM requires a CUDA GPU for production use. For CPU-only, use Ollama or llama.cpp instead.

---

### llama.cpp HTTP Server (CPU-Friendly)

llama.cpp runs quantized GGUF models on CPU (and GPU).

**1. Build and start llama-server**
```bash
# Download a GGUF model
wget https://huggingface.co/bartowski/Llama-3.2-3B-Instruct-GGUF/resolve/main/Llama-3.2-3B-Instruct-Q4_K_M.gguf

# Start the server
./llama-server -m Llama-3.2-3B-Instruct-Q4_K_M.gguf \
    --port 8080 \
    --ctx-size 4096
```

**2. Configure CGI Protocol**
```env
AI_BACKEND_TYPE=llamacpp_server
AI_ENDPOINT_URL=http://localhost:8080/v1
MODEL_ID=local-model
```

---

### HuggingFace Local (Subprocess)

Runs HuggingFace models directly via a Python subprocess. Requires `torch` and `transformers`.

```bash
pip install -r requirements.txt -r requirements-ml.txt
```

```env
AI_BACKEND_TYPE=huggingface_local
MODEL_PATH=./models/models/qwen_0_5b
MODEL_ID=qwen_0_5b
```

Download a model:
```python
# models/download_model.py
from transformers import AutoModelForCausalLM, AutoTokenizer
model_id = "Qwen/Qwen1.5-0.5B"
save_path = "./models/models/qwen_0_5b"
AutoTokenizer.from_pretrained(model_id).save_pretrained(save_path)
AutoModelForCausalLM.from_pretrained(model_id).save_pretrained(save_path)
```

> **Note**: This backend loads the model fresh on every subprocess call — high latency. For production local use, prefer `ollama_local` or `vllm_local`.

---

## Custom / Enterprise Endpoints

Any OpenAI-compatible API (LM Studio, LocalAI, Perplexity, etc.) works with `openai_compatible`:

```env
AI_BACKEND_TYPE=openai_compatible
AI_ENDPOINT_URL=http://your-server:port/v1
AI_API_KEY=your-key-or-empty
MODEL_ID=model-name-from-server
```

---

## System Prompt Customisation

All adapters support a configurable system prompt via `AI_SYSTEM_PROMPT`:

```env
AI_SYSTEM_PROMPT=You are a healthcare AI assistant operating under HIPAA governance. Provide evidence-based medical information only. Do not provide definitive diagnoses.
```

If not set, each adapter uses a built-in default: *"You are a controlled inference engine. Answer concisely and precisely."*

---

## Production Deployment Checklist

Before going to production, verify the following:

```
[ ] AI_API_KEY is set (not empty or "mock")
[ ] LICENSE_ENFORCEMENT=ENFORCE and LICENSE_KEY_PATH is set
[ ] API_KEYS_FILE=auth/api_keys.json and at least one key generated
[ ] CORS_ORIGINS set to your specific frontend domain (not [] or ["*"])
[ ] ENCLAVE_MODE=software
[ ] ANCHOR_ENABLED=true for blockchain audit trail
[ ] ENABLE_SENSITIVE_ENCRYPTION=true for PII/CLASSIFIED data
[ ] Docker runs as non-root user (already configured in Dockerfile)
[ ] Caddy/nginx TLS termination in front of the API
[ ] Rate limits set appropriately for your license tier
```

---

## Verification

After configuring your backend, verify it works:

```bash
# 1. Check health
curl http://localhost:8000/health

# 2. Check license status
curl http://localhost:8000/v1/license/status

# 3. Run your first verified inference
curl -X POST http://localhost:8000/v1/infer \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "prompt": "What is the capital of France?",
    "data_classification": "PUBLIC",
    "max_tokens": 100
  }'

# 4. The response includes a full attestation bundle with signature
# Verify it with the client SDK:
python client_sdk.py
```

---

## Troubleshooting

| Error | Likely Cause | Fix |
|-------|-------------|-----|
| `Inference backend failed: Gemini API error 401` | Invalid/missing API key | Set `AI_API_KEY` in .env |
| `Unknown AI_BACKEND_TYPE: 'xyz'` | Typo in backend name | Check the backend list above |
| `Cannot reach Ollama at localhost:11434` | Ollama not running | Run `ollama serve` |
| `Authentication is not configured` | No API keys file | Run `python auth/keygen.py --api-key "My Org"` |
| `Model 'xyz' not allowed` | Model not in ALLOWED_MODELS | Add to ALLOWED_MODELS or use LICENSE_ENFORCEMENT=DISABLED |

| `License EXPIRED` | License file past expiry | Contact your CGI Protocol vendor to renew |
| `HuggingFace model loading (503)` | Model warming up | Wait 20-60s and retry |
