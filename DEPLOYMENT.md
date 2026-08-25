# Deploying CGI-Protocol

CGI-Protocol is designed to be effortlessly deployed via Docker, whether you are bridging to a local open-source model (like Ollama or vLLM) or proxying to cloud APIs (like OpenAI or Gemini).

## Quick Start (Docker)

1. **Clone and Configure**
   ```bash
   git clone https://github.com/your-org/cgi-protocol.git
   cd cgi-protocol
   cp .env.example .env
   python cgi_setup.py
   ```
   *The setup wizard will ask if you are using Docker and automatically configure networking for local models.*

2. **Generate Keys**
   If you didn't do this during `cgi_setup.py`, provision your first API key and the node's cryptographic identity:
   ```bash
   python auth/keygen.py --api-key "Admin"
   ```

3. **Launch**
   ```bash
   docker-compose up --build -d
   ```

4. **Verify**
   ```bash
   curl http://localhost:8000/health
   ```

---

## Connecting to AI Models

### Local Models (Ollama, vLLM, LM Studio)
When deploying CGI-Protocol in Docker, the container's `localhost` does not point to your host machine.
- **Auto-Routing:** The protocol automatically detects when it is running in Docker and rewrites local endpoints to `host.docker.internal`.
- **Linux Users:** The `docker-compose.yml` includes the `host-gateway` mapping, meaning this works flawlessly on Linux, Mac, and Windows.

**Example Local Setup (vLLM):**
1. Start vLLM on your host: `vllm serve meta-llama/Llama-3.2-3B-Instruct --port 8000`
2. Set in `.env`:
   ```env
   AI_BACKEND_TYPE=vllm_local
   AI_ENDPOINT_URL=http://host.docker.internal:8000/v1
   MODEL_ID=meta-llama/Llama-3.2-3B-Instruct
   ```

### Cloud APIs (Gemini, OpenAI, Anthropic)
Cloud APIs work immediately without network mapping.
1. Set in `.env`:
   ```env
   AI_BACKEND_TYPE=gemini_native
   AI_API_KEY=AIzaSy...
   MODEL_ID=gemini-2.5-flash
   ```

---

## Production Readiness Checklist
- [x] **HTTPS Proxy:** Use the included `Caddyfile` for automatic Let's Encrypt TLS.
- [x] **Rate Limiting:** Managed automatically via your `API_KEYS_FILE`.
- [x] **Security:** Governance keys are encrypted at rest using `PRIVATE_KEY_PASSPHRASE`.
- [x] **Data Persistence:** The `/data` directory is correctly mounted to persist the SQLite WAL ledger.
