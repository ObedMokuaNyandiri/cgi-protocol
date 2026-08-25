# CGI Protocol — Healthcare Verifiable AI

**Cryptographic Governance Infrastructure for auditable, verifiable AI inference.**

CGI Protocol makes AI decision-making cryptographically provable. Every inference is signed, attested, and recorded in an immutable audit chain — designed for regulated industries where AI decisions must be explainable, tamper-evident, and independently verifiable.

## What It Does

```
Patient prompt  →  CGI Gateway  →  AI Worker (deterministic)  →  Signed Attestation Bundle
                   │                                               │
                   ├─ API Key Auth                                 ├─ ECDSA Signature
                   ├─ Rate Limiting                                ├─ Commitment Chain
                   ├─ Input Validation                             ├─ Constraint Lattice Proof
                   └─ Request Tracing                              └─ Audit Ledger Record
```

Every AI response includes a **Sovereign Attestation Bundle (SAB)** — a cryptographic proof that:
- The model ran deterministically (same seed + input = same output)
- No constraint violations occurred (deception, hidden intent, self-preservation)
- The output was signed by the governance key
- The attestation is linked to an immutable audit chain

## Use Cases

| Domain | Application |
|--------|-------------|
| **Healthcare** | Patient data privacy, clinical decision support audit trails |
| **Finance** | Regulatory compliance, trade execution verification |
| **Legal** | AI-generated document attestation, discovery audit |
| **Insurance** | Claims processing transparency, fraud detection audit |

## Quick Start

### 1. Prerequisites
- Python 3.10+
- Docker & Docker Compose

### 2. Setup

```bash
# Clone and enter
git clone https://github.com/YOUR_ORG/CGI-Protocol.git
cd CGI-Protocol

# Create environment
cp .env.example .env

# Create directories
mkdir -p auth outputs logs data

# Generate governance keys
python auth/keygen.py

# Generate API key
python auth/keygen.py --api-key "My Organization"
# SAVE THE API KEY — it won't be shown again!
```

### 3. Run Locally

```bash
# Install dependencies
pip install -r requirements.txt

# Start the API
python api_gateway.py
```

### 4. Run with Docker

```bash
# Build and start
docker-compose up -d

# Check health
curl http://localhost:8000/health

# Run inference
curl -X POST http://localhost:8000/v1/infer \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "prompt": "Explain the implications of elevated troponin levels",
    "data_classification": "PUBLIC",
    "max_tokens": 200
  }'
```

### 5. Verify Attestation

```bash
# Get the public key
curl http://localhost:8000/v1/public-key

# Use the client SDK to verify
python client_sdk.py
```

## Deploy to Google Cloud (Free Tier)

Deploy on GCP's always-free `e2-micro` VM:

```bash
# Prerequisites: Google Cloud SDK installed and authenticated
gcloud auth login
gcloud config set project YOUR_PROJECT_ID

# Deploy
chmod +x infrastructure/gcp/deploy.sh
./infrastructure/gcp/deploy.sh

# SSH into VM and complete setup
gcloud compute ssh cgi-protocol --zone=us-central1-a
cd ~/cgi-protocol
bash infrastructure/gcp/setup-vm.sh

# Copy your model
# (from local machine)
gcloud compute scp --recurse ./models/models/qwen_0_5b \
    cgi-protocol:~/cgi-protocol/models/models/ --zone=us-central1-a

# Start the service
docker-compose up -d
```

## API Endpoints

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| `GET` | `/health` | Health check | None |
| `GET` | `/v1/public-key` | Governance public key | None |
| `POST` | `/v1/infer` | Run verified inference | API Key |
| `GET` | `/v1/audit/export` | Export audit log | API Key + `audit` scope |
| `GET` | `/v1/attestation/{id}` | Get specific attestation | API Key |

## Enterprise & Security Features

- **Data Classification**: Tag inferences with sensitivity levels (e.g., `CONFIDENTIAL`, `RESTRICTED`, `PUBLIC`)
- **Purpose of Use**: Configurable purpose codes based on business domain
- **Audit Trail**: Every inference recorded with timestamp, user ID, request ID, and classification
- **Audit Export**: JSONL-format export for compliance reporting
- **API Key Scoping**: Per-organization keys with configurable permissions
- **Encryption at Rest**: SQLite WAL mode with optional sensitive field encryption

## Architecture

```
┌─────────────┐         ┌───────────────────────┐         ┌──────────────┐
│ Client SDK  │◄──TLS──►│  API Gateway (FastAPI) │◄───────►│ SQLite Ledger│
│ (verifier)  │         │  • Auth (API keys)     │         │ (WAL mode)   │
└─────────────┘         │  • Rate limiting       │         └──────────────┘
                        │  • Input validation    │
                        │  • Crypto signing      │         ┌──────────────┐
                        │  • Audit logging       │◄───────►│ Chain (JSONL)│
                        └─────────┬─────────────┘         └──────────────┘
                                  │
                                  ▼
                        ┌───────────────────────┐
                        │  Worker (subprocess)   │
                        │  • Model inference     │
                        │  • Deterministic output│
                        │  • Watermarking        │
                        │  • Constraint lattice  │
                        │  • Timeout enforced    │
                        └───────────────────────┘
```

## Security

- **ECDSA secp256k1** governance key for attestation signing
- **API key authentication** with SHA-256 hashed storage
- **Rate limiting** (sliding window, configurable)
- **Request ID tracing** for audit correlation
- **Security headers** (HSTS, X-Content-Type-Options, X-Frame-Options)
- **Non-root Docker container** with health checks
- **Caddy reverse proxy** with automatic TLS (Let's Encrypt)
- **Constraint Lattice v2**: Dual-mode (embedding + lexical) violation detection
- **Worker timeout**: Prevents infinite hangs

## Configuration

All settings via environment variables or `.env` file. See [`.env.example`](.env.example) for the full list.

Key settings:
| Variable | Default | Description |
|----------|---------|-------------|
| `ENCLAVE_MODE` | `software` | `software` |
| `API_KEYS_FILE` | `auth/api_keys.json` | Path to API keys |
| `RATE_LIMIT_RPM` | `30` | Requests per minute |
| `WORKER_TIMEOUT_SECONDS` | `180` | Max inference time |
| `DEFAULT_DATA_CLASSIFICATION` | `PUBLIC` | Default data class |
| `AUDIT_RETENTION_DAYS` | `2190` | 6 years default retention |

## License

See [LICENSE](LICENSE) for details.
