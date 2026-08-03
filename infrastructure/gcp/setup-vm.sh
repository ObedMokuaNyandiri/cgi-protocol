#!/bin/bash
# ================================================================
# CGI Protocol — VM Setup Script
# ================================================================
# Run this INSIDE the GCP VM after SSH-ing in.
# Sets up Docker, creates directories, generates API keys,
# and prepares the environment for docker-compose up.
#
# Usage:
#   cd ~/cgi-protocol
#   bash infrastructure/gcp/setup-vm.sh
# ================================================================

set -euo pipefail

echo "============================================================"
echo "  CGI Protocol — VM Setup"
echo "============================================================"

PROJECT_DIR="${HOME}/cgi-protocol"
cd "${PROJECT_DIR}"

# ── Step 1: Ensure Docker is running ─────────────────────────
echo "[1/6] Checking Docker..."
if ! command -v docker &>/dev/null; then
    echo "  Installing Docker..."
    sudo apt-get update -y
    sudo apt-get install -y docker.io docker-compose
    sudo systemctl enable docker
    sudo systemctl start docker
    sudo usermod -aG docker "${USER}"
    echo "  Docker installed. You may need to log out and back in."
fi
echo "  Docker: $(docker --version)"

# ── Step 2: Ensure swap ──────────────────────────────────────
echo "[2/6] Checking swap space..."
SWAP_SIZE=$(free -m | awk '/Swap/{print $2}')
if [ "${SWAP_SIZE}" -lt 1024 ]; then
    echo "  Creating 2GB swap file..."
    sudo fallocate -l 2G /swapfile
    sudo chmod 600 /swapfile
    sudo mkswap /swapfile
    sudo swapon /swapfile
    echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab
    echo "  Swap created: 2GB"
else
    echo "  Swap already configured: ${SWAP_SIZE}MB"
fi

# ── Step 3: Create directories ────────────────────────────────
echo "[3/6] Creating directories..."
mkdir -p auth outputs logs data models/models

# ── Step 4: Generate .env from template ───────────────────────
echo "[4/6] Setting up environment..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "  Created .env from template"
else
    echo "  .env already exists"
fi

# ── Step 5: Generate API keys ────────────────────────────────
echo "[5/6] Generating API keys..."
if [ ! -f auth/api_keys.json ]; then
    # Generate a random API key
    API_KEY=$(python3 -c "import os; print(os.urandom(32).hex())")
    API_KEY_HASH=$(python3 -c "import hashlib; print(hashlib.sha256('${API_KEY}'.encode()).hexdigest())")

    cat > auth/api_keys.json <<EOF
{
    "keys": [
        {
            "key_id": "admin-key-1",
            "key_hash": "${API_KEY_HASH}",
            "scopes": ["infer", "audit"],
            "organization": "Default Organization",
            "active": true
        }
    ]
}
EOF

    echo ""
    echo "  ┌──────────────────────────────────────────────────────┐"
    echo "  │  YOUR API KEY (save this — it won't be shown again): │"
    echo "  │  ${API_KEY}  │"
    echo "  └──────────────────────────────────────────────────────┘"
    echo ""
    echo "  Use it in requests: curl -H 'X-API-Key: ${API_KEY}' ..."
else
    echo "  API keys already configured"
fi

# ── Step 6: Create systemd service ────────────────────────────
echo "[6/6] Creating systemd service..."
sudo tee /etc/systemd/system/cgi-protocol.service > /dev/null <<EOF
[Unit]
Description=CGI Protocol - Healthcare Verifiable AI
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${PROJECT_DIR}
ExecStart=/usr/bin/docker-compose up -d
ExecStop=/usr/bin/docker-compose down
User=${USER}

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable cgi-protocol.service
echo "  Systemd service created and enabled"

echo ""
echo "============================================================"
echo "  SETUP COMPLETE"
echo "============================================================"
echo ""
echo "  To start the service:"
echo "    docker-compose up -d"
echo ""
echo "  Or use systemd:"
echo "    sudo systemctl start cgi-protocol"
echo ""
echo "  To check status:"
echo "    docker-compose ps"
echo "    curl http://localhost:8000/health"
echo ""
echo "  IMPORTANT: Copy your model files before starting:"
echo "    # From your local machine:"
echo "    gcloud compute scp --recurse ./models/models/qwen_0_5b \\"
echo "        cgi-protocol:~/cgi-protocol/models/models/ --zone=us-central1-a"
echo ""
echo "============================================================"
