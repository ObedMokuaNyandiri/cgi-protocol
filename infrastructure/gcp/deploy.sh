#!/bin/bash
# ================================================================
# CGI Protocol — Google Cloud Free Tier Deployment Script
# ================================================================
# Deploys to GCP e2-micro VM (always-free in us-central1)
#
# Prerequisites:
#   1. Google Cloud SDK installed: https://cloud.google.com/sdk/docs/install
#   2. Authenticated: gcloud auth login
#   3. Project set: gcloud config set project YOUR_PROJECT_ID
#
# Usage:
#   chmod +x deploy.sh
#   ./deploy.sh
# ================================================================

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────
PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
ZONE="us-central1-a"
INSTANCE_NAME="cgi-protocol"
MACHINE_TYPE="e2-micro"       # Always-free tier
IMAGE_FAMILY="debian-12"
IMAGE_PROJECT="debian-cloud"
DISK_SIZE="30"                # GB (free tier allows 30GB)

echo "============================================================"
echo "  CGI Protocol — GCP Free Tier Deployment"
echo "============================================================"
echo "  Project:  ${PROJECT_ID}"
echo "  Zone:     ${ZONE}"
echo "  Machine:  ${MACHINE_TYPE}"
echo "============================================================"
echo ""

# ── Step 1: Create firewall rules ─────────────────────────────
echo "[1/4] Configuring firewall rules..."

# Allow HTTP (for Caddy redirect) and HTTPS
gcloud compute firewall-rules create cgi-allow-web \
    --allow tcp:80,tcp:443 \
    --target-tags cgi-server \
    --description "Allow HTTP/HTTPS for CGI Protocol" \
    --quiet 2>/dev/null || echo "  Firewall rule 'cgi-allow-web' already exists."

# Allow SSH
gcloud compute firewall-rules create cgi-allow-ssh \
    --allow tcp:22 \
    --target-tags cgi-server \
    --description "Allow SSH for CGI Protocol" \
    --quiet 2>/dev/null || echo "  Firewall rule 'cgi-allow-ssh' already exists."

# ── Step 2: Create the VM ─────────────────────────────────────
echo ""
echo "[2/4] Creating VM instance '${INSTANCE_NAME}'..."

gcloud compute instances create "${INSTANCE_NAME}" \
    --zone="${ZONE}" \
    --machine-type="${MACHINE_TYPE}" \
    --image-family="${IMAGE_FAMILY}" \
    --image-project="${IMAGE_PROJECT}" \
    --boot-disk-size="${DISK_SIZE}GB" \
    --boot-disk-type=pd-standard \
    --tags=cgi-server \
    --metadata=startup-script='#!/bin/bash
# ── Auto-setup on first boot ──────────────────────────────
apt-get update -y
apt-get install -y docker.io docker-compose git

# Enable Docker
systemctl enable docker
systemctl start docker

# Add the default user to docker group
usermod -aG docker $(whoami)

# Create swap space (e2-micro has only 1GB RAM)
if [ ! -f /swapfile ]; then
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo "/swapfile none swap sw 0 0" >> /etc/fstab
fi

echo "[CGI] VM setup complete. Connect via SSH and run setup-vm.sh"
' \
    --quiet 2>/dev/null && echo "  VM created successfully." || echo "  VM '${INSTANCE_NAME}' already exists."

# ── Step 3: Wait for VM to be ready ──────────────────────────
echo ""
echo "[3/4] Waiting for VM to be ready..."
sleep 10

# Get the external IP
EXTERNAL_IP=$(gcloud compute instances describe "${INSTANCE_NAME}" \
    --zone="${ZONE}" \
    --format="get(networkInterfaces[0].accessConfigs[0].natIP)")

echo "  External IP: ${EXTERNAL_IP}"

# ── Step 4: Transfer files ────────────────────────────────────
echo ""
echo "[4/4] Transferring project files to VM..."

# Create a deployment tarball (excluding large files)
cd "$(dirname "$0")/../.."
tar czf /tmp/cgi-deploy.tar.gz \
    --exclude='venv' \
    --exclude='__pycache__' \
    --exclude='.git' \
    --exclude='CGI-Protocol-Release.zip' \
    --exclude='models/models' \
    --exclude='outputs' \
    --exclude='logs' \
    --exclude='data' \
    --exclude='*.db' \
    .

gcloud compute scp /tmp/cgi-deploy.tar.gz \
    "${INSTANCE_NAME}:~/cgi-deploy.tar.gz" \
    --zone="${ZONE}" --quiet

rm -f /tmp/cgi-deploy.tar.gz

echo ""
echo "============================================================"
echo "  DEPLOYMENT COMPLETE"
echo "============================================================"
echo ""
echo "  Next steps:"
echo "    1. SSH into the VM:"
echo "       gcloud compute ssh ${INSTANCE_NAME} --zone=${ZONE}"
echo ""
echo "    2. Extract and set up:"
echo "       mkdir -p ~/cgi-protocol && cd ~/cgi-protocol"
echo "       tar xzf ~/cgi-deploy.tar.gz"
echo "       bash infrastructure/gcp/setup-vm.sh"
echo ""
echo "    3. Copy your model files:"
echo "       gcloud compute scp --recurse ./models/models/qwen_0_5b \\"
echo "           ${INSTANCE_NAME}:~/cgi-protocol/models/models/qwen_0_5b --zone=${ZONE}"
echo ""
echo "    4. Start the service:"
echo "       cd ~/cgi-protocol && docker-compose up -d"
echo ""
echo "    5. Access the API at:"
echo "       http://${EXTERNAL_IP}/health"
echo "       http://${EXTERNAL_IP}/v1/public-key"
echo ""
echo "============================================================"
