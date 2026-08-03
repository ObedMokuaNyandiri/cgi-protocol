#!/bin/bash
set -e

# ==============================================================================
# CGI Protocol - AWS Nitro Enclave Build Script
# ==============================================================================
# This script must be run on an EC2 instance or Linux environment with Docker 
# and the aws-nitro-enclaves-cli installed.
# ==============================================================================

echo "=========================================="
echo " 1. Building CGI Nitro Docker Image"
echo "=========================================="

# Assuming script is run from the root of the CGI-Protocol repository
cd "$(dirname "$0")/.."

docker build -t cgi-nitro-runtime:latest -f enclave/Dockerfile.nitro .

echo ""
echo "=========================================="
echo " 2. Generating Enclave Image Format (.eif)"
echo "=========================================="

# Build the .eif file from the docker image
nitro-cli build-enclave \
    --docker-uri cgi-nitro-runtime:latest \
    --output-file cgi-runtime.eif

echo ""
echo "=========================================="
echo " 3. Enclave Cryptographic PCRs"
echo "=========================================="
echo "The PCR (Platform Configuration Register) values below mathematically"
echo "prove the exact contents of the running enclave. You MUST register"
echo "PCR0, PCR1, and PCR2 in the Smart Contract Verifier."
echo "=========================================="

# Describe the EIF to extract the measurements
nitro-cli describe-eif --eif-path cgi-runtime.eif

echo ""
echo "[OK] Build complete. The enclave image is at ./cgi-runtime.eif"
echo "To run the enclave in debug mode (attached to console), execute:"
echo "nitro-cli run-enclave --cpu-count 2 --memory 4096 --eif-path cgi-runtime.eif --debug-mode"
