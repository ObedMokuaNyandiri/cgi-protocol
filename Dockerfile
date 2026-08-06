FROM python:3.10-slim AS builder

WORKDIR /build

# Install build dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ─────────────────────────────────────────────────
# Runtime Stage
# ─────────────────────────────────────────────────
FROM python:3.10-slim

# Security: run as non-root user
RUN groupadd -r cgi && useradd -r -g cgi -d /app -s /sbin/nologin cgi

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy source code
COPY *.py ./
COPY *.txt ./
COPY *.md ./
COPY *.html ./
COPY adapters/ ./adapters/
COPY zk/ ./zk/
COPY circuits/ ./circuits/
COPY auth/ ./auth/

# Create required directories with correct ownership
RUN mkdir -p /app/auth /app/outputs /app/logs /app/data /app/models /app/enclave && \
    chown -R cgi:cgi /app

# Switch to non-root user
USER cgi

# Expose the API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Graceful shutdown signal
STOPSIGNAL SIGTERM

# Run the API Gateway
CMD ["python", "-m", "uvicorn", "api_gateway:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
