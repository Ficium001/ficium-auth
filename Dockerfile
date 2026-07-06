# =============================================================
# ficium-auth — Dockerfile
# Multi-stage build: builder + minimal production image
# =============================================================

# ── Stage 1: Builder ──────────────────────────────────────────
FROM python:3.14-slim AS builder

WORKDIR /build

# System deps for cryptography and argon2
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps into /install
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --prefix=/install --no-cache-dir -r requirements.txt

# ── Stage 2: Production ───────────────────────────────────────
FROM python:3.14-slim AS production

# Non-root user (bank security requirement)
RUN groupadd -r ficium && useradd -r -g ficium -s /sbin/nologin ficium

# Runtime system deps only
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY --chown=ficium:ficium src/ ./src/

# Security: no shell, no package managers
USER ficium

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health/live || exit 1

EXPOSE 8000

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

CMD ["python", "-m", "src.main"]
