# ═══════════════════════════════════════════════════════════════════════════════
# LLM-AndroidPentest Dockerfile
# Multi-stage build for optimized image size
# ═══════════════════════════════════════════════════════════════════════════════

FROM python:3.11-slim as base

# Prevent Python from writing pyc files and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # ADB and Android tools
    android-tools-adb \
    # Network utilities
    netcat-openbsd \
    curl \
    wget \
    # Build tools (for some Python packages)
    build-essential \
    # Git for potential package installs
    git \
    && rm -rf /var/lib/apt/lists/*

# ─── Builder Stage ───────────────────────────────────────────────────────────
FROM base as builder

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ─── Production Stage ────────────────────────────────────────────────────────
FROM base as production

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash pentester
WORKDIR /app

# Copy application code
COPY --chown=pentester:pentester . .

# Create necessary directories
RUN mkdir -p /app/output/logs /app/output/reports /app/output/artifacts \
    /app/scripts/generated /app/.chromadb \
    && chown -R pentester:pentester /app

# Switch to non-root user
USER pentester

# Expose Streamlit port
EXPOSE 8501

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Default command - run Streamlit
CMD ["streamlit", "run", "webapp/app.py", "--server.address", "0.0.0.0", "--server.port", "8501"]

# ─── Development Stage ───────────────────────────────────────────────────────
FROM production as development

USER root

# Install development dependencies
RUN pip install --no-cache-dir \
    pytest \
    pytest-cov \
    black \
    ruff \
    mypy \
    ipython

# Install Frida tools for dynamic analysis
RUN pip install --no-cache-dir \
    frida-tools \
    objection

USER pentester

# Override command for development
CMD ["bash"]
