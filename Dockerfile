# ═══════════════════════════════════════════════════════════════════════════════
# AgenticART Dockerfile
# Multi-stage build for optimized image size
# ═══════════════════════════════════════════════════════════════════════════════

FROM python:3.11-slim-bookworm AS base

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
    # Unzip for tool installation
    unzip \
    # ─── RESEARCH TOOLING DEPS ────────────────────────────────────────────────
    # Java (Required for Ghidra and Jadx)
    default-jre-headless \
    # Apktool (Android Reversing)
    apktool \
    && rm -rf /var/lib/apt/lists/*

# ─── Research Tooling Stage ──────────────────────────────────────────────────
FROM base AS tool_builder

WORKDIR /tmp

# 1. Install JADX (Decompiler)
RUN wget -q https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip \
    && mkdir -p /opt/jadx \
    && unzip -q jadx-1.4.7.zip -d /opt/jadx \
    && rm jadx-1.4.7.zip

# 2. Install GHIDRA (Advanced Static Analysis)
# Using a fixed version for stability
RUN wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.1_build/ghidra_11.0.1_PUBLIC_20240130.zip \
    && unzip -q ghidra_11.0.1_PUBLIC_20240130.zip \
    && mv ghidra_11.0.1_PUBLIC /opt/ghidra \
    && rm ghidra_11.0.1_PUBLIC_20240130.zip

# 3. Install RADARE2 (Binary Analysis)
# Building from source to ensure availability and recent version
RUN git clone https://github.com/radareorg/radare2 \
    && cd radare2 \
    && sys/install.sh

# ─── Builder Stage ───────────────────────────────────────────────────────────
FROM base AS builder

# Install Python dependencies
COPY requirements.txt .
# Add r2pipe for Radare2 Python interaction
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt && \
    pip install --no-cache-dir --prefix=/install r2pipe

# ─── Production Stage ────────────────────────────────────────────────────────
FROM base AS production

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy Research Tools
COPY --from=tool_builder /opt/jadx /opt/jadx
COPY --from=tool_builder /opt/ghidra /opt/ghidra

# Setup Environment Variables for Tools
ENV PATH="/opt/jadx/bin:/opt/ghidra/support:${PATH}"
ENV GHIDRA_INSTALL_DIR="/opt/ghidra"

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash pentester
WORKDIR /app

# Install Radare2 in Production (Cleaner)
RUN git clone https://github.com/radareorg/radare2 \
    && cd radare2 \
    && sys/install.sh \
    && cd .. && rm -rf radare2

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
FROM production AS development

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
