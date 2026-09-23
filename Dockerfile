FROM python:3.11-slim AS base

# ============================================================
# Single portable image: Cowrie SSH Honeypot + SOC Dashboard
# Ports: 22 (honeypot trap), 8501 (dashboard)
# Compatible with docker save/load for on-prem deployment
# ============================================================

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONPATH="/app" \
    COWRIE_HOME="/opt/cowrie" \
    COWRIE_VENV="/opt/cowrie/cowrie-env"

WORKDIR /app

# System deps: git for cowrie clone, sqlite3 for debugging, libssl for paramiko
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    sqlite3 \
    libssl-dev \
    libffi-dev \
    build-essential \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# ---- Install Cowrie in isolated venv ----
RUN python3 -m venv ${COWRIE_VENV} && \
    ${COWRIE_VENV}/bin/pip install --upgrade pip && \
    ${COWRIE_VENV}/bin/pip install cowrie

# Copy Cowrie config into place
COPY config/cowrie.cfg ${COWRIE_HOME}/cowrie-git/etc/cowrie.cfg
COPY config/userdb.txt ${COWRIE_HOME}/cowrie-git/etc/userdb.txt

# Create Cowrie data directories
RUN mkdir -p ${COWRIE_HOME}/cowrie-git/var/log/cowrie \
             ${COWRIE_HOME}/cowrie-git/var/lib/cowrie/downloads \
             ${COWRIE_HOME}/cowrie-git/var/lib/cowrie/tty \
             ${COWRIE_HOME}/cowrie-git/share/cowrie

# ---- Install SOC Dashboard Python deps ----
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY src/ ./src/
COPY pages/ ./pages/
COPY assets/ ./assets/
COPY entrypoint-combined.sh .
RUN chmod +x entrypoint-combined.sh

# Create non-root user for Streamlit
RUN groupadd -r socuser && useradd -r -g socuser -d /app socuser

# Volumes for persistent data (mount these on host for portability)
VOLUME ["/opt/cowrie/cowrie-git/var", "/app/data"]

EXPOSE 22 8501

ENTRYPOINT ["./entrypoint-combined.sh"]
