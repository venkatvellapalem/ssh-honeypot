#!/bin/bash
set -e

export PYTHONPATH="/app:${PYTHONPATH}"
COWRIE_HOME="${COWRIE_HOME:-/opt/cowrie}"
COWRIE_VENV="${COWRIE_VENV:-/opt/cowrie/cowrie-env}"
DB_PATH="${DATABASE_PATH:-/app/data/honeypot.db}"
COWRIE_LOG="${COWRIE_JSON_PATH:-/opt/cowrie/cowrie-git/var/log/cowrie/cowrie.json}"

# Ensure data & log dirs exist with correct permissions
mkdir -p "$(dirname "$DB_PATH")"
mkdir -p "$(dirname "$COWRIE_LOG")"
mkdir -p "${COWRIE_HOME}/cowrie-git/var/lib/cowrie/downloads"
mkdir -p "${COWRIE_HOME}/cowrie-git/var/lib/cowrie/tty"
mkdir -p "${COWRIE_HOME}/cowrie-git/var/run"

echo "============================================="
echo "  SSH Honeypot + SOC Dashboard (Combined)"
echo "  Trap Port: 22 | Dashboard: 8501"
echo "============================================="

echo "[*] Initializing SQLite database schema..."
python -c "import os; from src.db import init_db; init_db('${DB_PATH}')"

echo "[*] Starting Cowrie SSH Honeypot on port 22 (foreground)..."
cd "${COWRIE_HOME}/cowrie-git"
${COWRIE_VENV}/bin/twistd -n -l ${COWRIE_HOME}/cowrie-git/var/log/cowrie/cowrie.log cowrie &
COWRIE_PID=$!

# Wait for Cowrie to start writing its log
for i in $(seq 1 20); do
    if [ -f "$COWRIE_LOG" ] && [ -s "$COWRIE_LOG" ]; then
        echo "[+] Cowrie started and logging to ${COWRIE_LOG}"
        break
    fi
    sleep 1
done

echo "[*] Starting Real-Time Log Ingestion Daemon..."
cd /app
python -m src.ingest &
INGEST_PID=$!

echo "[*] Starting Streamlit SOC Dashboard on port 8501..."
streamlit run src/dashboard.py \
    --server.port 8501 \
    --server.address 0.0.0.0 \
    --server.headless true \
    --browser.gatherUsageStats false &
STREAMLIT_PID=$!

echo "[+] All services started. Honeypot is LIVE."

# Graceful shutdown
cleanup() {
    echo "[*] Shutting down services..."
    kill -TERM $STREAMLIT_PID $INGEST_PID $COWRIE_PID 2>/dev/null || true
    wait $STREAMLIT_PID $INGEST_PID $COWRIE_PID 2>/dev/null || true
    exit 0
}
trap cleanup SIGINT SIGTERM

# Wait for any child to exit
wait -n $COWRIE_PID $INGEST_PID $STREAMLIT_PID 2>/dev/null || true
cleanup
