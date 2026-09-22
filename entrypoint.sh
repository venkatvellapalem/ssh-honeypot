#!/bin/bash
set -e

echo "[*] Initializing SQLite database schema..."
python -c "from src.db import init_db; init_db(os.getenv('DATABASE_PATH', 'data/honeypot.db'))"

echo "[*] Launching Real-Time Cowrie Log Ingestion Daemon in background..."
python -m src.ingest &
INGEST_PID=$!

echo "[*] Launching Streamlit Web SOC Dashboard on port 8501..."
streamlit run src/dashboard.py \
    --server.port 8501 \
    --server.address 0.0.0.0 \
    --server.headless true \
    --browser.gatherUsageStats false

# Trap signals and kill ingest on exit
trap "kill -9 $INGEST_PID" SIGINT SIGTERM EXIT
