"""
Real-time Log Ingestion Daemon.
Continuously tails cowrie.json, normalizes event structures,
enriches threat intelligence, applies MITRE mappings, and updates SQLite.
"""

import json
import logging
import os
import time
from datetime import datetime
from dotenv import load_dotenv

from src.db import (
    close_session,
    init_db,
    record_auth_attempt,
    record_command,
    record_download,
    upsert_session,
)
from src.enrichment import ThreatEnricher
from src.mitre_mapper import map_command

load_dotenv()
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("honeypot.ingest")


class LogIngestionDaemon:
    def __init__(self, log_path: str = "var/log/cowrie/cowrie.json", db_path: str = "data/honeypot.db"):
        self.log_path = os.getenv("COWRIE_JSON_PATH", log_path)
        self.db_path = os.getenv("DATABASE_PATH", db_path)
        self.enricher = ThreatEnricher(db_path=self.db_path)
        init_db(self.db_path)

    def process_line(self, line: str) -> None:
        """Parses a single Cowrie JSON log line and updates storage/enrichment."""
        if not line.strip():
            return

        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return

        event_id = event.get("eventid")
        session_id = event.get("session")
        src_ip = event.get("src_ip", "")
        timestamp = event.get("timestamp", datetime.utcnow().isoformat())

        if not session_id or not src_ip:
            return

        # 1. Connection established
        if event_id == "cowrie.session.connect":
            logger.info(f"New session {session_id} from {src_ip}")
            upsert_session(self.db_path, session_id, src_ip, timestamp)
            # Background threat enrichment
            self.enricher.enrich_ip(src_ip)

        # 2. Login Failed
        elif event_id == "cowrie.login.failed":
            username = event.get("username", "")
            password = event.get("password", "")
            logger.debug(f"Auth FAILED [{session_id}] {src_ip} -> {username}:{password}")
            record_auth_attempt(self.db_path, session_id, src_ip, timestamp, username, password, "FAILED")

        # 3. Login Succeeded
        elif event_id == "cowrie.login.success":
            username = event.get("username", "")
            password = event.get("password", "")
            logger.warning(f"Auth SUCCESS [{session_id}] {src_ip} -> {username}:{password}")
            record_auth_attempt(self.db_path, session_id, src_ip, timestamp, username, password, "SUCCESS")

        # 4. Command Executed
        elif event_id == "cowrie.command.input":
            cmd = event.get("input", "")
            mitre_id, mitre_tech, mitre_tactic = map_command(cmd)
            logger.info(f"Command [{session_id}] {src_ip} -> '{cmd}' [{mitre_id} - {mitre_tech}]")
            record_command(self.db_path, session_id, src_ip, timestamp, cmd, mitre_id, mitre_tech, mitre_tactic)

        # 5. File Download Attempt
        elif event_id == "cowrie.session.file_download":
            url = event.get("url", "")
            sha256 = event.get("shasum", "")
            logger.warning(f"Payload Download [{session_id}] {src_ip} -> {url} (SHA256: {sha256})")
            record_download(self.db_path, session_id, src_ip, timestamp, url, sha256)

        # 6. Session Closed
        elif event_id == "cowrie.session.closed":
            duration = float(event.get("duration", 0.0))
            logger.info(f"Session closed {session_id} after {duration:.2f}s")
            close_session(self.db_path, session_id, timestamp, duration)

    def run(self) -> None:
        """Continuously tails the Cowrie JSON log."""
        logger.info(f"Starting ingestion daemon. Monitoring: {self.log_path}")
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

        while not os.path.exists(self.log_path):
            logger.info(f"Waiting for log file {self.log_path} to be created by Cowrie...")
            time.sleep(3)

        with open(self.log_path, "r", encoding="utf-8") as f:
            # Seek to end on startup
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if line:
                    self.process_line(line)
                else:
                    time.sleep(0.5)


if __name__ == "__main__":
    daemon = LogIngestionDaemon()
    daemon.run()
