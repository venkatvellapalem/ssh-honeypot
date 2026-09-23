"""
Real-time Log Ingestion Daemon.
Continuously tails cowrie.json, normalizes event structures,
enriches threat intelligence, records full telemetry (ciphers, banners, commands),
and logs every raw event with summaries and IST timestamps.
"""

import glob
import json
import logging
import os
import sys
import time
from pathlib import Path
from datetime import datetime, timezone
from dotenv import load_dotenv

# Ensure project root is in sys.path
_cur_dir = Path(__file__).resolve().parent
_root_dir = _cur_dir.parent if _cur_dir.name in ("src", "pages") else _cur_dir
if str(_root_dir) not in sys.path:
    sys.path.insert(0, str(_root_dir))

from src.db import (
    close_session,
    get_db_connection,
    init_db,
    record_auth_attempt,
    record_command,
    record_download,
    record_raw_log,
    update_session_client_version,
    update_session_kex,
    update_session_terminal,
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
        # Pre-seed session -> IP mapping from database
        self.session_ip_map = {}
        try:
            conn = get_db_connection(self.db_path)
            cur = conn.cursor()
            rows = cur.execute("SELECT session_id, ip FROM sessions").fetchall()
            for sid, ip in rows:
                if sid and ip:
                    self.session_ip_map[sid] = ip
            conn.close()
        except Exception:
            pass

    def process_line(self, line: str) -> None:
        """Parses a single Cowrie JSON log line and updates storage/enrichment."""
        if not line.strip():
            return

        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return

        event_id = event.get("eventid", "unknown")
        session_id = event.get("session")
        src_ip = event.get("src_ip", "")
        timestamp = event.get("timestamp", datetime.now(timezone.utc).isoformat())

        if not session_id:
            return

        # Track session to IP mapping
        if src_ip:
            self.session_ip_map[session_id] = src_ip
        else:
            src_ip = self.session_ip_map.get(session_id, "")

        summary = ""

        # 1. Connection established
        if event_id == "cowrie.session.connect":
            src_port = event.get("src_port", "")
            summary = f"Inbound connection from {src_ip}:{src_port}"
            logger.info(f"New session {session_id} from {src_ip}")
            upsert_session(self.db_path, session_id, src_ip, timestamp)
            self.enricher.enrich_ip(src_ip)

        # 2. Client SSH Version Banner
        elif event_id == "cowrie.client.version":
            version = event.get("version", "")
            summary = f"SSH Client Version: {version}"
            update_session_client_version(self.db_path, session_id, version)

        # 3. Client Key Exchange & Ciphers
        elif event_id == "cowrie.client.kex":
            kex_algs = ", ".join(event.get("kexAlgs", [])[:3])
            ciphers = ", ".join(event.get("encCS", [])[:3])
            cipher_summary = f"Ciphers: {ciphers} | Kex: {kex_algs}"
            summary = f"Negotiated Handshake -> {cipher_summary}"
            update_session_kex(self.db_path, session_id, cipher_summary)

        # 4. Terminal Resize
        elif event_id == "cowrie.client.size":
            width = event.get("width", 80)
            height = event.get("height", 24)
            term_str = f"{width}x{height}"
            summary = f"Terminal Window Sized: {term_str}"
            update_session_terminal(self.db_path, session_id, term_str)

        # 5. Login Failed
        elif event_id == "cowrie.login.failed":
            username = event.get("username", "")
            password = event.get("password", "")
            summary = f"Auth Failed: {username} (password: '{password}')"
            logger.debug(f"Auth FAILED [{session_id}] {src_ip} -> {username}:{password}")
            record_auth_attempt(self.db_path, session_id, src_ip, timestamp, username, password, "FAILED")

        # 6. Login Succeeded
        elif event_id == "cowrie.login.success":
            username = event.get("username", "")
            password = event.get("password", "")
            summary = f"Auth Succeeded: {username} (password: '{password}')"
            logger.warning(f"Auth SUCCESS [{session_id}] {src_ip} -> {username}:{password}")
            record_auth_attempt(self.db_path, session_id, src_ip, timestamp, username, password, "SUCCESS")

        # 7. Command Executed
        elif event_id == "cowrie.command.input":
            cmd = event.get("input", "")
            mitre_id, mitre_tech, mitre_tactic = map_command(cmd)
            summary = f"Command: '{cmd}' [{mitre_id} - {mitre_tech}]"
            logger.info(f"Command [{session_id}] {src_ip} -> '{cmd}' [{mitre_id} - {mitre_tech}]")
            record_command(self.db_path, session_id, src_ip, timestamp, cmd, mitre_id, mitre_tech, mitre_tactic)

        # 8. Command Failed / Unknown
        elif event_id == "cowrie.command.failed":
            cmd = event.get("input", "")
            summary = f"Command Not Found / Failed: '{cmd}'"

        # 9. File Download Attempt
        elif event_id == "cowrie.session.file_download":
            url = event.get("url", "")
            sha256 = event.get("shasum", "")
            summary = f"Malware Dropper Download: {url} (SHA256: {sha256[:12]}...)"
            logger.warning(f"Payload Download [{session_id}] {src_ip} -> {url} (SHA256: {sha256})")
            record_download(self.db_path, session_id, src_ip, timestamp, url, sha256)

        # 10. Direct TCP/IP Tunnel Request (Proxy Attempt)
        elif "direct-tcpip" in event_id:
            dst_ip = event.get("dst_ip", "")
            dst_port = event.get("dst_port", "")
            summary = f"Tunnel / Proxy Request to {dst_ip}:{dst_port}"

        # 11. Session Closed
        elif event_id == "cowrie.session.closed":
            duration = float(event.get("duration", 0.0))
            summary = f"Session Terminated (Duration: {duration:.2f}s)"
            logger.info(f"Session closed {session_id} after {duration:.2f}s")
            close_session(self.db_path, session_id, timestamp, duration)

        else:
            summary = f"Event: {event_id}"

        # Record into raw_logs for comprehensive audit trail
        record_raw_log(self.db_path, session_id, timestamp, event_id, line.strip(), ip=src_ip, summary=summary)

    def backfill_historical_logs(self) -> None:
        """Parses all existing Cowrie JSON files on startup to ensure zero historical data is lost."""
        log_dir = os.path.dirname(self.log_path)
        pattern = os.path.join(log_dir, "cowrie.json*")
        found_files = sorted(glob.glob(pattern))
        if not found_files:
            return

        logger.info(f"Scanning {len(found_files)} log file(s) for historical backfill: {found_files}")

        # Fetch existing keys from raw_logs to avoid duplicate ingestion
        existing_keys = set()
        try:
            conn = get_db_connection(self.db_path)
            cur = conn.cursor()
            rows = cur.execute("SELECT session_id, timestamp, event_id FROM raw_logs").fetchall()
            for r in rows:
                existing_keys.add(f"{r[0]}_{r[1]}_{r[2]}")
            conn.close()
        except Exception as e:
            logger.warning(f"Error fetching existing raw_logs keys: {e}")

        backfilled_count = 0
        for fpath in found_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line_str = line.strip()
                        if not line_str:
                            continue
                        try:
                            ev = json.loads(line_str)
                            key = f"{ev.get('session')}_{ev.get('timestamp')}_{ev.get('eventid')}"
                            if key not in existing_keys:
                                self.process_line(line_str)
                                existing_keys.add(key)
                                backfilled_count += 1
                        except Exception:
                            continue
            except Exception as e:
                logger.error(f"Failed to read file {fpath}: {e}")

        logger.info(f"Historical backfill complete. Processed {backfilled_count} new historical events.")

    def run(self) -> None:
        """Continuously tails the Cowrie JSON log."""
        logger.info(f"Starting ingestion daemon. Monitoring: {self.log_path}")
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

        while not os.path.exists(self.log_path):
            logger.info(f"Waiting for log file {self.log_path} to be created by Cowrie...")
            time.sleep(3)

        # Run historical backfill across all cowrie.json* files first
        self.backfill_historical_logs()

        with open(self.log_path, "r", encoding="utf-8") as f:
            # Seek to end after backfill
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
