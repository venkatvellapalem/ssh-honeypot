"""
Database layer for SSH Honeypot & Threat Intelligence System.
Manages SQLite schemas, session tracking, threat caching, and SOC analytics.
Includes full IST (Indian Standard Time, UTC+5:30) timestamping,
enhanced telemetry logging (client versions, ciphers, terminal sizes, raw events),
and Splunk-style time-window and entity drilldown filtering.
"""

import os
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

# Indian Standard Time (UTC+5:30)
IST = timezone(timedelta(hours=5, minutes=30))


def to_ist_str(utc_val: Optional[str] = None) -> str:
    """Converts a UTC ISO string (or current UTC) to 'YYYY-MM-DD HH:MM:SS IST'."""
    try:
        if not utc_val:
            dt = datetime.now(timezone.utc)
        elif isinstance(utc_val, (int, float)):
            dt = datetime.fromtimestamp(utc_val, tz=timezone.utc)
        else:
            # Handle ISO string with or without Z
            clean_str = str(utc_val).replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(IST).strftime("%Y-%m-%d %H:%M:%S IST")
    except Exception:
        # Fallback to current IST time
        return datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S IST")


def get_db_connection(db_path: str = "data/honeypot.db") -> sqlite3.Connection:
    """Creates directory if not existing and returns SQLite connection."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = "data/honeypot.db") -> None:
    """Initializes tables and indexes for sessions, auth attempts, commands, and IP intelligence cache."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()

    # 1. Sessions table (enriched with IST, client fingerprints, and usage info)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            start_time TIMESTAMP,
            start_time_ist TEXT,
            end_time TIMESTAMP,
            end_time_ist TEXT,
            duration REAL DEFAULT 0,
            country TEXT,
            country_code TEXT,
            city TEXT,
            asn TEXT,
            isp TEXT,
            abuse_score INTEGER DEFAULT 0,
            total_reports INTEGER DEFAULT 0,
            usage_type TEXT,
            client_version TEXT,
            ciphers TEXT,
            terminal_size TEXT,
            total_attempts INTEGER DEFAULT 0,
            total_commands INTEGER DEFAULT 0
        )
    """)

    # 2. Authentication attempts
    cur.execute("""
        CREATE TABLE IF NOT EXISTS auth_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            timestamp_ist TEXT,
            ip TEXT NOT NULL,
            username TEXT,
            password TEXT,
            status TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        )
    """)

    # 3. Executed commands
    cur.execute("""
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            timestamp_ist TEXT,
            ip TEXT NOT NULL,
            command_text TEXT NOT NULL,
            mitre_id TEXT,
            mitre_technique TEXT,
            mitre_tactic TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        )
    """)

    # 4. File downloads / Dropper capture
    cur.execute("""
        CREATE TABLE IF NOT EXISTS downloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            timestamp_ist TEXT,
            ip TEXT NOT NULL,
            url TEXT NOT NULL,
            sha256 TEXT,
            FOREIGN KEY (session_id) REFERENCES sessions(session_id)
        )
    """)

    # 5. IP Threat Intelligence Cache
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ip_cache (
            ip TEXT PRIMARY KEY,
            country TEXT,
            country_code TEXT,
            city TEXT,
            asn TEXT,
            isp TEXT,
            latitude REAL,
            longitude REAL,
            abuse_score INTEGER DEFAULT 0,
            total_reports INTEGER DEFAULT 0,
            usage_type TEXT,
            domain TEXT,
            last_reported TEXT,
            cached_at TIMESTAMP NOT NULL
        )
    """)

    # 6. Raw Event Telemetry Logs (Forensic Audit Trail)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS raw_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            timestamp_ist TEXT,
            ip TEXT,
            event_id TEXT NOT NULL,
            summary TEXT,
            raw_json TEXT NOT NULL
        )
    """)

    # Migration: Add any missing columns to existing database safely
    existing_cols = {col[1] for col in cur.execute("PRAGMA table_info(sessions)").fetchall()}
    for col_name, col_type in [
        ("start_time_ist", "TEXT"),
        ("end_time_ist", "TEXT"),
        ("total_reports", "INTEGER DEFAULT 0"),
        ("usage_type", "TEXT"),
        ("client_version", "TEXT"),
        ("ciphers", "TEXT"),
        ("terminal_size", "TEXT")
    ]:
        if col_name not in existing_cols:
            try:
                cur.execute(f"ALTER TABLE sessions ADD COLUMN {col_name} {col_type}")
            except Exception:
                pass

    auth_cols = {col[1] for col in cur.execute("PRAGMA table_info(auth_attempts)").fetchall()}
    if "timestamp_ist" not in auth_cols:
        try:
            cur.execute("ALTER TABLE auth_attempts ADD COLUMN timestamp_ist TEXT")
        except Exception:
            pass

    cmd_cols = {col[1] for col in cur.execute("PRAGMA table_info(commands)").fetchall()}
    if "timestamp_ist" not in cmd_cols:
        try:
            cur.execute("ALTER TABLE commands ADD COLUMN timestamp_ist TEXT")
        except Exception:
            pass

    raw_cols = {col[1] for col in cur.execute("PRAGMA table_info(raw_logs)").fetchall()}
    for col_name, col_type in [("timestamp_ist", "TEXT"), ("ip", "TEXT"), ("summary", "TEXT")]:
        if col_name not in raw_cols:
            try:
                cur.execute(f"ALTER TABLE raw_logs ADD COLUMN {col_name} {col_type}")
            except Exception:
                pass

    # High-performance indexes
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(ip);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_time ON sessions(start_time);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_auth_ip ON auth_attempts(ip);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_auth_user ON auth_attempts(username);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_auth_session ON auth_attempts(session_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_commands_mitre ON commands(mitre_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_raw_logs_session ON raw_logs(session_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_raw_logs_event ON raw_logs(event_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_raw_logs_time ON raw_logs(timestamp);")

    conn.commit()
    conn.close()


def upsert_session(db_path: str, session_id: str, ip: str, timestamp: str) -> None:
    """Registers or updates a session connection with IST timestamp."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    ist_time = to_ist_str(timestamp)
    cur.execute("""
        INSERT INTO sessions (session_id, ip, start_time, start_time_ist)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(session_id) DO UPDATE SET
            ip = excluded.ip,
            start_time_ist = COALESCE(sessions.start_time_ist, excluded.start_time_ist)
    """, (session_id, ip, timestamp, ist_time))
    conn.commit()
    conn.close()


def update_session_client_version(db_path: str, session_id: str, version: str) -> None:
    """Updates client SSH version banner (e.g. OpenSSH, Go, PuTTY)."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        UPDATE sessions
        SET client_version = ?
        WHERE session_id = ?
    """, (version, session_id))
    conn.commit()
    conn.close()


def update_session_kex(db_path: str, session_id: str, ciphers: str) -> None:
    """Updates negotiated SSH ciphers and key exchange suites."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        UPDATE sessions
        SET ciphers = ?
        WHERE session_id = ?
    """, (ciphers, session_id))
    conn.commit()
    conn.close()


def update_session_terminal(db_path: str, session_id: str, terminal_size: str) -> None:
    """Updates terminal dimensions from client resize events."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        UPDATE sessions
        SET terminal_size = ?
        WHERE session_id = ?
    """, (terminal_size, session_id))
    conn.commit()
    conn.close()


def close_session(db_path: str, session_id: str, end_time: str, duration: float) -> None:
    """Closes an active session with duration and IST end time."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    ist_time = to_ist_str(end_time)
    cur.execute("""
        UPDATE sessions
        SET end_time = ?, end_time_ist = ?, duration = ?
        WHERE session_id = ?
    """, (end_time, ist_time, duration, session_id))
    conn.commit()
    conn.close()


def record_auth_attempt(db_path: str, session_id: str, ip: str, timestamp: str,
                        username: str, password: str, status: str) -> None:
    """Records authentication attempt with IST timestamp."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    ist_time = to_ist_str(timestamp)
    cur.execute("""
        INSERT INTO auth_attempts (session_id, timestamp, timestamp_ist, ip, username, password, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (session_id, timestamp, ist_time, ip, username, password, status))

    cur.execute("""
        UPDATE sessions
        SET total_attempts = total_attempts + 1
        WHERE session_id = ?
    """, (session_id,))
    conn.commit()
    conn.close()


def record_command(db_path: str, session_id: str, ip: str, timestamp: str,
                   command_text: str, mitre_id: Optional[str] = None,
                   mitre_technique: Optional[str] = None, mitre_tactic: Optional[str] = None) -> None:
    """Records shell command and MITRE ATT&CK mapping with IST timestamp."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    ist_time = to_ist_str(timestamp)
    cur.execute("""
        INSERT INTO commands (session_id, timestamp, timestamp_ist, ip, command_text, mitre_id, mitre_technique, mitre_tactic)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (session_id, timestamp, ist_time, ip, command_text, mitre_id, mitre_technique, mitre_tactic))

    cur.execute("""
        UPDATE sessions
        SET total_commands = total_commands + 1
        WHERE session_id = ?
    """, (session_id,))
    conn.commit()
    conn.close()


def record_download(db_path: str, session_id: str, ip: str, timestamp: str,
                    url: str, sha256: Optional[str] = None) -> None:
    """Records payload/dropper download with IST timestamp."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    ist_time = to_ist_str(timestamp)
    cur.execute("""
        INSERT INTO downloads (session_id, timestamp, timestamp_ist, ip, url, sha256)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (session_id, timestamp, ist_time, ip, url, sha256))
    conn.commit()
    conn.close()


def record_raw_log(db_path: str, session_id: str, timestamp: str, event_id: str, raw_json: str,
                   ip: Optional[str] = None, summary: Optional[str] = None) -> None:
    """Stores exact unparsed raw JSON telemetry for forensic investigation."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    ist_time = to_ist_str(timestamp)
    cur.execute("""
        INSERT INTO raw_logs (session_id, timestamp, timestamp_ist, ip, event_id, summary, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (session_id, timestamp, ist_time, ip, event_id, summary, raw_json))
    conn.commit()
    conn.close()


def get_cached_ip(db_path: str, ip: str) -> Optional[Dict[str, Any]]:
    """Retrieves cached threat intelligence for an IP if exists."""
    init_db(db_path)
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM ip_cache WHERE ip = ?", (ip,))
    row = cur.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None


def set_cached_ip(db_path: str, ip_data: Dict[str, Any]) -> None:
    """Saves threat intelligence enrichment to cache and updates sessions table."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    now_iso = datetime.now(timezone.utc).isoformat()
    cur.execute("""
        INSERT INTO ip_cache (ip, country, country_code, city, asn, isp, latitude, longitude,
                             abuse_score, total_reports, usage_type, domain, last_reported, cached_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip) DO UPDATE SET
            country = excluded.country,
            country_code = excluded.country_code,
            city = excluded.city,
            asn = excluded.asn,
            isp = excluded.isp,
            latitude = excluded.latitude,
            longitude = excluded.longitude,
            abuse_score = excluded.abuse_score,
            total_reports = excluded.total_reports,
            usage_type = excluded.usage_type,
            domain = excluded.domain,
            last_reported = excluded.last_reported,
            cached_at = excluded.cached_at
    """, (
        ip_data.get("ip"),
        ip_data.get("country"),
        ip_data.get("country_code"),
        ip_data.get("city"),
        ip_data.get("asn"),
        ip_data.get("isp"),
        ip_data.get("latitude"),
        ip_data.get("longitude"),
        ip_data.get("abuse_score", 0),
        ip_data.get("total_reports", 0),
        ip_data.get("usage_type", ""),
        ip_data.get("domain", ""),
        ip_data.get("last_reported", ""),
        now_iso
    ))

    # Backfill sessions for this IP with geolocation and reputation
    cur.execute("""
        UPDATE sessions
        SET country = ?, country_code = ?, city = ?, asn = ?, isp = ?,
            abuse_score = ?, total_reports = ?, usage_type = ?
        WHERE ip = ?
    """, (
        ip_data.get("country"),
        ip_data.get("country_code"),
        ip_data.get("city"),
        ip_data.get("asn"),
        ip_data.get("isp"),
        ip_data.get("abuse_score", 0),
        ip_data.get("total_reports", 0),
        ip_data.get("usage_type", ""),
        ip_data.get("ip")
    ))

    conn.commit()
    conn.close()


def build_time_filter(time_range: str, col_name: str = "timestamp") -> Tuple[str, List[Any]]:
    """Builds SQL condition for Splunk-style time ranges."""
    if not time_range or time_range == "All Time":
        return "", []

    now = datetime.now(timezone.utc)
    delta_map = {
        "Last 15 Minutes": timedelta(minutes=15),
        "Last 1 Hour": timedelta(hours=1),
        "Last 4 Hours": timedelta(hours=4),
        "Last 24 Hours": timedelta(hours=24),
        "Last 7 Days": timedelta(days=7),
    }

    delta = delta_map.get(time_range)
    if not delta:
        return "", []

    cutoff = (now - delta).isoformat()
    return f"{col_name} >= ?", [cutoff]
