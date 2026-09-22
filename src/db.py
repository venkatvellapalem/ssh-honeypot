"""
Database layer for SSH Honeypot & Threat Intelligence System.
Manages SQLite schemas, session tracking, threat caching, and SOC analytics.
"""

import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional


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

    # 1. Sessions table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            start_time TIMESTAMP,
            end_time TIMESTAMP,
            duration REAL DEFAULT 0,
            country TEXT,
            country_code TEXT,
            city TEXT,
            asn TEXT,
            isp TEXT,
            abuse_score INTEGER DEFAULT 0,
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
            cached_at TIMESTAMP NOT NULL
        )
    """)

    # Indexes for fast querying in SOC dashboard
    cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_ip ON sessions(ip);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_auth_ip ON auth_attempts(ip);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_commands_session ON commands(session_id);")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_auth_session ON auth_attempts(session_id);")

    conn.commit()
    conn.close()


def upsert_session(db_path: str, session_id: str, ip: str, timestamp: str) -> None:
    """Registers or updates a session connection."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO sessions (session_id, ip, start_time)
        VALUES (?, ?, ?)
        ON CONFLICT(session_id) DO UPDATE SET
            ip = excluded.ip
    """, (session_id, ip, timestamp))
    conn.commit()
    conn.close()


def close_session(db_path: str, session_id: str, end_time: str, duration: float) -> None:
    """Closes an active session with duration."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        UPDATE sessions
        SET end_time = ?, duration = ?
        WHERE session_id = ?
    """, (end_time, duration, session_id))
    conn.commit()
    conn.close()


def record_auth_attempt(db_path: str, session_id: str, ip: str, timestamp: str,
                        username: str, password: str, status: str) -> None:
    """Records authentication attempt and increments session counter."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO auth_attempts (session_id, timestamp, ip, username, password, status)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (session_id, timestamp, ip, username, password, status))

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
    """Records shell command and MITRE ATT&CK mapping."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO commands (session_id, timestamp, ip, command_text, mitre_id, mitre_technique, mitre_tactic)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (session_id, timestamp, ip, command_text, mitre_id, mitre_technique, mitre_tactic))

    cur.execute("""
        UPDATE sessions
        SET total_commands = total_commands + 1
        WHERE session_id = ?
    """, (session_id,))
    conn.commit()
    conn.close()


def record_download(db_path: str, session_id: str, ip: str, timestamp: str,
                    url: str, sha256: Optional[str] = None) -> None:
    """Records payload/dropper download."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO downloads (session_id, timestamp, ip, url, sha256)
        VALUES (?, ?, ?, ?, ?)
    """, (session_id, timestamp, ip, url, sha256))
    conn.commit()
    conn.close()


def get_cached_ip(db_path: str, ip: str) -> Optional[Dict[str, Any]]:
    """Retrieves cached threat intelligence for an IP if exists."""
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
    now_iso = datetime.utcnow().isoformat()
    cur.execute("""
        INSERT INTO ip_cache (ip, country, country_code, city, asn, isp, latitude, longitude, abuse_score, total_reports, cached_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        now_iso
    ))

    # Also backfill active sessions for this IP with geolocation and reputation
    cur.execute("""
        UPDATE sessions
        SET country = ?, country_code = ?, city = ?, asn = ?, isp = ?, abuse_score = ?
        WHERE ip = ?
    """, (
        ip_data.get("country"),
        ip_data.get("country_code"),
        ip_data.get("city"),
        ip_data.get("asn"),
        ip_data.get("isp"),
        ip_data.get("abuse_score", 0),
        ip_data.get("ip")
    ))

    conn.commit()
    conn.close()


def get_summary_stats(db_path: str) -> Dict[str, Any]:
    """Computes high-level SOC dashboard metrics."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM sessions")
    total_sessions = cur.fetchone()[0]

    cur.execute("SELECT COUNT(DISTINCT ip) FROM sessions")
    unique_ips = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM auth_attempts")
    total_logins = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM auth_attempts WHERE status = 'SUCCESS'")
    successful_logins = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM commands")
    total_commands = cur.fetchone()[0]

    cur.execute("SELECT COUNT(DISTINCT country) FROM sessions WHERE country IS NOT NULL")
    unique_countries = cur.fetchone()[0]

    conn.close()
    return {
        "total_sessions": total_sessions,
        "unique_ips": unique_ips,
        "total_logins": total_logins,
        "successful_logins": successful_logins,
        "total_commands": total_commands,
        "unique_countries": unique_countries
    }
