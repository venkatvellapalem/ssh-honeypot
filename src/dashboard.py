"""
BCSSL Threat Intelligence & SSH Honeypot SOC Dashboard.
Enterprise-grade dark theme, Splunk-style time filtering, entity drilldowns,
sub-2-second live streaming, IST timestamps, and rich forensic telemetry.
"""

import json
import os
import sys
from pathlib import Path
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from PIL import Image

# Ensure project root is in sys.path
_cur_dir = Path(__file__).resolve().parent
_root_dir = _cur_dir.parent if _cur_dir.name in ("src", "pages") else _cur_dir
if str(_root_dir) not in sys.path:
    sys.path.insert(0, str(_root_dir))

from src.db import build_time_filter

load_dotenv()
DB_PATH = os.getenv("DATABASE_PATH", "data/honeypot.db")

# Robust path resolution for BCSS logo
FAVICON_PATH = None
for candidate in [
    os.path.join(str(_root_dir), "assets", "bcss_logo.png"),
    "assets/bcss_logo.png",
    "/app/assets/bcss_logo.png"
]:
    if os.path.exists(candidate):
        FAVICON_PATH = candidate
        break

favicon_img = Image.open(FAVICON_PATH) if (FAVICON_PATH and os.path.exists(FAVICON_PATH)) else None

st.set_page_config(
    page_title="BCSSL Threat Intelligence & SSH Honeypot SOC",
    page_icon=favicon_img or "BCSS",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- ADVANCED ULTRA-CLEAN ENTERPRISE SOC CSS ---
st.markdown("""
<style>
    /* Global Background & Typography */
    .stApp {
        background-color: #060913;
        color: #e2e8f0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }

    /* Top Header Banner */
    .soc-header-card {
        background: linear-gradient(135deg, #0b1329 0%, #0d1b3a 100%);
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 16px 20px;
        margin-bottom: 20px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.5);
    }
    .soc-title {
        font-size: 22px;
        font-weight: 800;
        color: #f8fafc;
        letter-spacing: -0.02em;
        margin: 0;
    }
    .soc-subtitle {
        font-size: 12px;
        color: #94a3b8;
        margin-top: 3px;
    }
    .soc-badge-live {
        display: inline-block;
        padding: 4px 10px;
        background-color: rgba(16, 185, 129, 0.15);
        border: 1px solid #10b981;
        border-radius: 20px;
        font-size: 11px;
        font-weight: 700;
        color: #34d399;
        text-transform: uppercase;
        letter-spacing: 0.08em;
    }

    /* Top Hero Section: Forensic Identity HUD Cards */
    .hero-container {
        background: #0b1120;
        border: 1px solid #1e2e4a;
        border-radius: 10px;
        padding: 18px 20px;
        margin-bottom: 24px;
        box-shadow: 0 10px 30px -5px rgba(0, 0, 0, 0.6);
    }
    .hero-title-bar {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 14px;
        border-bottom: 1px solid #1e293b;
        padding-bottom: 10px;
    }
    .hero-title {
        font-size: 15px;
        font-weight: 700;
        color: #38bdf8;
        text-transform: uppercase;
        letter-spacing: 0.06em;
    }

    .hud-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 14px;
        margin-bottom: 16px;
    }
    .hud-card {
        background: #0f172a;
        border: 1px solid #24344d;
        border-radius: 8px;
        padding: 14px;
        position: relative;
        overflow: hidden;
    }
    .hud-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 3px;
    }
    .hud-card-id::before { background: #38bdf8; }
    .hud-card-net::before { background: #818cf8; }
    .hud-card-threat::before { background: #f43f5e; }
    .hud-card-finger::before { background: #06b6d4; }

    .hud-label {
        font-size: 11px;
        font-weight: 700;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        margin-bottom: 6px;
    }
    .hud-value-ip {
        font-size: 17px;
        font-weight: 800;
        color: #38bdf8;
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }
    .hud-sub {
        font-size: 12px;
        color: #cbd5e1;
        margin-top: 4px;
    }
    .hud-meta {
        font-size: 11px;
        color: #64748b;
        margin-top: 2px;
    }

    /* Structured Storage Paths Grid */
    .paths-container {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 12px;
        margin-bottom: 22px;
    }
    .path-card {
        background-color: #0b1120;
        border: 1px solid #1e293b;
        border-top: 2px solid #38bdf8;
        border-radius: 6px;
        padding: 12px 14px;
    }
    .path-card-title {
        font-size: 11px;
        font-weight: 700;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 3px;
    }
    .path-card-purpose {
        font-size: 12px;
        font-weight: 600;
        color: #38bdf8;
        margin-bottom: 5px;
    }
    .path-card-loc {
        font-size: 11px;
        color: #cbd5e1;
        font-family: ui-monospace, Menlo, Consolas, monospace;
        word-break: break-all;
        background-color: #060913;
        padding: 4px 6px;
        border-radius: 4px;
        border: 1px solid #1e293b;
    }

    /* Executive KPI Metric Cards */
    .kpi-card {
        background-color: #0b1120;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 14px 16px;
        margin-bottom: 12px;
    }
    .kpi-title {
        font-size: 11px;
        font-weight: 700;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        margin-bottom: 4px;
    }
    .kpi-number {
        font-size: 26px;
        font-weight: 800;
        color: #f8fafc;
        letter-spacing: -0.02em;
    }
    .kpi-sub {
        font-size: 11px;
        color: #64748b;
        margin-top: 2px;
    }

    /* Filter Toolbar Container */
    .toolbar-card {
        background-color: #0b1120;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 12px 16px;
        margin-bottom: 20px;
    }

    /* Drilldown Banner */
    .drilldown-banner {
        background-color: #082f49;
        border: 1px solid #0284c7;
        border-radius: 6px;
        padding: 10px 16px;
        margin-bottom: 16px;
        color: #bae6fd;
        font-size: 13px;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)


def get_connection():
    if not os.path.exists(DB_PATH):
        return None
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def clean_val(val, fallback="Not Detected"):
    """Sanitizes database values to eliminate ugly 'nan' or 'None' strings."""
    if val is None or pd.isna(val):
        return fallback
    s = str(val).strip()
    if not s or s.lower() in ("nan", "none", "unknown", "null", "undefined"):
        return fallback
    return s


# Initialize session state for drilldowns and filters
if "drilldown_ip" not in st.session_state:
    st.session_state["drilldown_ip"] = None
if "drilldown_user" not in st.session_state:
    st.session_state["drilldown_user"] = None
if "drilldown_mitre" not in st.session_state:
    st.session_state["drilldown_mitre"] = None

# --- SIDEBAR BRANDING & CONTROLS ---
if FAVICON_PATH and os.path.exists(FAVICON_PATH):
    st.sidebar.image(FAVICON_PATH, width=190)

st.sidebar.title("BCSSL SOC Navigation")
st.sidebar.caption("Blue Cloud Softech Solutions Ltd.")

live_stream = st.sidebar.checkbox("Live Stream (Auto-refresh < 2s)", value=False)
st.sidebar.markdown("---")

st.sidebar.subheader("Operational Endpoints")
st.sidebar.markdown("""
* **Honeypot Trap Port**: `18.60.33.150:22`
* **Host Admin SSH**: `18.60.33.150:22222`
* **Log Explorer**: `/logs` (Full Event Feed)
""")

st.sidebar.markdown("---")
st.sidebar.subheader("Threat Intelligence Engine")
api_present = bool(os.getenv("ABUSEIPDB_API_KEY"))
vt_present = bool(os.getenv("VIRUSTOTAL_API_KEY"))
st.sidebar.markdown(f"**AbuseIPDB API:** {'Active (Online)' if api_present else 'Missing Key'}")
st.sidebar.markdown(f"**VirusTotal API v3:** {'Active (Online)' if vt_present else 'Missing Key'}")
st.sidebar.markdown("**GeoIP Provider:** ip-api.com (Active)")
st.sidebar.markdown("**Timezone:** Indian Standard Time (IST, UTC+5:30)")

conn = get_connection()
if conn is None:
    st.warning("Database not initialized yet. Waiting for honeypot events...")
    st.stop()

# --- TOP HEADER BAR ---
col_head1, col_head2 = st.columns([3.5, 1.5])
with col_head1:
    st.markdown("""
    <div style="padding-top: 4px; margin-bottom: 12px;">
        <div class="soc-title">BCSSL Threat Intelligence & SSH Honeypot SOC</div>
        <div class="soc-subtitle">Autonomous Intrusion Capture, Dual Threat Reputation (AbuseIPDB + VirusTotal), and MITRE ATT&CK Behavioral Telemetry</div>
    </div>
    """, unsafe_allow_html=True)
with col_head2:
    st.markdown("""
    <div style="text-align: right; padding-top: 8px;">
        <span class="soc-badge-live">TRAP ACTIVE &bull; PORT 22</span>
    </div>
    """, unsafe_allow_html=True)

# --- SPLUNK-STYLE TIME RANGE FILTER & DRILLDOWN TOOLBAR ---
st.markdown('<div class="toolbar-card">', unsafe_allow_html=True)
filter_col1, filter_col2 = st.columns([2.5, 1.5])

with filter_col1:
    time_range = st.selectbox(
        "Time Range Filter (Splunk Window)",
        options=["Last 15 Minutes", "Last 1 Hour", "Last 4 Hours", "Last 24 Hours", "Last 7 Days", "All Time"],
        index=5
    )

with filter_col2:
    if st.session_state["drilldown_ip"] or st.session_state["drilldown_user"] or st.session_state["drilldown_mitre"]:
        st.write("")
        if st.button("Clear Active Drilldowns"):
            st.session_state["drilldown_ip"] = None
            st.session_state["drilldown_user"] = None
            st.session_state["drilldown_mitre"] = None
            st.rerun()
st.markdown('</div>', unsafe_allow_html=True)

# Construct base SQL time filter
time_sql, time_params = build_time_filter(time_range, col_name="start_time")
time_where = f"WHERE {time_sql}" if time_sql else ""

# Apply drilldowns to queries
drill_where = []
drill_params = list(time_params)

if time_sql:
    drill_where.append(time_sql)

if st.session_state["drilldown_ip"]:
    drill_where.append("ip = ?")
    drill_params.append(st.session_state["drilldown_ip"])

combined_where = ("WHERE " + " AND ".join(drill_where)) if drill_where else ""

# Display active drilldown banner if set
if st.session_state["drilldown_ip"] or st.session_state["drilldown_user"] or st.session_state["drilldown_mitre"]:
    active_filters = []
    if st.session_state["drilldown_ip"]:
        active_filters.append(f"Attacker IP = {st.session_state['drilldown_ip']}")
    if st.session_state["drilldown_user"]:
        active_filters.append(f"Target Username = {st.session_state['drilldown_user']}")
    if st.session_state["drilldown_mitre"]:
        active_filters.append(f"MITRE Technique = {st.session_state['drilldown_mitre']}")
    st.markdown(f'<div class="drilldown-banner">Active Forensic Drilldown: {" | ".join(active_filters)}</div>', unsafe_allow_html=True)

# ==============================================================================
# SECTION 1 (TOP HERO SECTION): ATTACKER SESSION DEEP-DIVE & FORENSIC TELEMETRY
# ==============================================================================
session_list = pd.read_sql_query(f"""
    SELECT s.session_id, s.ip, s.country, s.city, s.start_time, s.start_time_ist, 
           s.duration, s.abuse_score, s.total_reports, s.usage_type, s.asn, s.isp,
           s.client_version, s.ciphers, s.terminal_size,
           COALESCE(s.vt_malicious, 0) as vt_malicious,
           COALESCE(s.vt_suspicious, 0) as vt_suspicious,
           COALESCE(s.vt_reputation, 0) as vt_reputation
    FROM sessions s 
    {combined_where}
    ORDER BY s.start_time DESC 
    LIMIT 100
""", conn, params=drill_params)

st.markdown('<div class="hero-container">', unsafe_allow_html=True)
st.markdown('<div class="hero-title-bar"><span class="hero-title">Attacker Session Deep-Dive & Forensic Inspection</span><span style="font-size:11px;color:#94a3b8;">Real-time telemetry, client banner fingerprinting, and keystroke replay</span></div>', unsafe_allow_html=True)

if not session_list.empty:
    def format_session_label(sid):
        row = session_list[session_list["session_id"] == sid].iloc[0]
        country = clean_val(row["country"], "Unknown")
        t_ist = clean_val(row["start_time_ist"], row["start_time"])
        abuse = row["abuse_score"] or 0
        vt_mal = int(row["vt_malicious"] or 0)
        vt_txt = f" | VT: {vt_mal} Malicious" if vt_mal > 0 else ""
        return f"[{sid}] | IP: {row['ip']} ({country}) | {t_ist} | Abuse: {abuse}%{vt_txt}"

    selected_session = st.selectbox(
        "Select Attacker Session to Inspect:",
        options=session_list["session_id"].tolist(),
        format_func=format_session_label
    )

    if selected_session:
        s_meta = session_list[session_list["session_id"] == selected_session].iloc[0]
        
        # 4 High-Impact HUD Identity Cards
        info1, info2, info3, info4 = st.columns(4)
        
        with info1:
            loc_str = f"{clean_val(s_meta['city'], 'Unknown')}, {clean_val(s_meta['country'], 'Unknown')}"
            st.markdown(f"""
            <div class="hud-card hud-card-id">
                <div class="hud-label">Attacker Identity</div>
                <div class="hud-value-ip">{s_meta['ip']}</div>
                <div class="hud-sub">Location: {loc_str}</div>
                <div class="hud-meta">Session ID: {s_meta['session_id']}</div>
            </div>
            """, unsafe_allow_html=True)
            if st.button(f"Drill Down on IP", key="drill_ip_hero_btn"):
                st.session_state["drilldown_ip"] = s_meta["ip"]
                st.rerun()

        with info2:
            st.markdown(f"""
            <div class="hud-card hud-card-net">
                <div class="hud-label">Network & ISP Infrastructure</div>
                <div style="font-size: 13px; font-weight: 700; color: #f8fafc;">{clean_val(s_meta['isp'], 'Unknown ISP')}</div>
                <div class="hud-sub">ASN: {clean_val(s_meta['asn'], 'AS0 / Unknown')}</div>
                <div class="hud-meta">Type: {clean_val(s_meta['usage_type'], 'Data Center / Transit')}</div>
            </div>
            """, unsafe_allow_html=True)

        with info3:
            abuse_val = int(s_meta['abuse_score'] or 0)
            abuse_color = "#f43f5e" if abuse_val > 50 else ("#f59e0b" if abuse_val > 20 else "#10b981")
            vt_mal = int(s_meta['vt_malicious'] or 0)
            vt_susp = int(s_meta['vt_suspicious'] or 0)
            vt_color = "#f43f5e" if vt_mal > 0 else "#10b981"
            dur_val = float(s_meta['duration'] or 0.0)
            st.markdown(f"""
            <div class="hud-card hud-card-threat">
                <div class="hud-label">Threat Reputation Scorecard</div>
                <div style="font-size: 14px; font-weight: 800; color: {abuse_color};">AbuseIPDB: {abuse_val}% Abuse Score</div>
                <div style="font-size: 12px; font-weight: 700; color: {vt_color}; margin-top: 3px;">
                    VirusTotal: {vt_mal} Malicious / {vt_susp} Suspicious
                </div>
                <div style="font-size: 11px; margin-top: 4px;">
                    <a href="https://www.virustotal.com/gui/ip-address/{s_meta['ip']}" target="_blank" style="color: #38bdf8; text-decoration: underline;">Inspect on VirusTotal &rarr;</a>
                </div>
                <div class="hud-meta">Reports: {int(s_meta['total_reports'] or 0):,} | Duration: {dur_val:.1f}s</div>
            </div>
            """, unsafe_allow_html=True)

        with info4:
            client_v = clean_val(s_meta['client_version'], 'SSH-2.0-Generic (Not Negotiated)')
            term_s = clean_val(s_meta['terminal_size'], '80x24 (Default)')
            ciphers_s = clean_val(s_meta['ciphers'], 'Standard Cipher Suite')
            st.markdown(f"""
            <div class="hud-card hud-card-finger">
                <div class="hud-label">Client Fingerprint</div>
                <div style="font-size: 12px; font-weight: 700; color: #38bdf8; font-family: ui-monospace, Menlo, monospace;">{client_v}</div>
                <div class="hud-sub">Terminal: {term_s}</div>
                <div class="hud-meta">Handshake: {ciphers_s}</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Tabs for Session Telemetry Investigation
        tab_keystrokes, tab_auth, tab_raw_json = st.tabs([
            "Keystroke Log & MITRE TTPs (IST)",
            "Authentication Sequence (IST)",
            "Underlying Raw JSON Telemetry Log"
        ])

        with tab_keystrokes:
            cmds = pd.read_sql_query("""
                SELECT timestamp_ist as "Timestamp (IST)", 
                       command_text as "Command Executed", 
                       mitre_id as "Technique ID", 
                       mitre_technique as "Technique Name", 
                       mitre_tactic as "Tactic"
                FROM commands 
                WHERE session_id = ? 
                ORDER BY id ASC
            """, conn, params=(selected_session,))
            if not cmds.empty:
                st.dataframe(cmds, use_container_width=True)
            else:
                st.info("No interactive shell commands executed in this session (connection probe or authentication failure).")

        with tab_auth:
            auths = pd.read_sql_query("""
                SELECT timestamp_ist as "Timestamp (IST)", 
                       username as "Username Tried", 
                       password as "Password Tried", 
                       status as "Auth Status"
                FROM auth_attempts 
                WHERE session_id = ? 
                ORDER BY id ASC
            """, conn, params=(selected_session,))
            if not auths.empty:
                st.dataframe(auths, use_container_width=True)
            else:
                st.caption("No authentication credentials attempted in this session.")

        with tab_raw_json:
            raw_logs = pd.read_sql_query("""
                SELECT id, timestamp_ist, event_category, summary, raw_json
                FROM raw_logs 
                WHERE session_id = ? 
                ORDER BY id ASC
            """, conn, params=(selected_session,))

            if not raw_logs.empty:
                for idx, row in raw_logs.iterrows():
                    with st.expander(f"Event #{row['id']} &bull; {row['timestamp_ist']} &bull; {row['event_category']} &bull; {row['summary']}"):
                        try:
                            parsed_json = json.loads(row["raw_json"])
                            st.json(parsed_json)
                        except Exception:
                            st.code(row["raw_json"], language="json")
            else:
                st.caption("No raw JSON events found for this session.")
else:
    st.info("No attack sessions recorded within the selected time window.")

st.markdown('</div>', unsafe_allow_html=True)

# ==============================================================================
# SECTION 2: FORENSIC STORAGE PATHS (SCREENSHOT 1 REDESIGNED)
# ==============================================================================
st.markdown("""
<div class="paths-container">
    <div class="path-card">
        <div class="path-card-title">Event Stream</div>
        <div class="path-card-purpose">Raw Cowrie JSON Audit Trail</div>
        <div class="path-card-loc">/home/ubuntu/ssh-honeypot/var/log/cowrie/cowrie.json</div>
    </div>
    <div class="path-card">
        <div class="path-card-title">Terminal Playback</div>
        <div class="path-card-purpose">TTY Keystroke Recordings</div>
        <div class="path-card-loc">/home/ubuntu/ssh-honeypot/var/lib/cowrie/tty/*.log</div>
    </div>
    <div class="path-card">
        <div class="path-card-title">Malware Forensics</div>
        <div class="path-card-purpose">Payloads & Droppers (SHA256)</div>
        <div class="path-card-loc">/home/ubuntu/ssh-honeypot/var/lib/cowrie/downloads/</div>
    </div>
    <div class="path-card">
        <div class="path-card-title">SOC Datastore</div>
        <div class="path-card-purpose">Analytical SQLite Database</div>
        <div class="path-card-loc">/home/ubuntu/ssh-honeypot/data/honeypot.db</div>
    </div>
</div>
""", unsafe_allow_html=True)

# ==============================================================================
# SECTION 3: TOP KPI EXECUTIVE METRICS
# ==============================================================================
cur = conn.cursor()
try:
    total_sessions = cur.execute(f"SELECT count(*) FROM sessions {combined_where}", drill_params).fetchone()[0]
    unique_ips = cur.execute(f"SELECT count(DISTINCT ip) FROM sessions {combined_where}", drill_params).fetchone()[0]
    
    # Auth counts with drilldown
    auth_where = []
    auth_params = []
    auth_time_sql, auth_time_params = build_time_filter(time_range, col_name="timestamp")
    if auth_time_sql:
        auth_where.append(auth_time_sql)
        auth_params.extend(auth_time_params)
    if st.session_state["drilldown_ip"]:
        auth_where.append("ip = ?")
        auth_params.append(st.session_state["drilldown_ip"])
    if st.session_state["drilldown_user"]:
        auth_where.append("username = ?")
        auth_params.append(st.session_state["drilldown_user"])
    auth_where_sql = ("WHERE " + " AND ".join(auth_where)) if auth_where else ""

    total_auth = cur.execute(f"SELECT count(*) FROM auth_attempts {auth_where_sql}", auth_params).fetchone()[0]
    success_auth = cur.execute(f"SELECT count(*) FROM auth_attempts {auth_where_sql} {'AND' if auth_where_sql else 'WHERE'} status = 'SUCCESS'", auth_params).fetchone()[0]

    # Command counts
    cmd_where = []
    cmd_params = []
    cmd_time_sql, cmd_time_params = build_time_filter(time_range, col_name="timestamp")
    if cmd_time_sql:
        cmd_where.append(cmd_time_sql)
        cmd_params.extend(cmd_time_params)
    if st.session_state["drilldown_ip"]:
        cmd_where.append("ip = ?")
        cmd_params.append(st.session_state["drilldown_ip"])
    if st.session_state["drilldown_mitre"]:
        cmd_where.append("mitre_id = ?")
        cmd_params.append(st.session_state["drilldown_mitre"])
    cmd_where_sql = ("WHERE " + " AND ".join(cmd_where)) if cmd_where else ""

    total_cmds = cur.execute(f"SELECT count(*) FROM commands {cmd_where_sql}", cmd_params).fetchone()[0]
    total_countries = cur.execute(f"SELECT count(DISTINCT country) FROM sessions {combined_where} {'AND' if combined_where else 'WHERE'} country IS NOT NULL AND country != 'Unknown' AND country != ''", drill_params).fetchone()[0]
except Exception as e:
    st.error(f"Database query error: {e}")
    st.stop()

col_kpi1, col_kpi2, col_kpi3, col_kpi4, col_kpi5, col_kpi6 = st.columns(6)
with col_kpi1:
    st.markdown(f'<div class="kpi-card"><div class="kpi-title">Inbound Sessions</div><div class="kpi-number">{total_sessions:,}</div><div class="kpi-sub">Network probes</div></div>', unsafe_allow_html=True)
with col_kpi2:
    st.markdown(f'<div class="kpi-card"><div class="kpi-title">Attacker Hosts</div><div class="kpi-number">{unique_ips:,}</div><div class="kpi-sub">Unique source IPs</div></div>', unsafe_allow_html=True)
with col_kpi3:
    st.markdown(f'<div class="kpi-card"><div class="kpi-title">Brute-Force Trials</div><div class="kpi-number">{total_auth:,}</div><div class="kpi-sub">Password attempts</div></div>', unsafe_allow_html=True)
with col_kpi4:
    st.markdown(f'<div class="kpi-card"><div class="kpi-title">Breached Shells</div><div class="kpi-number" style="color: #f43f5e;">{success_auth:,}</div><div class="kpi-sub">Interactive logins</div></div>', unsafe_allow_html=True)
with col_kpi5:
    st.markdown(f'<div class="kpi-card"><div class="kpi-title">Commands Captured</div><div class="kpi-number" style="color: #38bdf8;">{total_cmds:,}</div><div class="kpi-sub">Executed keystrokes</div></div>', unsafe_allow_html=True)
with col_kpi6:
    st.markdown(f'<div class="kpi-card"><div class="kpi-title">Source Nations</div><div class="kpi-number">{total_countries:,}</div><div class="kpi-sub">Geopolitical origins</div></div>', unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# ==============================================================================
# SECTION 4: GEOLOCATION MAP & TOP NATIONS
# ==============================================================================
st.subheader("Attacker Geolocation & Threat Distribution")

geo_df = pd.read_sql_query(f"""
    SELECT 
        s.ip, 
        s.country, 
        s.city, 
        s.asn, 
        s.abuse_score, 
        c.latitude, 
        c.longitude,
        COUNT(s.session_id) as attack_count
    FROM sessions s
    LEFT JOIN ip_cache c ON s.ip = c.ip
    {combined_where}
    GROUP BY s.ip
    HAVING c.latitude IS NOT NULL AND c.latitude != 0.0
""", conn, params=drill_params)

col_map, col_country = st.columns([2.6, 1.4])

with col_map:
    if not geo_df.empty:
        fig_map = px.scatter_geo(
            geo_df,
            lat="latitude",
            lon="longitude",
            hover_name="ip",
            size="attack_count",
            color="abuse_score",
            color_continuous_scale="Reds",
            range_color=[0, 100],
            projection="natural earth",
            hover_data={"country": True, "city": True, "asn": True, "abuse_score": True, "attack_count": True},
            template="plotly_dark"
        )
        fig_map.update_geos(showcountries=True, countrycolor="#334155", showocean=True, oceancolor="#070d1e", bgcolor="#060913")
        fig_map.update_layout(margin={"r": 0, "t": 15, "l": 0, "b": 0}, height=380, paper_bgcolor="#060913")
        st.plotly_chart(fig_map, use_container_width=True)
    else:
        st.info("No geographic coordinates captured within selected filter.")

with col_country:
    country_df = pd.read_sql_query(f"""
        SELECT country, COUNT(*) as sessions 
        FROM sessions 
        {combined_where} {'AND' if combined_where else 'WHERE'} country IS NOT NULL AND country != '' 
        GROUP BY country 
        ORDER BY sessions DESC 
        LIMIT 6
    """, conn, params=drill_params)
    if not country_df.empty:
        fig_country = px.bar(
            country_df, 
            x="sessions", 
            y="country", 
            orientation="h",
            title="Top Attacker Nations",
            color="sessions",
            color_continuous_scale="Blues",
            template="plotly_dark"
        )
        fig_country.update_layout(yaxis={'categoryorder': 'total ascending'}, height=380, showlegend=False, margin={"t": 35, "b": 0}, paper_bgcolor="#060913", plot_bgcolor="#060913")
        st.plotly_chart(fig_country, use_container_width=True)
    else:
        st.caption("No country statistics available for this window.")

st.markdown("<br>", unsafe_allow_html=True)

# ==============================================================================
# SECTION 5: AUTHENTICATION SPRAY & CREDENTIAL HARVESTING
# ==============================================================================
st.subheader("Authentication Telemetry & Password Spray Analysis")
st.caption("Select any username below to drill down into sessions targeted at that account.")

col_user, col_pass, col_ratio = st.columns([1.5, 1.5, 1])

with col_user:
    user_df = pd.read_sql_query(f"""
        SELECT username, count(*) as count 
        FROM auth_attempts 
        {auth_where_sql} {'AND' if auth_where_sql else 'WHERE'} username IS NOT NULL AND username != '' 
        GROUP BY username 
        ORDER BY count DESC 
        LIMIT 8
    """, conn, params=auth_params)
    if not user_df.empty:
        fig_user = px.bar(user_df, x="username", y="count", title="Top Targeted Usernames", color="count",
                          color_continuous_scale="Tealgrn", template="plotly_dark")
        fig_user.update_layout(height=280, showlegend=False, margin={"t": 30, "b": 0}, paper_bgcolor="#060913", plot_bgcolor="#060913")
        st.plotly_chart(fig_user, use_container_width=True)

        user_list = ["(None)"] + user_df["username"].tolist()
        selected_u = st.selectbox("Drill down by Username:", options=user_list, index=0)
        if selected_u != "(None)" and selected_u != st.session_state["drilldown_user"]:
            st.session_state["drilldown_user"] = selected_u
            st.rerun()
    else:
        st.caption("No authentication records in this time range.")

with col_pass:
    pass_df = pd.read_sql_query(f"""
        SELECT password, count(*) as count 
        FROM auth_attempts 
        {auth_where_sql} {'AND' if auth_where_sql else 'WHERE'} password IS NOT NULL AND password != '' 
        GROUP BY password 
        ORDER BY count DESC 
        LIMIT 8
    """, conn, params=auth_params)
    if not pass_df.empty:
        fig_pass = px.bar(pass_df, x="password", y="count", title="Top Attempted Passwords", color="count",
                          color_continuous_scale="Purp", template="plotly_dark")
        fig_pass.update_layout(height=280, showlegend=False, margin={"t": 30, "b": 0}, paper_bgcolor="#060913", plot_bgcolor="#060913")
        st.plotly_chart(fig_pass, use_container_width=True)
    else:
        st.caption("No passwords captured in this time range.")

with col_ratio:
    ratio_df = pd.read_sql_query(f"""
        SELECT status, count(*) as count 
        FROM auth_attempts 
        {auth_where_sql}
        GROUP BY status
    """, conn, params=auth_params)
    if not ratio_df.empty:
        fig_ratio = px.pie(ratio_df, names="status", values="count", title="Auth Outcome Ratios",
                           color="status", color_discrete_map={"FAILED": "#ef4444", "SUCCESS": "#10b981"},
                           hole=0.45, template="plotly_dark")
        fig_ratio.update_layout(height=280, margin={"t": 30, "b": 0}, paper_bgcolor="#060913")
        st.plotly_chart(fig_ratio, use_container_width=True)
    else:
        st.caption("No auth attempts in this window.")

st.markdown("<br>", unsafe_allow_html=True)

# ==============================================================================
# SECTION 6: MITRE ATT&CK BEHAVIORAL MATRIX & RECENT COMMAND STREAM
# ==============================================================================
st.subheader("MITRE ATT&CK Behavioral Mapping & Executed Commands")

m_col1, m_col2 = st.columns([1.3, 2.7])

with m_col1:
    mitre_df = pd.read_sql_query(f"""
        SELECT mitre_technique, mitre_id, count(*) as count 
        FROM commands 
        {cmd_where_sql} {'AND' if cmd_where_sql else 'WHERE'} mitre_id IS NOT NULL 
        GROUP BY mitre_id 
        ORDER BY count DESC
    """, conn, params=cmd_params)
    if not mitre_df.empty:
        fig_m = px.bar(
            mitre_df,
            x="count",
            y="mitre_technique",
            orientation="h",
            color="count",
            color_continuous_scale="Oranges",
            title="Observed MITRE ATT&CK Techniques",
            hover_data={"mitre_id": True},
            template="plotly_dark"
        )
        fig_m.update_layout(yaxis={'categoryorder': 'total ascending'}, height=340, showlegend=False, margin={"t": 30, "b": 0}, paper_bgcolor="#060913", plot_bgcolor="#060913")
        st.plotly_chart(fig_m, use_container_width=True)

        mitre_list = ["(None)"] + mitre_df["mitre_id"].tolist()
        selected_m = st.selectbox("Drill down by MITRE Technique ID:", options=mitre_list, index=0)
        if selected_m != "(None)" and selected_m != st.session_state["drilldown_mitre"]:
            st.session_state["drilldown_mitre"] = selected_m
            st.rerun()
    else:
        st.info("No commands mapped to MITRE yet.")

with m_col2:
    recent_cmds = pd.read_sql_query(f"""
        SELECT timestamp_ist as "Timestamp (IST)", ip as "Attacker IP", 
               command_text as "Command Executed", mitre_id as "Technique ID", 
               mitre_technique as "Technique Name", mitre_tactic as "Tactic"
        FROM commands 
        {cmd_where_sql}
        ORDER BY id DESC 
        LIMIT 10
    """, conn, params=cmd_params)
    if not recent_cmds.empty:
        st.write("**Recent Shell Keystrokes & TTP Classification (IST)**")
        st.dataframe(recent_cmds, use_container_width=True, height=290)
    else:
        st.caption("No commands executed in this window.")

st.markdown("<br>", unsafe_allow_html=True)

# ==============================================================================
# SECTION 7: EVIDENCE EXPORT FOR REPORTING
# ==============================================================================
st.subheader("Forensic Evidence Export & Lab Archival")
exp_col1, exp_col2 = st.columns(2)

with exp_col1:
    sessions_all = pd.read_sql_query(f"SELECT * FROM sessions {combined_where}", conn, params=drill_params)
    st.download_button(
        label="Download Enriched Sessions (CSV)",
        data=sessions_all.to_csv(index=False).encode('utf-8'),
        file_name="bcssl_honeypot_sessions.csv",
        mime="text/csv"
    )

with exp_col2:
    commands_all = pd.read_sql_query(f"SELECT * FROM commands {cmd_where_sql}", conn, params=cmd_params)
    st.download_button(
        label="Download Commands & MITRE Classifications (CSV)",
        data=commands_all.to_csv(index=False).encode('utf-8'),
        file_name="bcssl_honeypot_commands_mitre.csv",
        mime="text/csv"
    )

# Sub-2 second live streaming loop
if live_stream:
    import time
    time.sleep(1.5)
    st.rerun()
