"""
BCSSL Threat Intelligence & SSH Honeypot SOC Dashboard.
Enterprise-grade dark theme, Splunk-style time filtering, entity drilldowns,
sub-2-second live streaming, IST timestamps, and rich forensic telemetry.
"""

import json
import os
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

from src.db import build_time_filter

load_dotenv()
DB_PATH = os.getenv("DATABASE_PATH", "data/honeypot.db")
FAVICON_PATH = "assets/bcss_logo.png" if os.path.exists("assets/bcss_logo.png") else None

st.set_page_config(
    page_title="BCSSL Threat Intelligence & SSH Honeypot SOC",
    page_icon=FAVICON_PATH or "BCSS",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enterprise Dark Theme CSS (Zero emojis, crisp borders, dark blue/slate aesthetic)
st.markdown("""
<style>
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }

    /* Structured Paths Grid Cards */
    .paths-container {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 12px;
        margin-bottom: 20px;
    }
    .path-card {
        background-color: #131b2e;
        border: 1px solid #243048;
        border-top: 3px solid #38bdf8;
        border-radius: 6px;
        padding: 12px 14px;
    }
    .path-card-title {
        font-size: 11px;
        font-weight: 700;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 4px;
    }
    .path-card-purpose {
        font-size: 12px;
        font-weight: 600;
        color: #38bdf8;
        margin-bottom: 6px;
    }
    .path-card-loc {
        font-size: 11px;
        color: #cbd5e1;
        font-family: "Courier New", monospace;
        word-break: break-all;
        background-color: #0b1120;
        padding: 4px 6px;
        border-radius: 4px;
        border: 1px solid #1e293b;
    }

    /* Metric Cards */
    .metric-card {
        background-color: #131b2e;
        border: 1px solid #243048;
        border-radius: 6px;
        padding: 14px;
        margin-bottom: 10px;
    }
    .metric-title {
        font-size: 11px;
        font-weight: 600;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 4px;
    }
    .metric-number {
        font-size: 26px;
        font-weight: 700;
        color: #38bdf8;
    }
    .metric-sub {
        font-size: 11px;
        color: #64748b;
        margin-top: 2px;
    }

    /* Drilldown Banner */
    .drilldown-banner {
        background-color: #172554;
        border: 1px solid #1d4ed8;
        border-radius: 6px;
        padding: 10px 16px;
        margin-bottom: 16px;
        display: flex;
        align-items: center;
        justify-content: space-between;
    }

    /* Info card */
    .detail-card {
        background-color: #131b2e;
        border: 1px solid #243048;
        border-radius: 6px;
        padding: 12px;
    }
</style>
""", unsafe_allow_html=True)


def get_connection():
    if not os.path.exists(DB_PATH):
        return None
    return sqlite3.connect(DB_PATH, check_same_thread=False)


# Initialize session state for drilldowns and filters
if "drilldown_ip" not in st.session_state:
    st.session_state["drilldown_ip"] = None
if "drilldown_user" not in st.session_state:
    st.session_state["drilldown_user"] = None
if "drilldown_mitre" not in st.session_state:
    st.session_state["drilldown_mitre"] = None

# Sidebar
st.sidebar.title("BCSSL SOC Navigation")
st.sidebar.caption("Blue Cloud Softech Solutions Ltd.")

live_stream = st.sidebar.checkbox("Live Stream (Auto-refresh < 2s)", value=False)
st.sidebar.markdown("---")

st.sidebar.subheader("Server Endpoints")
st.sidebar.markdown("""
* **Honeypot Trap Port**: `18.60.33.150:22`
* **Host Admin SSH**: `18.60.33.150:22222`
* **Log Explorer**: `/logs` (Full Event Feed)
""")

st.sidebar.markdown("---")
st.sidebar.subheader("Threat Intelligence Status")
api_present = bool(os.getenv("ABUSEIPDB_API_KEY"))
st.sidebar.markdown(f"**AbuseIPDB Integration:** {'Active (Online)' if api_present else 'Missing Key'}")
st.sidebar.markdown("**Timezone:** Indian Standard Time (IST, UTC+5:30)")

conn = get_connection()
if conn is None:
    st.warning("Database not initialized yet.")
    st.stop()

# --- HEADER & STRUCTURED STORAGE PATHS (SCREENSHOT 1 REDESIGNED) ---
st.title("BCSSL Threat Intelligence & SSH Honeypot SOC")
st.caption("Real-time intrusion capture, threat intelligence enrichment, and MITRE ATT&CK behavioral profiling.")

# Clean structured 4-column card grid for storage paths
st.markdown("""
<div class="paths-container">
    <div class="path-card">
        <div class="path-card-title">Event Logging</div>
        <div class="path-card-purpose">Raw JSON Stream</div>
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
        <div class="path-card-purpose">SQLite Analytical DB</div>
        <div class="path-card-loc">/home/ubuntu/ssh-honeypot/data/honeypot.db</div>
    </div>
</div>
""", unsafe_allow_html=True)

# --- SPLUNK-STYLE TIME RANGE FILTER & DRILLDOWN CONTROLS ---
filter_col1, filter_col2 = st.columns([2, 2])

with filter_col1:
    time_range = st.selectbox(
        "Time Range Filter (Splunk Window)",
        options=["Last 15 Minutes", "Last 1 Hour", "Last 4 Hours", "Last 24 Hours", "Last 7 Days", "All Time"],
        index=5
    )

with filter_col2:
    if st.session_state["drilldown_ip"] or st.session_state["drilldown_user"] or st.session_state["drilldown_mitre"]:
        st.write("")
        st.write("")
        if st.button("Clear Drilldown Filters"):
            st.session_state["drilldown_ip"] = None
            st.session_state["drilldown_user"] = None
            st.session_state["drilldown_mitre"] = None
            st.rerun()

# Display active drilldown banner if set
if st.session_state["drilldown_ip"] or st.session_state["drilldown_user"] or st.session_state["drilldown_mitre"]:
    active_filters = []
    if st.session_state["drilldown_ip"]:
        active_filters.append(f"Attacker IP = {st.session_state['drilldown_ip']}")
    if st.session_state["drilldown_user"]:
        active_filters.append(f"Target Username = {st.session_state['drilldown_user']}")
    if st.session_state["drilldown_mitre"]:
        active_filters.append(f"MITRE Technique = {st.session_state['drilldown_mitre']}")
    st.info(f"Active Forensic Drilldown: {' | '.join(active_filters)}")

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

# --- TOP SUMMARY KPI METRICS ---
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
    st.markdown(f'<div class="metric-card"><div class="metric-title">Total Sessions</div><div class="metric-number">{total_sessions:,}</div><div class="metric-sub">Inbound probes</div></div>', unsafe_allow_html=True)
with col_kpi2:
    st.markdown(f'<div class="metric-card"><div class="metric-title">Attacker IPs</div><div class="metric-number">{unique_ips:,}</div><div class="metric-sub">Unique hosts</div></div>', unsafe_allow_html=True)
with col_kpi3:
    st.markdown(f'<div class="metric-card"><div class="metric-title">Brute-Force Trials</div><div class="metric-number">{total_auth:,}</div><div class="metric-sub">Password attempts</div></div>', unsafe_allow_html=True)
with col_kpi4:
    st.markdown(f'<div class="metric-card"><div class="metric-title">Breached Shells</div><div class="metric-number" style="color: #f43f5e;">{success_auth:,}</div><div class="metric-sub">Interactive logins</div></div>', unsafe_allow_html=True)
with col_kpi5:
    st.markdown(f'<div class="metric-card"><div class="metric-title">Commands Captured</div><div class="metric-number" style="color: #38bdf8;">{total_cmds:,}</div><div class="metric-sub">Shell keystrokes</div></div>', unsafe_allow_html=True)
with col_kpi6:
    st.markdown(f'<div class="metric-card"><div class="metric-title">Countries</div><div class="metric-number">{total_countries:,}</div><div class="metric-sub">Source nations</div></div>', unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# --- ROW 1: ATTACK MAP & GEOLOCATION THREAT INTEL ---
st.subheader("Attacker Geolocation & Threat Reputation")

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
        fig_map.update_geos(showcountries=True, countrycolor="#334155", showocean=True, oceancolor="#0f172a", bgcolor="#0b0f19")
        fig_map.update_layout(margin={"r": 0, "t": 20, "l": 0, "b": 0}, height=380, paper_bgcolor="#0b0f19")
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
        fig_country.update_layout(yaxis={'categoryorder': 'total ascending'}, height=380, showlegend=False, margin={"t": 35, "b": 0}, paper_bgcolor="#0b0f19", plot_bgcolor="#0b0f19")
        st.plotly_chart(fig_country, use_container_width=True)
    else:
        st.caption("No country statistics available for this window.")

st.markdown("<br>", unsafe_allow_html=True)

# --- ROW 2: CREDENTIAL HARVEST & BRUTE-FORCE DRILLDOWNS ---
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
        fig_user.update_layout(height=280, showlegend=False, margin={"t": 30, "b": 0}, paper_bgcolor="#0b0f19", plot_bgcolor="#0b0f19")
        st.plotly_chart(fig_user, use_container_width=True)

        # Drilldown selector for usernames
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
        fig_pass.update_layout(height=280, showlegend=False, margin={"t": 30, "b": 0}, paper_bgcolor="#0b0f19", plot_bgcolor="#0b0f19")
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
        fig_ratio = px.pie(ratio_df, names="status", values="count", title="Auth Ratios",
                           color="status", color_discrete_map={"FAILED": "#ef4444", "SUCCESS": "#10b981"},
                           hole=0.45, template="plotly_dark")
        fig_ratio.update_layout(height=280, margin={"t": 30, "b": 0}, paper_bgcolor="#0b0f19")
        st.plotly_chart(fig_ratio, use_container_width=True)
    else:
        st.caption("No auth attempts in this window.")

st.markdown("<br>", unsafe_allow_html=True)

# --- ROW 3: MITRE ATT&CK & COMMAND FEED ---
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
            title="Classified MITRE ATT&CK Techniques",
            hover_data={"mitre_id": True},
            template="plotly_dark"
        )
        fig_m.update_layout(yaxis={'categoryorder': 'total ascending'}, height=340, showlegend=False, margin={"t": 30, "b": 0}, paper_bgcolor="#0b0f19", plot_bgcolor="#0b0f19")
        st.plotly_chart(fig_m, use_container_width=True)

        # Drilldown selector for MITRE
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

# --- ROW 4: ENRICHED ATTACKER SESSION DEEP-DIVE (SCREENSHOT 2 REDESIGNED) ---
st.subheader("Attacker Session Deep-Dive & Forensic Telemetry")
st.caption("Inspect any individual probe or interactive attack session with full IST timeline, client signatures, and raw telemetry.")

session_list = pd.read_sql_query(f"""
    SELECT s.session_id, s.ip, s.country, s.city, s.start_time, s.start_time_ist, 
           s.duration, s.abuse_score, s.total_reports, s.usage_type, s.asn, s.isp,
           s.client_version, s.ciphers, s.terminal_size
    FROM sessions s 
    {combined_where}
    ORDER BY s.start_time DESC 
    LIMIT 100
""", conn, params=drill_params)

if not session_list.empty:
    def format_session_label(sid):
        row = session_list[session_list["session_id"] == sid].iloc[0]
        country = row["country"] or "Unknown"
        t_ist = row["start_time_ist"] or row["start_time"]
        abuse = row["abuse_score"] or 0
        return f"[{sid}] | IP: {row['ip']} ({country}) | {t_ist} | Abuse: {abuse}%"

    selected_session = st.selectbox(
        "Select Attacker Session to Inspect:",
        options=session_list["session_id"].tolist(),
        format_func=format_session_label
    )

    if selected_session:
        s_meta = session_list[session_list["session_id"] == selected_session].iloc[0]
        
        # Enriched Information Cards Grid
        info1, info2, info3, info4 = st.columns(4)
        with info1:
            st.markdown(f"""
            <div class="detail-card">
                <div class="metric-title">Attacker Identity</div>
                <div style="font-size: 16px; font-weight: 700; color: #38bdf8;">{s_meta['ip']}</div>
                <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">Location: {s_meta['city'] or 'Unknown'}, {s_meta['country'] or 'Unknown'}</div>
            </div>
            """, unsafe_allow_html=True)
            
            # Drilldown button by IP
            if st.button(f"Drill down on IP {s_meta['ip']}", key="drill_ip_btn"):
                st.session_state["drilldown_ip"] = s_meta["ip"]
                st.rerun()

        with info2:
            st.markdown(f"""
            <div class="detail-card">
                <div class="metric-title">Network & ISP</div>
                <div style="font-size: 13px; font-weight: 600; color: #e2e8f0;">{s_meta['isp'] or 'Unknown ISP'}</div>
                <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">ASN: {s_meta['asn'] or 'Unknown'}</div>
                <div style="font-size: 11px; color: #64748b;">Type: {s_meta['usage_type'] or 'Web Hosting/Transit'}</div>
            </div>
            """, unsafe_allow_html=True)

        with info3:
            abuse_val = s_meta['abuse_score'] or 0
            abuse_color = "#ef4444" if abuse_val > 50 else ("#f59e0b" if abuse_val > 20 else "#10b981")
            st.markdown(f"""
            <div class="detail-card">
                <div class="metric-title">Threat Reputation</div>
                <div style="font-size: 20px; font-weight: 700; color: {abuse_color};">{abuse_val}% Abuse Score</div>
                <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">Total Reports: {s_meta['total_reports'] or 0:,}</div>
                <div style="font-size: 11px; color: #64748b;">Duration: {s_meta['duration']:.2f} seconds</div>
            </div>
            """, unsafe_allow_html=True)

        with info4:
            st.markdown(f"""
            <div class="detail-card">
                <div class="metric-title">Client Fingerprint</div>
                <div style="font-size: 12px; font-weight: 600; color: #38bdf8; font-family: monospace;">{s_meta['client_version'] or 'SSH-2.0-Generic'}</div>
                <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">Terminal: {s_meta['terminal_size'] or 'N/A'}</div>
                <div style="font-size: 11px; color: #64748b;">Handshake: {s_meta['ciphers'] or 'Default Suite'}</div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # Tabs for Session Telemetry
        tab_keystrokes, tab_raw_json, tab_auth = st.tabs([
            "Keystroke History (IST)", 
            "Raw JSON Telemetry Log", 
            "Authentication Sequence (IST)"
        ])

        with tab_keystrokes:
            cmds = pd.read_sql_query("""
                SELECT timestamp_ist as "Timestamp (IST)", command_text as "Command Input", 
                       mitre_id as "Technique ID", mitre_technique as "Technique Name", mitre_tactic as "Tactic"
                FROM commands 
                WHERE session_id = ? 
                ORDER BY id ASC
            """, conn, params=(selected_session,))
            if not cmds.empty:
                st.write("**Chronological Commands Executed in Fake Shell (IST):**")
                st.dataframe(cmds, use_container_width=True)
            else:
                st.info("No interactive shell commands executed in this session (authentication attempt only).")

        with tab_raw_json:
            st.write("**Underlying Cowrie JSON Events (Audit Trail):**")
            raw_logs = pd.read_sql_query("""
                SELECT id, timestamp_ist, event_id, summary, raw_json
                FROM raw_logs 
                WHERE session_id = ? 
                ORDER BY id ASC
            """, conn, params=(selected_session,))

            if not raw_logs.empty:
                for idx, row in raw_logs.iterrows():
                    with st.expander(f"Event: {row['event_id']} — {row['timestamp_ist']} | {row['summary']}"):
                        try:
                            parsed_json = json.loads(row['raw_json'])
                            st.json(parsed_json)
                        except Exception:
                            st.code(row['raw_json'], language="json")
            else:
                st.caption("Raw logs will display for newly ingested events.")

        with tab_auth:
            auths = pd.read_sql_query("""
                SELECT timestamp_ist as "Timestamp (IST)", username as "Username Tried", 
                       password as "Password Tried", status as "Status"
                FROM auth_attempts 
                WHERE session_id = ? 
                ORDER BY id ASC
            """, conn, params=(selected_session,))
            if not auths.empty:
                st.dataframe(auths, use_container_width=True)
            else:
                st.caption("No authentication records for this session.")

st.markdown("<br>", unsafe_allow_html=True)

# --- ROW 5: EXPORT EVIDENCE ---
st.subheader("Export Evidence for Reporting")
exp_col1, exp_col2 = st.columns(2)

with exp_col1:
    sessions_all = pd.read_sql_query(f"SELECT * FROM sessions {combined_where}", conn, params=drill_params)
    st.download_button(
        label="Download Enriched Sessions CSV",
        data=sessions_all.to_csv(index=False).encode('utf-8'),
        file_name="honeypot_sessions_report.csv",
        mime="text/csv"
    )

with exp_col2:
    commands_all = pd.read_sql_query(f"SELECT * FROM commands {cmd_where_sql}", conn, params=cmd_params)
    st.download_button(
        label="Download Commands & MITRE Mapping CSV",
        data=commands_all.to_csv(index=False).encode('utf-8'),
        file_name="honeypot_commands_mitre.csv",
        mime="text/csv"
    )

# Sub-2 second live streaming loop
if live_stream:
    import time
    time.sleep(1.5)
    st.rerun()
