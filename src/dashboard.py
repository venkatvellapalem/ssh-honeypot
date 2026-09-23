"""
SSH Honeypot SOC Dashboard — BCSSL
Real-time threat capture, enrichment, and MITRE ATT&CK profiling.
"""

import json, os, sys
from pathlib import Path
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

_cur_dir = Path(__file__).resolve().parent
_root_dir = _cur_dir.parent if _cur_dir.name in ("src", "pages") else _cur_dir
if str(_root_dir) not in sys.path:
    sys.path.insert(0, str(_root_dir))

from src.db import build_time_filter

load_dotenv()
DB_PATH = os.getenv("DATABASE_PATH", "data/honeypot.db")

# --- Page config ---
FAVICON_PATH = None
for candidate in [
    os.path.join(str(_root_dir), "assets", "bcss_logo.png"),
    "assets/bcss_logo.png", "/app/assets/bcss_logo.png"
]:
    if os.path.exists(candidate):
        FAVICON_PATH = candidate
        break

try:
    from PIL import Image
    favicon_img = Image.open(FAVICON_PATH) if FAVICON_PATH and os.path.exists(FAVICON_PATH) else None
except Exception:
    favicon_img = None

st.set_page_config(
    page_title="SOC · SSH Honeypot",
    page_icon=favicon_img or ":shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Theme ──────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {
    --bg:      #0a0a0f;
    --surface: #111118;
    --border:  #1e1e2a;
    --text:    #e4e4e7;
    --muted:   #71717a;
    --accent:  #06b6d4;
    --red:     #ef4444;
    --green:   #22c55e;
    --amber:   #f59e0b;
}

/* Global */
.stApp, .stApp header, [data-testid="stSidebar"] {
    background: var(--bg) !important;
    font-family: 'Inter', -apple-system, system-ui, sans-serif !important;
}
.stMarkdown, .stMarkdown p, .stMarkdown li, .stMarkdown span,
[data-testid="stSidebar"] .stMarkdown {
    color: var(--text) !important;
    font-family: 'Inter', sans-serif !important;
}

/* Sidebar */
[data-testid="stSidebar"] {
    border-right: 1px solid var(--border) !important;
}
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h1 {
    font-size: 1.1rem !important;
    font-weight: 700 !important;
    letter-spacing: -0.02em !important;
}
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h3 {
    font-size: 0.75rem !important;
    font-weight: 600 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.08em !important;
    color: var(--muted) !important;
    margin-top: 1rem !important;
}

/* Section headers */
h2, .stMarkdown h2 {
    font-size: 1rem !important;
    font-weight: 700 !important;
    letter-spacing: -0.01em !important;
    color: var(--text) !important;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid var(--border);
    margin-bottom: 1rem !important;
}

/* Metric cards */
[data-testid="stMetric"] {
    background: var(--surface) !important;
    border: 1px solid var(--border) !important;
    border-radius: 10px !important;
    padding: 1rem 1.2rem !important;
}
[data-testid="stMetric"] label {
    font-size: 0.7rem !important;
    font-weight: 600 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.06em !important;
    color: var(--muted) !important;
}
[data-testid="stMetric"] [data-testid="stMetricValue"] {
    font-size: 1.8rem !important;
    font-weight: 800 !important;
    font-family: 'JetBrains Mono', monospace !important;
    letter-spacing: -0.03em !important;
}
[data-testid="stMetric"] [data-testid="stMetricDelta"] {
    font-size: 0.75rem !important;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    gap: 0 !important;
    border-bottom: 1px solid var(--border) !important;
}
.stTabs [data-baseweb="tab"] {
    font-size: 0.8rem !important;
    font-weight: 500 !important;
    padding: 0.6rem 1.2rem !important;
    color: var(--muted) !important;
}
.stTabs [aria-selected="true"] {
    color: var(--accent) !important;
    border-bottom-color: var(--accent) !important;
}

/* Dataframe */
[data-testid="stDataFrame"] {
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
}

/* Selectbox & inputs */
[data-baseweb="select"] > div,
[data-baseweb="input"] > div {
    background: var(--surface) !important;
    border-color: var(--border) !important;
    border-radius: 8px !important;
}

/* Download buttons */
.stDownloadButton button {
    border-radius: 8px !important;
    font-weight: 600 !important;
    font-size: 0.82rem !important;
}

/* Dividers */
hr {
    border-color: var(--border) !important;
    margin: 1.5rem 0 !important;
}

/* Info boxes */
.stAlert {
    border-radius: 8px !important;
    font-size: 0.85rem !important;
}

/* Expander details */
details {
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
    background: var(--surface) !important;
}
details summary {
    font-size: 0.82rem !important;
    font-weight: 500 !important;
}

/* Status badge */
.status-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    border-radius: 999px;
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
}
.status-live {
    background: rgba(34,197,94,0.12);
    color: #4ade80;
    border: 1px solid rgba(34,197,94,0.25);
}
.status-live::before {
    content: '';
    width: 6px; height: 6px;
    border-radius: 50%;
    background: #22c55e;
    animation: pulse 2s infinite;
}
@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
}

/* Compact info row */
.info-row {
    display: flex;
    gap: 24px;
    padding: 10px 14px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    margin-bottom: 12px;
    font-size: 0.78rem;
}
.info-row .label {
    color: var(--muted);
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-size: 0.68rem;
}
.info-row .value {
    color: var(--text);
    font-weight: 600;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.82rem;
}
</style>
""", unsafe_allow_html=True)


# ── Helpers ────────────────────────────────────────────────────────────────────
def clean_val(val, fallback="—"):
    if val is None:
        return fallback
    try:
        import pandas as _pd
        if _pd.isna(val):
            return fallback
    except Exception:
        pass
    s = str(val).strip()
    return fallback if not s or s.lower() in ("nan", "none", "null", "") else s


def get_connection():
    if not os.path.exists(DB_PATH):
        return None
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def bar_color(val, low=20, mid=50):
    """Return color based on thresholds."""
    if val >= mid:
        return "#ef4444"
    if val >= low:
        return "#f59e0b"
    return "#22c55e"


# ── Plotly shared layout ──────────────────────────────────────────────────────
PLOT_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Inter, sans-serif", size=12, color="#a1a1aa"),
    margin=dict(l=8, r=8, t=32, b=8),
    xaxis=dict(gridcolor="#1e1e2a", zerolinecolor="#1e1e2a"),
    yaxis=dict(gridcolor="#1e1e2a", zerolinecolor="#1e1e2a"),
)

GEO_LAYOUT = dict(
    showcountries=True, countrycolor="#1e1e2a",
    showocean=True, oceancolor="#0a0a0f",
    showcoastlines=True, coastlinecolor="#1e1e2a",
    showland=True, landcolor="#111118",
    bgcolor="rgba(0,0,0,0)",
    projection_type="natural earth",
)


# ── Session state ─────────────────────────────────────────────────────────────
for k, v in [("drilldown_ip", None), ("drilldown_user", None), ("drilldown_mitre", None)]:
    if k not in st.session_state:
        st.session_state[k] = v


# ── Connection ────────────────────────────────────────────────────────────────
conn = get_connection()
if conn is None:
    st.warning("Database not initialized. Waiting for honeypot events…")
    st.stop()

# ── Sidebar ───────────────────────────────────────────────────────────────────
if FAVICON_PATH and os.path.exists(FAVICON_PATH):
    st.sidebar.image(FAVICON_PATH, width=160)

st.sidebar.title("SOC")
st.sidebar.caption("Blue Cloud Softech Solutions")

st.sidebar.markdown("### Controls")
live_stream = st.sidebar.toggle("Live Stream", value=False, help="Auto-refresh every 1.5s")
time_range = st.sidebar.selectbox(
    "Time Range",
    ["Last 15 Minutes", "Last 1 Hour", "Last 4 Hours", "Last 24 Hours", "Last 7 Days", "All Time"],
    index=5,
    label_visibility="collapsed",
)

st.sidebar.markdown("### Active Drilldown")
_drill_active = bool(st.session_state["drilldown_ip"] or st.session_state["drilldown_user"] or st.session_state["drilldown_mitre"])
if _drill_active:
    if st.session_state["drilldown_ip"]:
        st.sidebar.badge(f"IP: {st.session_state['drilldown_ip']}", icon=":material/gps_fixed:")
    if st.session_state["drilldown_user"]:
        st.sidebar.badge(f"User: {st.session_state['drilldown_user']}", icon=":material/person:")
    if st.session_state["drilldown_mitre"]:
        st.sidebar.badge(f"MITRE: {st.session_state['drilldown_mitre']}", icon=":material/target:")
    if st.sidebar.button("Clear All", use_container_width=True):
        st.session_state["drilldown_ip"] = None
        st.session_state["drilldown_user"] = None
        st.session_state["drilldown_mitre"] = None
        st.rerun()
else:
    st.sidebar.caption("No filters active")

st.sidebar.markdown("### Endpoints")
try:
    import urllib.request
    _ip = urllib.request.urlopen("http://169.254.169.254/latest/meta-data/public-ipv4", timeout=1).read().decode()
except Exception:
    try:
        _ip = urllib.request.urlopen("https://ifconfig.me", timeout=3).read().decode().strip()
    except Exception:
        _ip = "—"
st.sidebar.code(f"Trap  {_ip}:22\nSSH   {_ip}:22222\nSOC   {_ip}:8501", language=None)

st.sidebar.markdown("### Intel Sources")
_api = bool(os.getenv("ABUSEIPDB_API_KEY"))
_vt = bool(os.getenv("VIRUSTOTAL_API_KEY"))
st.sidebar.markdown(f"- AbuseIPDB: {'✓ Active' if _api else '✗ Missing'}")
st.sidebar.markdown(f"- VirusTotal: {'✓ Active' if _vt else '✗ Missing'}")
st.sidebar.markdown("- GeoIP: ip-api.com")
st.sidebar.markdown("- Timezone: IST (UTC+5:30)")


# ── SQL filter builder ────────────────────────────────────────────────────────
time_sql, time_params = build_time_filter(time_range, col_name="start_time")

drill_where, drill_params = [], list(time_params)
if time_sql:
    drill_where.append(time_sql)
if st.session_state["drilldown_ip"]:
    drill_where.append("ip = ?")
    drill_params.append(st.session_state["drilldown_ip"])
combined_where = ("WHERE " + " AND ".join(drill_where)) if drill_where else ""

auth_where, auth_params = [], []
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

cmd_where, cmd_params = [], []
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


# ── Header ────────────────────────────────────────────────────────────────────
hdr_l, hdr_r = st.columns([4, 1])
with hdr_l:
    st.markdown("## SSH Honeypot SOC")
with hdr_r:
    st.markdown('<div style="text-align:right; padding-top:6px"><span class="status-pill status-live">Port 22 Active</span></div>', unsafe_allow_html=True)

st.divider()


# ── KPI Row ───────────────────────────────────────────────────────────────────
cur = conn.cursor()
try:
    total_sessions = cur.execute(f"SELECT count(*) FROM sessions {combined_where}", drill_params).fetchone()[0]
    unique_ips     = cur.execute(f"SELECT count(DISTINCT ip) FROM sessions {combined_where}", drill_params).fetchone()[0]
    total_auth     = cur.execute(f"SELECT count(*) FROM auth_attempts {auth_where_sql}", auth_params).fetchone()[0]
    success_auth   = cur.execute(f"SELECT count(*) FROM auth_attempts {auth_where_sql} {'AND' if auth_where_sql else 'WHERE'} status = 'SUCCESS'", auth_params).fetchone()[0]
    total_cmds     = cur.execute(f"SELECT count(*) FROM commands {cmd_where_sql}", cmd_params).fetchone()[0]
    total_countries= cur.execute(f"SELECT count(DISTINCT country) FROM sessions {combined_where} {'AND' if combined_where else 'WHERE'} country IS NOT NULL AND country != '' AND country != 'Unknown'", drill_params).fetchone()[0]
except Exception as e:
    st.error(f"Query error: {e}")
    st.stop()

k1, k2, k3, k4, k5, k6 = st.columns(6)
k1.metric("Sessions",   f"{total_sessions:,}")
k2.metric("Unique IPs", f"{unique_ips:,}")
k3.metric("Auth Trials", f"{total_auth:,}")
k4.metric("Breached",   f"{success_auth:,}", delta=None, delta_color="inverse")
k5.metric("Commands",   f"{total_cmds:,}")
k6.metric("Countries",  f"{total_countries:,}")

st.divider()


# ── Session Deep-Dive (top section) ───────────────────────────────────────────
st.markdown("### Session Inspector")

session_list = pd.read_sql_query(f"""
    SELECT s.session_id, s.ip, s.country, s.city, s.start_time_ist,
           s.duration, s.abuse_score, s.total_reports, s.usage_type, s.asn, s.isp,
           s.client_version, s.ciphers, s.terminal_size,
           COALESCE(s.vt_malicious, 0) as vt_malicious,
           COALESCE(s.vt_suspicious, 0) as vt_suspicious,
           COALESCE(s.vt_reputation, 0) as vt_reputation
    FROM sessions s {combined_where}
    ORDER BY s.start_time DESC LIMIT 100
""", conn, params=drill_params)

if session_list.empty:
    st.info("No sessions in this time window.")
else:
    def _label(sid):
        r = session_list[session_list["session_id"] == sid].iloc[0]
        abuse = r["abuse_score"] or 0
        vt = int(r["vt_malicious"] or 0)
        extra = f" · VT:{vt}mal" if vt > 0 else ""
        return f"{r['ip']}  ({clean_val(r['country'])})  ·  {clean_val(r['start_time_ist'])}  ·  Abuse:{abuse}%{extra}"

    sel = st.selectbox("Session", session_list["session_id"].tolist(), format_func=_label, label_visibility="collapsed")

    if sel:
        m = session_list[session_list["session_id"] == sel].iloc[0]

        # Info row
        abuse_val = int(m["abuse_score"] or 0)
        vt_mal = int(m["vt_malicious"] or 0)
        vt_susp = int(m["vt_suspicious"] or 0)
        dur = float(m["duration"] or 0)
        loc = f"{clean_val(m['city'])}, {clean_val(m['country'])}"

        st.markdown(f"""
<div class="info-row">
    <div><span class="label">IP</span><br><span class="value">{m['ip']}</span></div>
    <div><span class="label">Location</span><br><span class="value">{loc}</span></div>
    <div><span class="label">ISP</span><br><span class="value">{clean_val(m['isp'])}</span></div>
    <div><span class="label">ASN</span><br><span class="value">{clean_val(m['asn'])}</span></div>
    <div><span class="label">Abuse Score</span><br><span class="value" style="color:{bar_color(abuse_val)}">{abuse_val}%</span></div>
    <div><span class="label">VT Malicious</span><br><span class="value" style="color:{'#ef4444' if vt_mal > 0 else '#22c55e'}">{vt_mal}</span></div>
    <div><span class="label">Duration</span><br><span class="value">{dur:.1f}s</span></div>
    <div><span class="label">Client</span><br><span class="value">{clean_val(m['client_version'], '—')}</span></div>
    <div><span class="label">Terminal</span><br><span class="value">{clean_val(m['terminal_size'], '—')}</span></div>
</div>
""", unsafe_allow_html=True)

        c_btn1, c_btn2, _ = st.columns([1, 1, 4])
        with c_btn1:
            if st.button("Drill IP", use_container_width=True, key="dip"):
                st.session_state["drilldown_ip"] = m["ip"]
                st.rerun()
        with c_btn2:
            st.link_button("VirusTotal ↗", f"https://www.virustotal.com/gui/ip-address/{m['ip']}", use_container_width=True)

        tab_cmds, tab_auth, tab_raw = st.tabs(["Commands", "Auth Events", "Raw JSON"])

        with tab_cmds:
            cmds = pd.read_sql_query("""
                SELECT timestamp_ist as "Time", command_text as "Command",
                       mitre_id as "MITRE ID", mitre_technique as "Technique", mitre_tactic as "Tactic"
                FROM commands WHERE session_id = ? ORDER BY id ASC
            """, conn, params=(sel,))
            if not cmds.empty:
                st.dataframe(cmds, use_container_width=True, hide_index=True)
            else:
                st.caption("No commands executed.")

        with tab_auth:
            auths = pd.read_sql_query("""
                SELECT timestamp_ist as "Time", username as "Username",
                       password as "Password", status as "Status"
                FROM auth_attempts WHERE session_id = ? ORDER BY id ASC
            """, conn, params=(sel,))
            if not auths.empty:
                st.dataframe(auths, use_container_width=True, hide_index=True)
            else:
                st.caption("No auth events.")

        with tab_raw:
            raws = pd.read_sql_query("""
                SELECT id, timestamp_ist as time, event_category as category, summary, raw_json
                FROM raw_logs WHERE session_id = ? ORDER BY id ASC
            """, conn, params=(sel,))
            if not raws.empty:
                for _, r in raws.iterrows():
                    with st.expander(f"{r['time']}  ·  {r['category']}  ·  {r['summary']}"):
                        try:
                            st.json(json.loads(r["raw_json"]))
                        except Exception:
                            st.code(r["raw_json"], language="json")
            else:
                st.caption("No raw events.")

st.divider()


# ── Map + Country ─────────────────────────────────────────────────────────────
st.markdown("### Global Threat Map")

geo_df = pd.read_sql_query(f"""
    SELECT s.ip, s.country, s.city, s.abuse_score,
           c.latitude, c.longitude, COUNT(s.session_id) as hits
    FROM sessions s LEFT JOIN ip_cache c ON s.ip = c.ip
    {combined_where}
    GROUP BY s.ip
    HAVING c.latitude IS NOT NULL AND c.latitude != 0.0
""", conn, params=drill_params)

mc1, mc2 = st.columns([2.5, 1.5])

with mc1:
    if not geo_df.empty:
        fig = px.scatter_geo(
            geo_df, lat="latitude", lon="longitude",
            hover_name="ip", size="hits", color="abuse_score",
            color_continuous_scale=["#22c55e", "#f59e0b", "#ef4444"],
            range_color=[0, 100], projection="natural earth",
            hover_data={"country": True, "city": True, "abuse_score": True, "hits": True},
        )
        fig.update_geos(**GEO_LAYOUT)
        fig.update_layout(**PLOT_LAYOUT, height=360, coloraxis_colorbar=dict(title="Abuse %", len=0.6))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No geo data yet.")

with mc2:
    cdf = pd.read_sql_query(f"""
        SELECT country, COUNT(*) as n FROM sessions
        {combined_where} {'AND' if combined_where else 'WHERE'} country IS NOT NULL AND country != ''
        GROUP BY country ORDER BY n DESC LIMIT 8
    """, conn, params=drill_params)
    if not cdf.empty:
        fig = px.bar(cdf, x="n", y="country", orientation="h",
                     color="n", color_continuous_scale=["#0e7490", "#06b6d4"],
                     labels={"n": "Sessions", "country": ""})
        fig.update_layout(**PLOT_LAYOUT, height=360, showlegend=False,
                          yaxis=dict(autorange="reversed", **{k: v for k, v in PLOT_LAYOUT.get("yaxis", {}).items()}))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.caption("No country data.")

st.divider()


# ── Auth Analysis ─────────────────────────────────────────────────────────────
st.markdown("### Authentication Analysis")

ac1, ac2, ac3 = st.columns([1.2, 1.2, 0.8])

with ac1:
    udf = pd.read_sql_query(f"""
        SELECT username, count(*) as n FROM auth_attempts
        {auth_where_sql} {'AND' if auth_where_sql else 'WHERE'} username IS NOT NULL AND username != ''
        GROUP BY username ORDER BY n DESC LIMIT 8
    """, conn, params=auth_params)
    if not udf.empty:
        fig = px.bar(udf, x="username", y="n", color="n",
                     color_continuous_scale=["#0e7490", "#06b6d4"],
                     labels={"n": "Attempts", "username": ""})
        fig.update_layout(**PLOT_LAYOUT, height=260, showlegend=False, title="Usernames")
        st.plotly_chart(fig, use_container_width=True)
        _ul = ["(none)"] + udf["username"].tolist()
        _us = st.selectbox("Drill by username", _ul, index=0, key="user_dd", label_visibility="collapsed")
        if _us != "(none)" and _us != st.session_state["drilldown_user"]:
            st.session_state["drilldown_user"] = _us
            st.rerun()
    else:
        st.caption("No auth data.")

with ac2:
    pdf = pd.read_sql_query(f"""
        SELECT password, count(*) as n FROM auth_attempts
        {auth_where_sql} {'AND' if auth_where_sql else 'WHERE'} password IS NOT NULL AND password != ''
        GROUP BY password ORDER BY n DESC LIMIT 8
    """, conn, params=auth_params)
    if not pdf.empty:
        fig = px.bar(pdf, x="password", y="n", color="n",
                     color_continuous_scale=["#581c87", "#a855f7"],
                     labels={"n": "Attempts", "password": ""})
        fig.update_layout(**PLOT_LAYOUT, height=260, showlegend=False, title="Passwords")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.caption("No password data.")

with ac3:
    rdf = pd.read_sql_query(f"""
        SELECT status, count(*) as n FROM auth_attempts {auth_where_sql} GROUP BY status
    """, conn, params=auth_params)
    if not rdf.empty:
        fig = go.Figure(go.Pie(
            labels=rdf["status"], values=rdf["n"], hole=0.55,
            marker=dict(colors=["#ef4444", "#22c55e"]),
            textfont=dict(size=13, color="white"),
        ))
        fig.update_layout(**PLOT_LAYOUT, height=260, title="Outcome", showlegend=True,
                          legend=dict(orientation="h", yanchor="bottom", y=-0.15, x=0.5, xanchor="center"))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.caption("No auth outcomes.")

st.divider()


# ── MITRE + Commands ──────────────────────────────────────────────────────────
st.markdown("### MITRE ATT&CK")

mc_l, mc_r = st.columns([1, 2])

with mc_l:
    mitre_df = pd.read_sql_query(f"""
        SELECT mitre_technique, mitre_id, count(*) as n FROM commands
        {cmd_where_sql} {'AND' if cmd_where_sql else 'WHERE'} mitre_id IS NOT NULL
        GROUP BY mitre_id ORDER BY n DESC
    """, conn, params=cmd_params)
    if not mitre_df.empty:
        fig = px.bar(mitre_df, x="n", y="mitre_technique", orientation="h",
                     color="n", color_continuous_scale=["#92400e", "#f59e0b"],
                     hover_data=["mitre_id"], labels={"n": "Count", "mitre_technique": ""})
        fig.update_layout(**PLOT_LAYOUT, height=320, showlegend=False,
                          yaxis=dict(autorange="reversed", **{k: v for k, v in PLOT_LAYOUT.get("yaxis", {}).items()}))
        st.plotly_chart(fig, use_container_width=True)
        _ml = ["(none)"] + mitre_df["mitre_id"].tolist()
        _ms = st.selectbox("Drill by MITRE", _ml, index=0, key="mitre_dd", label_visibility="collapsed")
        if _ms != "(none)" and _ms != st.session_state["drilldown_mitre"]:
            st.session_state["drilldown_mitre"] = _ms
            st.rerun()
    else:
        st.info("No MITRE data yet.")

with mc_r:
    recent_cmds = pd.read_sql_query(f"""
        SELECT timestamp_ist as "Time", ip as "IP",
               command_text as "Command", mitre_id as "MITRE",
               mitre_technique as "Technique", mitre_tactic as "Tactic"
        FROM commands {cmd_where_sql} ORDER BY id DESC LIMIT 15
    """, conn, params=cmd_params)
    if not recent_cmds.empty:
        st.dataframe(recent_cmds, use_container_width=True, hide_index=True, height=320)
    else:
        st.caption("No commands captured.")

st.divider()


# ── Event Log ─────────────────────────────────────────────────────────────────
st.markdown("### Event Log")

try:
    total_raw = cur.execute(f"SELECT count(*) FROM raw_logs").fetchone()[0]
except Exception:
    total_raw = 0

raw_df = pd.read_sql_query(f"""
    SELECT id, timestamp_ist as "Time", event_category as "Category",
           ip as "IP", summary as "Summary", raw_json
    FROM raw_logs ORDER BY id DESC LIMIT 200
""", conn)

if not raw_df.empty:
    st.dataframe(raw_df.drop(columns=["raw_json"]), use_container_width=True, hide_index=True, height=350)

    with st.expander("Inspect Raw JSON"):
        _ids = raw_df["id"].tolist()
        _rid = st.selectbox("Log entry", _ids, format_func=lambda x: f"#{x}  {raw_df.loc[raw_df['id']==x, 'Time'].values[0]}  {raw_df.loc[raw_df['id']==x, 'Category'].values[0]}", label_visibility="collapsed")
        if _rid:
            _row = raw_df[raw_df["id"] == _rid].iloc[0]
            try:
                st.json(json.loads(_row["raw_json"]))
            except Exception:
                st.code(_row["raw_json"], language="json")
else:
    st.info("No events yet.")

st.divider()


# ── Export ─────────────────────────────────────────────────────────────────────
st.markdown("### Export")

ex1, ex2 = st.columns(2)
with ex1:
    _sess = pd.read_sql_query(f"SELECT * FROM sessions {combined_where}", conn, params=drill_params)
    st.download_button("Sessions CSV", _sess.to_csv(index=False).encode(), "sessions.csv", use_container_width=True)
with ex2:
    _cmds = pd.read_sql_query(f"SELECT * FROM commands {cmd_where_sql}", conn, params=cmd_params)
    st.download_button("Commands CSV", _cmds.to_csv(index=False).encode(), "commands.csv", use_container_width=True)


# ── Footer ────────────────────────────────────────────────────────────────────
st.divider()
st.caption(f"BCSSL SOC  ·  {total_sessions:,} sessions  ·  {unique_ips:,} IPs  ·  {total_cmds:,} commands  ·  IST {datetime.now(timezone(timedelta(hours=5, minutes=30))).strftime('%H:%M:%S')}")

# ── Live refresh ──────────────────────────────────────────────────────────────
if live_stream:
    import time
    time.sleep(1.5)
    st.rerun()
