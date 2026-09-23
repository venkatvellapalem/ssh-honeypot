"""
SSH Honeypot SOC Dashboard — BCSSL
Real-time threat capture, enrichment, and MITRE ATT&CK profiling.
"""

import json, os, sys, glob
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

# ── Favicon ───────────────────────────────────────────────────────────────────
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

st.set_page_config(page_title="SOC · SSH Honeypot", page_icon=favicon_img or ":shield:", layout="wide", initial_sidebar_state="expanded")

# ── Theme ──────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
:root { --bg:#050507; --surface:#0c0c10; --card:#111116; --border:#1a1a22; --text:#e4e4e7; --muted:#71717a; --accent:#06b6d4; --red:#ef4444; --green:#22c55e; --amber:#f59e0b; }
.stApp, .stApp header, [data-testid="stSidebar"] { background:var(--bg)!important; font-family:'Inter',sans-serif!important; }
.stMarkdown, .stMarkdown p, .stMarkdown li, .stMarkdown span, [data-testid="stSidebar"] .stMarkdown { color:var(--text)!important; }
[data-testid="stSidebar"] { border-right:1px solid var(--border)!important; background:#08080b!important; }
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h1 { font-size:1.1rem!important; font-weight:700!important; }
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h3 { font-size:.7rem!important; font-weight:600!important; text-transform:uppercase!important; letter-spacing:.1em!important; color:var(--muted)!important; margin-top:1.2rem!important; margin-bottom:.4rem!important; }
h2, .stMarkdown h2 { font-size:1rem!important; font-weight:700!important; color:var(--text)!important; padding-bottom:.5rem; border-bottom:1px solid var(--border); margin-bottom:1rem!important; }
[data-testid="stMetric"] { background:var(--card)!important; border:1px solid var(--border)!important; border-radius:10px!important; padding:1rem 1.2rem!important; }
[data-testid="stMetric"] label { font-size:.68rem!important; font-weight:600!important; text-transform:uppercase!important; letter-spacing:.08em!important; color:var(--muted)!important; }
[data-testid="stMetric"] [data-testid="stMetricValue"] { font-size:1.7rem!important; font-weight:800!important; font-family:'JetBrains Mono',monospace!important; letter-spacing:-.03em!important; }
.stTabs [data-baseweb="tab-list"] { gap:0!important; border-bottom:1px solid var(--border)!important; }
.stTabs [data-baseweb="tab"] { font-size:.78rem!important; font-weight:500!important; padding:.55rem 1.1rem!important; color:var(--muted)!important; }
.stTabs [aria-selected="true"] { color:var(--accent)!important; border-bottom-color:var(--accent)!important; }
[data-testid="stDataFrame"] { border:1px solid var(--border)!important; border-radius:8px!important; }
[data-baseweb="select"]>div, [data-baseweb="input"]>div { background:var(--surface)!important; border-color:var(--border)!important; border-radius:8px!important; }
.stDownloadButton button, .stLinkButton { border-radius:8px!important; font-weight:600!important; font-size:.8rem!important; }
hr { border-color:var(--border)!important; margin:1.2rem 0!important; }
details { border:1px solid var(--border)!important; border-radius:8px!important; background:var(--card)!important; }
.stAlert { border-radius:8px!important; }
.status-pill { display:inline-flex; align-items:center; gap:6px; padding:4px 12px; border-radius:999px; font-size:.7rem; font-weight:600; letter-spacing:.04em; text-transform:uppercase; }
.status-live { background:rgba(34,197,94,.1); color:#4ade80; border:1px solid rgba(34,197,94,.2); }
.status-live::before { content:''; width:6px; height:6px; border-radius:50%; background:#22c55e; animation:pulse 2s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }
.session-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(240px,1fr)); gap:10px; margin-bottom:16px; }
.session-card { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:14px 16px; transition:border-color .15s; }
.session-card:hover { border-color:#2a2a35; }
.session-card .ip { font-family:'JetBrains Mono',monospace; font-size:.88rem; font-weight:700; color:var(--accent); margin-bottom:4px; }
.session-card .meta { font-size:.72rem; color:var(--muted); line-height:1.6; }
.session-card .meta .val { color:var(--text); font-weight:500; }
.threat-meter { height:4px; border-radius:2px; background:#1a1a22; margin-top:8px; overflow:hidden; }
.threat-meter .fill { height:100%; border-radius:2px; }
.detail-panel { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:20px 24px; margin-top:8px; }
.detail-row { display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:16px; margin-bottom:16px; }
.detail-item .dlabel { font-size:.65rem; font-weight:600; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); margin-bottom:3px; }
.detail-item .dvalue { font-size:.85rem; font-weight:600; color:var(--text); font-family:'JetBrains Mono',monospace; }
.path-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:10px; margin-bottom:16px; }
.path-card { background:var(--card); border:1px solid var(--border); border-top:2px solid var(--accent); border-radius:8px; padding:12px 14px; }
.path-card .pt { font-size:.65rem; font-weight:600; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); margin-bottom:4px; }
.path-card .pp { font-size:.78rem; font-weight:600; color:var(--accent); margin-bottom:6px; }
.path-card .pl { font-size:.72rem; color:var(--text); font-family:'JetBrains Mono',monospace; background:var(--bg); padding:4px 6px; border-radius:4px; border:1px solid var(--border); word-break:break-all; }
.activity-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:10px; margin-bottom:16px; }
.activity-card { background:var(--card); border:1px solid var(--border); border-radius:8px; padding:14px; text-align:center; }
.activity-card .an { font-size:1.6rem; font-weight:800; font-family:'JetBrains Mono',monospace; }
.activity-card .al { font-size:.7rem; font-weight:600; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); margin-top:2px; }
</style>
""", unsafe_allow_html=True)


# ── Helpers ────────────────────────────────────────────────────────────────────
def clean_val(val, fallback="—"):
    if val is None: return fallback
    try:
        if pd.isna(val): return fallback
    except Exception: pass
    s = str(val).strip()
    return fallback if not s or s.lower() in ("nan","none","null","") else s

def get_connection():
    if not os.path.exists(DB_PATH): return None
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def tc(val, lo=20, hi=50):
    if val >= hi: return "#ef4444"
    if val >= lo: return "#f59e0b"
    return "#22c55e"

def tl(val, lo=20, hi=50):
    if val >= hi: return "Critical"
    if val >= lo: return "Suspicious"
    return "Clean"


# ── Plotly ────────────────────────────────────────────────────────────────────
PL = dict(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Inter,sans-serif",size=11,color="#71717a"),
    margin=dict(l=4,r=4,t=28,b=4),
    xaxis=dict(gridcolor="#141418",zerolinecolor="#141418"),
    yaxis=dict(gridcolor="#141418",zerolinecolor="#141418"))
GEO = dict(showcountries=True,countrycolor="#1a1a22",showocean=True,oceancolor="#050507",
    showcoastlines=True,coastlinecolor="#1a1a22",showland=True,landcolor="#0c0c10",
    bgcolor="rgba(0,0,0,0)",projection_type="natural earth")

def plot(**kw):
    d = {**PL}
    d.update(kw)
    return d

def yrev():
    return {**PL.get("yaxis",{}), "autorange":"reversed"}


# ── Session state ─────────────────────────────────────────────────────────────
for k, v in [("drilldown_ip",None),("drilldown_user",None),("drilldown_mitre",None),("selected_session",None)]:
    if k not in st.session_state: st.session_state[k] = v


# ── Connection ────────────────────────────────────────────────────────────────
conn = get_connection()
if conn is None:
    st.warning("Database not initialized."); st.stop()

# ── Sidebar ───────────────────────────────────────────────────────────────────
if FAVICON_PATH and os.path.exists(FAVICON_PATH):
    st.sidebar.image(FAVICON_PATH, width=150)

st.sidebar.title("SOC")
st.sidebar.caption("Blue Cloud Softech Solutions")

st.sidebar.markdown("### Controls")
live_stream = st.sidebar.toggle("Live Stream", value=False)
time_range = st.sidebar.selectbox("Time Range",
    ["Last 15 Minutes","Last 1 Hour","Last 4 Hours","Last 24 Hours","Last 7 Days","All Time"],
    index=5, label_visibility="collapsed")

st.sidebar.markdown("### Drilldown")
_d = any([st.session_state["drilldown_ip"],st.session_state["drilldown_user"],st.session_state["drilldown_mitre"]])
if _d:
    if st.session_state["drilldown_ip"]:    st.sidebar.badge(f"IP: {st.session_state['drilldown_ip']}", icon=":material/gps_fixed:")
    if st.session_state["drilldown_user"]:  st.sidebar.badge(f"User: {st.session_state['drilldown_user']}", icon=":material/person:")
    if st.session_state["drilldown_mitre"]: st.sidebar.badge(f"MITRE: {st.session_state['drilldown_mitre']}", icon=":material/target:")
    if st.sidebar.button("Clear All", use_container_width=True):
        for k in ["drilldown_ip","drilldown_user","drilldown_mitre"]: st.session_state[k] = None
        st.session_state["selected_session"] = None; st.rerun()
else:
    st.sidebar.caption("None active")

st.sidebar.markdown("### Endpoints")
try:
    import urllib.request
    _ip = urllib.request.urlopen("http://169.254.169.254/latest/meta-data/public-ipv4", timeout=1).read().decode()
except Exception:
    try: _ip = urllib.request.urlopen("https://ifconfig.me", timeout=3).read().decode().strip()
    except: _ip = "—"
st.sidebar.code(f"Trap  {_ip}:22\nSSH   {_ip}:22222\nSOC   {_ip}:8501", language=None)

st.sidebar.markdown("### Intel Sources")
st.sidebar.markdown(f"- AbuseIPDB: {'active' if os.getenv('ABUSEIPDB_API_KEY') else 'missing'}")
st.sidebar.markdown(f"- VirusTotal: {'active' if os.getenv('VIRUSTOTAL_API_KEY') else 'missing'}")
st.sidebar.markdown("- GeoIP: ip-api.com")
st.sidebar.markdown("- Clock: IST (UTC+5:30)")


# ── SQL filters (table-qualified to avoid ambiguity in JOINs) ─────────────────
time_sql, time_params = build_time_filter(time_range, col_name="start_time")

dw, dp = [], list(time_params)
if time_sql: dw.append(f"s.{time_sql}")
if st.session_state["drilldown_ip"]:
    dw.append("s.ip = ?"); dp.append(st.session_state["drilldown_ip"])
cwhere = ("WHERE " + " AND ".join(dw)) if dw else ""

aw, ap = [], []
atsql, atp = build_time_filter(time_range, col_name="timestamp")
if atsql: aw.append(atsql); ap.extend(atp)
if st.session_state["drilldown_ip"]: aw.append("ip = ?"); ap.append(st.session_state["drilldown_ip"])
if st.session_state["drilldown_user"]: aw.append("username = ?"); ap.append(st.session_state["drilldown_user"])
aws = ("WHERE " + " AND ".join(aw)) if aw else ""

cw, cp = [], []
ctsql,ctp = build_time_filter(time_range, col_name="timestamp")
if ctsql: cw.append(ctsql); cp.extend(ctp)
if st.session_state["drilldown_ip"]: cw.append("ip = ?"); cp.append(st.session_state["drilldown_ip"])
if st.session_state["drilldown_mitre"]: cw.append("mitre_id = ?"); cp.append(st.session_state["drilldown_mitre"])
cws = ("WHERE " + " AND ".join(cw)) if cw else ""


# ── Header ────────────────────────────────────────────────────────────────────
h1, h2 = st.columns([4,1])
with h1: st.markdown("## SSH Honeypot SOC")
with h2: st.markdown('<div style="text-align:right;padding-top:6px"><span class="status-pill status-live">Port 22 Active</span></div>', unsafe_allow_html=True)


# ── KPI Row ───────────────────────────────────────────────────────────────────
cur = conn.cursor()
try:
    _ts = cur.execute(f"SELECT count(*) FROM sessions s {cwhere}", dp).fetchone()[0]
    _ui = cur.execute(f"SELECT count(DISTINCT s.ip) FROM sessions s {cwhere}", dp).fetchone()[0]
    _ta = cur.execute(f"SELECT count(*) FROM auth_attempts {aws}", ap).fetchone()[0]
    _sa = cur.execute(f"SELECT count(*) FROM auth_attempts {aws} {'AND' if aws else 'WHERE'} status='SUCCESS'", ap).fetchone()[0]
    _tc = cur.execute(f"SELECT count(*) FROM commands {cws}", cp).fetchone()[0]
    _co = cur.execute(f"SELECT count(DISTINCT s.country) FROM sessions s {cwhere} {'AND' if cwhere else 'WHERE'} s.country IS NOT NULL AND s.country != '' AND s.country != 'Unknown'", dp).fetchone()[0]
    _dl = cur.execute(f"SELECT count(*) FROM downloads").fetchone()[0]
    _rl = cur.execute(f"SELECT count(*) FROM raw_logs").fetchone()[0]
except Exception as e:
    st.error(f"Query error: {e}"); st.stop()

c1,c2,c3,c4,c5,c6,c7,c8 = st.columns(8)
c1.metric("Sessions", f"{_ts:,}")
c2.metric("IPs", f"{_ui:,}")
c3.metric("Auth Trials", f"{_ta:,}")
c4.metric("Breached", f"{_sa:,}")
c5.metric("Commands", f"{_tc:,}")
c6.metric("Countries", f"{_co:,}")
c7.metric("Downloads", f"{_dl:,}")
c8.metric("Raw Events", f"{_rl:,}")


# ── Activity Recorded & Log Storage ───────────────────────────────────────────
st.markdown("### Activity Recorded")

_act_types = pd.read_sql_query("""
    SELECT event_category as cat, count(*) as n FROM raw_logs
    GROUP BY event_category ORDER BY n DESC
""", conn)

_act_html = '<div class="activity-grid">'
for _, r in _act_types.iterrows():
    _act_html += f'<div class="activity-card"><div class="an" style="color:var(--accent)">{int(r["n"]):,}</div><div class="al">{clean_val(r["cat"],"Other")}</div></div>'
_act_html += '</div>'
st.markdown(_act_html, unsafe_allow_html=True)

st.markdown("### Log Storage Paths")

# Detect actual paths from env or container defaults
_cowrie_log = os.getenv("COWRIE_JSON_PATH", "/cowrie/var/log/cowrie/cowrie.json")
_tty_dir = os.getenv("TTY_LOG_PATH", "/opt/cowrie/cowrie-git/var/lib/cowrie/tty")
_dl_dir = os.getenv("DOWNLOAD_PATH", "/opt/cowrie/cowrie-git/var/lib/cowrie/downloads")
_db_path = os.getenv("DATABASE_PATH", "/app/data/honeypot.db")

# Count TTY files
_tty_count = len(glob.glob(os.path.join(_tty_dir, "*.log"))) if os.path.isdir(_tty_dir) else 0
_dl_count = len(glob.glob(os.path.join(_dl_dir, "*"))) if os.path.isdir(_dl_dir) else 0

st.markdown(f"""
<div class="path-grid">
    <div class="path-card">
        <div class="pt">Event Stream</div>
        <div class="pp">Cowrie JSON Log</div>
        <div class="pl">{_cowrie_log}</div>
    </div>
    <div class="path-card">
        <div class="pt">Keystroke Recordings</div>
        <div class="pp">TTY Session Files ({_tty_count} recordings)</div>
        <div class="pl">{_tty_dir}/*.log</div>
    </div>
    <div class="path-card">
        <div class="pt">Captured Payloads</div>
        <div class="pp">Malware Downloads ({_dl_count} files)</div>
        <div class="pl">{_dl_dir}/</div>
    </div>
    <div class="path-card">
        <div class="pt">SOC Database</div>
        <div class="pp">SQLite Analytical Store</div>
        <div class="pl">{_db_path}</div>
    </div>
</div>
""", unsafe_allow_html=True)

st.divider()


# ── Session Inspector ─────────────────────────────────────────────────────────
st.markdown("### Session Inspector")

session_list = pd.read_sql_query(f"""
    SELECT s.session_id, s.ip, s.country, s.city, s.start_time_ist,
           s.duration, s.abuse_score, s.total_reports, s.usage_type, s.asn, s.isp,
           s.client_version, s.ciphers, s.terminal_size,
           COALESCE(s.vt_malicious,0) as vt_malicious,
           COALESCE(s.vt_suspicious,0) as vt_suspicious,
           COALESCE(s.total_attempts,0) as total_attempts,
           COALESCE(s.total_commands,0) as total_commands
    FROM sessions s {cwhere}
    ORDER BY (COALESCE(s.total_attempts,0) + COALESCE(s.total_commands,0)) DESC, s.start_time DESC
    LIMIT 50
""", conn, params=dp)

if session_list.empty:
    st.info("No sessions in this window.")
else:
    # Card grid — sorted by most active
    cards = '<div class="session-grid">'
    for _, r in session_list.head(12).iterrows():
        abuse = int(r["abuse_score"] or 0)
        atts = int(r["total_attempts"] or 0)
        cmds = int(r["total_commands"] or 0)
        dur = float(r["duration"] or 0)
        loc = f"{clean_val(r['city'])}, {clean_val(r['country'])}"
        pct = min(abuse, 100)
        cards += f"""
        <div class="session-card">
            <div class="ip">{r['ip']}</div>
            <div class="meta">
                {loc}<br>
                <span class="val">{clean_val(r['start_time_ist'])}</span><br>
                <span style="color:var(--amber)">{atts} auth</span> · <span style="color:var(--accent)">{cmds} cmds</span> · {dur:.0f}s<br>
                <span style="color:{tc(abuse)};font-weight:600">{tl(abuse)} · {abuse}%</span>
            </div>
            <div class="threat-meter"><div class="fill" style="width:{pct}%;background:{tc(abuse)}"></div></div>
        </div>"""
    cards += '</div>'
    st.markdown(cards, unsafe_allow_html=True)

    # Select for detail
    sel = st.selectbox("Inspect session", session_list["session_id"].tolist(),
        format_func=lambda sid: f"{session_list[session_list['session_id']==sid].iloc[0]['ip']}  ·  {session_list[session_list['session_id']==sid].iloc[0]['start_time_ist']}  ·  {int(session_list[session_list['session_id']==sid].iloc[0]['total_attempts'])+int(session_list[session_list['session_id']==sid].iloc[0]['total_commands'])} events",
        label_visibility="collapsed")

    if sel:
        m = session_list[session_list["session_id"]==sel].iloc[0]
        abuse_val = int(m["abuse_score"] or 0)
        vt_mal = int(m["vt_malicious"] or 0)
        dur = float(m["duration"] or 0)
        atts = int(m["total_attempts"] or 0)
        cmds = int(m["total_commands"] or 0)

        st.markdown(f"""
<div class="detail-panel">
    <div class="detail-row">
        <div class="detail-item"><div class="dlabel">IP</div><div class="dvalue" style="color:var(--accent)">{m['ip']}</div></div>
        <div class="detail-item"><div class="dlabel">Location</div><div class="dvalue">{clean_val(m['city'])}, {clean_val(m['country'])}</div></div>
        <div class="detail-item"><div class="dlabel">ISP</div><div class="dvalue">{clean_val(m['isp'])}</div></div>
        <div class="detail-item"><div class="dlabel">ASN</div><div class="dvalue">{clean_val(m['asn'])}</div></div>
        <div class="detail-item"><div class="dlabel">Abuse</div><div class="dvalue" style="color:{tc(abuse_val)}">{abuse_val}% {tl(abuse_val)}</div></div>
        <div class="detail-item"><div class="dlabel">VT Malicious</div><div class="dvalue" style="color:{'#ef4444' if vt_mal>0 else '#22c55e'}">{vt_mal}</div></div>
        <div class="detail-item"><div class="dlabel">Duration</div><div class="dvalue">{dur:.1f}s</div></div>
        <div class="detail-item"><div class="dlabel">Auth Attempts</div><div class="dvalue" style="color:var(--amber)">{atts}</div></div>
        <div class="detail-item"><div class="dlabel">Commands</div><div class="dvalue" style="color:var(--accent)">{cmds}</div></div>
        <div class="detail-item"><div class="dlabel">Client</div><div class="dvalue">{clean_val(m['client_version'])}</div></div>
        <div class="detail-item"><div class="dlabel">Terminal</div><div class="dvalue">{clean_val(m['terminal_size'])}</div></div>
        <div class="detail-item"><div class="dlabel">Ciphers</div><div class="dvalue">{clean_val(m['ciphers'])}</div></div>
    </div>
</div>
""", unsafe_allow_html=True)

        st.link_button("Check on VirusTotal", f"https://www.virustotal.com/gui/ip-address/{m['ip']}", use_container_width=False)

        t1, t2, t3, t4 = st.tabs(["Commands", "Auth Events", "Full Session Timeline", "Raw JSON"])
        with t1:
            cmds_df = pd.read_sql_query("""
                SELECT timestamp_ist as "Time", command_text as "Command",
                       mitre_id as "MITRE", mitre_technique as "Technique", mitre_tactic as "Tactic"
                FROM commands WHERE session_id = ? ORDER BY id ASC
            """, conn, params=(sel,))
            if not cmds_df.empty: st.dataframe(cmds_df, use_container_width=True, hide_index=True)
            else: st.caption("No commands executed.")
        with t2:
            auths = pd.read_sql_query("""
                SELECT timestamp_ist as "Time", username as "User",
                       password as "Password", status as "Status"
                FROM auth_attempts WHERE session_id = ? ORDER BY id ASC
            """, conn, params=(sel,))
            if not auths.empty: st.dataframe(auths, use_container_width=True, hide_index=True)
            else: st.caption("No auth events.")
        with t3:
            # Full session timeline — all events in chronological order
            timeline = pd.read_sql_query("""
                SELECT timestamp_ist as "Time", event_category as "Event",
                       summary as "Details"
                FROM raw_logs WHERE session_id = ? ORDER BY id ASC
            """, conn, params=(sel,))
            if not timeline.empty:
                st.dataframe(timeline, use_container_width=True, hide_index=True, height=300)
            else: st.caption("No events recorded.")
        with t4:
            raws = pd.read_sql_query("""
                SELECT id, timestamp_ist as time, event_category as cat, summary, raw_json
                FROM raw_logs WHERE session_id = ? ORDER BY id ASC
            """, conn, params=(sel,))
            if not raws.empty:
                for _, r in raws.iterrows():
                    with st.expander(f"{r['time']}  ·  {r['cat']}  ·  {r['summary']}"):
                        try: st.json(json.loads(r["raw_json"]))
                        except: st.code(r["raw_json"], language="json")
            else: st.caption("No raw events.")

st.divider()


# ── Charts Row 1: Map + Country ──────────────────────────────────────────────
st.markdown("### Global Threat Map")

geo_df = pd.read_sql_query(f"""
    SELECT s.ip, s.country, s.city, s.abuse_score,
           c.latitude, c.longitude, COUNT(s.session_id) as hits
    FROM sessions s LEFT JOIN ip_cache c ON s.ip = c.ip
    {cwhere}
    GROUP BY s.ip
    HAVING c.latitude IS NOT NULL AND c.latitude != 0.0
""", conn, params=dp)

gc1, gc2 = st.columns([2.5, 1.5])
with gc1:
    if not geo_df.empty:
        fig = px.scatter_geo(geo_df, lat="latitude", lon="longitude",
            hover_name="ip", size="hits", color="abuse_score",
            color_continuous_scale=["#22c55e","#f59e0b","#ef4444"],
            range_color=[0,100], projection="natural earth",
            hover_data={"country":True,"city":True,"abuse_score":True,"hits":True})
        fig.update_geos(**GEO)
        fig.update_layout(**plot(height=350, coloraxis_colorbar=dict(title="Abuse %",len=.5)))
        st.plotly_chart(fig, use_container_width=True)
    else: st.info("No geo data.")

with gc2:
    cdf = pd.read_sql_query(f"""
        SELECT s.country, COUNT(*) as n FROM sessions s
        {cwhere} {'AND' if cwhere else 'WHERE'} s.country IS NOT NULL AND s.country != ''
        GROUP BY s.country ORDER BY n DESC LIMIT 10
    """, conn, params=dp)
    if not cdf.empty:
        fig = px.bar(cdf, x="n", y="country", orientation="h",
            color="n", color_continuous_scale=["#0e7490","#06b6d4"], labels={"n":"","country":""})
        fig.update_layout(**plot(height=350, showlegend=False, yaxis=yrev()))
        st.plotly_chart(fig, use_container_width=True)
    else: st.caption("No country data.")

st.divider()


# ── Charts Row 2: Auth Analysis ──────────────────────────────────────────────
st.markdown("### Authentication Analysis")

ac1, ac2, ac3 = st.columns([1.2, 1.2, 0.8])
with ac1:
    udf = pd.read_sql_query(f"""
        SELECT username, count(*) as n FROM auth_attempts
        {aws} {'AND' if aws else 'WHERE'} username IS NOT NULL AND username != ''
        GROUP BY username ORDER BY n DESC LIMIT 10
    """, conn, params=ap)
    if not udf.empty:
        fig = px.bar(udf, x="username", y="n", color="n",
            color_continuous_scale=["#0e7490","#06b6d4"], labels={"n":"","username":""})
        fig.update_layout(**plot(height=260, showlegend=False, title="Usernames"))
        st.plotly_chart(fig, use_container_width=True)
        _ul = ["(none)"] + udf["username"].tolist()
        _us = st.selectbox("Drill by username", _ul, key="user_dd", label_visibility="collapsed")
        if _us != "(none)" and _us != st.session_state["drilldown_user"]:
            st.session_state["drilldown_user"] = _us; st.rerun()
    else: st.caption("No auth data.")

with ac2:
    pdf = pd.read_sql_query(f"""
        SELECT password, count(*) as n FROM auth_attempts
        {aws} {'AND' if aws else 'WHERE'} password IS NOT NULL AND password != ''
        GROUP BY password ORDER BY n DESC LIMIT 10
    """, conn, params=ap)
    if not pdf.empty:
        fig = px.bar(pdf, x="password", y="n", color="n",
            color_continuous_scale=["#581c87","#a855f7"], labels={"n":"","password":""})
        fig.update_layout(**plot(height=260, showlegend=False, title="Passwords"))
        st.plotly_chart(fig, use_container_width=True)
    else: st.caption("No password data.")

with ac3:
    rdf = pd.read_sql_query(f"""
        SELECT status, count(*) as n FROM auth_attempts {aws} GROUP BY status
    """, conn, params=ap)
    if not rdf.empty:
        fig = go.Figure(go.Pie(labels=rdf["status"], values=rdf["n"], hole=.6,
            marker=dict(colors=["#ef4444","#22c55e"]), textfont=dict(size=12,color="white")))
        fig.update_layout(**plot(height=260, title="Outcome", showlegend=True,
            legend=dict(orientation="h",yanchor="bottom",y=-.2,x=.5,xanchor="center")))
        st.plotly_chart(fig, use_container_width=True)
    else: st.caption("No outcomes.")

st.divider()


# ── Charts Row 3: MITRE + Malicious Score ────────────────────────────────────
st.markdown("### MITRE ATT&CK & Threat Scoring")

mc1, mc2 = st.columns([1.3, 1])
with mc1:
    mitre_df = pd.read_sql_query(f"""
        SELECT mitre_technique, mitre_id, mitre_tactic, count(*) as n FROM commands
        {cws} {'AND' if cws else 'WHERE'} mitre_id IS NOT NULL
        GROUP BY mitre_id ORDER BY n DESC
    """, conn, params=cp)
    if not mitre_df.empty:
        fig = px.bar(mitre_df, x="n", y="mitre_technique", orientation="h",
            color="n", color_continuous_scale=["#92400e","#f59e0b"],
            hover_data=["mitre_id","mitre_tactic"], labels={"n":"","mitre_technique":""})
        fig.update_layout(**plot(height=320, showlegend=False, yaxis=yrev()))
        st.plotly_chart(fig, use_container_width=True)
        _ml = ["(none)"] + mitre_df["mitre_id"].tolist()
        _ms = st.selectbox("Drill by MITRE", _ml, key="mitre_dd", label_visibility="collapsed")
        if _ms != "(none)" and _ms != st.session_state["drilldown_mitre"]:
            st.session_state["drilldown_mitre"] = _ms; st.rerun()
    else: st.info("No MITRE data.")

with mc2:
    # Abuse score distribution
    score_df = pd.read_sql_query(f"""
        SELECT abuse_score, count(*) as n FROM sessions s
        {cwhere} {'AND' if cwhere else 'WHERE'} abuse_score IS NOT NULL
        GROUP BY abuse_score ORDER BY abuse_score
    """, conn, params=dp)
    if not score_df.empty:
        fig = go.Figure()
        for _, r in score_df.iterrows():
            s = int(r["abuse_score"])
            fig.add_trace(go.Bar(x=[s], y=[int(r["n"])], marker_color=tc(s), name=f"{s}%", showlegend=False))
        fig.update_layout(**plot(height=320, title="Abuse Score Distribution",
            xaxis=dict(title="Abuse %",**PL["xaxis"]), yaxis=dict(title="Sessions",**PL["yaxis"])))
        st.plotly_chart(fig, use_container_width=True)
    else: st.caption("No score data.")

st.divider()


# ── Charts Row 4: Activity Timeline + Country Threat Table ───────────────────
st.markdown("### Activity & Country Intelligence")

tc1, tc2 = st.columns([1.5, 1])
with tc1:
    # Hourly activity timeline
    hourly = pd.read_sql_query("""
        SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour, count(*) as n
        FROM raw_logs
        WHERE timestamp >= datetime('now', '-7 days')
        GROUP BY hour ORDER BY hour
    """, conn)
    if not hourly.empty:
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=hourly["hour"], y=hourly["n"], mode="lines+markers",
            line=dict(color="#06b6d4", width=2), marker=dict(size=4, color="#06b6d4"),
            fill="tozeroy", fillcolor="rgba(6,182,212,0.08)"))
        fig.update_layout(**plot(height=280, title="Events per Hour (7 days)",
            xaxis=dict(gridcolor="#141418",zerolinecolor="#141418",tickangle=-45),
            yaxis=dict(gridcolor="#141418",zerolinecolor="#141418")))
        st.plotly_chart(fig, use_container_width=True)
    else: st.caption("No timeline data.")

with tc2:
    # Country threat table
    country_intel = pd.read_sql_query(f"""
        SELECT s.country as "Country",
               COUNT(DISTINCT s.ip) as "IPs",
               COUNT(*) as "Sessions",
               SUM(CASE WHEN aa.status='SUCCESS' THEN 1 ELSE 0 END) as "Breaches",
               ROUND(AVG(s.abuse_score),0) as "Avg Abuse"
        FROM sessions s
        LEFT JOIN auth_attempts aa ON s.session_id = aa.session_id
        {cwhere} {'AND' if cwhere else 'WHERE'} s.country IS NOT NULL AND s.country != ''
        GROUP BY s.country ORDER BY "Sessions" DESC LIMIT 10
    """, conn, params=dp)
    if not country_intel.empty:
        st.dataframe(country_intel, use_container_width=True, hide_index=True, height=280)
    else: st.caption("No country data.")

st.divider()


# ── Recent Commands ───────────────────────────────────────────────────────────
st.markdown("### Recent Commands")

rc = pd.read_sql_query(f"""
    SELECT timestamp_ist as "Time", ip as "IP",
           command_text as "Command", mitre_id as "MITRE",
           mitre_technique as "Technique", mitre_tactic as "Tactic"
    FROM commands {cws} ORDER BY id DESC LIMIT 20
""", conn, params=cp)
if not rc.empty:
    st.dataframe(rc, use_container_width=True, hide_index=True)
else: st.caption("No commands captured.")

st.divider()


# ── Event Log ─────────────────────────────────────────────────────────────────
st.markdown("### Event Log")

raw_df = pd.read_sql_query("""
    SELECT id, timestamp_ist as "Time", event_category as "Category",
           ip as "IP", summary as "Summary", raw_json
    FROM raw_logs ORDER BY id DESC LIMIT 200
""", conn)

if not raw_df.empty:
    st.dataframe(raw_df.drop(columns=["raw_json"]), use_container_width=True, hide_index=True, height=300)
    with st.expander("Inspect Raw JSON"):
        _ids = raw_df["id"].tolist()
        _rid = st.selectbox("Entry", _ids,
            format_func=lambda x: f"#{x}  {raw_df.loc[raw_df['id']==x,'Time'].values[0]}  {raw_df.loc[raw_df['id']==x,'Category'].values[0]}",
            label_visibility="collapsed")
        if _rid:
            _r = raw_df[raw_df["id"]==_rid].iloc[0]
            try: st.json(json.loads(_r["raw_json"]))
            except: st.code(_r["raw_json"], language="json")
else: st.info("No events.")


# ── Export ─────────────────────────────────────────────────────────────────────
st.markdown("### Export")
ex1, ex2, ex3 = st.columns(3)
with ex1:
    _s = pd.read_sql_query(f"SELECT * FROM sessions s {cwhere}", conn, params=dp)
    st.download_button("Sessions CSV", _s.to_csv(index=False).encode(), "sessions.csv", use_container_width=True)
with ex2:
    _c = pd.read_sql_query(f"SELECT * FROM commands {cws}", conn, params=cp)
    st.download_button("Commands CSV", _c.to_csv(index=False).encode(), "commands.csv", use_container_width=True)
with ex3:
    _a = pd.read_sql_query(f"SELECT * FROM auth_attempts {aws}", conn, params=ap)
    st.download_button("Auth CSV", _a.to_csv(index=False).encode(), "auth_attempts.csv", use_container_width=True)


# ── Footer ────────────────────────────────────────────────────────────────────
st.caption(f"BCSSL SOC  ·  {_ts:,} sessions  ·  {_ui:,} IPs  ·  {_tc:,} commands  ·  {_dl:,} downloads  ·  {_rl:,} raw events  ·  IST {datetime.now(timezone(timedelta(hours=5,minutes=30))).strftime('%H:%M:%S')}")

if live_stream:
    import time; time.sleep(1.5); st.rerun()
