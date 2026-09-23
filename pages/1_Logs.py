"""
SSH Honeypot — Event Log Explorer
Full forensic event viewer with time filtering, category search, and raw JSON inspection.
"""

import json, os, sys
from pathlib import Path
import sqlite3
import pandas as pd
import streamlit as st
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

_cur_dir = Path(__file__).resolve().parent
_root_dir = _cur_dir.parent if _cur_dir.name in ("src", "pages") else _cur_dir
if str(_root_dir) not in sys.path:
    sys.path.insert(0, str(_root_dir))

from src.db import get_honeypot_event_type, to_ist_str, init_db

load_dotenv()
DB_PATH = os.getenv("DATABASE_PATH", "data/honeypot.db")

# ── Page config ───────────────────────────────────────────────────────────────
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
    _img = Image.open(FAVICON_PATH) if FAVICON_PATH and os.path.exists(FAVICON_PATH) else None
    if _img:
        _fav = _img.copy()
        _fav.thumbnail((64, 64))
        if _fav.mode == 'RGBA':
            _bg = Image.new('RGB', _fav.size, (5,5,7))
            _bg.paste(_fav, mask=_fav.split()[3])
            _fav = _bg
        _fi = _fav
        _si = _img
    else:
        _fi = None; _si = None
except:
    _fi = None; _si = None

st.set_page_config(page_title="Event Log · SOC", page_icon=_fi or ":scroll:", layout="wide", initial_sidebar_state="expanded")

# ── Theme (same as main dashboard) ────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
:root { --bg:#0a0a0f; --surface:#111118; --border:#1e1e2a; --text:#e4e4e7; --muted:#71717a; --accent:#06b6d4; }
.stApp, .stApp header, [data-testid="stSidebar"] { background: var(--bg) !important; font-family: 'Inter', sans-serif !important; }
.stMarkdown, .stMarkdown p, .stMarkdown span, [data-testid="stSidebar"] .stMarkdown { color: var(--text) !important; }
[data-testid="stSidebar"] { border-right: 1px solid var(--border) !important; }
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h1 { font-size: 1.1rem !important; font-weight: 700 !important; }
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h3 { font-size: 0.75rem !important; font-weight: 600 !important; text-transform: uppercase !important; letter-spacing: 0.08em !important; color: var(--muted) !important; margin-top: 1rem !important; }
h2, .stMarkdown h2 { font-size: 1rem !important; font-weight: 700 !important; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }
[data-testid="stMetric"] { background: var(--surface) !important; border: 1px solid var(--border) !important; border-radius: 10px !important; padding: 1rem 1.2rem !important; }
[data-testid="stMetric"] label { font-size: 0.7rem !important; font-weight: 600 !important; text-transform: uppercase !important; letter-spacing: 0.06em !important; color: var(--muted) !important; }
[data-testid="stMetric"] [data-testid="stMetricValue"] { font-size: 1.6rem !important; font-weight: 800 !important; font-family: 'JetBrains Mono', monospace !important; }
.stTabs [data-baseweb="tab-list"] { gap: 0 !important; border-bottom: 1px solid var(--border) !important; }
.stTabs [data-baseweb="tab"] { font-size: 0.8rem !important; font-weight: 500 !important; color: var(--muted) !important; }
.stTabs [aria-selected="true"] { color: var(--accent) !important; border-bottom-color: var(--accent) !important; }
[data-testid="stDataFrame"] { border: 1px solid var(--border) !important; border-radius: 8px !important; }
[data-baseweb="select"] > div, [data-baseweb="input"] > div { background: var(--surface) !important; border-color: var(--border) !important; border-radius: 8px !important; }
.stDownloadButton button { border-radius: 8px !important; font-weight: 600 !important; }
hr { border-color: var(--border) !important; }
details { border: 1px solid var(--border) !important; border-radius: 8px !important; background: var(--surface) !important; }
</style>
""", unsafe_allow_html=True)


def get_connection():
    if not os.path.exists(DB_PATH):
        return None
    init_db(DB_PATH)
    return sqlite3.connect(DB_PATH, check_same_thread=False)


# ── Event categories ──────────────────────────────────────────────────────────
CATEGORIES = {
    "All Events": None,
    "Auth Success": "cowrie.login.success",
    "Auth Failed": "cowrie.login.failed",
    "Command Input": "cowrie.command.input",
    "File Download": "cowrie.session.file_download",
    "Connection": "cowrie.session.connect",
    "SSH Banner": "cowrie.client.version",
    "KEX Handshake": "cowrie.client.kex",
    "Terminal Size": "cowrie.client.size",
    "TCP Tunnel": "cowrie.direct-tcpip.request",
    "TTY Recording": "cowrie.log.closed",
    "Session Closed": "cowrie.session.closed",
}


# ── Sidebar ───────────────────────────────────────────────────────────────────
if FAVICON_PATH and os.path.exists(FAVICON_PATH):
    st.sidebar.image(_si if _si else FAVICON_PATH, width=160)
st.sidebar.title("SOC")
st.sidebar.caption("Blue Cloud Softech Solutions")

st.sidebar.markdown("### Filters")
live = st.sidebar.toggle("Live Stream", value=False)

st.sidebar.markdown("### Sensor")
st.sidebar.markdown("- Port 22 (Cowrie)\n- Timezone: IST")


# ── Connection ────────────────────────────────────────────────────────────────
conn = get_connection()
if conn is None:
    st.warning("Database not initialized.")
    st.stop()


# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("## Event Log Explorer")
st.caption("Full forensic event stream with filtering and raw JSON inspection.")
st.divider()


# ── Filter bar ────────────────────────────────────────────────────────────────
fc1, fc2, fc3, fc4 = st.columns([1, 1.5, 1, 1.5])
with fc1:
    time_f = st.selectbox("Time", ["Last 15 Minutes", "Last 1 Hour", "Last 4 Hours", "Last 24 Hours", "Last 7 Days", "All Time"], index=5, label_visibility="collapsed")
with fc2:
    cat_f = st.selectbox("Category", list(CATEGORIES.keys()), index=0, label_visibility="collapsed")
with fc3:
    ip_f = st.text_input("IP filter", placeholder="IP address", label_visibility="collapsed")
with fc4:
    search_f = st.text_input("Search", placeholder="Search commands or JSON…", label_visibility="collapsed")


# ── Build query ───────────────────────────────────────────────────────────────
where, params = [], []
now = datetime.now(timezone.utc)
deltas = {"Last 15 Minutes": 15, "Last 1 Hour": 60, "Last 4 Hours": 240, "Last 24 Hours": 1440, "Last 7 Days": 10080}
if time_f in deltas:
    where.append("timestamp >= ?")
    params.append((now - timedelta(minutes=deltas[time_f])).isoformat())

cat_id = CATEGORIES.get(cat_f)
if cat_id:
    where.append("event_id = ?")
    params.append(cat_id)
if ip_f.strip():
    where.append("ip LIKE ?")
    params.append(f"%{ip_f.strip()}%")
if search_f.strip():
    where.append("(raw_json LIKE ? OR summary LIKE ?)")
    params += [f"%{search_f.strip()}%"] * 2

wsql = ("WHERE " + " AND ".join(where)) if where else ""

df = pd.read_sql_query(f"""
    SELECT id, COALESCE(timestamp_ist, timestamp) as ts,
           COALESCE(event_category, event_id) as cat,
           COALESCE(ip, '—') as ip, session_id as sid,
           COALESCE(summary, event_id) as summary,
           event_id, raw_json
    FROM raw_logs {wsql} ORDER BY id DESC LIMIT 300
""", conn, params=params)

if not df.empty:
    df["cat"] = df["event_id"].apply(get_honeypot_event_type)
    df["ts"] = df["ts"].apply(to_ist_str)


# ── Metrics ───────────────────────────────────────────────────────────────────
m1, m2, m3, m4 = st.columns(4)
m1.metric("Events", f"{len(df):,}")
m2.metric("Sessions", f"{df['sid'].nunique() if not df.empty else 0:,}")
m3.metric("Source IPs", f"{df['ip'].nunique() if not df.empty else 0:,}")
m4.metric("Filters", f"{len(where)}")

st.divider()


# ── Table ─────────────────────────────────────────────────────────────────────
if df.empty:
    st.info("No events match the current filters.")
else:
    st.dataframe(
        df[["ts", "cat", "ip", "sid", "summary"]].rename(columns={
            "ts": "Time", "cat": "Category", "ip": "IP", "sid": "Session", "summary": "Summary"
        }),
        use_container_width=True, hide_index=True, height=440,
    )

    st.divider()
    st.markdown("### Raw JSON Inspector")

    _ids = df["id"].tolist()
    _sel = st.selectbox("Entry", _ids, format_func=lambda x: f"#{x}  ·  {df.loc[df['id']==x, 'ts'].values[0]}  ·  {df.loc[df['id']==x, 'cat'].values[0]}  ·  {df.loc[df['id']==x, 'ip'].values[0]}", label_visibility="collapsed")
    if _sel:
        row = df[df["id"] == _sel].iloc[0]
        ic1, ic2 = st.columns([1, 2])
        with ic1:
            st.markdown(f"**Time:** `{row['ts']}`")
            st.markdown(f"**Category:** `{row['cat']}`")
            st.markdown(f"**IP:** `{row['ip']}`")
            st.markdown(f"**Session:** `{row['sid']}`")
            st.markdown(f"**Summary:** {row['summary']}")
        with ic2:
            try:
                st.json(json.loads(row["raw_json"]))
            except Exception:
                st.code(row["raw_json"], language="json")

    st.divider()
    st.markdown("### Export")

    ex1, ex2 = st.columns(2)
    with ex1:
        st.download_button("CSV", df.drop(columns=["raw_json"]).to_csv(index=False).encode(), "events.csv", use_container_width=True)
    with ex2:
        st.download_button("JSON Lines", "\n".join(df["raw_json"].tolist()).encode(), "events.jsonl", use_container_width=True)


# ── Live refresh ──────────────────────────────────────────────────────────────
if live:
    import time
    time.sleep(1.5)
    st.rerun()
