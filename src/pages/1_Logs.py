"""
BCSSL Honeypot - Central Event Log Explorer (/logs).
Full end-to-end audit log viewer with Splunk-style time filtering,
event categorization, IST timestamps, free-text search, and raw JSON forensics.
"""

import json
import os
import sqlite3
import pandas as pd
import streamlit as st
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

load_dotenv()
DB_PATH = os.getenv("DATABASE_PATH", "data/honeypot.db")
FAVICON_PATH = "assets/bcss_logo.png" if os.path.exists("assets/bcss_logo.png") else None

st.set_page_config(
    page_title="BCSSL - Central Event Log Explorer (/logs)",
    page_icon=FAVICON_PATH or "BCSS",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Dark / Black theme without emojis
st.markdown("""
<style>
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    .filter-card {
        background-color: #161f30;
        border: 1px solid #243048;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 16px;
    }
    .log-badge {
        display: inline-block;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
        font-family: monospace;
    }
    .badge-connect { background-color: #1e3a8a; color: #93c5fd; }
    .badge-login-success { background-color: #064e3b; color: #6ee7b7; }
    .badge-login-failed { background-color: #7f1d1d; color: #fca5a5; }
    .badge-command { background-color: #431407; color: #fdba74; }
    .badge-kex { background-color: #312e81; color: #c7d2fe; }
    .badge-other { background-color: #334155; color: #cbd5e1; }
</style>
""", unsafe_allow_html=True)


def get_connection():
    if not os.path.exists(DB_PATH):
        return None
    return sqlite3.connect(DB_PATH, check_same_thread=False)


# Sidebar controls
st.sidebar.title("Navigation")
st.sidebar.caption("BCSSL Threat Intelligence & SOC")
st.sidebar.markdown("""
* **Main Dashboard**: Navigate via menu above
* **Log Explorer**: `/logs` (Active)
""")

live_stream = st.sidebar.checkbox("Live Stream (Update every 1.5s)", value=False)
st.sidebar.markdown("---")

st.title("Central Event Log Explorer (/logs)")
st.caption("Complete chronological forensic event stream across all honeypot sensors with IST timestamps.")

conn = get_connection()
if conn is None:
    st.warning("Database not initialized yet.")
    st.stop()

# --- SPLUNK-STYLE TIME RANGE & QUERY FILTERS ---
st.markdown('<div class="filter-card">', unsafe_allow_html=True)
col_time, col_event, col_ip, col_search = st.columns([1.5, 1.8, 1.5, 2.2])

with col_time:
    time_filter = st.selectbox(
        "Time Range",
        options=["Last 15 Minutes", "Last 1 Hour", "Last 4 Hours", "Last 24 Hours", "Last 7 Days", "All Time"],
        index=3
    )

with col_event:
    event_types = ["All Events", "cowrie.session.connect", "cowrie.client.version", "cowrie.client.kex",
                   "cowrie.login.success", "cowrie.login.failed", "cowrie.command.input",
                   "cowrie.session.file_download", "cowrie.session.closed"]
    selected_event = st.selectbox("Event Category", options=event_types, index=0)

with col_ip:
    filter_ip = st.text_input("Filter by IP", value="", placeholder="e.g. 18.60.33.150")

with col_search:
    search_keyword = st.text_input("Search (Command / Raw JSON)", value="", placeholder="e.g. uname, wget, root")
st.markdown('</div>', unsafe_allow_html=True)

# Build SQL query with filters
where_clauses = []
params = []

# Time filter
now = datetime.now(timezone.utc)
delta_map = {
    "Last 15 Minutes": timedelta(minutes=15),
    "Last 1 Hour": timedelta(hours=1),
    "Last 4 Hours": timedelta(hours=4),
    "Last 24 Hours": timedelta(hours=24),
    "Last 7 Days": timedelta(days=7),
}
if time_filter != "All Time" and time_filter in delta_map:
    cutoff = (now - delta_map[time_filter]).isoformat()
    where_clauses.append("timestamp >= ?")
    params.append(cutoff)

if selected_event != "All Events":
    where_clauses.append("event_id = ?")
    params.append(selected_event)

if filter_ip.strip():
    where_clauses.append("ip LIKE ?")
    params.append(f"%{filter_ip.strip()}%")

if search_keyword.strip():
    where_clauses.append("(raw_json LIKE ? OR summary LIKE ?)")
    params.append(f"%{search_keyword.strip()}%")
    params.append(f"%{search_keyword.strip()}%")

where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

query = f"""
    SELECT id, timestamp_ist as "Timestamp (IST)", event_id as "Event Type", 
           ip as "Attacker IP", session_id as "Session ID", summary as "Summary", raw_json
    FROM raw_logs
    {where_sql}
    ORDER BY id DESC
    LIMIT 250
"""

logs_df = pd.read_sql_query(query, conn, params=params)

# Metrics bar
m1, m2, m3, m4 = st.columns(4)
m1.metric("Matching Events", f"{len(logs_df):,}")
m2.metric("Unique Sessions", f"{logs_df['Session ID'].nunique() if not logs_df.empty else 0:,}")
m3.metric("Unique Attacker IPs", f"{logs_df['Attacker IP'].nunique() if not logs_df.empty else 0:,}")
m4.metric("Active Filters", f"{len(where_clauses)}")

st.markdown("---")

if logs_df.empty:
    st.info("No log events found matching the specified time range and filter criteria.")
else:
    # Display structured table
    display_df = logs_df.drop(columns=["raw_json", "id"])
    st.dataframe(display_df, use_container_width=True, height=420)

    # Detailed Forensic JSON Inspector
    st.subheader("Raw JSON Event Inspector")
    selected_log_id = st.selectbox(
        "Select Log Entry ID to Inspect Exact Raw Payload:",
        options=logs_df["id"].tolist(),
        format_func=lambda x: f"ID #{x} | {logs_df.loc[logs_df['id'] == x, 'Timestamp (IST)'].values[0]} | {logs_df.loc[logs_df['id'] == x, 'Event Type'].values[0]} | IP: {logs_df.loc[logs_df['id'] == x, 'Attacker IP'].values[0]}"
    )

    if selected_log_id:
        row = logs_df[logs_df["id"] == selected_log_id].iloc[0]
        c_left, c_right = st.columns([1, 2])
        with c_left:
            st.markdown(f"**Timestamp (IST):** `{row['Timestamp (IST)']}`")
            st.markdown(f"**Event Type:** `{row['Event Type']}`")
            st.markdown(f"**Attacker IP:** `{row['Attacker IP']}`")
            st.markdown(f"**Session ID:** `{row['Session ID']}`")
            st.markdown(f"**Summary:** {row['Summary']}")

        with c_right:
            st.markdown("**Complete Raw JSON Recorded on Disk:**")
            try:
                parsed_json = json.loads(row["raw_json"])
                st.json(parsed_json)
            except Exception:
                st.code(row["raw_json"], language="json")

    # Export Section
    st.markdown("---")
    exp_col1, exp_col2 = st.columns(2)
    with exp_col1:
        st.download_button(
            label="Export Filtered Logs as CSV",
            data=logs_df.to_csv(index=False).encode('utf-8'),
            file_name="bcssl_honeypot_logs.csv",
            mime="text/csv"
        )
    with exp_col2:
        st.download_button(
            label="Export Filtered Logs as JSON Lines",
            data="\n".join(logs_df["raw_json"].tolist()).encode('utf-8'),
            file_name="bcssl_honeypot_raw.jsonl",
            mime="application/json"
        )

# Live stream autorefresh (under 2 seconds)
if live_stream:
    import time
    time.sleep(1.5)
    st.rerun()
