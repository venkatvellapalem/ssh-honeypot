"""
Interactive Enterprise SOC Web Dashboard.
Built with Streamlit and Plotly for real-time Honeypot Threat Intelligence Visualization,
MITRE ATT&CK mapping, and student attack investigation.
"""

import os
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from dotenv import load_dotenv

load_dotenv()
DB_PATH = os.getenv("DATABASE_PATH", "data/honeypot.db")

st.set_page_config(
    page_title="SSH Honeypot Threat Intel SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for SOC aesthetic
st.markdown("""
<style>
    .metric-card {
        background-color: #1e2530;
        border: 1px solid #2e3846;
        border-radius: 8px;
        padding: 15px;
        text-align: center;
    }
    .metric-val {
        font-size: 28px;
        font-weight: bold;
        color: #4da6ff;
    }
    .metric-label {
        font-size: 14px;
        color: #a0aec0;
    }
</style>
""", unsafe_allow_html=True)


def get_connection():
    if not os.path.exists(DB_PATH):
        return None
    return sqlite3.connect(DB_PATH, check_same_thread=False)


# Sidebar controls
st.sidebar.title("🛡️ SOC Operations")
st.sidebar.caption("Enterprise Cowrie Honeypot Threat Feed")
auto_refresh = st.sidebar.checkbox("Auto-refresh (every 10s)", value=False)
if auto_refresh:
    st.empty()
    time_sleep = 10
    # Streamlit rerun handled at end of script

st.sidebar.markdown("---")
st.sidebar.subheader("Threat Intel Config")
api_status = "Active ✅" if os.getenv("ABUSEIPDB_API_KEY") else "Key Missing ⚠️"
st.sidebar.info(f"AbuseIPDB Status: **{api_status}**")
st.sidebar.caption("BCSSL Cybersecurity Internship - Lab 04")

conn = get_connection()

if conn is None:
    st.warning("Database not yet initialized or waiting for first connection. Run the honeypot to generate data!")
    st.stop()

# --- TOP SUMMARY METRICS ---
st.title("🛡️ Enterprise SSH Honeypot SOC & Threat Intelligence Center")

cur = conn.cursor()
try:
    total_sessions = cur.execute("SELECT count(*) FROM sessions").fetchone()[0]
    unique_ips = cur.execute("SELECT count(DISTINCT ip) FROM sessions").fetchone()[0]
    total_auth = cur.execute("SELECT count(*) FROM auth_attempts").fetchone()[0]
    success_auth = cur.execute("SELECT count(*) FROM auth_attempts WHERE status = 'SUCCESS'").fetchone()[0]
    total_cmds = cur.execute("SELECT count(*) FROM commands").fetchone()[0]
    total_countries = cur.execute("SELECT count(DISTINCT country) FROM sessions WHERE country IS NOT NULL AND country != 'Unknown'").fetchone()[0]
except Exception as e:
    st.error(f"Error querying statistics: {e}")
    st.stop()

col1, col2, col3, col4, col5, col6 = st.columns(6)
col1.metric("Total Sessions", f"{total_sessions:,}")
col2.metric("Attacker IPs", f"{unique_ips:,}")
col3.metric("Brute-Force Logins", f"{total_auth:,}")
col4.metric("Breached Shells", f"{success_auth:,}")
col5.metric("Commands Captured", f"{total_cmds:,}")
col6.metric("Countries", f"{total_countries:,}")

st.markdown("---")

# --- ROW 1: GEOSPATIAL THREAT MAP & COUNTRY BREAKDOWN ---
st.subheader("🌍 Real-time Attacker Geolocation & Threat Reputation")

geo_df = pd.read_sql_query("""
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
    WHERE c.latitude IS NOT NULL AND c.latitude != 0.0
    GROUP BY s.ip
""", conn)

col_map, col_country = st.columns([3, 1])

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
            title="Global Attacker Distribution (Colored by AbuseIPDB Confidence Score)"
        )
        fig_map.update_geos(showcountries=True, countrycolor="#444", showocean=True, oceancolor="#111827", bgcolor="#0e1117")
        fig_map.update_layout(margin={"r": 0, "t": 40, "l": 0, "b": 0}, height=450, paper_bgcolor="#0e1117")
        st.plotly_chart(fig_map, use_container_width=True)
    else:
        st.info("No external geographic attacks recorded yet. Waiting for inbound traffic or run test simulation.")

with col_country:
    country_df = pd.read_sql_query("""
        SELECT country, COUNT(*) as sessions 
        FROM sessions 
        WHERE country IS NOT NULL AND country != '' 
        GROUP BY country 
        ORDER BY sessions DESC 
        LIMIT 8
    """, conn)
    if not country_df.empty:
        fig_country = px.bar(
            country_df, 
            x="sessions", 
            y="country", 
            orientation="h",
            title="Top Attacker Nations",
            color="sessions",
            color_continuous_scale="Blues"
        )
        fig_country.update_layout(yaxis={'categoryorder': 'total ascending'}, height=450, showlegend=False)
        st.plotly_chart(fig_country, use_container_width=True)
    else:
        st.caption("Waiting for country data...")

st.markdown("---")

# --- ROW 2: BRUTE-FORCE CREDENTIAL INTELLIGENCE ---
st.subheader("🔑 Authentication & Credential Harvest Analysis")

col_user, col_pass, col_ratio = st.columns([1.5, 1.5, 1])

with col_user:
    user_df = pd.read_sql_query("""
        SELECT username, count(*) as count 
        FROM auth_attempts 
        WHERE username IS NOT NULL AND username != '' 
        GROUP BY username 
        ORDER BY count DESC 
        LIMIT 10
    """, conn)
    if not user_df.empty:
        fig_user = px.bar(user_df, x="username", y="count", title="Top Targeted Usernames", color="count", color_continuous_scale="Viridis")
        fig_user.update_layout(height=320)
        st.plotly_chart(fig_user, use_container_width=True)
    else:
        st.caption("No login attempts recorded yet.")

with col_pass:
    pass_df = pd.read_sql_query("""
        SELECT password, count(*) as count 
        FROM auth_attempts 
        WHERE password IS NOT NULL AND password != '' 
        GROUP BY password 
        ORDER BY count DESC 
        LIMIT 10
    """, conn)
    if not pass_df.empty:
        fig_pass = px.bar(pass_df, x="password", y="count", title="Top Attempted Passwords", color="count", color_continuous_scale="Plasma")
        fig_pass.update_layout(height=320)
        st.plotly_chart(fig_pass, use_container_width=True)
    else:
        st.caption("No passwords captured yet.")

with col_ratio:
    ratio_df = pd.read_sql_query("""
        SELECT status, count(*) as count 
        FROM auth_attempts 
        GROUP BY status
    """, conn)
    if not ratio_df.empty:
        fig_ratio = px.pie(ratio_df, names="status", values="count", title="Auth Success vs Failure", color="status",
                           color_discrete_map={"FAILED": "#ef4444", "SUCCESS": "#22c55e"}, hole=0.4)
        fig_ratio.update_layout(height=320)
        st.plotly_chart(fig_ratio, use_container_width=True)
    else:
        st.caption("No authentication data.")

st.markdown("---")

# --- ROW 3: MITRE ATT&CK MAPPING & EXECUTED COMMANDS ---
st.subheader("🎯 MITRE ATT&CK TTP Classification & Command Feed")

col_mitre, col_cmds = st.columns([1.2, 2.8])

with col_mitre:
    mitre_df = pd.read_sql_query("""
        SELECT mitre_technique, mitre_id, count(*) as count 
        FROM commands 
        WHERE mitre_id IS NOT NULL 
        GROUP BY mitre_id 
        ORDER BY count DESC
    """, conn)
    if not mitre_df.empty:
        fig_mitre = px.bar(
            mitre_df,
            x="count",
            y="mitre_technique",
            orientation="h",
            color="count",
            color_continuous_scale="Purples",
            title="Observed MITRE ATT&CK Techniques",
            hover_data={"mitre_id": True}
        )
        fig_mitre.update_layout(yaxis={'categoryorder': 'total ascending'}, height=400)
        st.plotly_chart(fig_mitre, use_container_width=True)
    else:
        st.info("No commands mapped to MITRE yet.")

with col_cmds:
    recent_cmds = pd.read_sql_query("""
        SELECT timestamp, ip, command_text, mitre_id, mitre_technique, mitre_tactic
        FROM commands 
        ORDER BY id DESC 
        LIMIT 12
    """, conn)
    if not recent_cmds.empty:
        st.write("Recent Executed Attacker Commands")
        st.dataframe(recent_cmds, use_container_width=True, height=360)
    else:
        st.caption("No interactive commands recorded yet.")

st.markdown("---")

# --- ROW 4: FORENSIC INVESTIGATION & ATTACKER REPLAY ---
st.subheader("🔍 Forensic Session Deep-Dive & Keystroke Replay")

session_list = pd.read_sql_query("SELECT session_id, ip, start_time FROM sessions ORDER BY start_time DESC LIMIT 50", conn)

if not session_list.empty:
    selected_session = st.selectbox(
        "Select Attacker Session to Inspect:",
        options=session_list["session_id"].tolist(),
        format_func=lambda x: f"Session {x} (IP: {session_list.loc[session_list['session_id'] == x, 'ip'].values[0]})"
    )

    if selected_session:
        session_details = pd.read_sql_query("SELECT * FROM sessions WHERE session_id = ?", conn, params=(selected_session,))
        session_auth = pd.read_sql_query("SELECT timestamp, username, password, status FROM auth_attempts WHERE session_id = ?", conn, params=(selected_session,))
        session_cmds = pd.read_sql_query("SELECT timestamp, command_text, mitre_id, mitre_technique FROM commands WHERE session_id = ? ORDER BY id ASC", conn, params=(selected_session,))

        c1, c2, c3, c4 = st.columns(4)
        if not session_details.empty:
            s = session_details.iloc[0]
            c1.info(f"**IP:** {s['ip']}")
            c2.info(f"**Location:** {s['city']}, {s['country']}")
            c3.info(f"**ASN / ISP:** {s['asn']} ({s['isp']})")
            c4.error(f"**Abuse Score:** {s['abuse_score']}%")

        f_auth_col, f_cmd_col = st.columns([1, 2])
        with f_auth_col:
            st.write("Authentication Attempts in Session:")
            st.dataframe(session_auth, use_container_width=True)

        with f_cmd_col:
            st.write("Chronological Keystrokes & Command History:")
            st.dataframe(session_cmds, use_container_width=True)

st.markdown("---")

# --- ROW 5: EXPORT FOR LAB REPORT SUBMISSION ---
st.subheader("📥 Export Evidence for BCSSL Lab Submission")
exp_col1, exp_col2 = st.columns(2)

sessions_all = pd.read_sql_query("SELECT * FROM sessions", conn)
commands_all = pd.read_sql_query("SELECT * FROM commands", conn)

with exp_col1:
    st.download_button(
        label="Download Sessions & Threat Intel CSV",
        data=sessions_all.to_csv(index=False).encode('utf-8'),
        file_name="honeypot_sessions_report.csv",
        mime="text/csv"
    )

with exp_col2:
    st.download_button(
        label="Download Captured Commands & MITRE TTPs CSV",
        data=commands_all.to_csv(index=False).encode('utf-8'),
        file_name="honeypot_commands_mitre.csv",
        mime="text/csv"
    )

if auto_refresh:
    import time
    time.sleep(10)
    st.rerun()
