"""
SSH Honeypot — Documentation
Clean reference for architecture, logs, MITRE ATT&CK, and system internals.
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

st.set_page_config(page_title="Documentation · SSH Honeypot SOC", page_icon=_fi or ":book:", layout="wide", initial_sidebar_state="expanded")

# ── Theme — matches main dashboard ───────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
:root { --bg:#050507; --surface:#0c0c10; --card:#111116; --border:#1a1a22; --text:#e4e4e7; --muted:#71717a; --accent:#06b6d4; --red:#ef4444; --green:#22c55e; --amber:#f59e0b; }

.stApp, .stApp header, [data-testid="stSidebar"] { background:var(--bg)!important; font-family:'Inter',sans-serif!important; }
.stMarkdown, .stMarkdown p, .stMarkdown li, .stMarkdown span, .stMarkdown h1, .stMarkdown h2, .stMarkdown h3, .stMarkdown h4, [data-testid="stSidebar"] .stMarkdown { color:var(--text)!important; }
[data-testid="stSidebar"] { border-right:1px solid var(--border)!important; background:#08080b!important; }
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h1 { font-size:1.1rem!important; font-weight:700!important; }
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h3 { font-size:.7rem!important; font-weight:600!important; text-transform:uppercase!important; letter-spacing:.1em!important; color:var(--muted)!important; margin-top:1.2rem!important; margin-bottom:.4rem!important; }

/* Typography */
h1, .stMarkdown h1 { font-size:1.8rem!important; font-weight:800!important; letter-spacing:-.03em!important; margin-bottom:.3rem!important; }
h2, .stMarkdown h2 { font-size:1.1rem!important; font-weight:700!important; letter-spacing:-.01em!important; padding-bottom:.4rem; border-bottom:1px solid var(--border); margin-top:2.5rem!important; margin-bottom:1rem!important; }
h3, .stMarkdown h3 { font-size:.92rem!important; font-weight:700!important; margin-top:1.5rem!important; margin-bottom:.5rem!important; }
h4, .stMarkdown h4 { font-size:.85rem!important; font-weight:600!important; color:var(--accent)!important; margin-top:1rem!important; }
p, .stMarkdown p { font-size:.88rem!important; line-height:1.75!important; color:#a1a1aa!important; }
li, .stMarkdown li { font-size:.88rem!important; line-height:1.75!important; color:#a1a1aa!important; }

/* Code blocks */
code { font-family:'JetBrains Mono',monospace!important; font-size:.8rem!important; background:var(--surface)!important; border:1px solid var(--border)!important; border-radius:4px!important; padding:1px 5px!important; }
.stCode>div { background:var(--surface)!important; border:1px solid var(--border)!important; border-radius:8px!important; }

hr { border-color:var(--border)!important; margin:2rem 0!important; }
.stTabs [data-baseweb="tab-list"] { gap:0!important; border-bottom:1px solid var(--border)!important; }
.stTabs [data-baseweb="tab"] { font-size:.82rem!important; font-weight:500!important; color:var(--muted)!important; }
.stTabs [aria-selected="true"] { color:var(--accent)!important; border-bottom-color:var(--accent)!important; }

/* Cards */
.section-card { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:24px 28px; margin-bottom:16px; }
.section-card h4 { margin-top:0!important; font-size:.78rem!important; text-transform:uppercase; letter-spacing:.08em; color:var(--muted)!important; margin-bottom:8px; }
.section-card p { margin-bottom:0; color:var(--text)!important; font-size:.88rem!important; }

/* Architecture diagram boxes */
.arch-box { background:var(--card); border:1px solid var(--border); border-radius:8px; padding:16px 20px; text-align:center; margin:0 auto; max-width:600px; }
.arch-box .ab-title { font-size:.82rem; font-weight:700; color:var(--accent); margin-bottom:4px; }
.arch-box .ab-desc { font-size:.78rem; color:var(--muted); margin:0; }
.arch-arrow { text-align:center; color:var(--muted); font-size:1.2rem; margin:6px 0; }

/* Flow steps */
.step { display:flex; gap:14px; align-items:flex-start; margin-bottom:14px; }
.step-num { min-width:28px; height:28px; border-radius:50%; background:var(--accent); color:#000; font-size:.78rem; font-weight:800; display:flex; align-items:center; justify-content:center; flex-shrink:0; }
.step-body { flex:1; }
.step-body strong { color:var(--text)!important; font-size:.88rem; }
.step-body p { margin:2px 0 0; font-size:.82rem!important; color:var(--muted)!important; }

/* Info table */
.info-table { width:100%; border-collapse:collapse; margin:12px 0; }
.info-table th { text-align:left; font-size:.72rem; font-weight:600; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); padding:8px 12px; border-bottom:1px solid var(--border); }
.info-table td { font-size:.84rem; color:var(--text); padding:10px 12px; border-bottom:1px solid var(--border); vertical-align:top; }
.info-table code { font-size:.76rem; }

/* MITRE grid */
.mitre-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(280px,1fr)); gap:10px; margin:12px 0; }
.mitre-item { background:var(--card); border:1px solid var(--border); border-radius:8px; padding:12px 14px; }
.mitre-item .mi-id { font-family:'JetBrains Mono',monospace; font-size:.76rem; color:var(--amber); font-weight:600; }
.mitre-item .mi-name { font-size:.84rem; font-weight:600; color:var(--text); margin:3px 0; }
.mitre-item .mi-desc { font-size:.76rem; color:var(--muted); }

/* Alert/tip boxes */
.tip { background:rgba(6,182,212,.06); border:1px solid rgba(6,182,212,.18); border-radius:8px; padding:14px 16px; margin:12px 0; }
.tip-title { font-size:.72rem; font-weight:700; color:var(--accent); text-transform:uppercase; letter-spacing:.06em; margin-bottom:4px; }
.tip p { color:var(--text)!important; font-size:.82rem!important; margin:0; }

.warn { background:rgba(245,158,11,.06); border:1px solid rgba(245,158,11,.18); border-radius:8px; padding:14px 16px; margin:12px 0; }
.warn-title { font-size:.72rem; font-weight:700; color:var(--amber); text-transform:uppercase; letter-spacing:.06em; margin-bottom:4px; }
.warn p { color:var(--text)!important; font-size:.82rem!important; margin:0; }
</style>
""", unsafe_allow_html=True)


# ── Sidebar ───────────────────────────────────────────────────────────────────
if FAVICON_PATH and os.path.exists(FAVICON_PATH):
    st.sidebar.image(_si if _si else FAVICON_PATH, width=150)
st.sidebar.title("Documentation")
st.sidebar.caption("Blue Cloud Softech Solutions")
st.sidebar.markdown("### Contents")
st.sidebar.markdown("""
- [Overview](#overview)
- [Architecture](#architecture)
- [How Attackers Interact](#how-attackers-interact)
- [Event Types](#event-types)
- [Log Storage](#log-storage)
- [MITRE ATT&CK](#mitre-att-ck)
- [Honey Credentials](#honey-credentials)
- [Threat Intelligence](#threat-intelligence)
- [Security Isolation](#security-isolation)
- [Deployment](#deployment)
""")
st.sidebar.markdown("---")
st.sidebar.markdown("[Dashboard](/)")
st.sidebar.markdown("[Logs](/logs)")


# ── Header ────────────────────────────────────────────────────────────────────
st.markdown("# SSH Honeypot SOC — Documentation")
st.markdown("Reference guide for the Cowrie-based SSH honeypot, threat intelligence pipeline, and SOC dashboard.")
st.divider()


# ── Overview ──────────────────────────────────────────────────────────────────
st.markdown("## Overview")

st.markdown("""
This system deploys a **Cowrie SSH honeypot** that captures real-world botnet traffic on port 22. Every connection attempt, password guess, shell command, and malware download is recorded, enriched with threat intelligence, mapped to the MITRE ATT&CK framework, and displayed on a real-time Streamlit dashboard.

**What gets captured:**
- Source IP, geolocation, ISP, ASN
- SSH client version and cipher negotiation
- Every username/password combination tried
- Every shell command typed in the fake environment
- Malware payloads downloaded by attackers
- Session duration and timing

**What attackers see:**
A convincing Ubuntu server (`srv-prod-db01`) running `OpenSSH_8.9p1`. The fake shell responds to `uname`, `whoami`, `ls`, `cat /etc/passwd`, and other common commands with emulated output. Attackers cannot distinguish this from a real server.
""")

st.divider()


# ── Architecture ──────────────────────────────────────────────────────────────
st.markdown("## Architecture")

st.markdown("""
<div class="arch-box">
    <div class="ab-title">Internet Attackers / Botnets</div>
    <div class="ab-desc">Port 22 open to 0.0.0.0 — scanners discover and attack within minutes</div>
</div>
<div class="arch-arrow">↓</div>
<div class="arch-box">
    <div class="ab-title">Cowrie Honeypot Container</div>
    <div class="ab-desc">SSH emulation, fake shell, credential capture, TTY recording, JSON logging</div>
</div>
<div class="arch-arrow">↓ Shared Docker Volume</div>
<div class="arch-box">
    <div class="ab-title">Ingestion Daemon (Python)</div>
    <div class="ab-desc">Tails cowrie.json, enriches IPs (GeoIP + AbuseIPDB + VirusTotal), maps to MITRE</div>
</div>
<div class="arch-arrow">↓ SQLite writes</div>
<div class="arch-box">
    <div class="ab-title">honeypot.db (SQLite)</div>
    <div class="ab-desc">6 tables: sessions, auth_attempts, commands, downloads, ip_cache, raw_logs</div>
</div>
<div class="arch-arrow">↓ Queries</div>
<div class="arch-box">
    <div class="ab-title">Streamlit SOC Dashboard</div>
    <div class="ab-desc">Port 8501 — threat map, credential analysis, MITRE classification, session replay</div>
</div>
""", unsafe_allow_html=True)

st.markdown("""
**Container isolation:** Cowrie runs in a minimal Docker container with no access to host tools (`curl`, `wget`, `cat`, `grep` are not installed). It's on an isolated bridge network and cannot reach the host system.
""")

st.divider()


# ── How Attackers Interact ────────────────────────────────────────────────────
st.markdown("## How Attackers Interact")

steps = [
    ("Connection", "Bot connects to port 22. Cowrie accepts the TCP connection and starts logging."),
    ("SSH Handshake", "Client sends version string. Cowrie responds with fake OpenSSH banner. Ciphers are negotiated."),
    ("Authentication", "Bot tries username/password pairs from dictionaries. Each attempt is logged. If a honey credential matches, access is granted."),
    ("Fake Shell", "Attacker gets a bash-like shell. Commands like `uname -a` return fake system info. The real system is never touched."),
    ("Payload Download", "If the attacker runs `wget` or `curl`, Cowrie intercepts the download, saves the file, and logs the SHA256 hash."),
    ("Session End", "Attacker disconnects. Duration is recorded. TTY replay file is saved."),
]

for i, (title, desc) in enumerate(steps, 1):
    st.markdown(f"""
<div class="step">
    <div class="step-num">{i}</div>
    <div class="step-body">
        <strong>{title}</strong>
        <p>{desc}</p>
    </div>
</div>
""", unsafe_allow_html=True)

st.divider()


# ── Event Types ───────────────────────────────────────────────────────────────
st.markdown("## Event Types")

st.markdown("Cowrie produces structured JSON events. Each line in `cowrie.json` is one event:")

events = [
    ("cowrie.session.connect", "New TCP connection arrives. Logs source IP and port."),
    ("cowrie.client.version", "SSH client version string (e.g., `SSH-2.0-Go`). Identifies botnet toolkits."),
    ("cowrie.client.kex", "Key exchange algorithms and ciphers offered by the client."),
    ("cowrie.login.failed", "Authentication failed. Logs attempted username and password."),
    ("cowrie.login.success", "Authentication succeeded (honey credential matched). Logs credentials used."),
    ("cowrie.command.input", "Command typed in the fake shell. Mapped to MITRE ATT&CK."),
    ("cowrie.command.failed", "Command not recognized by the fake shell."),
    ("cowrie.session.file_download", "File download attempted. Logs URL and SHA256 of captured file."),
    ("cowrie.direct-tcpip.request", "TCP tunnel/proxy request (attacker trying to pivot)."),
    ("cowrie.session.closed", "Session ended. Logs total duration."),
    ("cowrie.client.fingerprint", "SSH public key fingerprint (if key-based auth attempted)."),
    ("cowrie.client.size", "Terminal window dimensions. Helps distinguish automated tools from humans."),
    ("cowrie.log.closed", "TTY recording saved. Contains full keystroke replay."),
]

st.markdown("""
<table class="info-table">
<tr><th>Event ID</th><th>Description</th></tr>
""" + "".join(f"<tr><td><code>{eid}</code></td><td>{desc}</td></tr>" for eid, desc in events) + """
</table>
""", unsafe_allow_html=True)

st.divider()


# ── Log Storage ───────────────────────────────────────────────────────────────
st.markdown("## Log Storage")

st.markdown("""
<table class="info-table">
<tr><th>Data</th><th>Location</th><th>Format</th></tr>
<tr><td>Event stream</td><td><code>/opt/cowrie/cowrie-git/var/log/cowrie/cowrie.json</code></td><td>One JSON object per line</td></tr>
<tr><td>TTY recordings</td><td><code>/opt/cowrie/cowrie-git/var/lib/cowrie/tty/*.log</code></td><td>Binary keystroke replay</td></tr>
<tr><td>Malware downloads</td><td><code>/opt/cowrie/cowrie-git/var/lib/cowrie/downloads/</code></td><td>SHA256-named files</td></tr>
<tr><td>SOC database</td><td><code>/app/data/honeypot.db</code></td><td>SQLite (6 tables)</td></tr>
<tr><td>Cowrie config</td><td><code>/opt/cowrie/cowrie-git/etc/cowrie.cfg</code></td><td>INI format</td></tr>
<tr><td>Honey credentials</td><td><code>/opt/cowrie/cowrie-git/etc/userdb.txt</code></td><td><code>user:x:pass</code> per line</td></tr>
</table>
""", unsafe_allow_html=True)

st.markdown("""
<div class="tip">
    <div class="tip-title">Persistence</div>
    <p>All log paths are Docker volumes. Data survives container restarts. The SQLite database and cowrie logs are mounted from the host.</p>
</div>
""", unsafe_allow_html=True)

st.divider()


# ── MITRE ATT&CK ─────────────────────────────────────────────────────────────
st.markdown("## MITRE ATT&CK")

st.markdown("Commands captured in the fake shell are automatically classified into MITRE ATT&CK techniques:")

techniques = [
    ("T1110", "Brute Force", "Credential Access", "Dictionary password attacks against SSH."),
    ("T1078", "Valid Accounts", "Initial Access", "Authenticated with a honey credential."),
    ("T1082", "System Info Discovery", "Discovery", "`uname -a`, `cat /proc/cpuinfo`, `lscpu`."),
    ("T1033", "User Discovery", "Discovery", "`whoami`, `id`."),
    ("T1057", "Process Discovery", "Discovery", "`ps aux`, `top`."),
    ("T1083", "File Discovery", "Discovery", "`ls -la`, `cat /etc/passwd`, `find /`."),
    ("T1016", "Network Discovery", "Discovery", "`ifconfig`, `ip addr`, `netstat`."),
    ("T1105", "Ingress Tool Transfer", "Command and Control", "`wget`, `curl -O`. Downloads malware."),
    ("T1496", "Resource Hijacking", "Impact", "Cryptominer payloads (`xmrig`, `minerd`)."),
    ("T1070.003", "Clear History", "Defense Evasion", "`history -c`, `unset HISTFILE`."),
    ("T1562.001", "Disable Tools", "Defense Evasion", "`iptables -F`, `ufw disable`."),
    ("T1053.003", "Scheduled Task", "Persistence", "`crontab -l`."),
    ("T1222.002", "Permissions Mod", "Defense Evasion", "`chmod +x`, `chmod 777`."),
    ("T1059.004", "Shell Execution", "Execution", "`bash`, `sh`, `python -c`."),
]

st.markdown('<div class="mitre-grid">', unsafe_allow_html=True)
for tid, name, tactic, desc in techniques:
    st.markdown(f"""
<div class="mitre-item">
    <div class="mi-id">{tid}</div>
    <div class="mi-name">{name}</div>
    <div class="mi-desc">{tactic} — {desc}</div>
</div>
""", unsafe_allow_html=True)
st.markdown('</div>', unsafe_allow_html=True)

st.divider()


# ── Honey Credentials ─────────────────────────────────────────────────────────
st.markdown("## Honey Credentials")

st.markdown("The `userdb.txt` file defines credentials that attackers can 'crack'. When matched, they get a fake shell. Currently **97 credential pairs** are configured.")

st.markdown("""
<table class="info-table">
<tr><th>Category</th><th>Examples</th><th>Purpose</th></tr>
<tr><td>Root defaults</td><td><code>root:root</code>, <code>root:toor</code>, <code>root:123456</code></td><td>Most common botnet targets</td></tr>
<tr><td>Admin accounts</td><td><code>admin:admin</code>, <code>admin:admin123</code>, <code>admin:password</code></td><td>IoT and web admin defaults</td></tr>
<tr><td>Cloud defaults</td><td><code>ubuntu:ubuntu</code>, <code>pi:raspberry</code></td><td>Cloud instance defaults</td></tr>
<tr><td>Service accounts</td><td><code>oracle:oracle</code>, <code>postgres:postgres</code>, <code>mysql:mysql</code></td><td>Database defaults</td></tr>
<tr><td>Mirai variants</td><td><code>root:vizxv</code>, <code>root:xc3511</code>, <code>admin:5up</code></td><td>Known botnet hardcoded creds</td></tr>
</table>
""", unsafe_allow_html=True)

st.divider()


# ── Threat Intelligence ──────────────────────────────────────────────────────
st.markdown("## Threat Intelligence")

st.markdown("Every attacker IP is enriched automatically:")

st.markdown("""
<table class="info-table">
<tr><th>Source</th><th>Data Provided</th><th>Rate Limit</th></tr>
<tr><td>ip-api.com</td><td>Country, city, ISP, ASN, lat/lon</td><td>45 req/min (free)</td></tr>
<tr><td>AbuseIPDB</td><td>Abuse confidence score (0-100%), total reports, usage type</td><td>1000 checks/day (free)</td></tr>
<tr><td>VirusTotal</td><td>Malicious count, suspicious count, reputation score</td><td>4 req/min (free)</td></tr>
</table>
""", unsafe_allow_html=True)

st.markdown("Results are cached in `ip_cache` table for 24 hours to protect API limits.")

st.divider()


# ── Security Isolation ───────────────────────────────────────────────────────
st.markdown("## Security Isolation")

st.markdown("The honeypot is designed so attackers **cannot access the real system**:")

st.markdown("""
<table class="info-table">
<tr><th>What attacker sees</th><th>Reality</th></tr>
<tr><td>Hostname: <code>srv-prod-db01</code></td><td>Docker container hostname</td></tr>
<tr><td>SSH: <code>OpenSSH_8.9p1 Ubuntu</code></td><td>Cowrie fake banner</td></tr>
<tr><td>Kernel: <code>5.15.0-89-generic</code></td><td>Cowrie emulated response</td></tr>
<tr><td><code>cat /etc/passwd</code></td><td>Cowrie emulated filesystem</td></tr>
<tr><td><code>uname -a</code></td><td>Cowrie emulated output</td></tr>
</table>
""", unsafe_allow_html=True)

st.markdown("""
<div class="warn">
    <div class="warn-title">Isolation</div>
    <p>The Cowrie container has no <code>curl</code>, <code>wget</code>, <code>cat</code>, <code>grep</code>, or <code>whoami</code> binaries. It's on an isolated Docker bridge network. The real SSH server runs on port 22222, accessible only from your IP.</p>
</div>
""", unsafe_allow_html=True)

st.divider()


# ── Deployment ────────────────────────────────────────────────────────────────
st.markdown("## Deployment")

st.markdown("""
<table class="info-table">
<tr><th>Step</th><th>Command</th></tr>
<tr><td>Connect</td><td><code>ssh -i key.pem ubuntu@&lt;EC2-IP&gt;</code></td></tr>
<tr><td>Clone</td><td><code>git clone &lt;repo&gt; && cd ssh-honeypot</code></td></tr>
<tr><td>Host setup</td><td><code>sudo bash scripts/setup_host.sh</code></td></tr>
<tr><td>Deploy</td><td><code>./deploy.sh</code></td></tr>
<tr><td>Dashboard</td><td><code>http://&lt;EC2-IP&gt;:8501</code></td></tr>
<tr><td>Teardown</td><td><code>docker compose down</code></td></tr>
</table>
""", unsafe_allow_html=True)

st.caption("BCSSL Documentation  ·  Blue Cloud Softech Solutions Ltd.")
