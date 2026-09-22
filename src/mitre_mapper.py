"""
MITRE ATT&CK Behavioral Mapping Engine.
Analyzes captured honeypot shell commands and behavioral patterns,
mapping them directly to MITRE ATT&CK tactics and techniques.
"""

import re
from typing import Dict, Optional, Tuple

# Comprehensive rule matrix matching shell commands to MITRE techniques
MITRE_RULES = [
    {
        "pattern": r"(?:curl|wget|ftpget|tftp|busybox\s+wget|fetch)\b",
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Command and Control"
    },
    {
        "pattern": r"\b(?:xmrig|minerd|cryptonight|stratum\+tcp|kdevtmpfsi|kintegrityd)\b",
        "technique_id": "T1496",
        "technique_name": "Resource Hijacking (Cryptomining)",
        "tactic": "Impact"
    },
    {
        "pattern": r"\b(?:uname\s+-a|cat\s+/proc/cpuinfo|cat\s+/etc/\*release|lscpu|cat\s+/etc/issue|hostnamectl)\b",
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "Discovery"
    },
    {
        "pattern": r"\b(?:whoami|id|w|last|users|who)\b",
        "technique_id": "T1033",
        "technique_name": "System Owner/User Discovery",
        "tactic": "Discovery"
    },
    {
        "pattern": r"\b(?:ps\s+(?:aux|ef)|top|htop|pstree|pgrep)\b",
        "technique_id": "T1057",
        "technique_name": "Process Discovery",
        "tactic": "Discovery"
    },
    {
        "pattern": r"\b(?:ifconfig|ip\s+(?:addr|a|route)|netstat|ss\s+-[a-z]+|route\s+-n|arp\s+-a)\b",
        "technique_id": "T1016",
        "technique_name": "System Network Configuration Discovery",
        "tactic": "Discovery"
    },
    {
        "pattern": r"\b(?:cat\s+/etc/passwd|cat\s+/etc/shadow|find\s+/|ls\s+-[a-zA-Z]*|pwd|tree)\b",
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery"
    },
    {
        "pattern": r"\b(?:history\s+-c|rm\s+-[rf]*\s+.*history|unset\s+HISTFILE|export\s+HISTFILE=/dev/null)\b",
        "technique_id": "T1070.003",
        "technique_name": "Clear Command History",
        "tactic": "Defense Evasion"
    },
    {
        "pattern": r"\b(?:iptables\s+-F|ufw\s+disable|setenforce\s+0|systemctl\s+stop\s+firewalld)\b",
        "technique_id": "T1562.001",
        "technique_name": "Disable or Modify Tools",
        "tactic": "Defense Evasion"
    },
    {
        "pattern": r"\b(?:crontab\s+-[el]|/etc/cron|systemctl\s+enable)\b",
        "technique_id": "T1053.003",
        "technique_name": "Scheduled Task/Cron",
        "tactic": "Persistence"
    },
    {
        "pattern": r"\b(?:chmod\s+\+x|chmod\s+777)\b",
        "technique_id": "T1222.002",
        "technique_name": "Linux and Mac Permissions Modification",
        "tactic": "Defense Evasion"
    },
    {
        "pattern": r"(?:/bin/sh|/bin/bash|bash|sh|python\s+-c|perl\s+-e)",
        "technique_id": "T1059.004",
        "technique_name": "Unix Shell Execution",
        "tactic": "Execution"
    }
]


def map_command(command_text: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Evaluates a shell command against the MITRE ATT&CK rules.
    Returns: (technique_id, technique_name, tactic)
    """
    if not command_text:
        return (None, None, None)

    for rule in MITRE_RULES:
        if re.search(rule["pattern"], command_text, re.IGNORECASE):
            return (rule["technique_id"], rule["technique_name"], rule["tactic"])

    # Fallback for generic interactive command execution
    return ("T1059.004", "Unix Shell Execution", "Execution")


def map_auth_event(status: str) -> Tuple[str, str, str]:
    """Maps authentication attempts to MITRE techniques."""
    if status == "SUCCESS":
        return ("T1078", "Valid Accounts", "Initial Access / Persistence")
    else:
        return ("T1110", "Brute Force", "Credential Access")
