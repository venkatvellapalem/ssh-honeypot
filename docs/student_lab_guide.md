# Lab 04: SSH Honeypot & Threat Intelligence — Student Lab Guide

**Program**: BCSSL Cybersecurity Internship Program  
**Track**: Linux / Threat Intelligence / SIEM  
**Difficulty**: Intermediate–Advanced  
**Estimated Duration**: 3 Days  

---

## 1. Learning Objectives
By completing this lab, you will:
1. Deploy a Cowrie-style medium-interaction SSH honeypot to trap automated scanners and botnets.
2. Intercept and parse structured JSON session telemetry (credentials, interactive shell commands, downloads).
3. Enrich captured attacker IPs using Threat Intelligence APIs (AbuseIPDB reputation and IP Geolocation) with local caching to protect rate limits.
4. Visualize attack patterns on an interactive SOC Web Dashboard.
5. Map attacker Tactics, Techniques, and Procedures (TTPs) directly to the **MITRE ATT&CK** Enterprise framework.
6. Conduct forensic analysis on captured commands and perform safe cloud teardown.

---

## 2. Lab Architecture

```
Attacker (Internet)  ---> [AWS EC2 Port 22]  ---> [Cowrie Honeypot Container]
                                                           |
                                               Logs: cowrie.json
                                                           |
                                                           v
Admin (Port 22222)   ---> [Host Ubuntu sshd]    [Ingestion Daemon]
Admin (Port 8501)    ---> [Web SOC Dashboard] <--- [SQLite DB] <---> [AbuseIPDB & GeoIP API]
```

---

## 3. Step-by-Step Lab Execution

### Phase 1: Host Hardening & Container Deployment
1. Connect to your EC2 instance using your `.pem` key:
   ```bash
   ssh -i ssh-honeypot.pem ubuntu@<YOUR-EC2-IP>
   ```
2. Clone this repository onto your EC2 instance:
   ```bash
   git clone https://github.com/venkatvellapalem/ssh-honeypot.git
   cd ssh-honeypot
   ```
3. Run the host hardening script with sudo:
   ```bash
   sudo bash scripts/setup_host.sh
   ```
   > **Note**: This moves the host's real SSH server to **Port 22222** so that port 22 is free for the Cowrie honeypot.
4. **Before closing your session**, open a second terminal on your computer and verify management login:
   ```bash
   ssh -p 22222 -i ssh-honeypot.pem ubuntu@<YOUR-EC2-IP>
   ```
5. Deploy the Honeypot & SOC Dashboard stack:
   ```bash
   ./deploy.sh
   ```

---

### Phase 2: Threat Intelligence & Telemetry Verification
1. Access your interactive Web SOC Dashboard in your browser:
   ```
   http://<YOUR-EC2-IP>:8501
   ```
2. Verify Cowrie is active and listening:
   ```bash
   docker ps
   docker logs --tail 20 cowrie-honeypot
   ```
3. Run the automated attacker simulation test:
   ```bash
   python3 test/simulate_attack.py --host 127.0.0.1 --port 22
   ```
   Observe the following actions in the simulation:
   * Dictionary attack against common usernames (`root`, `admin`, `oracle`).
   * Successful breach into the fake shell using a honeypot credential.
   * Execution of reconnaissance commands (`uname -a`, `whoami`, `cat /proc/cpuinfo`).
   * Ingress tool transfer attempt (`curl -O ...`).
4. Refresh your SOC Dashboard at `http://<YOUR-EC2-IP>:8501`:
   * Confirm the authentication attempts appear in the **Credential Intelligence** section.
   * Confirm executed commands appear in the **MITRE ATT&CK Classification** table.

---

### Phase 3: Opening Port 22 to the Public Internet
Once local testing passes, expose port 22 to the global internet to begin capturing live wild botnets:
1. In the **AWS Management Console**, navigate to **EC2 > Security Groups > launch-wizard-4**.
2. Edit Inbound Rules:
   * Rule 1: `Port 22` -> Change Source from `My IP` to **`Anywhere-IPv4` (`0.0.0.0/0`)**.
   * Rule 2: Keep `Port 22222` restricted to **`My IP`**.
   * Rule 3: Keep `Port 8501` restricted to **`My IP`**.
3. Within 30 to 120 minutes, public bots (Mirai variants, SSH brute-forcers) will discover port 22 and begin attacking.

---

### Phase 4: MITRE ATT&CK Analysis & Threat Reporting
1. Examine captured commands in the dashboard and correlate with the MITRE ATT&CK framework:
   * `T1110` (Brute Force): High-frequency password attempts.
   * `T1082` (System Information Discovery): `uname -a`, `lscpu`.
   * `T1033` (System Owner Discovery): `whoami`, `id`.
   * `T1105` (Ingress Tool Transfer): `wget`, `curl`.
   * `T1070.003` (Clear Command History): `history -c`.
   * `T1496` (Resource Hijacking): Cryptominer droppers.
2. Select an active attacker IP in the **Forensic Session Deep-Dive** section of the dashboard to trace the attacker's keystrokes.
3. Download the evidence CSV reports directly from the dashboard:
   * `honeypot_sessions_report.csv`
   * `honeypot_commands_mitre.csv`

---

## 4. Lab Deliverables & Submission Checklist

Prepare a lab report containing:
- [ ] Screenshot of running `docker ps` showing both `cowrie-honeypot` and `soc-dashboard` containers healthy.
- [ ] Screenshot of the **Geospatial Threat Map** displaying attacker geolocations.
- [ ] Screenshot of **Authentication & Credential Harvest Analysis** showing top attempted usernames and passwords.
- [ ] Screenshot of **MITRE ATT&CK TTP Classification** table with mapped techniques.
- [ ] Deep-dive case study on at least one captured real attacker session (analyzing IP, ISP, country, AbuseIPDB score, and commands typed).
- [ ] Analysis of at least one payload/dropper URL attempted via `wget` or `curl`.

---

## 5. Teardown & Cloud Cost Control

> [!IMPORTANT]
> To avoid unnecessary AWS charges and prevent prolonged public exposure of the honeypot:
1. Stop all containers on the EC2 instance:
   ```bash
   docker compose down
   ```
2. In the **AWS EC2 Console**, select your instance:
   * Click **Instance State > Stop Instance** (if resuming later) OR
   * Click **Instance State > Terminate Instance** (if lab is complete).
