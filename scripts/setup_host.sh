#!/usr/bin/env bash
# ==============================================================================
# Host Hardening & Pre-requisite Setup Script for Ubuntu 22.04 / 24.04 LTS
# Safely re-ports host sshd to 22222 to free port 22 for Cowrie Honeypot Docker
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================================${NC}"
echo -e "${BLUE}   SSH Honeypot Lab - Host Pre-flight & Hardening     ${NC}"
echo -e "${BLUE}======================================================${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Please run this script with sudo:${NC} sudo bash scripts/setup_host.sh"
    exit 1
fi

ADMIN_PORT=22222

# 1. Re-porting host SSH to 22222
echo -e "\n${YELLOW}[1/4] Re-porting host OpenSSH to port ${ADMIN_PORT}...${NC}"

# Backup sshd_config
if [ ! -f /etc/ssh/sshd_config.bak ]; then
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    echo "[+] Backed up /etc/ssh/sshd_config to /etc/ssh/sshd_config.bak"
fi

# Ensure Port 22222 is set in sshd_config
if grep -q "^#\?Port " /etc/ssh/sshd_config; then
    sed -i "s/^#\?Port .*/Port ${ADMIN_PORT}/" /etc/ssh/sshd_config
else
    echo "Port ${ADMIN_PORT}" >> /etc/ssh/sshd_config
fi

# Configure Keep-Alive so inactive SSH connections never drop or time out
echo "[*] Configuring persistent SSH keep-alive (2-hour inactivity tolerance)..."
sed -i '/^#\?ClientAliveInterval/d' /etc/ssh/sshd_config
sed -i '/^#\?ClientAliveCountMax/d' /etc/ssh/sshd_config
sed -i '/^#\?TCPKeepAlive/d' /etc/ssh/sshd_config
echo "ClientAliveInterval 60" >> /etc/ssh/sshd_config
echo "ClientAliveCountMax 120" >> /etc/ssh/sshd_config
echo "TCPKeepAlive yes" >> /etc/ssh/sshd_config

# Handle Ubuntu 22.10+ and 24.04 systemd socket activation for ssh
if systemctl is-active --quiet ssh.socket; then
    echo "[*] Adjusting systemd ssh.socket port..."
    mkdir -p /etc/systemd/system/ssh.socket.d
    cat <<EOF > /etc/systemd/system/ssh.socket.d/listen.conf
[Socket]
ListenStream=
ListenStream=${ADMIN_PORT}
EOF
    systemctl daemon-reload
    systemctl restart ssh.socket
fi

# Restart ssh service
if systemctl is-active --quiet ssh; then
    systemctl restart ssh
elif systemctl is-active --quiet sshd; then
    systemctl restart sshd
fi

echo -e "${GREEN}[+] Host SSH daemon now listening on port ${ADMIN_PORT}.${NC}"
echo -e "${YELLOW}[!] CRITICAL: DO NOT CLOSE THIS TERMINAL!${NC}"
echo -e "${YELLOW}[!] Open a new terminal and verify: ssh -p ${ADMIN_PORT} -i <your-key.pem> ubuntu@<your-ec2-ip>${NC}"

# 2. Update and Install System Dependencies & Docker
echo -e "\n${YELLOW}[2/4] Updating packages and installing Docker Engine...${NC}"
apt-get update -y
apt-get install -y --no-install-recommends \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    sqlite3 \
    git

# Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo "[*] Installing official Docker Engine..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg --yes
    chmod a+r /etc/apt/keyrings/docker.gpg

    echo \
      "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
      "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
      tee /etc/apt/sources.list.d/docker.list > /dev/null

    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    echo -e "${GREEN}[+] Docker installed successfully.${NC}"
else
    echo -e "${GREEN}[+] Docker is already installed.${NC}"
fi

# Add current user (or ubuntu) to docker group
ACTUAL_USER="${SUDO_USER:-ubuntu}"
usermod -aG docker "$ACTUAL_USER" || true
echo -e "${GREEN}[+] Added user '$ACTUAL_USER' to docker group.${NC}"

# 3. Create persistent directories
echo -e "\n${YELLOW}[3/4] Preparing project directories...${NC}"
mkdir -p data
chown -R "$ACTUAL_USER":"$ACTUAL_USER" data config

# 4. Completion
echo -e "\n${GREEN}[4/4] Host setup complete!${NC}"
echo -e "${BLUE}======================================================${NC}"
echo -e "${GREEN}NEXT STEPS:${NC}"
echo -e "1. From a new terminal, confirm connection on port 22222:"
echo -e "   ${YELLOW}ssh -p 22222 -i ssh-honeypot.pem ubuntu@<EC2-IP>${NC}"
echo -e "2. Launch the Honeypot & SOC Dashboard container stack:"
echo -e "   ${YELLOW}./deploy.sh${NC}"
echo -e "${BLUE}======================================================${NC}"
