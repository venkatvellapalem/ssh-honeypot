#!/usr/bin/env bash
# ==============================================================================
# Master Deployment Script for Cowrie SSH Honeypot & SOC Dashboard
# ==============================================================================

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}     Deploying Enterprise SSH Honeypot & SOC Dashboard          ${NC}"
echo -e "${BLUE}================================================================${NC}"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}[!] Docker is not installed. Please run:${NC} sudo bash scripts/setup_host.sh"
    exit 1
fi

# Ensure data folder exists
mkdir -p data

echo -e "\n${YELLOW}[*] Building SOC Analytics & Dashboard Image...${NC}"
docker compose build

echo -e "\n${YELLOW}[*] Launching Cowrie Honeypot and SOC Dashboard Containers...${NC}"
docker compose up -d

echo -e "\n${YELLOW}[*] Verifying running containers...${NC}"
sleep 3
docker compose ps

# Detect Public IP
PUBLIC_IP=$(curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/public-ipv4 || curl -s --connect-timeout 3 ifconfig.me || echo "YOUR-EC2-PUBLIC-IP")

echo -e "\n${GREEN}================================================================${NC}"
echo -e "${GREEN}  SUCCESS: Honeypot & SOC Dashboard are Live!                    ${NC}"
echo -e "${GREEN}================================================================${NC}"
echo -e "  Trap Honeypot SSH Port : ${YELLOW}22${NC} (Attackers connect here)"
echo -e "  Host Admin SSH Port     : ${YELLOW}22222${NC} (Your management access)"
echo -e "  Web SOC Dashboard URL  : ${BLUE}http://${PUBLIC_IP}:8501${NC}"
echo -e ""
echo -e "  To monitor live honeypot logs:"
echo -e "    ${YELLOW}docker logs -f cowrie-honeypot${NC}"
echo -e ""
echo -e "  To simulate a test attack immediately:"
echo -e "    ${YELLOW}python3 test/simulate_attack.py --host 127.0.0.1 --port 22${NC}"
echo -e "${GREEN}================================================================${NC}"
