#!/usr/bin/env python3
"""
AWS SDK (Boto3) Automated Provisioning & Deployment Script for SSH Honeypot Lab.
Terminates stale instance, launches clean Ubuntu 24.04 instance with cloud-init,
attaches Elastic IP, and monitors startup.
"""

import base64
import sys
import time
import boto3

REGION = "ap-south-2"
AMI_ID = "ami-03f1d2b3639314198"  # Ubuntu 24.04 LTS Noble in ap-south-2
INSTANCE_TYPE = "c7i-flex.large"
KEY_NAME = "ssh-honeypot"
SECURITY_GROUP_ID = "sg-08f4728cdaa98632a"
SUBNET_ID = "subnet-01cecae2aa389ea2c"
ELASTIC_IP_ALLOC_ID = "eipalloc-0318cfa28ddc5ca76"
ELASTIC_IP = "18.60.33.150"
ABUSEIPDB_KEY = "your_abuseipdb_api_key_here"

USER_DATA_SCRIPT = f"""#!/bin/bash
set -euxo pipefail

exec > /var/log/user-data.log 2>&1
echo "[*] Starting automated honeypot bootstrap at $(date)..."

# 1. Update system packages
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl git sqlite3

# 2. Re-port host OpenSSH safely to Port 22222 and enable keepalive
echo "[*] Migrating OpenSSH to Port 22222..."
systemctl stop ssh.socket || true
systemctl disable ssh.socket || true

sed -i 's/^#*Port .*/Port 22222/' /etc/ssh/sshd_config
if ! grep -q "^Port 22222" /etc/ssh/sshd_config; then
    echo "Port 22222" >> /etc/ssh/sshd_config
fi

sed -i '/^#*ClientAliveInterval/d' /etc/ssh/sshd_config
sed -i '/^#*ClientAliveCountMax/d' /etc/ssh/sshd_config
sed -i '/^#*TCPKeepAlive/d' /etc/ssh/sshd_config
echo "ClientAliveInterval 60" >> /etc/ssh/sshd_config
echo "ClientAliveCountMax 120" >> /etc/ssh/sshd_config
echo "TCPKeepAlive yes" >> /etc/ssh/sshd_config

systemctl enable ssh.service
systemctl restart ssh.service
echo "[+] OpenSSH successfully listening on Port 22222."

# 3. Install official Docker Engine
echo "[*] Installing Docker Engine..."
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu noble stable" > /etc/apt/sources.list.d/docker.list

apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
usermod -aG docker ubuntu

# 4. Clone Honeypot repository
echo "[*] Cloning SSH Honeypot repo..."
cd /home/ubuntu
rm -rf ssh-honeypot
git clone https://github.com/venkatvellapalem/ssh-honeypot.git
cd ssh-honeypot

# 5. Populate .env file with AbuseIPDB key
cat << 'EOF' > .env
ABUSEIPDB_API_KEY={ABUSEIPDB_KEY}
COWRIE_JSON_PATH=/cowrie/var/log/cowrie/cowrie.json
DATABASE_PATH=/app/data/honeypot.db
GEOIP_CACHE_TTL_HOURS=24
EOF

mkdir -p data
chown -R ubuntu:ubuntu /home/ubuntu/ssh-honeypot

# 6. Launch Docker containers (Cowrie on Port 22, SOC Dashboard on Port 80 and 8501)
echo "[*] Launching Cowrie Honeypot and SOC Dashboard containers..."
docker compose up -d --build

echo "[+] Deployment completed successfully at $(date)!"
"""


def main():
    print(f"[*] Initializing AWS EC2 Client in region {REGION}...")
    ec2 = boto3.client("ec2", region_name=REGION)

    # 1. Terminate old honeypot instances
    print("[*] Finding existing 'ssh-honeypot' instances...")
    res = ec2.describe_instances(
        Filters=[
            {"Name": "tag:Name", "Values": ["ssh-honeypot"]},
            {"Name": "instance-state-name", "Values": ["running", "stopped", "pending"]}
        ]
    )
    old_instance_ids = [
        inst["InstanceId"]
        for r in res["Reservations"]
        for inst in r["Instances"]
    ]

    if old_instance_ids:
        print(f"[*] Terminating old instance(s): {old_instance_ids}...")
        ec2.terminate_instances(InstanceIds=old_instance_ids)
        waiter = ec2.get_waiter("instance_terminated")
        print("[*] Waiting for old instance(s) to terminate...")
        waiter.wait(InstanceIds=old_instance_ids)
        print("[+] Old instance(s) terminated.")

    # 2. Launch fresh instance with automated cloud-init
    print(f"[*] Launching fresh Ubuntu 24.04 ({AMI_ID}) on {INSTANCE_TYPE}...")
    run_res = ec2.run_instances(
        ImageId=AMI_ID,
        InstanceType=INSTANCE_TYPE,
        KeyName=KEY_NAME,
        MinCount=1,
        MaxCount=1,
        SubnetId=SUBNET_ID,
        SecurityGroupIds=[SECURITY_GROUP_ID],
        UserData=USER_DATA_SCRIPT,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": "ssh-honeypot"}]
            }
        ]
    )

    new_instance_id = run_res["Instances"][0]["InstanceId"]
    print(f"[+] New instance created: {new_instance_id}")

    # 3. Wait until instance is running
    print(f"[*] Waiting for instance {new_instance_id} to enter 'running' state...")
    running_waiter = ec2.get_waiter("instance_running")
    running_waiter.wait(InstanceIds=[new_instance_id])
    print("[+] Instance is running!")

    # 4. Associate Elastic IP 18.60.33.150
    print(f"[*] Associating Elastic IP {ELASTIC_IP} ({ELASTIC_IP_ALLOC_ID}) to {new_instance_id}...")
    assoc_res = ec2.associate_address(
        AllocationId=ELASTIC_IP_ALLOC_ID,
        InstanceId=new_instance_id,
        AllowReassociation=True
    )
    print(f"[+] Elastic IP associated! AssociationId: {assoc_res.get('AssociationId')}")

    print("\n" + "=" * 65)
    print(f"[+] SUCCESS! New instance {new_instance_id} is live at {ELASTIC_IP}.")
    print("=" * 65)


if __name__ == "__main__":
    main()
