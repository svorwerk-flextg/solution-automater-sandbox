#!/bin/bash
# Network Security Rules for AI Sandbox
# This script configures iptables to enforce read-only database access

# Exit on error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}[*] Configuring AI Sandbox Network Security Rules${NC}"

# Flush existing rules (careful in production!)
echo -e "${YELLOW}[!] Flushing existing rules...${NC}"
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Set default policies
echo -e "${GREEN}[*] Setting default policies to DROP${NC}"
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Allow loopback
echo -e "${GREEN}[*] Allowing loopback traffic${NC}"
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
echo -e "${GREEN}[*] Allowing established connections${NC}"
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# =====================================
# DATABASE WRITE PROTECTION RULES
# =====================================

echo -e "${GREEN}[*] Installing database write protection rules${NC}"

# MySQL/MariaDB - Block write commands at packet level
# MySQL uses specific command bytes in the protocol
# 0x03 = COM_QUERY (we'll inspect these)
# 0x16 = COM_STMT_PREPARE (block prepared statements with writes)
iptables -A FORWARD -p tcp --dport 3306 -m string --algo bm --hex-string "|03|INSERT" -j DROP
iptables -A FORWARD -p tcp --dport 3306 -m string --algo bm --hex-string "|03|UPDATE" -j DROP
iptables -A FORWARD -p tcp --dport 3306 -m string --algo bm --hex-string "|03|DELETE" -j DROP
iptables -A FORWARD -p tcp --dport 3306 -m string --algo bm --hex-string "|03|REPLACE" -j DROP
iptables -A FORWARD -p tcp --dport 3306 -m string --algo bm --hex-string "|03|CREATE" -j DROP
iptables -A FORWARD -p tcp --dport 3306 -m string --algo bm --hex-string "|03|DROP" -j DROP
iptables -A FORWARD -p tcp --dport 3306 -m string --algo bm --hex-string "|03|ALTER" -j DROP
iptables -A FORWARD -p tcp --dport 3306 -m string --algo bm --hex-string "|03|TRUNCATE" -j DROP

# MSSQL/TDS Protocol - Block T-SQL write operations
iptables -A FORWARD -p tcp --dport 1433 -m string --algo bm --string "INSERT" -j DROP
iptables -A FORWARD -p tcp --dport 1433 -m string --algo bm --string "UPDATE" -j DROP
iptables -A FORWARD -p tcp --dport 1433 -m string --algo bm --string "DELETE" -j DROP
iptables -A FORWARD -p tcp --dport 1433 -m string --algo bm --string "CREATE" -j DROP
iptables -A FORWARD -p tcp --dport 1433 -m string --algo bm --string "DROP" -j DROP
iptables -A FORWARD -p tcp --dport 1433 -m string --algo bm --string "ALTER" -j DROP

# MongoDB - Block write operations in BSON
iptables -A FORWARD -p tcp --dport 27017 -m string --algo bm --string "insert" -j DROP
iptables -A FORWARD -p tcp --dport 27017 -m string --algo bm --string "update" -j DROP
iptables -A FORWARD -p tcp --dport 27017 -m string --algo bm --string "delete" -j DROP
iptables -A FORWARD -p tcp --dport 27017 -m string --algo bm --string "findAndModify" -j DROP
iptables -A FORWARD -p tcp --dport 27017 -m string --algo bm --string "remove" -j DROP

# =====================================
# DOCKER NETWORK RULES
# =====================================

echo -e "${GREEN}[*] Configuring Docker network isolation${NC}"

# Allow Docker bridge traffic (customize based on your Docker networks)
# Agent network (172.22.0.0/24)
iptables -A FORWARD -s 172.22.0.0/24 -d 172.21.0.0/24 -j ACCEPT  # Agent to Proxy
iptables -A FORWARD -s 172.21.0.0/24 -d 172.22.0.0/24 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Management network (172.23.0.0/24)
iptables -A FORWARD -s 172.23.0.0/24 -j ACCEPT  # Management can access all
iptables -A FORWARD -d 172.23.0.0/24 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Block inter-agent communication
iptables -A FORWARD -s 172.22.0.0/24 -d 172.22.0.0/24 -j DROP

# =====================================
# EXTERNAL ACCESS RULES
# =====================================

echo -e "${GREEN}[*] Configuring external access rules${NC}"

# Allow HTTPS inbound (gateway)
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow DNS
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# Allow NTP
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT

# Allow HTTP/HTTPS outbound for package updates
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

# Allow S3 access (port 443 already allowed)
# Add specific S3 endpoint IPs if needed for tighter control

# =====================================
# RATE LIMITING
# =====================================

echo -e "${GREEN}[*] Configuring rate limiting${NC}"

# Rate limit new connections (prevent DoS)
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m limit --limit 10/second --limit-burst 20 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -j DROP

# Rate limit database connections
iptables -A FORWARD -p tcp --dport 3306 -m state --state NEW -m limit --limit 5/second --limit-burst 10 -j ACCEPT
iptables -A FORWARD -p tcp --dport 3306 -m state --state NEW -j DROP

# =====================================
# LOGGING RULES
# =====================================

echo -e "${GREEN}[*] Configuring logging rules${NC}"

# Log dropped packets for analysis
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "IPT-DROP-INPUT: " --log-level 4
iptables -A FORWARD -m limit --limit 5/min -j LOG --log-prefix "IPT-DROP-FORWARD: " --log-level 4
iptables -A OUTPUT -m limit --limit 5/min -j LOG --log-prefix "IPT-DROP-OUTPUT: " --log-level 4

# Log database write attempts
iptables -I FORWARD 1 -p tcp --dport 3306 -m string --algo bm --string "INSERT" -j LOG --log-prefix "BLOCKED-DB-WRITE: " --log-level 3
iptables -I FORWARD 1 -p tcp --dport 1433 -m string --algo bm --string "UPDATE" -j LOG --log-prefix "BLOCKED-DB-WRITE: " --log-level 3
iptables -I FORWARD 1 -p tcp --dport 27017 -m string --algo bm --string "update" -j LOG --log-prefix "BLOCKED-DB-WRITE: " --log-level 3

# =====================================
# SAVE RULES
# =====================================

echo -e "${GREEN}[*] Saving iptables rules${NC}"

# Save rules (varies by distribution)
if command -v netfilter-persistent &> /dev/null; then
    netfilter-persistent save
elif command -v iptables-save &> /dev/null; then
    iptables-save > /etc/iptables/rules.v4
else
    echo -e "${YELLOW}[!] Could not save rules automatically. Please save manually.${NC}"
fi

# =====================================
# VERIFICATION
# =====================================

echo -e "${GREEN}[*] Current iptables rules:${NC}"
iptables -L -n -v

echo -e "${GREEN}[+] Network security rules configured successfully!${NC}"
echo -e "${YELLOW}[!] Remember to test database connections to ensure read access works${NC}"

# Create systemd service for persistence
cat > /etc/systemd/system/sandbox-firewall.service << EOF
[Unit]
Description=AI Sandbox Firewall Rules
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/opt/sandbox/network-policies/iptables-rules.sh
ExecStop=/sbin/iptables -F
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sandbox-firewall.service

echo -e "${GREEN}[+] Firewall service installed and enabled${NC}"