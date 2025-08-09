# AI Sandbox Security Implementation Guide

## Overview

This guide provides step-by-step instructions for implementing the bulletproof security architecture for the Solution-Automater-Sandbox. The architecture ensures zero write operations to production/dev databases while enabling safe AI agent operations.

## Quick Start

```bash
# Clone the security architecture
cd /path/to/solution-automater-sandbox

# Create required directories
mkdir -p volumes/{proxy-logs,vault-data,vault-logs,audit-logs,monitor-logs,gateway-certs,gateway-logs,shared-artifacts}

# Set proper permissions
chmod 700 volumes/vault-data
chmod 755 volumes/audit-logs

# Generate self-signed certificates (for testing)
cd security-architecture
./scripts/generate-certs.sh

# Build all components
docker-compose -f docker-compose.security.yml build

# Start the security infrastructure
docker-compose -f docker-compose.security.yml up -d

# Verify all services are running
docker-compose -f docker-compose.security.yml ps
```

## Component Setup

### 1. Database Proxy (Read-Only Enforcement)

The database proxy intercepts all database connections and blocks write operations at the protocol level.

```bash
# Build the proxy
cd db-proxy
docker build -t sandbox-db-proxy .

# Configure backend databases
cp config.example.yaml config.yaml
# Edit config.yaml with your database endpoints

# Test the proxy
docker run --rm -p 3306:3306 sandbox-db-proxy --test-mode
```

**Configuration Example:**
```yaml
backends:
  - name: mysql-prod
    type: mysql
    address: prod-mysql.example.com
    port: 3306
    username: readonly_user
    password: ${MYSQL_PASSWORD}
    database: production_db
    
  - name: mssql-prod
    type: mssql
    address: prod-mssql.example.com
    port: 1433
    username: readonly_user
    password: ${MSSQL_PASSWORD}
    
  - name: mongodb-prod
    type: mongodb
    address: mongodb-cluster.example.com
    port: 27017
    username: readonly_user
    password: ${MONGO_PASSWORD}
    database: production_db
    
security:
  enforce_read_only: true
  blocked_commands:
    - INSERT
    - UPDATE
    - DELETE
    - DROP
    - CREATE
    - ALTER
    - TRUNCATE
    - MERGE
    - REPLACE
  audit_enabled: true
  allowed_ips:
    - 172.22.0.0/24  # Agent network only
```

### 2. Session Manager Setup

The session manager handles automated lifecycle of AI agent containers.

```bash
# Configure session manager
cd session-manager
pip install -r requirements.txt

# Set environment variables
export SESSION_TIMEOUT=3600
export S3_BUCKET=ai-sandbox-artifacts
export AWS_DEFAULT_REGION=us-east-1
export AUTO_DESTROY=true
export ENCRYPTION_ENABLED=true

# Run session manager
python session_manager.py
```

### 3. Network Security Configuration

Apply the network security rules:

```bash
# Make script executable
chmod +x network-policies/iptables-rules.sh

# Apply firewall rules
sudo ./network-policies/iptables-rules.sh

# Verify rules are applied
sudo iptables -L -n -v
```

### 4. Multi-Agent Orchestrator

Set up the orchestrator for managing multiple AI agents:

```bash
# Configure orchestrator
cd multi-agent-orchestrator
pip install -r requirements.txt

# Set configuration
export MAX_CONCURRENT_AGENTS=10
export SESSION_MANAGER_URL=http://session-manager:8080

# Run orchestrator
python orchestrator.py
```

## Security Verification

### 1. Test Read-Only Enforcement

```sql
-- This should work
SELECT * FROM users LIMIT 10;

-- These should be blocked
INSERT INTO users (name) VALUES ('test');
UPDATE users SET name = 'test' WHERE id = 1;
DELETE FROM users WHERE id = 1;
```

### 2. Verify Network Isolation

```bash
# From agent container, try to access another agent
docker exec -it sandbox-agent-1 ping sandbox-agent-2
# Should fail - inter-agent communication blocked

# Try to access external database directly
docker exec -it sandbox-agent-1 telnet prod-mysql.example.com 3306
# Should fail - only proxy access allowed
```

### 3. Check Audit Logs

```bash
# View audit logs
tail -f volumes/audit-logs/audit.json

# Check for blocked operations
grep "BLOCKED" volumes/audit-logs/audit.json | jq .
```

## Production Deployment

### 1. Certificate Setup

Replace self-signed certificates with proper SSL certificates:

```bash
# Copy your certificates
cp /path/to/server.crt volumes/gateway-certs/
cp /path/to/server.key volumes/gateway-certs/
cp /path/to/ca.crt volumes/gateway-certs/

# Set permissions
chmod 644 volumes/gateway-certs/*.crt
chmod 600 volumes/gateway-certs/*.key
```

### 2. Vault Configuration

Initialize HashiCorp Vault for production:

```bash
# Initialize Vault
docker exec -it sandbox-vault vault operator init

# Save the unseal keys and root token securely!

# Unseal Vault (repeat 3 times with different keys)
docker exec -it sandbox-vault vault operator unseal

# Configure secrets
docker exec -it sandbox-vault vault login
vault secrets enable -path=sandbox kv-v2
vault kv put sandbox/database/mysql username=readonly password=...
```

### 3. Environment Variables

Create `.env` file for production:

```bash
# Database credentials
MYSQL_READONLY_PASSWORD=secure_password_here
MSSQL_READONLY_PASSWORD=secure_password_here
MONGO_READONLY_PASSWORD=secure_password_here

# AWS credentials for S3 backup
AWS_ACCESS_KEY_ID=your_key_here
AWS_SECRET_ACCESS_KEY=your_secret_here

# Session configuration
SESSION_TIMEOUT=3600
MAX_SESSIONS_PER_USER=5
S3_BACKUP_BUCKET=ai-sandbox-artifacts

# Security settings
ENFORCE_READ_ONLY=true
AUDIT_ENABLED=true
AUTO_DESTROY_SESSIONS=true
```

### 4. Monitoring Setup

Configure Prometheus and Grafana for monitoring:

```yaml
# Add to docker-compose.security.yml
prometheus:
  image: prom/prometheus
  volumes:
    - ./prometheus.yml:/etc/prometheus/prometheus.yml
    - prometheus-data:/prometheus
  command:
    - '--config.file=/etc/prometheus/prometheus.yml'
    - '--storage.tsdb.path=/prometheus'
  networks:
    - management-network

grafana:
  image: grafana/grafana
  environment:
    - GF_SECURITY_ADMIN_PASSWORD=admin
  volumes:
    - grafana-data:/var/lib/grafana
  networks:
    - management-network
  ports:
    - "3000:3000"
```

## Operational Procedures

### Daily Operations

1. **Check System Health**
   ```bash
   docker-compose -f docker-compose.security.yml ps
   docker-compose -f docker-compose.security.yml logs --tail=100
   ```

2. **Review Audit Logs**
   ```bash
   # Check for security violations
   grep -E "BLOCKED|DENIED|FAILED" volumes/audit-logs/audit.json | tail -20
   ```

3. **Monitor Resource Usage**
   ```bash
   docker stats --no-stream
   ```

### Incident Response

1. **Suspected Write Attempt**
   ```bash
   # Immediately check audit logs
   grep "BLOCKED-DB-WRITE" /var/log/syslog | tail -50
   
   # Identify source
   docker-compose -f docker-compose.security.yml logs db-proxy | grep -i "write"
   
   # Terminate suspicious sessions
   curl -X DELETE http://localhost:8080/api/sessions/{session_id}
   ```

2. **Container Escape Attempt**
   ```bash
   # Check container security
   docker inspect sandbox-agent-suspicious | grep -A 10 "SecurityOpt"
   
   # Review system calls
   dmesg | grep -i "denied"
   ```

3. **Data Exfiltration Attempt**
   ```bash
   # Check network traffic
   docker-compose -f docker-compose.security.yml logs network-monitor
   
   # Review S3 uploads
   aws s3 ls s3://ai-sandbox-artifacts/ --recursive | tail -50
   ```

## Security Checklist

Before going to production, verify:

- [ ] All database connections go through the read-only proxy
- [ ] Network isolation is properly configured
- [ ] Session timeout is enforced
- [ ] Audit logging is enabled and working
- [ ] SSL certificates are properly installed
- [ ] Vault is initialized and unsealed
- [ ] Monitoring alerts are configured
- [ ] Backup procedures are tested
- [ ] Incident response plan is documented
- [ ] All default passwords are changed
- [ ] Firewall rules are persistent across reboots
- [ ] Resource limits are properly set
- [ ] Inter-agent communication is blocked
- [ ] S3 backup encryption is enabled

## Troubleshooting

### Common Issues

1. **Proxy Connection Refused**
   ```bash
   # Check proxy is running
   docker logs sandbox-db-proxy
   
   # Verify backend connectivity
   docker exec sandbox-db-proxy nc -zv prod-mysql.example.com 3306
   ```

2. **Session Creation Fails**
   ```bash
   # Check session manager logs
   docker logs sandbox-session-manager
   
   # Verify Docker socket permissions
   ls -la /var/run/docker.sock
   ```

3. **Network Isolation Not Working**
   ```bash
   # Verify iptables rules
   sudo iptables -L -n -v | grep -E "DROP|REJECT"
   
   # Check Docker network configuration
   docker network inspect agent-network
   ```

## Support

For security issues or questions:
- Review audit logs first
- Check the troubleshooting section
- Contact security team with full audit trail

Remember: **Security is paramount. When in doubt, block the operation.**