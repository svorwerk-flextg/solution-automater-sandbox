# Cloud Integration Module

Comprehensive multi-cloud integration for the Solution-Automater-Sandbox, providing seamless, secure access to Microsoft Fabric, AWS services, and other cloud platforms.

## Overview

This module provides:

- **Microsoft Fabric Integration**: Direct access to Lakehouse, Delta tables, and Spark SQL
- **AWS Services Management**: S3, RDS, EC2 MongoDB clusters, CloudFront
- **Multi-Cloud Orchestration**: Unified management across cloud platforms
- **Security & Compliance**: Cross-cloud IAM, encryption, and compliance monitoring
- **Monitoring & Observability**: Real-time metrics, alerts, and cost tracking

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Solution-Automater-Sandbox                 │
├─────────────────────────────────────────────────────────────┤
│                    Cloud Integration Layer                   │
├──────────────┬──────────────┬──────────────┬───────────────┤
│   Fabric     │     AWS      │   Security   │   Monitoring  │
│  Connector   │   Manager    │   Manager    │    System     │
├──────────────┴──────────────┴──────────────┴───────────────┤
│                 Multi-Cloud Orchestrator                     │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Installation

```bash
# Run the deployment script
./scripts/deploy_cloud_integration.sh

# Or manually install
pip install -r requirements.txt
```

### 2. Configuration

Update `configs/cloud_integration_config.yaml` with your cloud credentials:

```yaml
providers:
  fabric:
    workspace_id: "your-workspace-id"
    lakehouse_id: "your-lakehouse-id"
    sql_endpoint: "your-sql-endpoint.datawarehouse.fabric.microsoft.com"
    tenant_id: "your-tenant-id"
    client_id: "your-client-id"
    client_secret: "your-client-secret"
    
  aws:
    region: "us-east-1"
    profile: "default"  # or use access keys
```

### 3. Environment Variables

Set sensitive credentials as environment variables:

```bash
# Azure/Fabric
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"
export FABRIC_WORKSPACE_ID="your-workspace-id"
export FABRIC_LAKEHOUSE_ID="your-lakehouse-id"
export FABRIC_SQL_ENDPOINT="your-endpoint"

# AWS (if not using AWS CLI profile)
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"

# RDS
export RDS_MAIN_HOST="your-rds-endpoint"
export RDS_MAIN_USER="admin"
export RDS_MAIN_PASSWORD="your-password"
export RDS_MAIN_DATABASE="your-database"

# MongoDB
export MONGODB_NODE1="10.0.1.10"
export MONGODB_NODE2="10.0.1.11"
export MONGODB_NODE3="10.0.1.12"
```

## Usage

### CLI Commands

```bash
# Add to PATH
export PATH="/path/to/project/bin:$PATH"

# Microsoft Fabric operations
cloud-cli fabric tables                    # List all tables
cloud-cli fabric query "SELECT * FROM toner_features LIMIT 10"
cloud-cli fabric schema toner_features     # Show table schema

# AWS operations
cloud-cli aws rds                         # List RDS instances
cloud-cli aws mongodb                     # List MongoDB clusters
cloud-cli aws backup "data" "backup.json" # Create S3 backup
cloud-cli aws costs --days 30            # Cost analysis

# Multi-cloud operations
cloud-cli cloud resources                 # List all resources
cloud-cli cloud health                    # Check resource health
cloud-cli cloud sync-status              # Show sync jobs
cloud-cli cloud optimize                 # Cost optimization

# Security operations
cloud-cli security policies              # List security policies
cloud-cli security compliance            # Run compliance scan
cloud-cli security incidents             # List incidents
cloud-cli security posture              # Security assessment

# Monitoring operations
cloud-cli monitor status                 # System status
cloud-cli monitor alerts                 # Active alerts
cloud-cli monitor metric cpu_usage       # Metric details
cloud-cli monitor cost-report --days 30  # Cost report
```

### Python API

```python
from cloud_integration import FabricConnector, AWSServicesManager, MultiCloudOrchestrator

# Microsoft Fabric
fabric_config = FabricConfig(
    workspace_id="your-workspace-id",
    lakehouse_id="your-lakehouse-id",
    sql_endpoint="your-endpoint",
    tenant_id="your-tenant-id",
    client_id="your-client-id",
    client_secret="your-secret"
)
fabric = FabricConnector(fabric_config)
fabric.initialize()

# Query Fabric
df = fabric.execute_query("SELECT * FROM toner_features LIMIT 100")

# AWS Services
aws_config = AWSConfig(
    region="us-east-1",
    s3_backup_bucket="solution-automater-backups"
)
aws = AWSServicesManager(aws_config)
aws.initialize()

# Create backup
etag = aws.create_backup(df, "backups/toner_data.parquet")

# Multi-Cloud Orchestrator
orchestrator = MultiCloudOrchestrator("configs/cloud_integration_config.yaml")
orchestrator.initialize()

# Discover all resources
resources = orchestrator.discover_all_resources()

# Run cross-cloud query
results = orchestrator.execute_cross_cloud_query(
    "SELECT * FROM customers",
    [CloudProvider.FABRIC, CloudProvider.AWS]
)
```

## Features

### 1. Microsoft Fabric Integration

- **SQL Endpoint Access**: Direct connection to Fabric SQL endpoints
- **Delta Lake Support**: Read/write Delta tables with full schema support
- **Query Optimization**: Intelligent query routing and caching
- **Streaming Support**: Handle large result sets with streaming
- **Schema Discovery**: Automatic table and column discovery

### 2. AWS Services Management

- **S3 Operations**: Encrypted backup/restore with lifecycle management
- **RDS Access**: Connection pooling for MySQL databases
- **MongoDB Clusters**: Auto-discovery and connection management
- **Cost Tracking**: Real-time cost monitoring and optimization
- **Security Groups**: Automated security group management

### 3. Multi-Cloud Orchestration

- **Unified Resource Management**: Single interface for all clouds
- **Cross-Cloud Sync**: Data synchronization between platforms
- **Disaster Recovery**: Automated failover and backup strategies
- **Service Discovery**: Automatic resource discovery and health monitoring
- **Cost Optimization**: Cross-cloud cost analysis and recommendations

### 4. Security & Compliance

- **Cross-Cloud IAM**: Unified access control management
- **Encryption**: Key management across all platforms
- **Compliance Scanning**: SOC2, HIPAA, GDPR, PCI-DSS monitoring
- **Incident Response**: Automated threat detection and response
- **Audit Logging**: Comprehensive audit trail across clouds

### 5. Monitoring & Alerting

- **Real-Time Metrics**: Performance and availability monitoring
- **Custom Alerts**: Configurable thresholds and notifications
- **Cost Alerts**: Budget monitoring and anomaly detection
- **Dashboard Support**: Pre-built monitoring dashboards
- **SIEM Integration**: Forward logs to security systems

## Security

### Authentication

- **Microsoft Fabric**: Service Principal or Managed Identity
- **AWS**: IAM roles, access keys, or instance profiles
- **Encryption**: All data encrypted in transit and at rest
- **Credential Storage**: Use environment variables or secure vaults

### Network Security

- **VPC Isolation**: All resources in private subnets
- **Security Groups**: Least-privilege access rules
- **Encryption**: TLS 1.2+ for all connections
- **WAF Protection**: Web application firewall for public endpoints

### Compliance

- **Data Residency**: Configurable region restrictions
- **Audit Logging**: All operations logged with full context
- **Access Control**: Role-based access with MFA support
- **Compliance Reports**: Automated compliance scanning

## Infrastructure as Code

Deploy cloud resources using Terraform:

```bash
cd infrastructure/terraform
terraform init
terraform plan
terraform apply
```

Key resources created:
- VPC with public/private subnets
- RDS MySQL with read replicas
- S3 buckets with encryption
- MongoDB cluster on EC2
- CloudWatch monitoring
- IAM roles and policies

## Monitoring

### Metrics

The system automatically tracks:
- Resource availability and health
- Query performance and latency
- Cost metrics by service and tag
- Security compliance scores
- Data sync status and lag

### Alerts

Pre-configured alerts for:
- High CPU/memory usage (>80%)
- Low disk space (<10%)
- Failed health checks
- Cost anomalies
- Security incidents

### Dashboards

Access monitoring dashboards:

```python
# Create dashboard
dashboard_id = monitor.create_dashboard(
    name="Cloud Overview",
    description="Multi-cloud monitoring",
    widgets=[
        {
            'type': 'line_chart',
            'title': 'Resource Health',
            'metrics': [{'name': 'health.status'}]
        },
        {
            'type': 'gauge',
            'title': 'Cost Trend',
            'metrics': [{'name': 'cloud.daily_cost'}]
        }
    ]
)

# Get dashboard data
data = monitor.get_dashboard_data(dashboard_id)
```

## Troubleshooting

### Common Issues

1. **Fabric Connection Failed**
   - Verify service principal credentials
   - Check firewall rules for SQL endpoint
   - Ensure correct workspace/lakehouse IDs

2. **AWS Authentication Error**
   - Run `aws configure` to set up credentials
   - Check IAM permissions for required services
   - Verify S3 bucket names are globally unique

3. **MongoDB Connection Issues**
   - Verify EC2 instances are running
   - Check security group allows port 27017
   - Ensure replica set is properly configured

4. **High Costs**
   - Review cost optimization recommendations
   - Check for unused resources
   - Enable auto-scaling where appropriate

### Debug Mode

Enable detailed logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Or via environment variable
export CLOUD_INTEGRATION_LOG_LEVEL=DEBUG
```

## Performance Optimization

### Connection Pooling

All database connections use connection pooling:
- Fabric: 10 connections (configurable)
- RDS: 5 connections per pool
- MongoDB: 50 max connections

### Caching

Enable caching for better performance:
- Metadata caching: 1 hour TTL
- Query result caching: Configurable TTL
- Cross-request cache sharing

### Batch Operations

Use batch operations for efficiency:
```python
# Batch S3 uploads
files = [("local1.csv", "s3/key1.csv"), ("local2.csv", "s3/key2.csv")]
uploaded = await aws.upload_files_async(files, "bucket-name")

# Batch metric recording
for metric in metrics:
    monitor.record_metric(metric.name, metric.value, metric.tags)
```

## Best Practices

1. **Use Environment Variables**: Never hardcode credentials
2. **Enable Monitoring**: Set up alerts for critical resources
3. **Regular Backups**: Schedule automated backups
4. **Cost Optimization**: Review recommendations monthly
5. **Security Scanning**: Run compliance scans weekly
6. **Update Dependencies**: Keep libraries up to date
7. **Use Connection Pools**: Don't create new connections per request
8. **Handle Errors**: Implement retry logic with exponential backoff

## Contributing

1. Follow the existing code style
2. Add tests for new features
3. Update documentation
4. Run security scanning before commits

## License

This module is part of the Solution-Automater-Sandbox project.