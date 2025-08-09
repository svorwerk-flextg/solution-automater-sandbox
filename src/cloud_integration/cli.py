"""
Cloud Integration CLI

Command-line interface for cloud integration management
"""

import click
import json
import yaml
import os
from datetime import datetime, timedelta
from tabulate import tabulate
import pandas as pd
from typing import Optional

from .fabric_connector import FabricConnector, FabricConfig
from .aws_manager import AWSServicesManager, AWSConfig, S3BackupConfig
from .multi_cloud_orchestrator import (
    MultiCloudOrchestrator, CloudProvider, DataSyncConfig, 
    DisasterRecoveryConfig
)
from .security_manager import (
    CloudSecurityManager, SecurityPolicy, ComplianceFramework,
    ThreatLevel
)
from .monitoring import CloudMonitor, AlertSeverity, Alert

# Load configuration
CONFIG_FILE = os.getenv('CLOUD_CONFIG_FILE', 'configs/cloud_integration_config.yaml')


def load_config():
    """Load configuration from file"""
    with open(CONFIG_FILE, 'r') as f:
        config = yaml.safe_load(f)
    
    # Substitute environment variables
    def substitute_env_vars(obj):
        if isinstance(obj, str) and obj.startswith('${') and obj.endswith('}'):
            env_var = obj[2:-1]
            return os.getenv(env_var, obj)
        elif isinstance(obj, dict):
            return {k: substitute_env_vars(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [substitute_env_vars(item) for item in obj]
        return obj
    
    return substitute_env_vars(config)


@click.group()
@click.pass_context
def cli(ctx):
    """Cloud Integration Management CLI"""
    ctx.ensure_object(dict)
    ctx.obj['config'] = load_config()


# Fabric Commands
@cli.group()
@click.pass_context
def fabric(ctx):
    """Microsoft Fabric operations"""
    config = ctx.obj['config']['providers']['fabric']
    fabric_config = FabricConfig(**config)
    ctx.obj['fabric'] = FabricConnector(fabric_config)
    ctx.obj['fabric'].initialize()


@fabric.command()
@click.pass_context
def tables(ctx):
    """List all Fabric tables"""
    connector = ctx.obj['fabric']
    
    click.echo("Discovering Fabric tables...")
    tables = connector.discover_tables()
    
    if not tables:
        click.echo("No tables found")
        return
    
    # Format as table
    table_data = []
    for table in tables:
        table_data.append([
            table.schema,
            table.name,
            len(table.columns),
            table.format,
            table.properties.get('row_count', 'N/A')
        ])
    
    headers = ['Schema', 'Table', 'Columns', 'Format', 'Row Count']
    click.echo(tabulate(table_data, headers=headers, tablefmt='grid'))


@fabric.command()
@click.argument('query')
@click.option('--limit', default=10, help='Limit number of results')
@click.pass_context
def query(ctx, query, limit):
    """Execute SQL query on Fabric"""
    connector = ctx.obj['fabric']
    
    # Add limit if not present
    if 'limit' not in query.lower() and 'top' not in query.lower():
        query = f"{query} LIMIT {limit}"
    
    click.echo(f"Executing query: {query}")
    
    try:
        df = connector.execute_query(query)
        click.echo(f"\nResults ({len(df)} rows):")
        click.echo(df.to_string())
    except Exception as e:
        click.echo(f"Error: {e}", err=True)


@fabric.command()
@click.argument('table_name')
@click.pass_context
def schema(ctx, table_name):
    """Show table schema"""
    connector = ctx.obj['fabric']
    
    # Parse schema.table format
    if '.' in table_name:
        schema_name, table_name = table_name.split('.', 1)
    else:
        schema_name = 'dbo'
    
    schema_info = connector.get_table_schema(table_name, schema_name)
    
    if not schema_info:
        click.echo(f"Table {schema_name}.{table_name} not found")
        return
    
    click.echo(f"\nTable: {schema_info['schema']}.{schema_info['table_name']}")
    click.echo(f"Location: {schema_info['location']}")
    click.echo("\nColumns:")
    
    # Format columns
    column_data = []
    for col in schema_info['columns']:
        column_data.append([
            col['name'],
            col['type'],
            'YES' if col['nullable'] else 'NO',
            col.get('default', '')
        ])
    
    headers = ['Column', 'Type', 'Nullable', 'Default']
    click.echo(tabulate(column_data, headers=headers, tablefmt='grid'))


# AWS Commands
@cli.group()
@click.pass_context
def aws(ctx):
    """AWS services operations"""
    config = ctx.obj['config']['providers']['aws']
    aws_config = AWSConfig(**config)
    ctx.obj['aws'] = AWSServicesManager(aws_config)
    ctx.obj['aws'].initialize()


@aws.command()
@click.pass_context
def rds(ctx):
    """List RDS instances"""
    manager = ctx.obj['aws']
    
    click.echo("Discovering RDS instances...")
    instances = manager.discover_rds_instances()
    
    if not instances:
        click.echo("No RDS instances found")
        return
    
    # Format as table
    instance_data = []
    for instance in instances:
        instance_data.append([
            instance.identifier,
            instance.endpoint,
            instance.port,
            instance.database,
            'SSL' if instance.ssl_enabled else 'No SSL'
        ])
    
    headers = ['Identifier', 'Endpoint', 'Port', 'Database', 'SSL']
    click.echo(tabulate(instance_data, headers=headers, tablefmt='grid'))


@aws.command()
@click.pass_context
def mongodb(ctx):
    """List MongoDB clusters"""
    manager = ctx.obj['aws']
    
    click.echo("Discovering MongoDB clusters...")
    clusters = manager.discover_ec2_mongodb()
    
    if not clusters:
        click.echo("No MongoDB clusters found")
        return
    
    for cluster_name, nodes in clusters.items():
        click.echo(f"\nCluster: {cluster_name}")
        click.echo(f"Nodes: {', '.join(nodes)}")


@aws.command()
@click.argument('data')
@click.argument('key')
@click.option('--encrypt/--no-encrypt', default=True)
@click.pass_context
def backup(ctx, data, key, encrypt):
    """Create S3 backup"""
    manager = ctx.obj['aws']
    
    # Create backup
    click.echo(f"Creating backup: {key}")
    
    try:
        etag = manager.create_backup(data, key)
        click.echo(f"Backup created successfully: {etag}")
    except Exception as e:
        click.echo(f"Backup failed: {e}", err=True)


@aws.command()
@click.option('--days', default=7, help='Number of days to analyze')
@click.pass_context
def costs(ctx, days):
    """Show AWS cost analysis"""
    manager = ctx.obj['aws']
    
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    
    click.echo(f"Analyzing costs from {start_date.date()} to {end_date.date()}")
    
    df = manager.get_cost_metrics(start_date, end_date)
    
    if df.empty:
        click.echo("No cost data available")
        return
    
    # Group by service
    service_costs = df.groupby('service')['cost'].sum().sort_values(ascending=False)
    
    click.echo("\nCost by Service:")
    for service, cost in service_costs.items():
        click.echo(f"  {service}: ${cost:.2f}")
    
    click.echo(f"\nTotal: ${service_costs.sum():.2f}")


# Multi-Cloud Commands
@cli.group()
@click.pass_context
def cloud(ctx):
    """Multi-cloud orchestration"""
    orchestrator = MultiCloudOrchestrator(CONFIG_FILE)
    orchestrator.initialize()
    ctx.obj['orchestrator'] = orchestrator


@cloud.command()
@click.pass_context
def resources(ctx):
    """List all cloud resources"""
    orchestrator = ctx.obj['orchestrator']
    
    click.echo("Discovering cloud resources...")
    resources = orchestrator.discover_all_resources()
    
    for provider, resource_list in resources.items():
        click.echo(f"\n{provider.value.upper()} Resources:")
        
        if not resource_list:
            click.echo("  No resources found")
            continue
        
        # Format as table
        resource_data = []
        for resource in resource_list:
            resource_data.append([
                resource.name,
                resource.resource_type.value,
                resource.region,
                resource.status
            ])
        
        headers = ['Name', 'Type', 'Region', 'Status']
        click.echo(tabulate(resource_data, headers=headers, tablefmt='grid'))


@cloud.command()
@click.pass_context
def health(ctx):
    """Check health of all resources"""
    orchestrator = ctx.obj['orchestrator']
    
    click.echo("Checking resource health...")
    
    healthy_count = 0
    unhealthy_count = 0
    
    for resource_id, resource in orchestrator.resources.items():
        status = resource.status
        
        if status == 'healthy':
            healthy_count += 1
            click.echo(f"✓ {resource.name} ({resource.provider.value}): {status}")
        else:
            unhealthy_count += 1
            click.echo(f"✗ {resource.name} ({resource.provider.value}): {status}")
    
    click.echo(f"\nSummary: {healthy_count} healthy, {unhealthy_count} unhealthy")


@cloud.command()
@click.pass_context
def sync_status(ctx):
    """Show data sync status"""
    orchestrator = ctx.obj['orchestrator']
    
    click.echo("Data Synchronization Jobs:")
    
    for job_id, config in orchestrator.sync_jobs.items():
        click.echo(f"\n{job_id}:")
        click.echo(f"  Source: {config.source_provider.value} - {config.source_resource}")
        click.echo(f"  Target: {config.target_provider.value} - {config.target_resource}")
        click.echo(f"  Type: {config.sync_type}")
        click.echo(f"  Schedule: {config.schedule}")


@cloud.command()
@click.argument('job_id')
@click.pass_context
def run_sync(ctx, job_id):
    """Run a sync job manually"""
    orchestrator = ctx.obj['orchestrator']
    
    if job_id not in orchestrator.sync_jobs:
        click.echo(f"Sync job {job_id} not found", err=True)
        return
    
    click.echo(f"Running sync job {job_id}...")
    
    try:
        orchestrator._process_sync_job(job_id)
        click.echo("Sync completed successfully")
    except Exception as e:
        click.echo(f"Sync failed: {e}", err=True)


@cloud.command()
@click.pass_context
def optimize(ctx):
    """Show cost optimization recommendations"""
    orchestrator = ctx.obj['orchestrator']
    
    click.echo("Analyzing for cost optimization...")
    recommendations = orchestrator.optimize_costs()
    
    click.echo(f"\nTotal Monthly Cost: ${recommendations['total_monthly_cost']:.2f}")
    click.echo(f"Potential Savings: ${recommendations['potential_savings']:.2f}")
    
    if recommendations['recommendations']:
        click.echo("\nRecommendations:")
        for rec in recommendations['recommendations']:
            click.echo(f"\n- Resource: {rec['resource']}")
            click.echo(f"  Action: {rec['action']}")
            click.echo(f"  Reason: {rec['reason']}")
            click.echo(f"  Monthly Savings: ${rec['monthly_savings']:.2f}")


# Security Commands
@cli.group()
@click.pass_context
def security(ctx):
    """Security management"""
    security_manager = CloudSecurityManager(CONFIG_FILE)
    security_manager.initialize()
    ctx.obj['security'] = security_manager


@security.command()
@click.pass_context
def policies(ctx):
    """List security policies"""
    manager = ctx.obj['security']
    
    click.echo("Security Policies:")
    
    for policy_id, policy in manager.policies.items():
        click.echo(f"\n{policy.name}:")
        click.echo(f"  ID: {policy_id}")
        click.echo(f"  Description: {policy.description}")
        click.echo(f"  Rules: {len(policy.rules)}")
        click.echo(f"  Frameworks: {', '.join(f.value for f in policy.compliance_frameworks)}")


@security.command()
@click.option('--frameworks', '-f', multiple=True, 
              help='Compliance frameworks to scan')
@click.pass_context
def compliance(ctx, frameworks):
    """Run compliance scan"""
    manager = ctx.obj['security']
    
    # Use all frameworks if none specified
    if not frameworks:
        frameworks = [f.value for f in ComplianceFramework]
    
    framework_enums = [ComplianceFramework(f) for f in frameworks]
    
    click.echo(f"Running compliance scan for: {', '.join(frameworks)}")
    
    results = manager.run_compliance_scan(framework_enums)
    
    click.echo(f"\nOverall Score: {results['overall_score']:.1f}%")
    
    for framework, details in results['frameworks'].items():
        click.echo(f"\n{framework.upper()}:")
        click.echo(f"  Score: {details['score']:.1f}%")
        click.echo(f"  Passed: {details['passed_rules']}/{details['total_rules']}")
        
        if details['violations']:
            click.echo("  Violations:")
            for violation in details['violations'][:5]:  # Show first 5
                click.echo(f"    - {violation['description']}")


@security.command()
@click.pass_context
def incidents(ctx):
    """List security incidents"""
    manager = ctx.obj['security']
    
    active_incidents = [
        inc for inc in manager.incidents.values()
        if inc.remediation_status != 'resolved'
    ]
    
    if not active_incidents:
        click.echo("No active security incidents")
        return
    
    click.echo(f"Active Security Incidents ({len(active_incidents)}):")
    
    for incident in active_incidents:
        click.echo(f"\n{incident.incident_id}:")
        click.echo(f"  Severity: {incident.threat_level.value}")
        click.echo(f"  Time: {incident.timestamp}")
        click.echo(f"  Description: {incident.description}")
        click.echo(f"  Status: {incident.remediation_status}")


@security.command()
@click.pass_context
def posture(ctx):
    """Assess security posture"""
    manager = ctx.obj['security']
    
    click.echo("Assessing security posture...")
    assessment = manager.assess_security_posture()
    
    click.echo(f"\nOverall Security Score: {assessment['overall_score']:.1f}%")
    
    click.echo("\nCategory Scores:")
    for category, details in assessment['categories'].items():
        click.echo(f"  {category.replace('_', ' ').title()}: {details['score']:.1f}%")
    
    if assessment['recommendations']:
        click.echo("\nTop Recommendations:")
        for rec in assessment['recommendations'][:5]:
            click.echo(f"  - {rec}")


# Monitoring Commands
@cli.group()
@click.pass_context
def monitor(ctx):
    """Monitoring and alerting"""
    monitor = CloudMonitor(ctx.obj['config'].get('monitoring', {}))
    monitor.initialize()
    ctx.obj['monitor'] = monitor


@monitor.command()
@click.pass_context
def status(ctx):
    """Show monitoring status"""
    monitor = ctx.obj['monitor']
    
    status = monitor.get_monitoring_status()
    
    click.echo("Monitoring System Status:")
    click.echo(f"  Running: {status['running']}")
    click.echo(f"  Metric Series: {status['metrics']['total_series']}")
    click.echo(f"  Data Points: {status['metrics']['total_points']}")
    click.echo(f"  Alerts: {status['alerts']['total']} ({status['alerts']['firing']} firing)")
    click.echo(f"  Dashboards: {status['dashboards']}")


@monitor.command()
@click.pass_context
def alerts(ctx):
    """List active alerts"""
    monitor = ctx.obj['monitor']
    
    firing_alerts = [
        instance for instance in monitor.alert_instances.values()
        if instance.state.value == 'firing'
    ]
    
    if not firing_alerts:
        click.echo("No active alerts")
        return
    
    click.echo(f"Active Alerts ({len(firing_alerts)}):")
    
    for instance in firing_alerts:
        click.echo(f"\n{instance.alert.name}:")
        click.echo(f"  Severity: {instance.alert.severity.value}")
        click.echo(f"  Triggered: {instance.triggered_at}")
        click.echo(f"  Current Value: {instance.current_value}")
        click.echo(f"  Threshold: {instance.alert.threshold}")


@monitor.command()
@click.argument('metric_name')
@click.option('--period', default='1h', help='Time period (1h, 6h, 24h)')
@click.pass_context
def metric(ctx, metric_name, period):
    """Show metric details"""
    monitor = ctx.obj['monitor']
    
    # Parse period
    period_map = {
        '1h': timedelta(hours=1),
        '6h': timedelta(hours=6),
        '24h': timedelta(hours=24),
        '7d': timedelta(days=7)
    }
    
    time_delta = period_map.get(period, timedelta(hours=1))
    end_time = datetime.now()
    start_time = end_time - time_delta
    
    metrics = monitor.get_metrics(metric_name, start_time=start_time, end_time=end_time)
    
    if not metrics:
        click.echo(f"No data for metric: {metric_name}")
        return
    
    # Get statistics
    stats = monitor.get_metric_statistics(metric_name)
    
    click.echo(f"\nMetric: {metric_name}")
    click.echo(f"Period: {period}")
    click.echo(f"Data Points: {len(metrics)}")
    
    if stats:
        click.echo("\nStatistics:")
        click.echo(f"  Average: {stats.get('avg', 0):.2f}")
        click.echo(f"  Min: {stats.get('min', 0):.2f}")
        click.echo(f"  Max: {stats.get('max', 0):.2f}")
        click.echo(f"  P95: {stats.get('p95', 0):.2f}")


@monitor.command()
@click.option('--days', default=30, help='Number of days to analyze')
@click.option('--group-by', multiple=True, help='Group by fields')
@click.pass_context
def cost_report(ctx, days, group_by):
    """Generate cost report"""
    monitor = ctx.obj['monitor']
    
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    
    click.echo(f"Cost Report: {start_date.date()} to {end_date.date()}")
    
    df = monitor.get_cost_report(start_date, end_date, list(group_by))
    
    if df.empty:
        click.echo("No cost data available")
        return
    
    # Display summary
    total_cost = df['cost'].sum()
    click.echo(f"\nTotal Cost: ${total_cost:.2f}")
    
    if group_by:
        click.echo(f"\nGrouped by: {', '.join(group_by)}")
        click.echo(df.to_string())
    else:
        # Show daily costs
        daily_costs = df.groupby(pd.Grouper(key='timestamp', freq='D'))['cost'].sum()
        click.echo("\nDaily Costs:")
        for date, cost in daily_costs.items():
            click.echo(f"  {date.date()}: ${cost:.2f}")


# Main entry point
if __name__ == '__main__':
    cli()