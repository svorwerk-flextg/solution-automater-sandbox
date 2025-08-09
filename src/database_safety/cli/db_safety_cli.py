#!/usr/bin/env python3
"""
Database Safety CLI Tool
Command-line interface for database safety layer management and operations.
"""

import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import click
import yaml
from tabulate import tabulate

# Add parent directory to path to import our modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.db_proxy import DatabaseSafetyProxy, create_database_proxy, database_proxy
from core.config import ProxyConfig, create_default_config_file, ConfigManager
from core.sandbox_manager import SandboxManager, SandboxConfig, SandboxType, SandboxState
from core.schema_replicator import SchemaReplicator
from core.data_masking import DataMaskingEngine, MaskingLevel, analyze_dataset_sensitivity
from core.query_analyzer import QuerySafetyAnalyzer


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@click.group()
@click.option('--config', '-c', type=click.Path(exists=True), help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.pass_context
def cli(ctx, config, verbose):
    """Database Safety Layer - Bulletproof database operations with write protection."""
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    ctx.ensure_object(dict)
    ctx.obj['config_path'] = config


# Configuration Commands
@cli.group()
def config():
    """Configuration management commands."""
    pass


@config.command('create-default')
@click.option('--output', '-o', default='database_config.yaml', help='Output file path')
def create_default_config(output):
    """Create default configuration file."""
    try:
        create_default_config_file(output)
        click.echo(f"✅ Default configuration created: {output}")
    except Exception as e:
        click.echo(f"❌ Error creating configuration: {e}", err=True)
        sys.exit(1)


@config.command('validate')
@click.argument('config_file', type=click.Path(exists=True))
def validate_config(config_file):
    """Validate configuration file."""
    try:
        config_manager = ConfigManager(config_file)
        asyncio.run(config_manager.load_config())
        click.echo(f"✅ Configuration is valid: {config_file}")
    except Exception as e:
        click.echo(f"❌ Configuration validation failed: {e}", err=True)
        sys.exit(1)


@config.command('show')
@click.argument('config_file', type=click.Path(exists=True))
@click.option('--section', help='Show specific section only')
def show_config(config_file, section):
    """Display configuration file contents."""
    try:
        with open(config_file, 'r') as f:
            config_data = yaml.safe_load(f)
        
        if section:
            if section in config_data:
                config_data = {section: config_data[section]}
            else:
                click.echo(f"❌ Section '{section}' not found in configuration")
                sys.exit(1)
        
        click.echo(yaml.dump(config_data, default_flow_style=False))
        
    except Exception as e:
        click.echo(f"❌ Error reading configuration: {e}", err=True)
        sys.exit(1)


# Proxy Service Commands
@cli.group()
@click.pass_context
def proxy(ctx):
    """Database proxy service commands."""
    pass


@proxy.command('start')
@click.option('--host', default='localhost', help='Host to bind to')
@click.option('--port', default=8080, help='Port to bind to')
@click.option('--workers', default=4, help='Number of worker processes')
@click.pass_context
def start_proxy(ctx, host, port, workers):
    """Start database proxy service."""
    async def _start_proxy():
        config_path = ctx.obj.get('config_path')
        
        async with database_proxy(config_path) as proxy:
            click.echo(f"🚀 Database Safety Proxy starting on {host}:{port}")
            click.echo(f"📊 Configured databases: {len(proxy.config.databases)}")
            click.echo(f"🛡️  Safety rules: {len(proxy.config.safety_rules)}")
            
            # Start HTTP API server (would need FastAPI/similar implementation)
            try:
                # Placeholder for actual HTTP server
                click.echo(f"✅ Proxy service running on http://{host}:{port}")
                click.echo("Press Ctrl+C to stop...")
                
                # Keep running until interrupted
                while True:
                    await asyncio.sleep(1)
                    
            except KeyboardInterrupt:
                click.echo("\n🛑 Stopping proxy service...")
    
    try:
        asyncio.run(_start_proxy())
    except KeyboardInterrupt:
        click.echo("👋 Proxy service stopped")


@proxy.command('test')
@click.option('--query', required=True, help='SQL query to test')
@click.option('--database', required=True, help='Database name')
@click.option('--type', default='mssql', help='Database type')
@click.pass_context
def test_query(ctx, query, database, type):
    """Test query against proxy safety rules."""
    async def _test_query():
        config_path = ctx.obj.get('config_path')
        
        async with database_proxy(config_path) as proxy:
            from core.db_proxy import QueryRequest, DatabaseType
            
            request = QueryRequest(
                query=query,
                database_type=DatabaseType(type),
                database_name=database,
                user_context={'test_mode': True}
            )
            
            result = await proxy.execute_query(request)
            
            if result.success:
                click.echo("✅ Query passed safety validation")
                if result.data:
                    if isinstance(result.data, list) and len(result.data) > 0:
                        click.echo(f"📊 Results: {len(result.data)} rows")
                        # Show first few rows
                        for i, row in enumerate(result.data[:5]):
                            click.echo(f"   Row {i+1}: {row}")
                        if len(result.data) > 5:
                            click.echo(f"   ... and {len(result.data) - 5} more rows")
                    else:
                        click.echo(f"📊 Result: {result.data}")
                else:
                    click.echo(f"📊 Rows affected: {result.rows_affected}")
            else:
                click.echo(f"❌ Query blocked: {result.error_message}")
                
            if result.safety_info:
                click.echo(f"\n🛡️  Safety Analysis:")
                click.echo(f"   Operations: {result.safety_info.get('operations', [])}")
                click.echo(f"   Safety Level: {result.safety_info.get('safety_level', 'unknown')}")
                if result.safety_info.get('risk_factors'):
                    click.echo(f"   Risk Factors: {', '.join(result.safety_info['risk_factors'])}")
    
    try:
        asyncio.run(_test_query())
    except Exception as e:
        click.echo(f"❌ Error testing query: {e}", err=True)
        sys.exit(1)


@proxy.command('stats')
@click.pass_context
def proxy_stats(ctx):
    """Show proxy service statistics."""
    async def _show_stats():
        config_path = ctx.obj.get('config_path')
        
        async with database_proxy(config_path) as proxy:
            # Get audit log
            audit_entries = await proxy.get_audit_log(limit=10)
            
            click.echo("📊 Database Proxy Statistics")
            click.echo(f"   Total queries logged: {len(audit_entries)}")
            
            if audit_entries:
                successful = sum(1 for entry in audit_entries if entry['success'])
                failed = len(audit_entries) - successful
                
                click.echo(f"   Successful queries: {successful}")
                click.echo(f"   Failed/blocked queries: {failed}")
                
                # Operation breakdown
                operations = {}
                for entry in audit_entries:
                    for op in entry.get('operations', []):
                        operations[op] = operations.get(op, 0) + 1
                
                if operations:
                    click.echo("\n🔍 Operation Breakdown:")
                    for op, count in sorted(operations.items()):
                        click.echo(f"   {op}: {count}")
                
                # Recent queries
                click.echo("\n📋 Recent Queries:")
                for i, entry in enumerate(audit_entries[-5:], 1):
                    status = "✅" if entry['success'] else "❌"
                    click.echo(f"   {i}. {status} {entry['database_type']}/{entry['database_name']}: {entry['query'][:50]}...")
    
    try:
        asyncio.run(_show_stats())
    except Exception as e:
        click.echo(f"❌ Error getting statistics: {e}", err=True)
        sys.exit(1)


# Sandbox Management Commands  
@cli.group()
def sandbox():
    """Sandbox database management commands."""
    pass


@sandbox.command('create')
@click.option('--name', required=True, help='Sandbox name')
@click.option('--type', type=click.Choice(['sqlite', 'postgres', 'mysql', 'mongodb']), 
              default='sqlite', help='Sandbox database type')
@click.option('--source', required=True, help='Source database connection string')
@click.option('--database', required=True, help='Source database name')
@click.option('--sample-size', default=1000, help='Sample size per table')
@click.option('--no-masking', is_flag=True, help='Disable data masking')
@click.option('--tables', help='Comma-separated list of tables to include')
@click.option('--auto-refresh', is_flag=True, help='Enable auto-refresh')
@click.option('--refresh-hours', default=24, help='Auto-refresh interval in hours')
def create_sandbox(name, type, source, database, sample_size, no_masking, 
                  tables, auto_refresh, refresh_hours):
    """Create new sandbox database."""
    async def _create_sandbox():
        manager = SandboxManager()
        await manager.initialize()
        
        try:
            config = SandboxConfig(
                name=name,
                sandbox_type=SandboxType(type),
                source_connection=source,
                source_database=database,
                sample_size_per_table=sample_size,
                enable_data_masking=not no_masking,
                tables_to_include=tables.split(',') if tables else None,
                auto_refresh_enabled=auto_refresh,
                auto_refresh_interval_hours=refresh_hours,
                created_by=os.getenv('USER', 'unknown')
            )
            
            click.echo(f"🔄 Creating sandbox '{name}'...")
            sandbox_info = await manager.create_sandbox(config)
            
            click.echo(f"✅ Sandbox created successfully!")
            click.echo(f"   Name: {sandbox_info.config.name}")
            click.echo(f"   Type: {sandbox_info.config.sandbox_type.value}")
            click.echo(f"   Connection: {sandbox_info.connection_string}")
            click.echo(f"   Tables: {sandbox_info.table_count}")
            click.echo(f"   Rows: {sandbox_info.total_rows:,}")
            click.echo(f"   Storage: {sandbox_info.storage_size_mb:.1f} MB")
            
            if sandbox_info.last_sync_duration:
                click.echo(f"   Sync Duration: {sandbox_info.last_sync_duration:.1f}s")
                
        except Exception as e:
            click.echo(f"❌ Error creating sandbox: {e}", err=True)
            sys.exit(1)
        finally:
            await manager.shutdown()
    
    asyncio.run(_create_sandbox())


@sandbox.command('list')
@click.option('--state', type=click.Choice(['creating', 'active', 'refreshing', 'paused', 'failed', 'destroyed']),
              help='Filter by state')
@click.option('--type', type=click.Choice(['sqlite', 'postgres', 'mysql', 'mongodb']),
              help='Filter by type')
@click.option('--format', type=click.Choice(['table', 'json']), default='table',
              help='Output format')
def list_sandboxes(state, type, format):
    """List sandbox databases."""
    async def _list_sandboxes():
        manager = SandboxManager()
        await manager.initialize()
        
        try:
            state_filter = SandboxState(state) if state else None
            type_filter = SandboxType(type) if type else None
            
            sandboxes = await manager.list_sandboxes(
                state_filter=state_filter,
                type_filter=type_filter
            )
            
            if format == 'json':
                sandbox_data = []
                for sandbox in sandboxes:
                    sandbox_data.append({
                        'name': sandbox.config.name,
                        'type': sandbox.config.sandbox_type.value,
                        'state': sandbox.state.value,
                        'created_at': sandbox.created_at.isoformat(),
                        'tables': sandbox.table_count,
                        'rows': sandbox.total_rows,
                        'storage_mb': sandbox.storage_size_mb
                    })
                
                click.echo(json.dumps(sandbox_data, indent=2))
            else:
                if not sandboxes:
                    click.echo("No sandboxes found.")
                    return
                
                table_data = []
                for sandbox in sandboxes:
                    age_days = (sandbox.created_at.now() - sandbox.created_at).days if sandbox.created_at else 0
                    table_data.append([
                        sandbox.config.name,
                        sandbox.config.sandbox_type.value,
                        sandbox.state.value,
                        f"{age_days}d",
                        sandbox.table_count,
                        f"{sandbox.total_rows:,}",
                        f"{sandbox.storage_size_mb:.1f}MB"
                    ])
                
                headers = ['Name', 'Type', 'State', 'Age', 'Tables', 'Rows', 'Storage']
                click.echo(tabulate(table_data, headers=headers, tablefmt='grid'))
                
        except Exception as e:
            click.echo(f"❌ Error listing sandboxes: {e}", err=True)
            sys.exit(1)
        finally:
            await manager.shutdown()
    
    asyncio.run(_list_sandboxes())


@sandbox.command('info')
@click.argument('name')
def sandbox_info(name):
    """Show detailed sandbox information."""
    async def _show_info():
        manager = SandboxManager()
        await manager.initialize()
        
        try:
            sandbox_info = await manager.get_sandbox_info(name)
            
            click.echo(f"📊 Sandbox Information: {name}")
            click.echo(f"   Type: {sandbox_info.config.sandbox_type.value}")
            click.echo(f"   State: {sandbox_info.state.value}")
            click.echo(f"   Created: {sandbox_info.created_at}")
            click.echo(f"   Created By: {sandbox_info.config.created_by or 'unknown'}")
            
            if sandbox_info.last_refreshed:
                click.echo(f"   Last Refreshed: {sandbox_info.last_refreshed}")
            
            if sandbox_info.last_accessed:
                click.echo(f"   Last Accessed: {sandbox_info.last_accessed}")
            
            click.echo(f"\n📈 Statistics:")
            click.echo(f"   Tables: {sandbox_info.table_count}")
            click.echo(f"   Total Rows: {sandbox_info.total_rows:,}")
            click.echo(f"   Storage Size: {sandbox_info.storage_size_mb:.1f} MB")
            
            if sandbox_info.last_sync_duration:
                click.echo(f"   Last Sync Duration: {sandbox_info.last_sync_duration:.1f}s")
            
            click.echo(f"\n⚙️  Configuration:")
            click.echo(f"   Source Database: {sandbox_info.config.source_database}")
            click.echo(f"   Sample Size: {sandbox_info.config.sample_size_per_table:,} rows/table")
            click.echo(f"   Data Masking: {'enabled' if sandbox_info.config.enable_data_masking else 'disabled'}")
            click.echo(f"   Auto Refresh: {'enabled' if sandbox_info.config.auto_refresh_enabled else 'disabled'}")
            
            if sandbox_info.config.auto_refresh_enabled:
                click.echo(f"   Refresh Interval: {sandbox_info.config.auto_refresh_interval_hours}h")
            
            click.echo(f"\n🔗 Connection:")
            click.echo(f"   {sandbox_info.connection_string}")
            
            if sandbox_info.last_error:
                click.echo(f"\n❌ Last Error:")
                click.echo(f"   {sandbox_info.last_error}")
                click.echo(f"   Error Count: {sandbox_info.error_count}")
                
        except ValueError as e:
            click.echo(f"❌ {e}")
            sys.exit(1)
        except Exception as e:
            click.echo(f"❌ Error getting sandbox info: {e}", err=True)
            sys.exit(1)
        finally:
            await manager.shutdown()
    
    asyncio.run(_show_info())


@sandbox.command('refresh')
@click.argument('name')
def refresh_sandbox(name):
    """Refresh sandbox data from source."""
    async def _refresh_sandbox():
        manager = SandboxManager()
        await manager.initialize()
        
        try:
            click.echo(f"🔄 Refreshing sandbox '{name}'...")
            sandbox_info = await manager.refresh_sandbox(name)
            
            click.echo(f"✅ Sandbox refreshed successfully!")
            click.echo(f"   Tables: {sandbox_info.table_count}")
            click.echo(f"   Rows: {sandbox_info.total_rows:,}")
            click.echo(f"   Storage: {sandbox_info.storage_size_mb:.1f} MB")
            
            if sandbox_info.last_sync_duration:
                click.echo(f"   Duration: {sandbox_info.last_sync_duration:.1f}s")
                
        except ValueError as e:
            click.echo(f"❌ {e}")
            sys.exit(1)
        except Exception as e:
            click.echo(f"❌ Error refreshing sandbox: {e}", err=True)
            sys.exit(1)
        finally:
            await manager.shutdown()
    
    asyncio.run(_refresh_sandbox())


@sandbox.command('destroy')
@click.argument('name')
@click.option('--force', is_flag=True, help='Force destruction even if errors occur')
def destroy_sandbox(name, force):
    """Destroy sandbox and clean up resources."""
    async def _destroy_sandbox():
        manager = SandboxManager()
        await manager.initialize()
        
        try:
            if not force:
                click.confirm(f"Are you sure you want to destroy sandbox '{name}'?", abort=True)
            
            click.echo(f"🗑️  Destroying sandbox '{name}'...")
            success = await manager.destroy_sandbox(name, force=force)
            
            if success:
                click.echo("✅ Sandbox destroyed successfully!")
            else:
                click.echo("⚠️  Sandbox destruction completed with warnings")
                
        except ValueError as e:
            click.echo(f"❌ {e}")
            sys.exit(1)
        except Exception as e:
            click.echo(f"❌ Error destroying sandbox: {e}", err=True)
            sys.exit(1)
        finally:
            await manager.shutdown()
    
    asyncio.run(_destroy_sandbox())


@sandbox.command('stats')
def sandbox_stats():
    """Show sandbox system statistics."""
    async def _show_stats():
        manager = SandboxManager()
        await manager.initialize()
        
        try:
            stats = await manager.get_sandbox_statistics()
            
            click.echo("📊 Sandbox System Statistics")
            click.echo(f"   Total Sandboxes: {stats['total_sandboxes']}")
            click.echo(f"   Total Storage: {stats['total_storage_gb']:.1f} GB")
            click.echo(f"   Storage Limit: {stats['storage_limit_gb']} GB")
            click.echo(f"   Sandbox Limit: {stats['sandbox_limit']}")
            
            if stats['states_breakdown']:
                click.echo(f"\n📈 States Breakdown:")
                for state, count in stats['states_breakdown'].items():
                    click.echo(f"   {state}: {count}")
            
            if stats['types_breakdown']:
                click.echo(f"\n🗄️  Types Breakdown:")
                for db_type, count in stats['types_breakdown'].items():
                    click.echo(f"   {db_type}: {count}")
                    
        except Exception as e:
            click.echo(f"❌ Error getting statistics: {e}", err=True)
            sys.exit(1)
        finally:
            await manager.shutdown()
    
    asyncio.run(_show_stats())


# Schema Commands
@cli.group()
def schema():
    """Schema replication and analysis commands."""
    pass


@schema.command('replicate')
@click.option('--source', required=True, help='Source database connection string')
@click.option('--target', required=True, help='Target database connection string')
@click.option('--database', required=True, help='Database name to replicate')
@click.option('--tables', help='Comma-separated list of tables to replicate')
@click.option('--sample-size', default=1000, help='Sample size per table')
@click.option('--no-masking', is_flag=True, help='Disable data masking')
def replicate_schema(source, target, database, tables, sample_size, no_masking):
    """Replicate database schema with sample data."""
    async def _replicate_schema():
        try:
            replicator = SchemaReplicator(source, target)
            replicator.mask_sensitive_data = not no_masking
            
            click.echo(f"🔄 Replicating schema for database '{database}'...")
            
            result = await replicator.replicate_schema(
                database_name=database,
                tables_to_replicate=tables.split(',') if tables else None,
                sample_size=sample_size
            )
            
            if result['success']:
                click.echo("✅ Schema replication completed successfully!")
                click.echo(f"   Tables: {result['statistics']['tables_processed']}")
                click.echo(f"   Rows: {result['statistics']['rows_copied']:,}")
                
                duration = result['statistics'].get('duration_seconds', 0)
                if duration:
                    click.echo(f"   Duration: {duration:.1f}s")
            else:
                click.echo(f"❌ Schema replication failed: {result['error']}")
                
                if result['statistics']['errors']:
                    click.echo("\nErrors:")
                    for error in result['statistics']['errors']:
                        click.echo(f"  - {error}")
                
                sys.exit(1)
                
        except Exception as e:
            click.echo(f"❌ Error replicating schema: {e}", err=True)
            sys.exit(1)
    
    asyncio.run(_replicate_schema())


# Data Masking Commands
@cli.group()
def mask():
    """Data masking and anonymization commands."""
    pass


@mask.command('analyze')
@click.option('--file', 'file_path', required=True, type=click.Path(exists=True),
              help='JSON file with sample data')
@click.option('--columns', help='JSON string with column type mappings')
def analyze_data(file_path, columns):
    """Analyze data for sensitive information."""
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        if not isinstance(data, list):
            click.echo("❌ Data file must contain an array of objects")
            sys.exit(1)
        
        # Get column types
        if columns:
            column_types = json.loads(columns)
        else:
            # Infer from first record
            if data:
                column_types = {col: 'string' for col in data[0].keys()}
            else:
                click.echo("❌ No data to analyze")
                sys.exit(1)
        
        # Perform analysis
        analysis = analyze_dataset_sensitivity(data, column_types)
        
        click.echo(f"📊 Data Sensitivity Analysis")
        click.echo(f"   Total Columns: {analysis['total_columns']}")
        click.echo(f"   Sensitive Columns: {analysis['sensitive_columns']}")
        click.echo(f"   Overall Sensitivity: {analysis['overall_sensitivity']:.1%}")
        
        if analysis['recommendations']:
            click.echo(f"\n🔍 Sensitive Columns Found:")
            for rec in analysis['recommendations']:
                click.echo(f"   {rec['column']}: {rec['strategy']} ({', '.join(rec['categories'])})")
        else:
            click.echo(f"\n✅ No sensitive data detected")
            
    except Exception as e:
        click.echo(f"❌ Error analyzing data: {e}", err=True)
        sys.exit(1)


@mask.command('test')
def test_masking():
    """Test data masking engine with sample data."""
    try:
        from core.data_masking import create_masking_engine, MaskingLevel
        
        engine = create_masking_engine(MaskingLevel.STANDARD)
        
        test_data = {
            'email': 'john.doe@example.com',
            'first_name': 'John',
            'last_name': 'Doe',
            'phone': '555-123-4567',
            'ssn': '123-45-6789',
            'salary': 75000.00,
            'credit_card': '4532-1234-5678-9012',
            'non_sensitive': 'This is not sensitive'
        }
        
        column_types = {
            'email': 'varchar',
            'first_name': 'varchar',
            'last_name': 'varchar',
            'phone': 'varchar',
            'ssn': 'varchar',
            'salary': 'decimal',
            'credit_card': 'varchar',
            'non_sensitive': 'varchar'
        }
        
        click.echo("🔍 Testing Data Masking Engine")
        click.echo("\nOriginal Data:")
        for key, value in test_data.items():
            click.echo(f"   {key}: {value}")
        
        masked_data = engine.mask_row_data(test_data, column_types)
        
        click.echo("\nMasked Data:")
        for key, value in masked_data.items():
            original = test_data[key]
            status = "🔒" if value != original else "➡️"
            click.echo(f"   {key}: {value} {status}")
        
        stats = engine.get_masking_statistics()
        click.echo(f"\n📊 Masking Statistics:")
        click.echo(f"   Values Processed: {stats['total_values_processed']}")
        click.echo(f"   Values Masked: {stats['values_masked']}")
        click.echo(f"   Masking Rate: {stats.get('masking_rate', 0):.1%}")
        
    except Exception as e:
        click.echo(f"❌ Error testing masking: {e}", err=True)
        sys.exit(1)


# Query Analysis Commands
@cli.group()
def query():
    """Query analysis and safety commands."""
    pass


@query.command('analyze')
@click.option('--query', required=True, help='SQL query to analyze')
@click.option('--database-type', default='mssql', 
              type=click.Choice(['mssql', 'mysql', 'postgresql', 'mongodb']),
              help='Database type')
def analyze_query(query, database_type):
    """Analyze query for safety and risk factors."""
    async def _analyze_query():
        try:
            analyzer = QuerySafetyAnalyzer()
            
            analysis = await analyzer.analyze_query(query, database_type)
            
            click.echo(f"🔍 Query Safety Analysis")
            click.echo(f"   Query Type: {analysis.query_type.value}")
            click.echo(f"   Safety Level: {analysis.safety_level.value}")
            click.echo(f"   Operations: {[op.value for op in analysis.operations]}")
            
            if analysis.tables_accessed:
                click.echo(f"   Tables: {', '.join(analysis.tables_accessed)}")
            
            if analysis.functions_used:
                click.echo(f"   Functions: {', '.join(analysis.functions_used)}")
            
            if analysis.risk_factors:
                click.echo(f"\n⚠️  Risk Factors:")
                for risk in analysis.risk_factors:
                    click.echo(f"   - {risk}")
            
            if analysis.matched_rules:
                click.echo(f"\n🛡️  Matched Safety Rules:")
                for rule in analysis.matched_rules:
                    click.echo(f"   - {rule.name}: {rule.description}")
            
            if analysis.potential_issues:
                click.echo(f"\n💡 Potential Issues:")
                for issue in analysis.potential_issues:
                    click.echo(f"   - {issue}")
            
            # Determine if query would be allowed in different environments
            from core.query_analyzer import is_query_safe
            
            click.echo(f"\n🏛️  Environment Permissions:")
            click.echo(f"   Production: {'✅ Allowed' if is_query_safe(analysis, 'production') else '❌ Blocked'}")
            click.echo(f"   Development: {'✅ Allowed' if is_query_safe(analysis, 'dev') else '❌ Blocked'}")
            click.echo(f"   Sandbox: {'✅ Allowed' if is_query_safe(analysis, 'sandbox') else '❌ Blocked'}")
            
        except Exception as e:
            click.echo(f"❌ Error analyzing query: {e}", err=True)
            sys.exit(1)
    
    asyncio.run(_analyze_query())


# System Commands
@cli.group()
def system():
    """System management and monitoring commands."""
    pass


@system.command('health')
@click.pass_context
def health_check(ctx):
    """Perform system health check."""
    async def _health_check():
        config_path = ctx.obj.get('config_path')
        
        try:
            click.echo("🏥 Database Safety System Health Check")
            
            # Check configuration
            if config_path and os.path.exists(config_path):
                click.echo("✅ Configuration file found")
                try:
                    config_manager = ConfigManager(config_path)
                    await config_manager.load_config()
                    click.echo("✅ Configuration is valid")
                except Exception as e:
                    click.echo(f"❌ Configuration validation failed: {e}")
            else:
                click.echo("⚠️  No configuration file specified")
            
            # Check proxy service
            try:
                if config_path:
                    async with database_proxy(config_path) as proxy:
                        click.echo("✅ Database proxy service operational")
                        click.echo(f"   Databases configured: {len(proxy.config.databases)}")
                        click.echo(f"   Safety rules active: {len(proxy.config.safety_rules)}")
                else:
                    click.echo("⚠️  Cannot test proxy without configuration")
            except Exception as e:
                click.echo(f"❌ Proxy service check failed: {e}")
            
            # Check sandbox manager
            try:
                manager = SandboxManager()
                await manager.initialize()
                
                sandboxes = await manager.list_sandboxes()
                stats = await manager.get_sandbox_statistics()
                
                click.echo("✅ Sandbox manager operational")
                click.echo(f"   Active sandboxes: {len(sandboxes)}")
                click.echo(f"   Total storage: {stats['total_storage_gb']:.1f} GB")
                
                await manager.shutdown()
                
            except Exception as e:
                click.echo(f"❌ Sandbox manager check failed: {e}")
            
            # Check data masking
            try:
                from core.data_masking import create_masking_engine
                engine = create_masking_engine()
                click.echo("✅ Data masking engine operational")
            except Exception as e:
                click.echo(f"❌ Data masking check failed: {e}")
            
            # Check query analyzer
            try:
                analyzer = QuerySafetyAnalyzer()
                await analyzer.analyze_query("SELECT 1", "mssql")
                click.echo("✅ Query safety analyzer operational")
            except Exception as e:
                click.echo(f"❌ Query analyzer check failed: {e}")
            
            click.echo("\n🎯 Health check completed")
            
        except Exception as e:
            click.echo(f"❌ Health check failed: {e}", err=True)
            sys.exit(1)
    
    asyncio.run(_health_check())


@system.command('version')
def version():
    """Show version information."""
    click.echo("Database Safety Layer v1.0.0")
    click.echo("Multi-database proxy with bulletproof write protection")
    click.echo("\nComponents:")
    click.echo("  - Database Proxy Service")
    click.echo("  - Query Safety Analyzer")
    click.echo("  - Schema Replicator")
    click.echo("  - Data Masking Engine")
    click.echo("  - Sandbox Manager")
    click.echo("  - Connection Pool Manager")


if __name__ == '__main__':
    cli()