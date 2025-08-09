#!/usr/bin/env python3
"""
Configuration Management System
Centralized configuration for database safety layer with environment-specific settings.
"""

import os
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from pathlib import Path

import yaml
from pydantic import BaseModel, Field, validator
from cryptography.fernet import Fernet


class DatabaseType(str):
    """Database type constants."""
    MSSQL = "mssql"
    MONGODB = "mongodb"
    MYSQL = "mysql"
    FABRIC = "fabric"
    LOCAL_SANDBOX = "local_sandbox"


@dataclass
class DatabaseConfig:
    """Individual database configuration."""
    name: str
    type: DatabaseType
    connection_string: str
    environment: str = "production"
    
    # Connection settings
    connection_timeout: int = 30
    command_timeout: int = 60
    
    # Pool settings
    min_connections: int = 2
    max_connections: int = 10
    
    # Health monitoring
    health_check_interval: int = 30
    
    # Security
    encrypted: bool = False
    
    def get_connection_string(self, encryption_key: Optional[str] = None) -> str:
        """Get decrypted connection string."""
        if self.encrypted and encryption_key:
            f = Fernet(encryption_key.encode())
            return f.decrypt(self.connection_string.encode()).decode()
        return self.connection_string


@dataclass
class SafetyRule:
    """Safety rule configuration."""
    name: str
    pattern: str
    risk_level: str  # safe, moderate, dangerous, critical
    description: str
    block_in_production: bool = True
    block_in_dev: bool = True
    block_in_sandbox: bool = False
    enabled: bool = True


@dataclass
class ProxyConfig:
    """Main proxy configuration."""
    # Database configurations
    databases: List[DatabaseConfig]
    
    # Safety rules
    safety_rules: List[SafetyRule]
    
    # Connection pool settings
    connection_pools: Dict[str, Any] = field(default_factory=dict)
    
    # Monitoring settings
    audit_logging: bool = True
    metrics_enabled: bool = True
    health_check_interval: int = 30
    
    # Security settings
    encryption_enabled: bool = False
    encryption_key: Optional[str] = None
    
    # Performance settings
    query_timeout: int = 300
    max_concurrent_queries: int = 100
    
    @classmethod
    def from_file(cls, config_path: str) -> 'ProxyConfig':
        """Load configuration from YAML file."""
        with open(config_path, 'r') as file:
            data = yaml.safe_load(file)
        
        return cls.from_dict(data)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProxyConfig':
        """Create configuration from dictionary."""
        # Parse databases
        databases = []
        for db_config in data.get('databases', []):
            databases.append(DatabaseConfig(**db_config))
        
        # Parse safety rules
        safety_rules = []
        for rule_config in data.get('safety_rules', []):
            safety_rules.append(SafetyRule(**rule_config))
        
        return cls(
            databases=databases,
            safety_rules=safety_rules,
            connection_pools=data.get('connection_pools', {}),
            audit_logging=data.get('audit_logging', True),
            metrics_enabled=data.get('metrics_enabled', True),
            health_check_interval=data.get('health_check_interval', 30),
            encryption_enabled=data.get('encryption_enabled', False),
            encryption_key=data.get('encryption_key'),
            query_timeout=data.get('query_timeout', 300),
            max_concurrent_queries=data.get('max_concurrent_queries', 100)
        )
    
    @classmethod
    def from_environment(cls) -> 'ProxyConfig':
        """Create configuration from environment variables."""
        # Default configuration with environment variables
        databases = cls._parse_databases_from_env()
        safety_rules = cls._get_default_safety_rules()
        
        return cls(
            databases=databases,
            safety_rules=safety_rules,
            audit_logging=os.getenv('DB_AUDIT_LOGGING', 'true').lower() == 'true',
            metrics_enabled=os.getenv('DB_METRICS_ENABLED', 'true').lower() == 'true',
            encryption_enabled=os.getenv('DB_ENCRYPTION_ENABLED', 'false').lower() == 'true',
            encryption_key=os.getenv('DB_ENCRYPTION_KEY'),
            query_timeout=int(os.getenv('DB_QUERY_TIMEOUT', '300')),
            max_concurrent_queries=int(os.getenv('DB_MAX_CONCURRENT', '100'))
        )
    
    @staticmethod
    def _parse_databases_from_env() -> List[DatabaseConfig]:
        """Parse database configurations from environment variables."""
        databases = []
        
        # Production MSSQL
        mssql_prod = os.getenv('MSSQL_PROD_CONNECTION')
        if mssql_prod:
            databases.append(DatabaseConfig(
                name="mssql_production",
                type=DatabaseType.MSSQL,
                connection_string=mssql_prod,
                environment="production"
            ))
        
        # Dev MSSQL
        mssql_dev = os.getenv('MSSQL_DEV_CONNECTION')
        if mssql_dev:
            databases.append(DatabaseConfig(
                name="mssql_dev",
                type=DatabaseType.MSSQL,
                connection_string=mssql_dev,
                environment="dev"
            ))
        
        # MongoDB Replicaset
        mongodb_connection = os.getenv('MONGODB_CONNECTION')
        if mongodb_connection:
            databases.append(DatabaseConfig(
                name="mongodb_replica",
                type=DatabaseType.MONGODB,
                connection_string=mongodb_connection,
                environment="production"
            ))
        
        # MySQL RDS
        mysql_connection = os.getenv('MYSQL_RDS_CONNECTION')
        if mysql_connection:
            databases.append(DatabaseConfig(
                name="mysql_rds",
                type=DatabaseType.MYSQL,
                connection_string=mysql_connection,
                environment="production"
            ))
        
        # Microsoft Fabric
        fabric_connection = os.getenv('FABRIC_SQL_ENDPOINT')
        if fabric_connection:
            databases.append(DatabaseConfig(
                name="fabric_lakehouse",
                type=DatabaseType.FABRIC,
                connection_string=fabric_connection,
                environment="production"
            ))
        
        # Local Sandbox
        sandbox_db = os.getenv('LOCAL_SANDBOX_DB', '/tmp/sandbox.db')
        databases.append(DatabaseConfig(
            name="local_sandbox",
            type=DatabaseType.LOCAL_SANDBOX,
            connection_string=f"sqlite:///{sandbox_db}",
            environment="sandbox",
            min_connections=1,
            max_connections=5
        ))
        
        return databases
    
    @staticmethod
    def _get_default_safety_rules() -> List[SafetyRule]:
        """Get default safety rules."""
        return [
            SafetyRule(
                name="block_drop_operations",
                pattern=r'\b(drop|truncate)\s+(table|database|schema|collection)',
                risk_level="critical",
                description="DROP/TRUNCATE operations are destructive",
                block_in_sandbox=True
            ),
            SafetyRule(
                name="block_system_commands",
                pattern=r'\b(xp_cmdshell|sp_configure|openrowset|opendatasource)\b',
                risk_level="critical",
                description="System command execution",
                block_in_sandbox=True
            ),
            SafetyRule(
                name="unsafe_deletes",
                pattern=r'\bdelete\s+from\s+\w+\s*(?!where)',
                risk_level="dangerous",
                description="DELETE without WHERE clause"
            ),
            SafetyRule(
                name="unsafe_updates", 
                pattern=r'\bupdate\s+\w+\s+set\s+.*?(?!where)',
                risk_level="dangerous",
                description="UPDATE without WHERE clause"
            ),
            SafetyRule(
                name="system_table_access",
                pattern=r'\b(sys\.|information_schema\.|master\.|msdb\.)',
                risk_level="moderate",
                description="System table/schema access",
                block_in_production=True,
                block_in_dev=False,
                block_in_sandbox=False
            ),
            SafetyRule(
                name="bulk_operations",
                pattern=r'\b(bulk\s+insert|load\s+data)\b',
                risk_level="moderate", 
                description="Bulk data operations"
            )
        ]


class ConfigManager:
    """Configuration management with validation and hot-reload."""
    
    def __init__(self, config_path: Optional[str] = None):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.config_path = config_path
        self.config: Optional[ProxyConfig] = None
        self._file_watcher_task: Optional[Any] = None
        
    async def load_config(self) -> ProxyConfig:
        """Load configuration from file or environment."""
        if self.config_path and os.path.exists(self.config_path):
            self.logger.info(f"Loading configuration from file: {self.config_path}")
            self.config = ProxyConfig.from_file(self.config_path)
        else:
            self.logger.info("Loading configuration from environment variables")
            self.config = ProxyConfig.from_environment()
        
        # Validate configuration
        self._validate_config()
        
        return self.config
    
    def _validate_config(self) -> None:
        """Validate configuration completeness and consistency."""
        if not self.config:
            raise ValueError("Configuration not loaded")
        
        # Validate databases
        if not self.config.databases:
            raise ValueError("No databases configured")
        
        # Validate connection strings
        for db_config in self.config.databases:
            if not db_config.connection_string:
                raise ValueError(f"Empty connection string for database: {db_config.name}")
        
        # Validate safety rules
        for rule in self.config.safety_rules:
            if not rule.pattern:
                raise ValueError(f"Empty pattern for safety rule: {rule.name}")
        
        self.logger.info("Configuration validation passed")
    
    def get_database_config(self, name: str) -> Optional[DatabaseConfig]:
        """Get configuration for specific database."""
        if not self.config:
            return None
        
        for db_config in self.config.databases:
            if db_config.name == name:
                return db_config
        
        return None
    
    def get_databases_by_type(self, database_type: str) -> List[DatabaseConfig]:
        """Get all databases of specific type."""
        if not self.config:
            return []
        
        return [db for db in self.config.databases if db.type == database_type]
    
    def get_databases_by_environment(self, environment: str) -> List[DatabaseConfig]:
        """Get all databases in specific environment."""
        if not self.config:
            return []
        
        return [db for db in self.config.databases if db.environment == environment]


def create_default_config_file(output_path: str) -> None:
    """Create default configuration file template."""
    
    config_template = {
        'databases': [
            {
                'name': 'mssql_production',
                'type': 'mssql',
                'connection_string': 'Driver={ODBC Driver 17 for SQL Server};Server=prod-server;Database=main_db;Trusted_Connection=yes;',
                'environment': 'production',
                'connection_timeout': 30,
                'min_connections': 5,
                'max_connections': 20
            },
            {
                'name': 'mssql_dev',
                'type': 'mssql', 
                'connection_string': 'Driver={ODBC Driver 17 for SQL Server};Server=dev-server;Database=dev_db;Trusted_Connection=yes;',
                'environment': 'dev',
                'connection_timeout': 30,
                'min_connections': 2,
                'max_connections': 10
            },
            {
                'name': 'mongodb_replica',
                'type': 'mongodb',
                'connection_string': 'mongodb://user:pass@mongo1:27017,mongo2:27017,mongo3:27017/?replicaSet=rs0',
                'environment': 'production',
                'connection_timeout': 30,
                'min_connections': 3,
                'max_connections': 15
            },
            {
                'name': 'mysql_rds',
                'type': 'mysql',
                'connection_string': 'mysql://user:pass@rds-endpoint:3306/database',
                'environment': 'production', 
                'connection_timeout': 30,
                'min_connections': 3,
                'max_connections': 15
            },
            {
                'name': 'fabric_lakehouse',
                'type': 'fabric',
                'connection_string': 'https://workspacename.fabric.microsoft.com/v1/workspaces/guid/items/guid/sqlEndpoint',
                'environment': 'production',
                'connection_timeout': 60,
                'min_connections': 2,
                'max_connections': 8
            },
            {
                'name': 'local_sandbox',
                'type': 'local_sandbox',
                'connection_string': 'sqlite:///tmp/sandbox.db',
                'environment': 'sandbox',
                'connection_timeout': 10,
                'min_connections': 1,
                'max_connections': 3
            }
        ],
        
        'safety_rules': [
            {
                'name': 'block_drop_operations',
                'pattern': r'\b(drop|truncate)\s+(table|database|schema|collection)',
                'risk_level': 'critical',
                'description': 'DROP/TRUNCATE operations are destructive',
                'block_in_production': True,
                'block_in_dev': True,
                'block_in_sandbox': True,
                'enabled': True
            },
            {
                'name': 'unsafe_deletes',
                'pattern': r'\bdelete\s+from\s+\w+\s*(?!where)',
                'risk_level': 'dangerous',
                'description': 'DELETE without WHERE clause',
                'block_in_production': True,
                'block_in_dev': True,
                'block_in_sandbox': False,
                'enabled': True
            }
        ],
        
        'connection_pools': {
            'default_pool_size': 10,
            'max_pool_size': 50,
            'connection_lifetime': 3600,
            'idle_timeout': 300
        },
        
        'audit_logging': True,
        'metrics_enabled': True,
        'health_check_interval': 30,
        'encryption_enabled': False,
        'query_timeout': 300,
        'max_concurrent_queries': 100
    }
    
    with open(output_path, 'w') as file:
        yaml.dump(config_template, file, default_flow_style=False, indent=2)
    
    print(f"Default configuration created at: {output_path}")


def encrypt_connection_string(connection_string: str, key: Optional[str] = None) -> tuple[str, str]:
    """Encrypt connection string for secure storage."""
    if key is None:
        key = Fernet.generate_key()
    else:
        key = key.encode()
    
    f = Fernet(key)
    encrypted = f.encrypt(connection_string.encode())
    
    return encrypted.decode(), key.decode()


def decrypt_connection_string(encrypted_string: str, key: str) -> str:
    """Decrypt connection string."""
    f = Fernet(key.encode())
    return f.decrypt(encrypted_string.encode()).decode()


# Environment variable helpers
def get_required_env(var_name: str) -> str:
    """Get required environment variable or raise error."""
    value = os.getenv(var_name)
    if not value:
        raise ValueError(f"Required environment variable not set: {var_name}")
    return value


def get_optional_env(var_name: str, default_value: str = "") -> str:
    """Get optional environment variable with default."""
    return os.getenv(var_name, default_value)


def load_env_file(env_file_path: str) -> None:
    """Load environment variables from .env file."""
    if not os.path.exists(env_file_path):
        return
    
    with open(env_file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if line and not line.startswith('#'):
                key, value = line.split('=', 1)
                os.environ[key] = value


# CLI helper for configuration management
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "create-default":
            output_path = sys.argv[2] if len(sys.argv) > 2 else "database_config.yaml"
            create_default_config_file(output_path)
        elif sys.argv[1] == "encrypt":
            if len(sys.argv) < 3:
                print("Usage: python config.py encrypt <connection_string> [key]")
                sys.exit(1)
            
            connection_string = sys.argv[2]
            key = sys.argv[3] if len(sys.argv) > 3 else None
            
            encrypted, encryption_key = encrypt_connection_string(connection_string, key)
            print(f"Encrypted: {encrypted}")
            print(f"Key: {encryption_key}")
        else:
            print("Available commands: create-default, encrypt")
    else:
        print("Usage: python config.py [create-default|encrypt] [args...]")