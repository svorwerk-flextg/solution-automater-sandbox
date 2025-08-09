"""
Microsoft Fabric Connector

Provides secure access to Microsoft Fabric resources including:
- Lakehouse SQL endpoints
- Delta Lake tables
- Spark SQL queries
- Data lineage tracking
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
import pandas as pd
import pyodbc
import requests
from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.storage.filedatalake import DataLakeServiceClient
from sqlalchemy import create_engine, MetaData, Table
from sqlalchemy.pool import QueuePool
from contextlib import contextmanager
import asyncio
import aiohttp
from cachetools import TTLCache
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class FabricAuthMethod(Enum):
    """Authentication methods for Microsoft Fabric"""
    SERVICE_PRINCIPAL = "service_principal"
    MANAGED_IDENTITY = "managed_identity"
    INTERACTIVE = "interactive"


@dataclass
class FabricConfig:
    """Configuration for Microsoft Fabric connection"""
    workspace_id: str
    lakehouse_id: str
    sql_endpoint: str
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    auth_method: FabricAuthMethod = FabricAuthMethod.SERVICE_PRINCIPAL
    connection_timeout: int = 30
    query_timeout: int = 300
    max_pool_size: int = 10
    enable_caching: bool = True
    cache_ttl: int = 3600


@dataclass
class DeltaTableInfo:
    """Information about a Delta Lake table"""
    name: str
    schema: str
    location: str
    format: str
    num_files: int
    size_bytes: int
    last_modified: datetime
    columns: List[Dict[str, Any]]
    partitions: Optional[List[str]] = None
    properties: Optional[Dict[str, Any]] = None


class FabricConnector:
    """Secure connector for Microsoft Fabric resources"""
    
    def __init__(self, config: FabricConfig):
        self.config = config
        self._credential = None
        self._sql_engine = None
        self._metadata_cache = TTLCache(maxsize=1000, ttl=config.cache_ttl) if config.enable_caching else None
        self._connection_pool = None
        self._is_initialized = False
        
    def initialize(self):
        """Initialize the Fabric connector"""
        if self._is_initialized:
            return
            
        try:
            # Set up authentication
            self._setup_authentication()
            
            # Initialize SQL connection pool
            self._setup_sql_connection()
            
            # Test connection
            self._test_connection()
            
            self._is_initialized = True
            logger.info("Microsoft Fabric connector initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Fabric connector: {e}")
            raise
            
    def _setup_authentication(self):
        """Set up Azure authentication"""
        if self.config.auth_method == FabricAuthMethod.SERVICE_PRINCIPAL:
            if not all([self.config.tenant_id, self.config.client_id, self.config.client_secret]):
                raise ValueError("Service principal authentication requires tenant_id, client_id, and client_secret")
                
            self._credential = ClientSecretCredential(
                tenant_id=self.config.tenant_id,
                client_id=self.config.client_id,
                client_secret=self.config.client_secret
            )
        elif self.config.auth_method == FabricAuthMethod.MANAGED_IDENTITY:
            self._credential = DefaultAzureCredential()
        else:
            # Interactive authentication
            self._credential = DefaultAzureCredential(
                exclude_managed_identity_credential=True,
                exclude_shared_token_cache_credential=False
            )
            
    def _setup_sql_connection(self):
        """Set up SQL connection pool"""
        # Build connection string for Fabric SQL endpoint
        conn_str = self._build_connection_string()
        
        # Create SQLAlchemy engine with connection pooling
        self._sql_engine = create_engine(
            f"mssql+pyodbc:///?odbc_connect={conn_str}",
            pool_size=self.config.max_pool_size,
            pool_recycle=3600,
            pool_pre_ping=True,
            pool_class=QueuePool,
            connect_args={
                "timeout": self.config.connection_timeout,
                "autocommit": True
            }
        )
        
    def _build_connection_string(self) -> str:
        """Build ODBC connection string for Fabric SQL endpoint"""
        # Get access token
        token = self._credential.get_token("https://database.windows.net/.default")
        
        conn_str = (
            f"Driver={{ODBC Driver 18 for SQL Server}};"
            f"Server={self.config.sql_endpoint};"
            f"Database={self.config.lakehouse_id};"
            f"Authentication=ActiveDirectoryAccessToken;"
            f"AccessToken={token.token};"
            f"Encrypt=yes;"
            f"TrustServerCertificate=no;"
            f"Connection Timeout={self.config.connection_timeout};"
        )
        
        return conn_str
        
    def _test_connection(self):
        """Test the SQL connection"""
        try:
            with self._sql_engine.connect() as conn:
                result = conn.execute("SELECT 1 as test")
                result.fetchone()
            logger.info("Fabric SQL connection test successful")
        except Exception as e:
            logger.error(f"Fabric SQL connection test failed: {e}")
            raise
            
    @contextmanager
    def get_connection(self):
        """Get a database connection from the pool"""
        if not self._is_initialized:
            self.initialize()
            
        conn = self._sql_engine.connect()
        try:
            yield conn
        finally:
            conn.close()
            
    def discover_tables(self, schema: Optional[str] = None) -> List[DeltaTableInfo]:
        """Discover all Delta Lake tables in the lakehouse"""
        tables = []
        
        query = """
        SELECT 
            t.TABLE_SCHEMA,
            t.TABLE_NAME,
            t.TABLE_TYPE
        FROM INFORMATION_SCHEMA.TABLES t
        WHERE t.TABLE_TYPE IN ('BASE TABLE', 'VIEW')
        """
        
        if schema:
            query += f" AND t.TABLE_SCHEMA = '{schema}'"
            
        query += " ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME"
        
        with self.get_connection() as conn:
            result = conn.execute(query)
            
            for row in result:
                # Get detailed table info
                table_info = self._get_table_details(row.TABLE_SCHEMA, row.TABLE_NAME)
                if table_info:
                    tables.append(table_info)
                    
        return tables
        
    def _get_table_details(self, schema: str, table_name: str) -> Optional[DeltaTableInfo]:
        """Get detailed information about a Delta table"""
        try:
            # Get column information
            columns_query = f"""
            SELECT 
                COLUMN_NAME,
                DATA_TYPE,
                IS_NULLABLE,
                COLUMN_DEFAULT,
                CHARACTER_MAXIMUM_LENGTH,
                NUMERIC_PRECISION,
                NUMERIC_SCALE
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = '{schema}' AND TABLE_NAME = '{table_name}'
            ORDER BY ORDINAL_POSITION
            """
            
            columns = []
            with self.get_connection() as conn:
                result = conn.execute(columns_query)
                
                for row in result:
                    columns.append({
                        'name': row.COLUMN_NAME,
                        'type': row.DATA_TYPE,
                        'nullable': row.IS_NULLABLE == 'YES',
                        'default': row.COLUMN_DEFAULT,
                        'max_length': row.CHARACTER_MAXIMUM_LENGTH,
                        'precision': row.NUMERIC_PRECISION,
                        'scale': row.NUMERIC_SCALE
                    })
                    
            # Get table statistics
            stats_query = f"""
            SELECT COUNT(*) as row_count
            FROM [{schema}].[{table_name}]
            """
            
            with self.get_connection() as conn:
                result = conn.execute(stats_query)
                row_count = result.fetchone()[0]
                
            # Create table info object
            table_info = DeltaTableInfo(
                name=table_name,
                schema=schema,
                location=f"abfss://{self.config.lakehouse_id}@onelake.dfs.fabric.microsoft.com/{schema}/{table_name}",
                format="delta",
                num_files=0,  # Would need to query Delta metadata
                size_bytes=0,  # Would need to query Delta metadata
                last_modified=datetime.now(),  # Would need to query Delta metadata
                columns=columns,
                properties={'row_count': row_count}
            )
            
            return table_info
            
        except Exception as e:
            logger.error(f"Error getting details for table {schema}.{table_name}: {e}")
            return None
            
    def execute_query(self, query: str, params: Optional[Dict] = None) -> pd.DataFrame:
        """Execute a SQL query and return results as DataFrame"""
        if not self._is_initialized:
            self.initialize()
            
        try:
            # Add query timeout
            query = f"SET QUERY_TIMEOUT {self.config.query_timeout};\n{query}"
            
            # Execute query
            df = pd.read_sql_query(query, self._sql_engine, params=params)
            
            logger.info(f"Query executed successfully, returned {len(df)} rows")
            return df
            
        except Exception as e:
            logger.error(f"Query execution failed: {e}")
            raise
            
    async def execute_query_async(self, query: str, params: Optional[Dict] = None) -> pd.DataFrame:
        """Execute a SQL query asynchronously"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.execute_query, query, params)
        
    def stream_query_results(self, query: str, chunk_size: int = 10000):
        """Stream query results in chunks for large datasets"""
        if not self._is_initialized:
            self.initialize()
            
        with self.get_connection() as conn:
            result = conn.execution_options(stream_results=True).execute(query)
            
            while True:
                chunk = result.fetchmany(chunk_size)
                if not chunk:
                    break
                    
                # Convert to DataFrame
                df_chunk = pd.DataFrame(chunk)
                df_chunk.columns = result.keys()
                
                yield df_chunk
                
    def get_table_schema(self, table_name: str, schema: str = 'dbo') -> Dict[str, Any]:
        """Get schema information for a specific table"""
        cache_key = f"{schema}.{table_name}"
        
        # Check cache first
        if self._metadata_cache and cache_key in self._metadata_cache:
            return self._metadata_cache[cache_key]
            
        table_info = self._get_table_details(schema, table_name)
        
        if table_info:
            schema_dict = {
                'table_name': table_info.name,
                'schema': table_info.schema,
                'columns': table_info.columns,
                'location': table_info.location,
                'properties': table_info.properties
            }
            
            # Cache the result
            if self._metadata_cache:
                self._metadata_cache[cache_key] = schema_dict
                
            return schema_dict
            
        return {}
        
    def validate_query(self, query: str) -> Tuple[bool, Optional[str]]:
        """Validate a SQL query before execution"""
        try:
            # Use EXPLAIN to validate query syntax
            explain_query = f"EXPLAIN {query}"
            
            with self.get_connection() as conn:
                conn.execute(explain_query)
                
            return True, None
            
        except Exception as e:
            return False, str(e)
            
    def get_query_cost(self, query: str) -> Dict[str, Any]:
        """Estimate the cost and resources for a query"""
        try:
            # Get query plan
            explain_query = f"EXPLAIN (FORMAT JSON) {query}"
            
            with self.get_connection() as conn:
                result = conn.execute(explain_query)
                plan = result.fetchone()[0]
                
            # Parse plan to extract cost information
            plan_json = json.loads(plan)
            
            return {
                'estimated_rows': plan_json.get('estimated_rows', 0),
                'estimated_cost': plan_json.get('total_cost', 0),
                'estimated_time_ms': plan_json.get('estimated_time', 0),
                'plan': plan_json
            }
            
        except Exception as e:
            logger.error(f"Failed to get query cost: {e}")
            return {
                'error': str(e),
                'estimated_rows': -1,
                'estimated_cost': -1
            }
            
    def create_external_table(self, table_name: str, location: str, 
                            schema: Dict[str, str], format: str = 'DELTA') -> bool:
        """Create an external table pointing to Delta Lake files"""
        try:
            # Build CREATE EXTERNAL TABLE statement
            columns = ", ".join([f"{col} {dtype}" for col, dtype in schema.items()])
            
            create_stmt = f"""
            CREATE EXTERNAL TABLE IF NOT EXISTS {table_name} (
                {columns}
            )
            STORED AS {format}
            LOCATION '{location}'
            """
            
            with self.get_connection() as conn:
                conn.execute(create_stmt)
                
            logger.info(f"External table {table_name} created successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create external table: {e}")
            return False
            
    def refresh_metadata(self):
        """Refresh cached metadata"""
        if self._metadata_cache:
            self._metadata_cache.clear()
            
        logger.info("Metadata cache refreshed")
        
    def get_connection_status(self) -> Dict[str, Any]:
        """Get current connection status and health"""
        status = {
            'initialized': self._is_initialized,
            'connection_pool_size': self.config.max_pool_size if self._sql_engine else 0,
            'active_connections': 0,
            'last_check': datetime.now().isoformat()
        }
        
        if self._is_initialized:
            try:
                with self.get_connection() as conn:
                    result = conn.execute("SELECT @@VERSION as version")
                    version = result.fetchone()[0]
                    
                status['connected'] = True
                status['server_version'] = version
                status['endpoint'] = self.config.sql_endpoint
                
            except Exception as e:
                status['connected'] = False
                status['error'] = str(e)
                
        return status
        
    def close(self):
        """Close all connections and clean up resources"""
        if self._sql_engine:
            self._sql_engine.dispose()
            
        if self._metadata_cache:
            self._metadata_cache.clear()
            
        self._is_initialized = False
        logger.info("Fabric connector closed")