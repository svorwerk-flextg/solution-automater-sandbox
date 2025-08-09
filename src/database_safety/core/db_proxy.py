#!/usr/bin/env python3
"""
Multi-Database Safety Proxy
Provides unified interface to MSSQL, MongoDB, MySQL, and Microsoft Fabric
with bulletproof write protection and intelligent query routing.
"""

import asyncio
import logging
import os
import re
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union

import aiohttp
import aiodns
import motor.motor_asyncio
import pymongo
import pymssql  
import aiomysql
import sqlparse
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
from azure.identity import DefaultAzureCredential
from azure.core.exceptions import ClientAuthenticationError

from .query_analyzer import QuerySafetyAnalyzer, QueryType, SafetyLevel
from .connection_pool import ConnectionPoolManager
from .config import DatabaseConfig, ProxyConfig


class DatabaseType(str, Enum):
    """Supported database types."""
    MSSQL = "mssql"
    MONGODB = "mongodb" 
    MYSQL = "mysql"
    FABRIC = "fabric"
    LOCAL_SANDBOX = "local_sandbox"


class OperationType(str, Enum):
    """Database operation types for safety validation."""
    SELECT = "select"
    INSERT = "insert"
    UPDATE = "update"
    DELETE = "delete"
    CREATE = "create"
    DROP = "drop"
    ALTER = "alter"
    TRUNCATE = "truncate"
    UNKNOWN = "unknown"


@dataclass
class QueryRequest:
    """Standardized query request format."""
    query: str
    database_type: DatabaseType
    database_name: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    connection_id: Optional[str] = None
    user_context: Optional[Dict[str, Any]] = field(default_factory=dict)


@dataclass
class QueryResult:
    """Standardized query result format."""
    success: bool
    data: Optional[Union[List[Dict], Dict, Any]] = None
    rows_affected: Optional[int] = None
    error_message: Optional[str] = None
    execution_time: Optional[float] = None
    connection_info: Optional[Dict[str, str]] = None
    safety_info: Optional[Dict[str, Any]] = None


class DatabaseSafetyProxy:
    """
    Multi-database proxy with comprehensive safety controls.
    
    Features:
    - Multi-protocol support (SQL/NoSQL)
    - AST-level query analysis and blocking
    - Intelligent routing (local vs external)
    - Connection pooling and failover
    - Audit logging and monitoring
    """
    
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Initialize core components
        self.query_analyzer = QuerySafetyAnalyzer(config.safety_rules)
        self.connection_manager = ConnectionPoolManager(config.connection_pools)
        
        # Operation safety matrix
        self.safety_matrix = self._build_safety_matrix()
        
        # Runtime state
        self.is_initialized = False
        self._audit_log = []
        
    def _build_safety_matrix(self) -> Dict[str, Dict[OperationType, bool]]:
        """Build operation safety matrix based on environment."""
        return {
            "production": {
                OperationType.SELECT: True,
                OperationType.INSERT: False,
                OperationType.UPDATE: False, 
                OperationType.DELETE: False,
                OperationType.CREATE: False,
                OperationType.DROP: False,
                OperationType.ALTER: False,
                OperationType.TRUNCATE: False,
            },
            "dev": {
                OperationType.SELECT: True,
                OperationType.INSERT: False,
                OperationType.UPDATE: False,
                OperationType.DELETE: False, 
                OperationType.CREATE: False,
                OperationType.DROP: False,
                OperationType.ALTER: False,
                OperationType.TRUNCATE: False,
            },
            "local_sandbox": {
                OperationType.SELECT: True,
                OperationType.INSERT: True,
                OperationType.UPDATE: True,
                OperationType.DELETE: False,  # NEVER ALLOW DELETE
                OperationType.CREATE: True,
                OperationType.DROP: False,    # NEVER ALLOW DROP
                OperationType.ALTER: True,
                OperationType.TRUNCATE: False,
            }
        }
    
    async def initialize(self) -> None:
        """Initialize proxy components."""
        if self.is_initialized:
            return
            
        self.logger.info("Initializing Database Safety Proxy...")
        
        try:
            # Initialize connection pools
            await self.connection_manager.initialize()
            
            # Validate all configured connections
            await self._validate_connections()
            
            self.is_initialized = True
            self.logger.info("Database Safety Proxy initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize proxy: {e}")
            raise
    
    async def _validate_connections(self) -> None:
        """Validate all configured database connections."""
        for db_config in self.config.databases:
            try:
                await self._test_connection(db_config)
                self.logger.info(f"Connection validated: {db_config.name}")
            except Exception as e:
                self.logger.warning(f"Connection failed: {db_config.name} - {e}")
    
    async def _test_connection(self, db_config: DatabaseConfig) -> None:
        """Test individual database connection."""
        if db_config.type == DatabaseType.MSSQL:
            await self._test_mssql_connection(db_config)
        elif db_config.type == DatabaseType.MONGODB:
            await self._test_mongodb_connection(db_config)
        elif db_config.type == DatabaseType.MYSQL:
            await self._test_mysql_connection(db_config)
        elif db_config.type == DatabaseType.FABRIC:
            await self._test_fabric_connection(db_config)
    
    async def execute_query(self, request: QueryRequest) -> QueryResult:
        """
        Execute query with comprehensive safety validation.
        
        Safety Flow:
        1. Parse and analyze query
        2. Check operation permissions
        3. Route to appropriate backend
        4. Log and audit operation
        """
        start_time = asyncio.get_event_loop().time()
        
        try:
            # 1. Query Analysis
            analysis = await self.query_analyzer.analyze_query(
                request.query, 
                request.database_type
            )
            
            # 2. Safety Validation
            safety_check = await self._validate_operation_safety(
                analysis, 
                request.database_type,
                request.database_name
            )
            
            if not safety_check.allowed:
                return QueryResult(
                    success=False,
                    error_message=f"Operation blocked: {safety_check.reason}",
                    safety_info=safety_check.__dict__
                )
            
            # 3. Route Query
            result = await self._route_query(request, analysis)
            
            # 4. Audit Logging
            execution_time = asyncio.get_event_loop().time() - start_time
            await self._log_operation(request, analysis, result, execution_time)
            
            result.execution_time = execution_time
            result.safety_info = analysis.__dict__
            
            return result
            
        except Exception as e:
            self.logger.error(f"Query execution failed: {e}")
            return QueryResult(
                success=False,
                error_message=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time
            )
    
    async def _validate_operation_safety(
        self, 
        analysis: 'QueryAnalysis', 
        db_type: DatabaseType,
        db_name: str
    ) -> 'SafetyCheck':
        """Validate operation against safety matrix."""
        from .query_analyzer import SafetyCheck
        
        # Determine environment
        environment = self._get_environment(db_name, db_type)
        
        # Check safety matrix
        allowed_operations = self.safety_matrix.get(environment, {})
        
        for operation in analysis.operations:
            if not allowed_operations.get(operation, False):
                return SafetyCheck(
                    allowed=False,
                    reason=f"{operation.value.upper()} operation not allowed in {environment}",
                    risk_level="HIGH",
                    blocked_operations=[operation]
                )
        
        # Additional safety checks
        if analysis.safety_level == SafetyLevel.DANGEROUS:
            return SafetyCheck(
                allowed=False,
                reason="Query marked as dangerous by analyzer",
                risk_level="CRITICAL",
                blocked_operations=analysis.operations
            )
        
        return SafetyCheck(
            allowed=True,
            reason="Operation approved",
            risk_level="LOW"
        )
    
    def _get_environment(self, db_name: str, db_type: DatabaseType) -> str:
        """Determine database environment from name/type."""
        if db_type == DatabaseType.LOCAL_SANDBOX:
            return "local_sandbox"
        elif "prod" in db_name.lower() or "production" in db_name.lower():
            return "production"
        else:
            return "dev"
    
    async def _route_query(
        self, 
        request: QueryRequest, 
        analysis: 'QueryAnalysis'
    ) -> QueryResult:
        """Route query to appropriate database backend."""
        
        if request.database_type == DatabaseType.MSSQL:
            return await self._execute_mssql_query(request)
        elif request.database_type == DatabaseType.MONGODB:
            return await self._execute_mongodb_query(request)
        elif request.database_type == DatabaseType.MYSQL:
            return await self._execute_mysql_query(request)
        elif request.database_type == DatabaseType.FABRIC:
            return await self._execute_fabric_query(request)
        elif request.database_type == DatabaseType.LOCAL_SANDBOX:
            return await self._execute_local_query(request)
        else:
            raise ValueError(f"Unsupported database type: {request.database_type}")
    
    async def _execute_mssql_query(self, request: QueryRequest) -> QueryResult:
        """Execute MSSQL query with connection pooling."""
        try:
            async with self.connection_manager.get_connection(
                request.database_name, 
                DatabaseType.MSSQL
            ) as conn:
                
                # Use aioodbc or similar async driver
                cursor = await conn.cursor()
                await cursor.execute(request.query, request.parameters)
                
                if cursor.description:
                    # SELECT query
                    rows = await cursor.fetchall()
                    columns = [desc[0] for desc in cursor.description]
                    data = [dict(zip(columns, row)) for row in rows]
                    
                    return QueryResult(
                        success=True,
                        data=data,
                        rows_affected=len(data)
                    )
                else:
                    # DML query
                    rows_affected = cursor.rowcount
                    await conn.commit()
                    
                    return QueryResult(
                        success=True,
                        rows_affected=rows_affected
                    )
                    
        except Exception as e:
            self.logger.error(f"MSSQL query failed: {e}")
            return QueryResult(
                success=False,
                error_message=str(e)
            )
    
    async def _execute_mongodb_query(self, request: QueryRequest) -> QueryResult:
        """Execute MongoDB query with motor async driver."""
        try:
            # Parse MongoDB query from request
            # This would need MongoDB query parsing logic
            db_name = request.database_name
            
            async with self.connection_manager.get_connection(
                db_name, 
                DatabaseType.MONGODB
            ) as client:
                
                database = client[db_name]
                
                # Simple find operation example
                # Real implementation would parse MongoDB operations
                collection_name = request.parameters.get('collection')
                if not collection_name:
                    raise ValueError("MongoDB queries require collection name")
                
                collection = database[collection_name]
                
                query_filter = request.parameters.get('filter', {})
                limit = request.parameters.get('limit', 1000)
                
                cursor = collection.find(query_filter).limit(limit)
                documents = await cursor.to_list(length=limit)
                
                return QueryResult(
                    success=True,
                    data=documents,
                    rows_affected=len(documents)
                )
                
        except Exception as e:
            self.logger.error(f"MongoDB query failed: {e}")
            return QueryResult(
                success=False,
                error_message=str(e)
            )
    
    async def _execute_mysql_query(self, request: QueryRequest) -> QueryResult:
        """Execute MySQL query with aiomysql."""
        try:
            async with self.connection_manager.get_connection(
                request.database_name,
                DatabaseType.MYSQL
            ) as conn:
                
                async with conn.cursor(aiomysql.DictCursor) as cursor:
                    await cursor.execute(request.query, request.parameters)
                    
                    if cursor.description:
                        # SELECT query
                        rows = await cursor.fetchall()
                        
                        return QueryResult(
                            success=True,
                            data=rows,
                            rows_affected=len(rows)
                        )
                    else:
                        # DML query
                        await conn.commit()
                        
                        return QueryResult(
                            success=True,
                            rows_affected=cursor.rowcount
                        )
                        
        except Exception as e:
            self.logger.error(f"MySQL query failed: {e}")
            return QueryResult(
                success=False,
                error_message=str(e)
            )
    
    async def _execute_fabric_query(self, request: QueryRequest) -> QueryResult:
        """Execute Microsoft Fabric query via SQL endpoint."""
        try:
            # Use Azure authentication
            credential = DefaultAzureCredential()
            
            # Fabric SQL endpoint connection
            # This would use the Fabric REST API or ODBC connection
            fabric_config = self._get_fabric_config(request.database_name)
            
            # Implementation would depend on Fabric SDK
            # Placeholder for actual Fabric query execution
            
            return QueryResult(
                success=True,
                data=[],
                error_message="Fabric integration not fully implemented"
            )
            
        except Exception as e:
            self.logger.error(f"Fabric query failed: {e}")
            return QueryResult(
                success=False,
                error_message=str(e)
            )
    
    async def _execute_local_query(self, request: QueryRequest) -> QueryResult:
        """Execute query on local sandbox database."""
        try:
            # Local sandbox gets full CRUD operations
            # Route to appropriate local database based on type
            local_config = self._get_local_config(request.database_name)
            
            if local_config['type'] == 'sqlite':
                return await self._execute_sqlite_query(request, local_config)
            elif local_config['type'] == 'postgres':
                return await self._execute_postgres_query(request, local_config)
            else:
                raise ValueError(f"Unsupported local database type: {local_config['type']}")
                
        except Exception as e:
            self.logger.error(f"Local query failed: {e}")
            return QueryResult(
                success=False,
                error_message=str(e)
            )
    
    def _get_fabric_config(self, database_name: str) -> Dict[str, Any]:
        """Get Fabric connection configuration."""
        # Load from config
        return {
            'workspace_id': os.getenv('FABRIC_WORKSPACE_ID'),
            'lakehouse_id': os.getenv('FABRIC_LAKEHOUSE_ID'),
            'sql_endpoint': os.getenv('FABRIC_SQL_ENDPOINT')
        }
    
    def _get_local_config(self, database_name: str) -> Dict[str, Any]:
        """Get local database configuration."""
        return {
            'type': 'sqlite',
            'path': f'/tmp/sandbox_{database_name}.db'
        }
    
    async def _log_operation(
        self, 
        request: QueryRequest, 
        analysis: 'QueryAnalysis',
        result: QueryResult,
        execution_time: float
    ) -> None:
        """Log database operation for audit trail."""
        log_entry = {
            'timestamp': asyncio.get_event_loop().time(),
            'database_type': request.database_type,
            'database_name': request.database_name,
            'query': request.query[:200],  # Truncate for logging
            'operations': [op.value for op in analysis.operations],
            'safety_level': analysis.safety_level.value,
            'success': result.success,
            'rows_affected': result.rows_affected,
            'execution_time': execution_time,
            'error': result.error_message,
            'user_context': request.user_context
        }
        
        self._audit_log.append(log_entry)
        self.logger.info(f"Query executed: {log_entry}")
    
    async def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent audit log entries."""
        return self._audit_log[-limit:]
    
    async def shutdown(self) -> None:
        """Gracefully shutdown proxy."""
        self.logger.info("Shutting down Database Safety Proxy...")
        await self.connection_manager.shutdown()
        self.is_initialized = False


# Factory function for easy instantiation
def create_database_proxy(config_path: Optional[str] = None) -> DatabaseSafetyProxy:
    """Create configured database proxy instance."""
    if config_path:
        config = ProxyConfig.from_file(config_path)
    else:
        config = ProxyConfig.from_environment()
    
    return DatabaseSafetyProxy(config)


# Context manager for automatic lifecycle management
@asynccontextmanager
async def database_proxy(config_path: Optional[str] = None):
    """Context manager for database proxy lifecycle."""
    proxy = create_database_proxy(config_path)
    try:
        await proxy.initialize()
        yield proxy
    finally:
        await proxy.shutdown()