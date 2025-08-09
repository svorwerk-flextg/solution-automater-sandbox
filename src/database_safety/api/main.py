#!/usr/bin/env python3
"""
Database Safety HTTP API Service
FastAPI-based REST API for database safety layer operations.
"""

import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Depends, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn

# Add parent directory to path to import our modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.db_proxy import DatabaseSafetyProxy, create_database_proxy, QueryRequest, QueryResult, DatabaseType
from core.config import ConfigManager
from core.sandbox_manager import SandboxManager, SandboxConfig, SandboxType, SandboxState, MaskingLevel
from core.schema_replicator import SchemaReplicator
from core.data_masking import DataMaskingEngine, analyze_dataset_sensitivity
from core.query_analyzer import QuerySafetyAnalyzer


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Global instances
proxy_service: Optional[DatabaseSafetyProxy] = None
sandbox_manager: Optional[SandboxManager] = None
config_manager: Optional[ConfigManager] = None


# API Models
class QueryExecuteRequest(BaseModel):
    query: str = Field(..., description="SQL or MongoDB query to execute")
    database_type: DatabaseType = Field(..., description="Type of database")
    database_name: str = Field(..., description="Target database name")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Query parameters")
    user_context: Dict[str, Any] = Field(default_factory=dict, description="User context information")


class QueryExecuteResponse(BaseModel):
    success: bool
    data: Optional[Any] = None
    rows_affected: Optional[int] = None
    error_message: Optional[str] = None
    execution_time: Optional[float] = None
    connection_info: Optional[Dict[str, str]] = None
    safety_info: Optional[Dict[str, Any]] = None


class QueryAnalysisRequest(BaseModel):
    query: str = Field(..., description="Query to analyze")
    database_type: str = Field(default="mssql", description="Database type for analysis")


class QueryAnalysisResponse(BaseModel):
    query_type: str
    safety_level: str
    operations: List[str]
    tables_accessed: List[str]
    risk_factors: List[str]
    matched_rules: List[Dict[str, Any]]
    environment_permissions: Dict[str, bool]


class SandboxCreateRequest(BaseModel):
    name: str = Field(..., description="Unique sandbox name")
    sandbox_type: SandboxType = Field(default=SandboxType.SQLITE, description="Type of sandbox database")
    source_connection: str = Field(..., description="Source database connection string")
    source_database: str = Field(..., description="Source database name")
    sample_size_per_table: int = Field(default=1000, description="Sample size per table")
    tables_to_include: Optional[List[str]] = Field(None, description="Specific tables to include")
    tables_to_exclude: Optional[List[str]] = Field(None, description="Tables to exclude")
    enable_data_masking: bool = Field(default=True, description="Enable data masking")
    masking_level: MaskingLevel = Field(default=MaskingLevel.STANDARD, description="Data masking level")
    auto_refresh_enabled: bool = Field(default=False, description="Enable automatic refresh")
    auto_refresh_interval_hours: int = Field(default=24, description="Auto-refresh interval in hours")
    max_age_days: int = Field(default=7, description="Maximum age before cleanup")
    tags: List[str] = Field(default_factory=list, description="Tags for categorization")


class SandboxResponse(BaseModel):
    name: str
    sandbox_type: str
    state: str
    connection_string: str
    created_at: datetime
    last_refreshed: Optional[datetime] = None
    last_accessed: Optional[datetime] = None
    table_count: int
    total_rows: int
    storage_size_mb: float
    source_database: str
    enable_data_masking: bool
    auto_refresh_enabled: bool
    tags: List[str]


class SchemaReplicationRequest(BaseModel):
    source_connection: str = Field(..., description="Source database connection string")
    target_connection: str = Field(..., description="Target database connection string")
    database_name: str = Field(..., description="Database name to replicate")
    tables_to_replicate: Optional[List[str]] = Field(None, description="Specific tables to replicate")
    sample_size: int = Field(default=1000, description="Sample size per table")
    enable_masking: bool = Field(default=True, description="Enable data masking")


class DataMaskingRequest(BaseModel):
    data: List[Dict[str, Any]] = Field(..., description="Data to mask")
    column_types: Dict[str, str] = Field(..., description="Column name to type mapping")
    masking_level: MaskingLevel = Field(default=MaskingLevel.STANDARD, description="Masking level")


# Application Lifecycle
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management."""
    global proxy_service, sandbox_manager, config_manager
    
    # Startup
    logger.info("Starting Database Safety API Service")
    
    try:
        # Initialize configuration
        config_path = os.getenv('DB_SAFETY_CONFIG')
        config_manager = ConfigManager(config_path)
        await config_manager.load_config()
        
        # Initialize database proxy
        proxy_service = create_database_proxy(config_path)
        await proxy_service.initialize()
        
        # Initialize sandbox manager
        sandbox_manager = SandboxManager()
        await sandbox_manager.initialize()
        
        logger.info("Database Safety API Service started successfully")
        
    except Exception as e:
        logger.error(f"Failed to start API service: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down Database Safety API Service")
    
    if proxy_service:
        await proxy_service.shutdown()
    
    if sandbox_manager:
        await sandbox_manager.shutdown()
    
    logger.info("Database Safety API Service stopped")


# Create FastAPI application
app = FastAPI(
    title="Database Safety API",
    description="Multi-database proxy with bulletproof write protection",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Dependency injection
def get_proxy_service() -> DatabaseSafetyProxy:
    """Get database proxy service instance."""
    if proxy_service is None:
        raise HTTPException(status_code=503, detail="Proxy service not initialized")
    return proxy_service


def get_sandbox_manager() -> SandboxManager:
    """Get sandbox manager instance."""
    if sandbox_manager is None:
        raise HTTPException(status_code=503, detail="Sandbox manager not initialized")
    return sandbox_manager


# Health and System Endpoints
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "services": {
            "proxy": proxy_service is not None,
            "sandbox_manager": sandbox_manager is not None,
            "config_manager": config_manager is not None
        }
    }


@app.get("/system/info")
async def system_info():
    """Get system information."""
    return {
        "service": "Database Safety Layer",
        "version": "1.0.0",
        "components": [
            "Database Proxy Service",
            "Query Safety Analyzer", 
            "Schema Replicator",
            "Data Masking Engine",
            "Sandbox Manager",
            "Connection Pool Manager"
        ]
    }


@app.get("/system/stats")
async def system_stats(proxy: DatabaseSafetyProxy = Depends(get_proxy_service),
                      manager: SandboxManager = Depends(get_sandbox_manager)):
    """Get comprehensive system statistics."""
    # Proxy statistics
    audit_log = await proxy.get_audit_log(limit=100)
    successful_queries = sum(1 for entry in audit_log if entry['success'])
    failed_queries = len(audit_log) - successful_queries
    
    # Sandbox statistics
    sandbox_stats = await manager.get_sandbox_statistics()
    
    return {
        "proxy": {
            "total_queries": len(audit_log),
            "successful_queries": successful_queries,
            "failed_queries": failed_queries,
            "configured_databases": len(proxy.config.databases),
            "active_safety_rules": len(proxy.config.safety_rules)
        },
        "sandbox": sandbox_stats,
        "timestamp": datetime.now().isoformat()
    }


# Query Execution Endpoints
@app.post("/query/execute", response_model=QueryExecuteResponse)
async def execute_query(
    request: QueryExecuteRequest,
    proxy: DatabaseSafetyProxy = Depends(get_proxy_service)
):
    """Execute query through safety proxy."""
    try:
        query_request = QueryRequest(
            query=request.query,
            database_type=request.database_type,
            database_name=request.database_name,
            parameters=request.parameters,
            user_context=request.user_context
        )
        
        result = await proxy.execute_query(query_request)
        
        return QueryExecuteResponse(
            success=result.success,
            data=result.data,
            rows_affected=result.rows_affected,
            error_message=result.error_message,
            execution_time=result.execution_time,
            connection_info=result.connection_info,
            safety_info=result.safety_info
        )
        
    except Exception as e:
        logger.error(f"Query execution failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/query/analyze", response_model=QueryAnalysisResponse)
async def analyze_query(request: QueryAnalysisRequest):
    """Analyze query for safety and risk factors."""
    try:
        analyzer = QuerySafetyAnalyzer()
        analysis = await analyzer.analyze_query(request.query, request.database_type)
        
        from core.query_analyzer import is_query_safe
        
        return QueryAnalysisResponse(
            query_type=analysis.query_type.value,
            safety_level=analysis.safety_level.value,
            operations=[op.value for op in analysis.operations],
            tables_accessed=analysis.tables_accessed,
            risk_factors=analysis.risk_factors,
            matched_rules=[
                {
                    "name": rule.name,
                    "description": rule.description,
                    "risk_level": rule.risk_level.value,
                    "category": rule.category.value
                }
                for rule in analysis.matched_rules
            ],
            environment_permissions={
                "production": is_query_safe(analysis, "production"),
                "development": is_query_safe(analysis, "dev"),
                "sandbox": is_query_safe(analysis, "sandbox")
            }
        )
        
    except Exception as e:
        logger.error(f"Query analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/query/audit")
async def get_audit_log(
    limit: int = Query(default=50, le=1000),
    proxy: DatabaseSafetyProxy = Depends(get_proxy_service)
):
    """Get query audit log."""
    try:
        audit_entries = await proxy.get_audit_log(limit=limit)
        return {"entries": audit_entries}
        
    except Exception as e:
        logger.error(f"Failed to get audit log: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Sandbox Management Endpoints
@app.post("/sandbox", response_model=SandboxResponse)
async def create_sandbox(
    request: SandboxCreateRequest,
    background_tasks: BackgroundTasks,
    manager: SandboxManager = Depends(get_sandbox_manager)
):
    """Create new sandbox database."""
    try:
        config = SandboxConfig(
            name=request.name,
            sandbox_type=request.sandbox_type,
            source_connection=request.source_connection,
            source_database=request.source_database,
            sample_size_per_table=request.sample_size_per_table,
            tables_to_include=request.tables_to_include,
            tables_to_exclude=request.tables_to_exclude,
            enable_data_masking=request.enable_data_masking,
            masking_level=request.masking_level,
            auto_refresh_enabled=request.auto_refresh_enabled,
            auto_refresh_interval_hours=request.auto_refresh_interval_hours,
            max_age_days=request.max_age_days,
            tags=request.tags,
            created_by="api_user"  # Could be extracted from auth context
        )
        
        # Create sandbox in background for large datasets
        sandbox_info = await manager.create_sandbox(config)
        
        return _sandbox_info_to_response(sandbox_info)
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Sandbox creation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/sandbox", response_model=List[SandboxResponse])
async def list_sandboxes(
    state: Optional[SandboxState] = Query(None),
    sandbox_type: Optional[SandboxType] = Query(None),
    manager: SandboxManager = Depends(get_sandbox_manager)
):
    """List sandbox databases."""
    try:
        sandboxes = await manager.list_sandboxes(
            state_filter=state,
            type_filter=sandbox_type
        )
        
        return [_sandbox_info_to_response(sandbox) for sandbox in sandboxes]
        
    except Exception as e:
        logger.error(f"Failed to list sandboxes: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/sandbox/{name}", response_model=SandboxResponse)
async def get_sandbox_info(
    name: str,
    manager: SandboxManager = Depends(get_sandbox_manager)
):
    """Get detailed sandbox information."""
    try:
        sandbox_info = await manager.get_sandbox_info(name)
        return _sandbox_info_to_response(sandbox_info)
        
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Sandbox not found: {name}")
    except Exception as e:
        logger.error(f"Failed to get sandbox info: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/sandbox/{name}/refresh", response_model=SandboxResponse)
async def refresh_sandbox(
    name: str,
    background_tasks: BackgroundTasks,
    manager: SandboxManager = Depends(get_sandbox_manager)
):
    """Refresh sandbox data from source."""
    try:
        # Perform refresh in background for large datasets
        sandbox_info = await manager.refresh_sandbox(name)
        return _sandbox_info_to_response(sandbox_info)
        
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Sandbox not found: {name}")
    except Exception as e:
        logger.error(f"Sandbox refresh failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/sandbox/{name}/pause")
async def pause_sandbox(
    name: str,
    manager: SandboxManager = Depends(get_sandbox_manager)
):
    """Pause sandbox (stop container if applicable)."""
    try:
        sandbox_info = await manager.pause_sandbox(name)
        return {"message": f"Sandbox '{name}' paused successfully"}
        
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Sandbox not found: {name}")
    except Exception as e:
        logger.error(f"Failed to pause sandbox: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/sandbox/{name}/resume")
async def resume_sandbox(
    name: str,
    manager: SandboxManager = Depends(get_sandbox_manager)
):
    """Resume paused sandbox."""
    try:
        sandbox_info = await manager.resume_sandbox(name)
        return {"message": f"Sandbox '{name}' resumed successfully"}
        
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Sandbox not found: {name}")
    except Exception as e:
        logger.error(f"Failed to resume sandbox: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/sandbox/{name}")
async def destroy_sandbox(
    name: str,
    force: bool = Query(default=False),
    manager: SandboxManager = Depends(get_sandbox_manager)
):
    """Destroy sandbox and clean up resources."""
    try:
        success = await manager.destroy_sandbox(name, force=force)
        
        if success:
            return {"message": f"Sandbox '{name}' destroyed successfully"}
        else:
            return {"message": f"Sandbox '{name}' destruction completed with warnings"}
        
    except ValueError:
        raise HTTPException(status_code=404, detail=f"Sandbox not found: {name}")
    except Exception as e:
        logger.error(f"Failed to destroy sandbox: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/sandbox/stats")
async def get_sandbox_stats(manager: SandboxManager = Depends(get_sandbox_manager)):
    """Get sandbox system statistics."""
    try:
        stats = await manager.get_sandbox_statistics()
        return stats
        
    except Exception as e:
        logger.error(f"Failed to get sandbox statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Schema Replication Endpoints
@app.post("/schema/replicate")
async def replicate_schema(request: SchemaReplicationRequest):
    """Replicate database schema with sample data."""
    try:
        replicator = SchemaReplicator(
            source_connection=request.source_connection,
            target_connection=request.target_connection
        )
        
        replicator.mask_sensitive_data = request.enable_masking
        
        result = await replicator.replicate_schema(
            database_name=request.database_name,
            tables_to_replicate=request.tables_to_replicate,
            sample_size=request.sample_size
        )
        
        return result
        
    except Exception as e:
        logger.error(f"Schema replication failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Data Masking Endpoints
@app.post("/mask/data")
async def mask_data(request: DataMaskingRequest):
    """Mask sensitive data in dataset."""
    try:
        from core.data_masking import mask_dataset
        
        masked_data = mask_dataset(
            data=request.data,
            column_types=request.column_types,
            masking_level=request.masking_level
        )
        
        return {"masked_data": masked_data}
        
    except Exception as e:
        logger.error(f"Data masking failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/mask/analyze")
async def analyze_data_sensitivity(request: DataMaskingRequest):
    """Analyze dataset for sensitive information."""
    try:
        analysis = analyze_dataset_sensitivity(
            data=request.data,
            column_types=request.column_types
        )
        
        return analysis
        
    except Exception as e:
        logger.error(f"Data analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Helper Functions
def _sandbox_info_to_response(sandbox_info) -> SandboxResponse:
    """Convert SandboxInfo to API response model."""
    return SandboxResponse(
        name=sandbox_info.config.name,
        sandbox_type=sandbox_info.config.sandbox_type.value,
        state=sandbox_info.state.value,
        connection_string=sandbox_info.connection_string,
        created_at=sandbox_info.created_at,
        last_refreshed=sandbox_info.last_refreshed,
        last_accessed=sandbox_info.last_accessed,
        table_count=sandbox_info.table_count,
        total_rows=sandbox_info.total_rows,
        storage_size_mb=sandbox_info.storage_size_mb,
        source_database=sandbox_info.config.source_database,
        enable_data_masking=sandbox_info.config.enable_data_masking,
        auto_refresh_enabled=sandbox_info.config.auto_refresh_enabled,
        tags=sandbox_info.config.tags
    )


# Development server
def main():
    """Run development server."""
    config = uvicorn.Config(
        app=app,
        host="0.0.0.0",
        port=8080,
        log_level="info",
        reload=True
    )
    
    server = uvicorn.Server(config)
    server.run()


if __name__ == "__main__":
    main()