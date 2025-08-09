#!/usr/bin/env python3
"""
Sandbox Database Lifecycle Management System
Manages local sandbox databases with schema replication, data refresh, and cleanup.
"""

import asyncio
import logging
import os
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import aiosqlite
import docker
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from .config import DatabaseConfig
from .schema_replicator import SchemaReplicator, DatabaseSchema
from .data_masking import DataMaskingEngine, MaskingLevel


class SandboxState(str, Enum):
    """Sandbox database states."""
    CREATING = "creating"
    ACTIVE = "active"
    REFRESHING = "refreshing"
    PAUSED = "paused"
    FAILED = "failed"
    DESTROYED = "destroyed"


class SandboxType(str, Enum):
    """Types of sandbox databases."""
    SQLITE = "sqlite"
    POSTGRES = "postgres"
    MYSQL = "mysql"
    MONGODB = "mongodb"


@dataclass
class SandboxConfig:
    """Configuration for sandbox database."""
    name: str
    sandbox_type: SandboxType
    source_connection: str
    source_database: str
    
    # Data settings
    sample_size_per_table: int = 1000
    tables_to_include: Optional[List[str]] = None
    tables_to_exclude: Optional[List[str]] = None
    
    # Masking settings
    enable_data_masking: bool = True
    masking_level: MaskingLevel = MaskingLevel.STANDARD
    
    # Lifecycle settings
    auto_refresh_enabled: bool = False
    auto_refresh_interval_hours: int = 24
    max_age_days: int = 7
    auto_cleanup: bool = True
    
    # Resources
    storage_path: Optional[str] = None
    max_storage_mb: int = 1024  # 1GB default
    
    # Metadata
    created_by: Optional[str] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class SandboxInfo:
    """Runtime information about sandbox database."""
    config: SandboxConfig
    state: SandboxState
    connection_string: str
    
    # Timestamps
    created_at: datetime
    last_refreshed: Optional[datetime] = None
    last_accessed: Optional[datetime] = None
    
    # Statistics
    table_count: int = 0
    total_rows: int = 0
    storage_size_mb: float = 0.0
    
    # Source sync info
    source_schema_version: Optional[str] = None
    last_sync_duration: Optional[float] = None
    
    # Errors
    last_error: Optional[str] = None
    error_count: int = 0


class SandboxManager:
    """
    Comprehensive sandbox database management system.
    
    Features:
    - Multi-database type support (SQLite, Postgres, MySQL, MongoDB)
    - Automated schema replication with data masking
    - Lifecycle management (create, refresh, pause, destroy)
    - Resource monitoring and cleanup
    - Docker container management for non-SQLite databases
    - Background refresh scheduling
    """
    
    def __init__(self, base_storage_path: str = "/tmp/database_sandbox"):
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Storage
        self.base_storage_path = Path(base_storage_path)
        self.base_storage_path.mkdir(parents=True, exist_ok=True)
        
        # Active sandboxes
        self.sandboxes: Dict[str, SandboxInfo] = {}
        
        # Docker client for containerized databases
        try:
            self.docker_client = docker.from_env()
        except Exception as e:
            self.logger.warning(f"Docker not available: {e}")
            self.docker_client = None
        
        # Background tasks
        self._cleanup_task: Optional[asyncio.Task] = None
        self._refresh_task: Optional[asyncio.Task] = None
        self._monitoring_task: Optional[asyncio.Task] = None
        
        # Resource limits
        self.max_total_storage_gb = 10
        self.max_concurrent_sandboxes = 50
        
    async def initialize(self) -> None:
        """Initialize sandbox manager."""
        self.logger.info("Initializing Sandbox Manager")
        
        # Load existing sandboxes
        await self._load_existing_sandboxes()
        
        # Start background tasks
        self._cleanup_task = asyncio.create_task(self._cleanup_worker())
        self._refresh_task = asyncio.create_task(self._refresh_worker())
        self._monitoring_task = asyncio.create_task(self._monitoring_worker())
        
        self.logger.info(f"Sandbox Manager initialized with {len(self.sandboxes)} existing sandboxes")
    
    async def create_sandbox(self, config: SandboxConfig) -> SandboxInfo:
        """
        Create new sandbox database.
        
        Args:
            config: Sandbox configuration
            
        Returns:
            SandboxInfo with connection details
        """
        if config.name in self.sandboxes:
            raise ValueError(f"Sandbox already exists: {config.name}")
        
        if len(self.sandboxes) >= self.max_concurrent_sandboxes:
            raise ValueError(f"Maximum concurrent sandboxes reached: {self.max_concurrent_sandboxes}")
        
        self.logger.info(f"Creating sandbox: {config.name}")
        
        # Create sandbox info
        sandbox_info = SandboxInfo(
            config=config,
            state=SandboxState.CREATING,
            connection_string="",
            created_at=datetime.now(),
            created_by=config.created_by
        )
        
        self.sandboxes[config.name] = sandbox_info
        
        try:
            # Create storage directory
            sandbox_path = self._get_sandbox_path(config.name)
            sandbox_path.mkdir(parents=True, exist_ok=True)
            
            # Create database based on type
            if config.sandbox_type == SandboxType.SQLITE:
                connection_string = await self._create_sqlite_sandbox(config, sandbox_path)
            elif config.sandbox_type == SandboxType.POSTGRES:
                connection_string = await self._create_postgres_sandbox(config, sandbox_path)
            elif config.sandbox_type == SandboxType.MYSQL:
                connection_string = await self._create_mysql_sandbox(config, sandbox_path)
            elif config.sandbox_type == SandboxType.MONGODB:
                connection_string = await self._create_mongodb_sandbox(config, sandbox_path)
            else:
                raise ValueError(f"Unsupported sandbox type: {config.sandbox_type}")
            
            sandbox_info.connection_string = connection_string
            sandbox_info.state = SandboxState.ACTIVE
            
            # Replicate schema and data
            await self._replicate_sandbox_data(sandbox_info)
            
            # Save metadata
            await self._save_sandbox_metadata(sandbox_info)
            
            self.logger.info(f"Sandbox created successfully: {config.name}")
            return sandbox_info
            
        except Exception as e:
            self.logger.error(f"Failed to create sandbox {config.name}: {e}")
            sandbox_info.state = SandboxState.FAILED
            sandbox_info.last_error = str(e)
            raise
    
    async def _create_sqlite_sandbox(self, config: SandboxConfig, sandbox_path: Path) -> str:
        """Create SQLite sandbox database."""
        db_path = sandbox_path / "sandbox.db"
        
        # Create empty database
        async with aiosqlite.connect(str(db_path)) as conn:
            await conn.execute("CREATE TABLE _sandbox_info (key TEXT, value TEXT)")
            await conn.execute(
                "INSERT INTO _sandbox_info VALUES (?, ?)",
                ("created_at", datetime.now().isoformat())
            )
            await conn.commit()
        
        return f"sqlite:///{db_path}"
    
    async def _create_postgres_sandbox(self, config: SandboxConfig, sandbox_path: Path) -> str:
        """Create PostgreSQL sandbox database in Docker container."""
        if not self.docker_client:
            raise RuntimeError("Docker not available for PostgreSQL sandbox")
        
        container_name = f"sandbox_postgres_{config.name}"
        port = await self._find_available_port(5432, 5532)
        
        # Create Docker container
        container = self.docker_client.containers.run(
            "postgres:13",
            name=container_name,
            environment={
                "POSTGRES_DB": "sandbox",
                "POSTGRES_USER": "sandbox_user",
                "POSTGRES_PASSWORD": "sandbox_pass"
            },
            ports={"5432/tcp": port},
            volumes={str(sandbox_path): {"bind": "/var/lib/postgresql/backup", "mode": "rw"}},
            detach=True,
            remove=True
        )
        
        # Wait for container to start
        await asyncio.sleep(5)
        
        return f"postgresql://sandbox_user:sandbox_pass@localhost:{port}/sandbox"
    
    async def _create_mysql_sandbox(self, config: SandboxConfig, sandbox_path: Path) -> str:
        """Create MySQL sandbox database in Docker container."""
        if not self.docker_client:
            raise RuntimeError("Docker not available for MySQL sandbox")
        
        container_name = f"sandbox_mysql_{config.name}"
        port = await self._find_available_port(3306, 3406)
        
        # Create Docker container
        container = self.docker_client.containers.run(
            "mysql:8.0",
            name=container_name,
            environment={
                "MYSQL_DATABASE": "sandbox",
                "MYSQL_USER": "sandbox_user",
                "MYSQL_PASSWORD": "sandbox_pass",
                "MYSQL_ROOT_PASSWORD": "root_pass"
            },
            ports={"3306/tcp": port},
            volumes={str(sandbox_path): {"bind": "/var/lib/mysql/backup", "mode": "rw"}},
            detach=True,
            remove=True
        )
        
        # Wait for container to start
        await asyncio.sleep(10)
        
        return f"mysql://sandbox_user:sandbox_pass@localhost:{port}/sandbox"
    
    async def _create_mongodb_sandbox(self, config: SandboxConfig, sandbox_path: Path) -> str:
        """Create MongoDB sandbox database in Docker container."""
        if not self.docker_client:
            raise RuntimeError("Docker not available for MongoDB sandbox")
        
        container_name = f"sandbox_mongo_{config.name}"
        port = await self._find_available_port(27017, 27117)
        
        # Create Docker container
        container = self.docker_client.containers.run(
            "mongo:4.4",
            name=container_name,
            ports={"27017/tcp": port},
            volumes={str(sandbox_path): {"bind": "/data/backup", "mode": "rw"}},
            detach=True,
            remove=True
        )
        
        # Wait for container to start
        await asyncio.sleep(5)
        
        return f"mongodb://localhost:{port}/sandbox"
    
    async def _find_available_port(self, start_port: int, end_port: int) -> int:
        """Find available port in range."""
        import socket
        
        for port in range(start_port, end_port):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                result = sock.connect_ex(('localhost', port))
                if result != 0:  # Port is available
                    return port
        
        raise RuntimeError(f"No available ports in range {start_port}-{end_port}")
    
    async def _replicate_sandbox_data(self, sandbox_info: SandboxInfo) -> None:
        """Replicate schema and data to sandbox."""
        config = sandbox_info.config
        
        self.logger.info(f"Replicating data for sandbox: {config.name}")
        
        # Create schema replicator
        replicator = SchemaReplicator(
            source_connection=config.source_connection,
            target_connection=sandbox_info.connection_string
        )
        
        # Configure data masking
        replicator.mask_sensitive_data = config.enable_data_masking
        replicator.masker.masking_level = config.masking_level
        
        # Perform replication
        result = await replicator.replicate_schema(
            database_name=config.source_database,
            tables_to_replicate=config.tables_to_include,
            sample_size=config.sample_size_per_table
        )
        
        if result['success']:
            # Update sandbox statistics
            sandbox_info.table_count = result['schema_info']['table_count']
            sandbox_info.total_rows = result['statistics']['rows_copied']
            sandbox_info.last_refreshed = datetime.now()
            sandbox_info.last_sync_duration = result['statistics'].get('duration_seconds')
            
            self.logger.info(f"Data replication completed for {config.name}: "
                           f"{sandbox_info.table_count} tables, {sandbox_info.total_rows} rows")
        else:
            raise Exception(f"Data replication failed: {result['error']}")
    
    async def refresh_sandbox(self, sandbox_name: str) -> SandboxInfo:
        """Refresh sandbox data from source."""
        if sandbox_name not in self.sandboxes:
            raise ValueError(f"Sandbox not found: {sandbox_name}")
        
        sandbox_info = self.sandboxes[sandbox_name]
        sandbox_info.state = SandboxState.REFRESHING
        
        try:
            self.logger.info(f"Refreshing sandbox: {sandbox_name}")
            
            # Clear existing data
            await self._clear_sandbox_data(sandbox_info)
            
            # Replicate fresh data
            await self._replicate_sandbox_data(sandbox_info)
            
            sandbox_info.state = SandboxState.ACTIVE
            sandbox_info.last_refreshed = datetime.now()
            sandbox_info.error_count = 0
            sandbox_info.last_error = None
            
            # Update metadata
            await self._save_sandbox_metadata(sandbox_info)
            
            self.logger.info(f"Sandbox refreshed successfully: {sandbox_name}")
            return sandbox_info
            
        except Exception as e:
            self.logger.error(f"Failed to refresh sandbox {sandbox_name}: {e}")
            sandbox_info.state = SandboxState.FAILED
            sandbox_info.last_error = str(e)
            sandbox_info.error_count += 1
            raise
    
    async def _clear_sandbox_data(self, sandbox_info: SandboxInfo) -> None:
        """Clear data from sandbox database."""
        config = sandbox_info.config
        
        if config.sandbox_type == SandboxType.SQLITE:
            # Recreate SQLite database
            db_path = Path(sandbox_info.connection_string.replace("sqlite:///", ""))
            if db_path.exists():
                db_path.unlink()
            
            # Create new empty database
            async with aiosqlite.connect(str(db_path)) as conn:
                await conn.execute("CREATE TABLE _sandbox_info (key TEXT, value TEXT)")
                await conn.commit()
        
        else:
            # For containerized databases, drop and recreate tables
            engine = create_engine(sandbox_info.connection_string)
            with engine.connect() as conn:
                # Get all tables
                result = conn.execute(text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'sandbox'"))
                tables = [row[0] for row in result]
                
                # Drop all tables
                for table in tables:
                    conn.execute(text(f"DROP TABLE IF EXISTS {table} CASCADE"))
                
                conn.commit()
    
    async def pause_sandbox(self, sandbox_name: str) -> SandboxInfo:
        """Pause sandbox (stop container if applicable)."""
        if sandbox_name not in self.sandboxes:
            raise ValueError(f"Sandbox not found: {sandbox_name}")
        
        sandbox_info = self.sandboxes[sandbox_name]
        config = sandbox_info.config
        
        if config.sandbox_type != SandboxType.SQLITE and self.docker_client:
            container_name = f"sandbox_{config.sandbox_type.value}_{config.name}"
            
            try:
                container = self.docker_client.containers.get(container_name)
                container.pause()
                self.logger.info(f"Paused container for sandbox: {sandbox_name}")
            except docker.errors.NotFound:
                self.logger.warning(f"Container not found for sandbox: {sandbox_name}")
        
        sandbox_info.state = SandboxState.PAUSED
        await self._save_sandbox_metadata(sandbox_info)
        
        return sandbox_info
    
    async def resume_sandbox(self, sandbox_name: str) -> SandboxInfo:
        """Resume paused sandbox."""
        if sandbox_name not in self.sandboxes:
            raise ValueError(f"Sandbox not found: {sandbox_name}")
        
        sandbox_info = self.sandboxes[sandbox_name]
        config = sandbox_info.config
        
        if config.sandbox_type != SandboxType.SQLITE and self.docker_client:
            container_name = f"sandbox_{config.sandbox_type.value}_{config.name}"
            
            try:
                container = self.docker_client.containers.get(container_name)
                container.unpause()
                self.logger.info(f"Resumed container for sandbox: {sandbox_name}")
            except docker.errors.NotFound:
                self.logger.warning(f"Container not found for sandbox: {sandbox_name}")
        
        sandbox_info.state = SandboxState.ACTIVE
        sandbox_info.last_accessed = datetime.now()
        await self._save_sandbox_metadata(sandbox_info)
        
        return sandbox_info
    
    async def destroy_sandbox(self, sandbox_name: str, force: bool = False) -> bool:
        """Destroy sandbox and clean up resources."""
        if sandbox_name not in self.sandboxes:
            if not force:
                raise ValueError(f"Sandbox not found: {sandbox_name}")
            return False
        
        sandbox_info = self.sandboxes[sandbox_name]
        config = sandbox_info.config
        
        self.logger.info(f"Destroying sandbox: {sandbox_name}")
        
        try:
            # Stop and remove container if applicable
            if config.sandbox_type != SandboxType.SQLITE and self.docker_client:
                container_name = f"sandbox_{config.sandbox_type.value}_{config.name}"
                
                try:
                    container = self.docker_client.containers.get(container_name)
                    container.stop()
                    container.remove()
                    self.logger.info(f"Removed container for sandbox: {sandbox_name}")
                except docker.errors.NotFound:
                    self.logger.warning(f"Container not found for sandbox: {sandbox_name}")
            
            # Remove storage directory
            sandbox_path = self._get_sandbox_path(sandbox_name)
            if sandbox_path.exists():
                shutil.rmtree(sandbox_path)
                self.logger.info(f"Removed storage for sandbox: {sandbox_name}")
            
            # Remove from active sandboxes
            sandbox_info.state = SandboxState.DESTROYED
            del self.sandboxes[sandbox_name]
            
            self.logger.info(f"Sandbox destroyed successfully: {sandbox_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to destroy sandbox {sandbox_name}: {e}")
            if not force:
                raise
            return False
    
    async def get_sandbox_info(self, sandbox_name: str) -> SandboxInfo:
        """Get detailed information about sandbox."""
        if sandbox_name not in self.sandboxes:
            raise ValueError(f"Sandbox not found: {sandbox_name}")
        
        sandbox_info = self.sandboxes[sandbox_name]
        
        # Update storage size
        await self._update_sandbox_storage_info(sandbox_info)
        
        return sandbox_info
    
    async def list_sandboxes(
        self, 
        state_filter: Optional[SandboxState] = None,
        type_filter: Optional[SandboxType] = None,
        tag_filter: Optional[List[str]] = None
    ) -> List[SandboxInfo]:
        """List sandboxes with optional filtering."""
        sandboxes = list(self.sandboxes.values())
        
        if state_filter:
            sandboxes = [s for s in sandboxes if s.state == state_filter]
        
        if type_filter:
            sandboxes = [s for s in sandboxes if s.config.sandbox_type == type_filter]
        
        if tag_filter:
            sandboxes = [s for s in sandboxes if any(tag in s.config.tags for tag in tag_filter)]
        
        return sandboxes
    
    async def get_sandbox_statistics(self) -> Dict[str, Any]:
        """Get comprehensive sandbox statistics."""
        total_storage_mb = 0
        states_count = {}
        types_count = {}
        
        for sandbox_info in self.sandboxes.values():
            # Update storage info
            await self._update_sandbox_storage_info(sandbox_info)
            total_storage_mb += sandbox_info.storage_size_mb
            
            # Count states
            state = sandbox_info.state.value
            states_count[state] = states_count.get(state, 0) + 1
            
            # Count types
            sandbox_type = sandbox_info.config.sandbox_type.value
            types_count[sandbox_type] = types_count.get(sandbox_type, 0) + 1
        
        return {
            'total_sandboxes': len(self.sandboxes),
            'total_storage_mb': total_storage_mb,
            'total_storage_gb': total_storage_mb / 1024,
            'states_breakdown': states_count,
            'types_breakdown': types_count,
            'storage_limit_gb': self.max_total_storage_gb,
            'sandbox_limit': self.max_concurrent_sandboxes
        }
    
    def _get_sandbox_path(self, sandbox_name: str) -> Path:
        """Get storage path for sandbox."""
        return self.base_storage_path / sandbox_name
    
    async def _update_sandbox_storage_info(self, sandbox_info: SandboxInfo) -> None:
        """Update storage information for sandbox."""
        sandbox_path = self._get_sandbox_path(sandbox_info.config.name)
        
        if sandbox_path.exists():
            total_size = 0
            for file_path in sandbox_path.rglob('*'):
                if file_path.is_file():
                    total_size += file_path.stat().st_size
            
            sandbox_info.storage_size_mb = total_size / (1024 * 1024)
        else:
            sandbox_info.storage_size_mb = 0.0
    
    async def _save_sandbox_metadata(self, sandbox_info: SandboxInfo) -> None:
        """Save sandbox metadata to disk."""
        sandbox_path = self._get_sandbox_path(sandbox_info.config.name)
        metadata_path = sandbox_path / "metadata.json"
        
        import json
        
        metadata = {
            'config': {
                'name': sandbox_info.config.name,
                'sandbox_type': sandbox_info.config.sandbox_type.value,
                'source_connection': sandbox_info.config.source_connection,
                'source_database': sandbox_info.config.source_database,
                'sample_size_per_table': sandbox_info.config.sample_size_per_table,
                'enable_data_masking': sandbox_info.config.enable_data_masking,
                'masking_level': sandbox_info.config.masking_level.value,
                'auto_refresh_enabled': sandbox_info.config.auto_refresh_enabled,
                'auto_refresh_interval_hours': sandbox_info.config.auto_refresh_interval_hours,
                'max_age_days': sandbox_info.config.max_age_days,
                'created_by': sandbox_info.config.created_by,
                'tags': sandbox_info.config.tags
            },
            'info': {
                'state': sandbox_info.state.value,
                'connection_string': sandbox_info.connection_string,
                'created_at': sandbox_info.created_at.isoformat(),
                'last_refreshed': sandbox_info.last_refreshed.isoformat() if sandbox_info.last_refreshed else None,
                'last_accessed': sandbox_info.last_accessed.isoformat() if sandbox_info.last_accessed else None,
                'table_count': sandbox_info.table_count,
                'total_rows': sandbox_info.total_rows,
                'storage_size_mb': sandbox_info.storage_size_mb,
                'last_error': sandbox_info.last_error,
                'error_count': sandbox_info.error_count
            }
        }
        
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    async def _load_existing_sandboxes(self) -> None:
        """Load existing sandboxes from disk."""
        if not self.base_storage_path.exists():
            return
        
        for sandbox_dir in self.base_storage_path.iterdir():
            if not sandbox_dir.is_dir():
                continue
            
            metadata_path = sandbox_dir / "metadata.json"
            if not metadata_path.exists():
                continue
            
            try:
                await self._load_sandbox_from_metadata(metadata_path)
            except Exception as e:
                self.logger.warning(f"Failed to load sandbox from {metadata_path}: {e}")
    
    async def _load_sandbox_from_metadata(self, metadata_path: Path) -> None:
        """Load sandbox from metadata file."""
        import json
        
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)
        
        # Reconstruct config
        config_data = metadata['config']
        config = SandboxConfig(
            name=config_data['name'],
            sandbox_type=SandboxType(config_data['sandbox_type']),
            source_connection=config_data['source_connection'],
            source_database=config_data['source_database'],
            sample_size_per_table=config_data['sample_size_per_table'],
            enable_data_masking=config_data['enable_data_masking'],
            masking_level=MaskingLevel(config_data['masking_level']),
            auto_refresh_enabled=config_data['auto_refresh_enabled'],
            auto_refresh_interval_hours=config_data['auto_refresh_interval_hours'],
            max_age_days=config_data['max_age_days'],
            created_by=config_data.get('created_by'),
            tags=config_data.get('tags', [])
        )
        
        # Reconstruct info
        info_data = metadata['info']
        sandbox_info = SandboxInfo(
            config=config,
            state=SandboxState(info_data['state']),
            connection_string=info_data['connection_string'],
            created_at=datetime.fromisoformat(info_data['created_at']),
            last_refreshed=datetime.fromisoformat(info_data['last_refreshed']) if info_data['last_refreshed'] else None,
            last_accessed=datetime.fromisoformat(info_data['last_accessed']) if info_data['last_accessed'] else None,
            table_count=info_data['table_count'],
            total_rows=info_data['total_rows'],
            storage_size_mb=info_data['storage_size_mb'],
            last_error=info_data.get('last_error'),
            error_count=info_data.get('error_count', 0)
        )
        
        self.sandboxes[config.name] = sandbox_info
        self.logger.info(f"Loaded existing sandbox: {config.name}")
    
    async def _cleanup_worker(self) -> None:
        """Background cleanup worker."""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour
                await self._perform_cleanup()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Cleanup worker error: {e}")
    
    async def _refresh_worker(self) -> None:
        """Background refresh worker."""
        while True:
            try:
                await asyncio.sleep(1800)  # Run every 30 minutes
                await self._perform_auto_refresh()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Refresh worker error: {e}")
    
    async def _monitoring_worker(self) -> None:
        """Background monitoring worker."""
        while True:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes
                await self._perform_monitoring()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Monitoring worker error: {e}")
    
    async def _perform_cleanup(self) -> None:
        """Perform cleanup of old/failed sandboxes."""
        cleanup_count = 0
        current_time = datetime.now()
        
        for sandbox_name, sandbox_info in list(self.sandboxes.items()):
            should_cleanup = False
            
            # Check age limit
            age_days = (current_time - sandbox_info.created_at).days
            if sandbox_info.config.auto_cleanup and age_days > sandbox_info.config.max_age_days:
                should_cleanup = True
                self.logger.info(f"Sandbox {sandbox_name} exceeded age limit ({age_days} days)")
            
            # Check failed state
            if sandbox_info.state == SandboxState.FAILED and sandbox_info.error_count > 3:
                should_cleanup = True
                self.logger.info(f"Sandbox {sandbox_name} has too many failures")
            
            if should_cleanup:
                try:
                    await self.destroy_sandbox(sandbox_name, force=True)
                    cleanup_count += 1
                except Exception as e:
                    self.logger.error(f"Failed to cleanup sandbox {sandbox_name}: {e}")
        
        if cleanup_count > 0:
            self.logger.info(f"Cleaned up {cleanup_count} sandboxes")
    
    async def _perform_auto_refresh(self) -> None:
        """Perform auto-refresh of eligible sandboxes."""
        refresh_count = 0
        current_time = datetime.now()
        
        for sandbox_name, sandbox_info in self.sandboxes.items():
            if not sandbox_info.config.auto_refresh_enabled:
                continue
            
            if sandbox_info.state != SandboxState.ACTIVE:
                continue
            
            # Check if refresh is due
            last_refresh = sandbox_info.last_refreshed or sandbox_info.created_at
            hours_since_refresh = (current_time - last_refresh).total_seconds() / 3600
            
            if hours_since_refresh >= sandbox_info.config.auto_refresh_interval_hours:
                try:
                    self.logger.info(f"Auto-refreshing sandbox: {sandbox_name}")
                    await self.refresh_sandbox(sandbox_name)
                    refresh_count += 1
                except Exception as e:
                    self.logger.error(f"Auto-refresh failed for {sandbox_name}: {e}")
        
        if refresh_count > 0:
            self.logger.info(f"Auto-refreshed {refresh_count} sandboxes")
    
    async def _perform_monitoring(self) -> None:
        """Perform health monitoring of sandboxes."""
        for sandbox_name, sandbox_info in self.sandboxes.items():
            try:
                # Update storage info
                await self._update_sandbox_storage_info(sandbox_info)
                
                # Check container health for non-SQLite sandboxes
                if (sandbox_info.config.sandbox_type != SandboxType.SQLITE and 
                    self.docker_client and 
                    sandbox_info.state == SandboxState.ACTIVE):
                    
                    container_name = f"sandbox_{sandbox_info.config.sandbox_type.value}_{sandbox_name}"
                    
                    try:
                        container = self.docker_client.containers.get(container_name)
                        if container.status != 'running':
                            self.logger.warning(f"Container not running for sandbox {sandbox_name}: {container.status}")
                            sandbox_info.state = SandboxState.FAILED
                            sandbox_info.last_error = f"Container status: {container.status}"
                    except docker.errors.NotFound:
                        self.logger.warning(f"Container not found for sandbox: {sandbox_name}")
                        sandbox_info.state = SandboxState.FAILED
                        sandbox_info.last_error = "Container not found"
                
            except Exception as e:
                self.logger.error(f"Monitoring error for sandbox {sandbox_name}: {e}")
    
    async def shutdown(self) -> None:
        """Shutdown sandbox manager."""
        self.logger.info("Shutting down Sandbox Manager")
        
        # Cancel background tasks
        if self._cleanup_task:
            self._cleanup_task.cancel()
        if self._refresh_task:
            self._refresh_task.cancel()
        if self._monitoring_task:
            self._monitoring_task.cancel()
        
        # Wait for tasks to complete
        tasks = [t for t in [self._cleanup_task, self._refresh_task, self._monitoring_task] if t]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        # Save all sandbox metadata
        for sandbox_info in self.sandboxes.values():
            try:
                await self._save_sandbox_metadata(sandbox_info)
            except Exception as e:
                self.logger.error(f"Failed to save metadata for {sandbox_info.config.name}: {e}")
        
        self.logger.info("Sandbox Manager shutdown complete")


# CLI interface for sandbox management
async def main():
    """CLI interface for sandbox management."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Database Sandbox Manager")
    parser.add_argument("command", choices=['create', 'list', 'refresh', 'destroy', 'info'])
    parser.add_argument("--name", help="Sandbox name")
    parser.add_argument("--type", choices=['sqlite', 'postgres', 'mysql', 'mongodb'], default='sqlite')
    parser.add_argument("--source", help="Source database connection string")
    parser.add_argument("--database", help="Source database name")
    parser.add_argument("--sample-size", type=int, default=1000)
    parser.add_argument("--no-masking", action='store_true', help="Disable data masking")
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create sandbox manager
    manager = SandboxManager()
    await manager.initialize()
    
    try:
        if args.command == 'create':
            if not args.name or not args.source or not args.database:
                print("Error: --name, --source, and --database are required for create command")
                return
            
            config = SandboxConfig(
                name=args.name,
                sandbox_type=SandboxType(args.type),
                source_connection=args.source,
                source_database=args.database,
                sample_size_per_table=args.sample_size,
                enable_data_masking=not args.no_masking
            )
            
            sandbox_info = await manager.create_sandbox(config)
            print(f"✅ Sandbox created: {sandbox_info.config.name}")
            print(f"📊 Connection: {sandbox_info.connection_string}")
            print(f"📊 Tables: {sandbox_info.table_count}, Rows: {sandbox_info.total_rows}")
        
        elif args.command == 'list':
            sandboxes = await manager.list_sandboxes()
            print(f"📋 Found {len(sandboxes)} sandboxes:")
            
            for sandbox in sandboxes:
                print(f"  - {sandbox.config.name} ({sandbox.config.sandbox_type.value}) - {sandbox.state.value}")
                print(f"    Tables: {sandbox.table_count}, Rows: {sandbox.total_rows}, Size: {sandbox.storage_size_mb:.1f}MB")
        
        elif args.command == 'info':
            if not args.name:
                print("Error: --name is required for info command")
                return
            
            try:
                sandbox_info = await manager.get_sandbox_info(args.name)
                print(f"📊 Sandbox: {sandbox_info.config.name}")
                print(f"   Type: {sandbox_info.config.sandbox_type.value}")
                print(f"   State: {sandbox_info.state.value}")
                print(f"   Created: {sandbox_info.created_at}")
                print(f"   Tables: {sandbox_info.table_count}")
                print(f"   Rows: {sandbox_info.total_rows}")
                print(f"   Storage: {sandbox_info.storage_size_mb:.1f}MB")
                print(f"   Connection: {sandbox_info.connection_string}")
                
                if sandbox_info.last_error:
                    print(f"   Last Error: {sandbox_info.last_error}")
                    
            except ValueError as e:
                print(f"❌ {e}")
        
        elif args.command == 'refresh':
            if not args.name:
                print("Error: --name is required for refresh command")
                return
            
            try:
                sandbox_info = await manager.refresh_sandbox(args.name)
                print(f"✅ Sandbox refreshed: {args.name}")
                print(f"📊 Tables: {sandbox_info.table_count}, Rows: {sandbox_info.total_rows}")
            except ValueError as e:
                print(f"❌ {e}")
        
        elif args.command == 'destroy':
            if not args.name:
                print("Error: --name is required for destroy command")
                return
            
            try:
                success = await manager.destroy_sandbox(args.name)
                if success:
                    print(f"✅ Sandbox destroyed: {args.name}")
                else:
                    print(f"❌ Failed to destroy sandbox: {args.name}")
            except ValueError as e:
                print(f"❌ {e}")
    
    finally:
        await manager.shutdown()


if __name__ == "__main__":
    asyncio.run(main())