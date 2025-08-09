#!/usr/bin/env python3
"""
Advanced Connection Pool Manager
Handles multi-database connections with failover, load balancing, and health monitoring.
"""

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

import aiomysql
import aiopg
import motor.motor_asyncio
import aioodbc
from azure.identity import DefaultAzureCredential


class ConnectionState(str, Enum):
    """Connection health states."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    UNKNOWN = "unknown"


class LoadBalanceStrategy(str, Enum):
    """Load balancing strategies."""
    ROUND_ROBIN = "round_robin"
    LEAST_CONNECTIONS = "least_connections"
    RANDOM = "random"
    WEIGHTED = "weighted"


@dataclass
class ConnectionPoolConfig:
    """Configuration for individual connection pool."""
    name: str
    database_type: str
    connection_string: str
    
    # Pool settings
    min_size: int = 5
    max_size: int = 20
    max_idle_time: int = 300  # 5 minutes
    connection_timeout: int = 30
    command_timeout: int = 60
    
    # Health monitoring
    health_check_interval: int = 30
    max_retries: int = 3
    retry_delay: int = 5
    
    # Load balancing
    weight: float = 1.0
    priority: int = 1
    
    # Failover
    failover_pools: List[str] = field(default_factory=list)
    
    # Environment
    environment: str = "production"  # production, dev, sandbox


@dataclass
class ConnectionInfo:
    """Information about active connection."""
    connection_id: str
    pool_name: str
    created_at: float
    last_used: float
    query_count: int = 0
    is_healthy: bool = True
    connection_object: Any = None


class ConnectionPool:
    """Individual database connection pool."""
    
    def __init__(self, config: ConnectionPoolConfig):
        self.config = config
        self.logger = logging.getLogger(f"{self.__class__.__name__}.{config.name}")
        
        # Pool state
        self._connections: List[ConnectionInfo] = []
        self._available_connections = asyncio.Queue()
        self._active_connections: Dict[str, ConnectionInfo] = {}
        
        # Health monitoring
        self.state = ConnectionState.UNKNOWN
        self.last_health_check = 0
        self.consecutive_failures = 0
        
        # Statistics
        self.total_connections_created = 0
        self.total_queries_executed = 0
        self.avg_response_time = 0.0
        
        # Synchronization
        self._lock = asyncio.Lock()
        self._health_check_task: Optional[asyncio.Task] = None
        
    async def initialize(self) -> None:
        """Initialize connection pool."""
        self.logger.info(f"Initializing connection pool: {self.config.name}")
        
        try:
            # Create minimum connections
            for i in range(self.config.min_size):
                conn_info = await self._create_connection()
                await self._available_connections.put(conn_info)
                
            self.state = ConnectionState.HEALTHY
            
            # Start health monitoring
            self._health_check_task = asyncio.create_task(self._health_monitor())
            
            self.logger.info(f"Pool initialized with {self.config.min_size} connections")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize pool: {e}")
            self.state = ConnectionState.FAILED
            raise
    
    @asynccontextmanager
    async def get_connection(self):
        """Get connection from pool with automatic return."""
        conn_info = None
        try:
            conn_info = await self._acquire_connection()
            yield conn_info.connection_object
        finally:
            if conn_info:
                await self._release_connection(conn_info)
    
    async def _acquire_connection(self) -> ConnectionInfo:
        """Acquire connection from pool."""
        start_time = time.time()
        
        try:
            # Try to get available connection
            try:
                conn_info = await asyncio.wait_for(
                    self._available_connections.get(),
                    timeout=self.config.connection_timeout
                )
                
                # Validate connection health
                if await self._validate_connection(conn_info):
                    conn_info.last_used = time.time()
                    self._active_connections[conn_info.connection_id] = conn_info
                    return conn_info
                else:
                    # Connection is unhealthy, create new one
                    await self._dispose_connection(conn_info)
                    
            except asyncio.TimeoutError:
                pass
            
            # No available connections, try to create new one
            if len(self._connections) < self.config.max_size:
                async with self._lock:
                    if len(self._connections) < self.config.max_size:
                        conn_info = await self._create_connection()
                        conn_info.last_used = time.time()
                        self._active_connections[conn_info.connection_id] = conn_info
                        return conn_info
            
            # Pool is at maximum, wait for connection
            conn_info = await asyncio.wait_for(
                self._available_connections.get(),
                timeout=self.config.connection_timeout
            )
            
            conn_info.last_used = time.time()
            self._active_connections[conn_info.connection_id] = conn_info
            return conn_info
            
        except Exception as e:
            self.logger.error(f"Failed to acquire connection: {e}")
            raise
        finally:
            acquisition_time = time.time() - start_time
            self.logger.debug(f"Connection acquisition took {acquisition_time:.3f}s")
    
    async def _release_connection(self, conn_info: ConnectionInfo) -> None:
        """Release connection back to pool."""
        try:
            # Remove from active connections
            self._active_connections.pop(conn_info.connection_id, None)
            
            # Check if connection is still healthy
            if await self._validate_connection(conn_info):
                await self._available_connections.put(conn_info)
            else:
                await self._dispose_connection(conn_info)
                
        except Exception as e:
            self.logger.error(f"Failed to release connection: {e}")
            await self._dispose_connection(conn_info)
    
    async def _create_connection(self) -> ConnectionInfo:
        """Create new database connection."""
        connection_id = f"{self.config.name}_{len(self._connections)}"
        
        try:
            if self.config.database_type == "mssql":
                conn = await self._create_mssql_connection()
            elif self.config.database_type == "mysql":
                conn = await self._create_mysql_connection()
            elif self.config.database_type == "postgresql":
                conn = await self._create_postgresql_connection()
            elif self.config.database_type == "mongodb":
                conn = await self._create_mongodb_connection()
            else:
                raise ValueError(f"Unsupported database type: {self.config.database_type}")
            
            conn_info = ConnectionInfo(
                connection_id=connection_id,
                pool_name=self.config.name,
                created_at=time.time(),
                last_used=time.time(),
                connection_object=conn
            )
            
            self._connections.append(conn_info)
            self.total_connections_created += 1
            
            self.logger.debug(f"Created connection: {connection_id}")
            return conn_info
            
        except Exception as e:
            self.logger.error(f"Failed to create connection: {e}")
            raise
    
    async def _create_mssql_connection(self):
        """Create MSSQL connection using aioodbc."""
        return await aioodbc.connect(
            dsn=self.config.connection_string,
            timeout=self.config.connection_timeout
        )
    
    async def _create_mysql_connection(self):
        """Create MySQL connection using aiomysql."""
        # Parse connection string
        parsed = urlparse(self.config.connection_string)
        
        return await aiomysql.connect(
            host=parsed.hostname,
            port=parsed.port or 3306,
            user=parsed.username,
            password=parsed.password,
            db=parsed.path.lstrip('/') if parsed.path else None,
            connect_timeout=self.config.connection_timeout
        )
    
    async def _create_postgresql_connection(self):
        """Create PostgreSQL connection using aiopg."""
        return await aiopg.connect(
            dsn=self.config.connection_string,
            timeout=self.config.connection_timeout
        )
    
    async def _create_mongodb_connection(self):
        """Create MongoDB connection using motor."""
        client = motor.motor_asyncio.AsyncIOMotorClient(
            self.config.connection_string,
            serverSelectionTimeoutMS=self.config.connection_timeout * 1000
        )
        
        # Test connection
        await client.admin.command('ping')
        return client
    
    async def _validate_connection(self, conn_info: ConnectionInfo) -> bool:
        """Validate connection health."""
        try:
            if self.config.database_type == "mongodb":
                await conn_info.connection_object.admin.command('ping')
            else:
                # SQL databases - execute simple query
                if hasattr(conn_info.connection_object, 'cursor'):
                    async with conn_info.connection_object.cursor() as cursor:
                        await cursor.execute("SELECT 1")
                else:
                    # ODBC connection
                    cursor = await conn_info.connection_object.cursor()
                    await cursor.execute("SELECT 1")
                    await cursor.close()
            
            conn_info.is_healthy = True
            return True
            
        except Exception as e:
            self.logger.warning(f"Connection validation failed: {e}")
            conn_info.is_healthy = False
            return False
    
    async def _dispose_connection(self, conn_info: ConnectionInfo) -> None:
        """Dispose of unhealthy connection."""
        try:
            if conn_info.connection_object:
                if hasattr(conn_info.connection_object, 'close'):
                    if asyncio.iscoroutinefunction(conn_info.connection_object.close):
                        await conn_info.connection_object.close()
                    else:
                        conn_info.connection_object.close()
            
            # Remove from connections list
            if conn_info in self._connections:
                self._connections.remove(conn_info)
                
            self.logger.debug(f"Disposed connection: {conn_info.connection_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to dispose connection: {e}")
    
    async def _health_monitor(self) -> None:
        """Background health monitoring task."""
        while True:
            try:
                await asyncio.sleep(self.config.health_check_interval)
                await self._perform_health_check()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Health check failed: {e}")
    
    async def _perform_health_check(self) -> None:
        """Perform comprehensive health check."""
        self.logger.debug("Performing health check")
        
        healthy_connections = 0
        unhealthy_connections = []
        
        # Check all connections
        for conn_info in self._connections:
            if await self._validate_connection(conn_info):
                healthy_connections += 1
            else:
                unhealthy_connections.append(conn_info)
        
        # Dispose of unhealthy connections
        for conn_info in unhealthy_connections:
            await self._dispose_connection(conn_info)
        
        # Update pool state
        if healthy_connections == 0:
            self.state = ConnectionState.FAILED
            self.consecutive_failures += 1
        elif healthy_connections < self.config.min_size:
            self.state = ConnectionState.DEGRADED
            # Try to create new connections
            await self._ensure_minimum_connections()
        else:
            self.state = ConnectionState.HEALTHY
            self.consecutive_failures = 0
        
        self.last_health_check = time.time()
        
        self.logger.debug(f"Health check complete. State: {self.state}, "
                         f"Healthy: {healthy_connections}, "
                         f"Total: {len(self._connections)}")
    
    async def _ensure_minimum_connections(self) -> None:
        """Ensure minimum number of connections."""
        while len(self._connections) < self.config.min_size:
            try:
                conn_info = await self._create_connection()
                await self._available_connections.put(conn_info)
            except Exception as e:
                self.logger.error(f"Failed to create minimum connection: {e}")
                break
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get pool statistics."""
        return {
            'pool_name': self.config.name,
            'state': self.state.value,
            'total_connections': len(self._connections),
            'active_connections': len(self._active_connections),
            'available_connections': self._available_connections.qsize(),
            'total_created': self.total_connections_created,
            'total_queries': self.total_queries_executed,
            'consecutive_failures': self.consecutive_failures,
            'last_health_check': self.last_health_check,
            'avg_response_time': self.avg_response_time
        }
    
    async def shutdown(self) -> None:
        """Shutdown connection pool."""
        self.logger.info(f"Shutting down pool: {self.config.name}")
        
        # Cancel health check task
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        
        # Close all connections
        all_connections = self._connections.copy()
        for conn_info in all_connections:
            await self._dispose_connection(conn_info)
        
        self._connections.clear()
        self._active_connections.clear()


class ConnectionPoolManager:
    """
    Manages multiple connection pools with failover and load balancing.
    
    Features:
    - Multi-database pool management
    - Automatic failover
    - Load balancing strategies
    - Health monitoring
    - Connection routing
    """
    
    def __init__(self, pool_configs: List[ConnectionPoolConfig]):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.pools: Dict[str, ConnectionPool] = {}
        self.pool_configs = pool_configs
        
        # Load balancing state
        self.round_robin_counters: Dict[str, int] = {}
        
        # Failover mapping
        self.failover_mapping: Dict[str, List[str]] = {}
        
    async def initialize(self) -> None:
        """Initialize all connection pools."""
        self.logger.info("Initializing Connection Pool Manager")
        
        # Create pools
        for config in self.pool_configs:
            pool = ConnectionPool(config)
            self.pools[config.name] = pool
            self.failover_mapping[config.name] = config.failover_pools
        
        # Initialize pools in parallel
        initialization_tasks = []
        for pool in self.pools.values():
            initialization_tasks.append(pool.initialize())
        
        # Wait for all pools to initialize
        results = await asyncio.gather(*initialization_tasks, return_exceptions=True)
        
        # Check for initialization failures
        failed_pools = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                pool_name = self.pool_configs[i].name
                failed_pools.append(pool_name)
                self.logger.error(f"Failed to initialize pool {pool_name}: {result}")
        
        if failed_pools:
            self.logger.warning(f"Failed to initialize pools: {failed_pools}")
        
        self.logger.info("Connection Pool Manager initialized")
    
    @asynccontextmanager
    async def get_connection(
        self, 
        database_name: str, 
        database_type: str,
        load_balance_strategy: LoadBalanceStrategy = LoadBalanceStrategy.ROUND_ROBIN
    ):
        """Get connection with automatic failover and load balancing."""
        
        # Find suitable pools
        suitable_pools = self._find_suitable_pools(database_name, database_type)
        
        if not suitable_pools:
            raise ValueError(f"No suitable pools found for {database_name} ({database_type})")
        
        # Apply load balancing
        pool_name = self._select_pool(suitable_pools, load_balance_strategy)
        
        # Try primary pool
        pool = self.pools[pool_name]
        
        try:
            async with pool.get_connection() as conn:
                yield conn
                return
                
        except Exception as e:
            self.logger.warning(f"Primary pool {pool_name} failed: {e}")
            
            # Try failover pools
            for failover_pool_name in self.failover_mapping.get(pool_name, []):
                if failover_pool_name in self.pools:
                    failover_pool = self.pools[failover_pool_name]
                    try:
                        async with failover_pool.get_connection() as conn:
                            self.logger.info(f"Using failover pool: {failover_pool_name}")
                            yield conn
                            return
                    except Exception as failover_error:
                        self.logger.warning(f"Failover pool {failover_pool_name} failed: {failover_error}")
            
            # All pools failed
            raise Exception(f"All pools failed for {database_name}")
    
    def _find_suitable_pools(self, database_name: str, database_type: str) -> List[str]:
        """Find pools suitable for database and type."""
        suitable_pools = []
        
        for pool_name, pool in self.pools.items():
            config = pool.config
            
            # Check database type match
            if config.database_type != database_type:
                continue
                
            # Check if pool is healthy
            if pool.state == ConnectionState.FAILED:
                continue
            
            # Check if pool serves this database
            # This would depend on your naming/routing strategy
            suitable_pools.append(pool_name)
        
        return suitable_pools
    
    def _select_pool(
        self, 
        suitable_pools: List[str], 
        strategy: LoadBalanceStrategy
    ) -> str:
        """Select pool based on load balancing strategy."""
        
        if len(suitable_pools) == 1:
            return suitable_pools[0]
        
        if strategy == LoadBalanceStrategy.ROUND_ROBIN:
            return self._round_robin_selection(suitable_pools)
        elif strategy == LoadBalanceStrategy.LEAST_CONNECTIONS:
            return self._least_connections_selection(suitable_pools)
        elif strategy == LoadBalanceStrategy.RANDOM:
            import random
            return random.choice(suitable_pools)
        elif strategy == LoadBalanceStrategy.WEIGHTED:
            return self._weighted_selection(suitable_pools)
        else:
            return suitable_pools[0]
    
    def _round_robin_selection(self, pools: List[str]) -> str:
        """Round-robin pool selection."""
        pool_group = ','.join(sorted(pools))
        
        if pool_group not in self.round_robin_counters:
            self.round_robin_counters[pool_group] = 0
        
        index = self.round_robin_counters[pool_group] % len(pools)
        self.round_robin_counters[pool_group] += 1
        
        return pools[index]
    
    def _least_connections_selection(self, pools: List[str]) -> str:
        """Select pool with least active connections."""
        min_connections = float('inf')
        selected_pool = pools[0]
        
        for pool_name in pools:
            pool = self.pools[pool_name]
            active_connections = len(pool._active_connections)
            
            if active_connections < min_connections:
                min_connections = active_connections
                selected_pool = pool_name
        
        return selected_pool
    
    def _weighted_selection(self, pools: List[str]) -> str:
        """Weighted random selection based on pool weights."""
        import random
        
        weights = [self.pools[pool_name].config.weight for pool_name in pools]
        return random.choices(pools, weights=weights)[0]
    
    async def get_all_statistics(self) -> Dict[str, Any]:
        """Get statistics for all pools."""
        statistics = {}
        
        for pool_name, pool in self.pools.items():
            statistics[pool_name] = await pool.get_statistics()
        
        return statistics
    
    async def health_check(self) -> Dict[str, str]:
        """Get health status of all pools."""
        health_status = {}
        
        for pool_name, pool in self.pools.items():
            health_status[pool_name] = pool.state.value
        
        return health_status
    
    async def shutdown(self) -> None:
        """Shutdown all connection pools."""
        self.logger.info("Shutting down Connection Pool Manager")
        
        shutdown_tasks = []
        for pool in self.pools.values():
            shutdown_tasks.append(pool.shutdown())
        
        await asyncio.gather(*shutdown_tasks, return_exceptions=True)
        
        self.pools.clear()
        self.logger.info("Connection Pool Manager shutdown complete")