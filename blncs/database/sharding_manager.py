"""
Database Sharding and Read Replica Manager
Enterprise-grade database architecture with horizontal scaling and high availability.
"""

import asyncio
import asyncpg
import json
import logging
import hashlib
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple, Callable
from enum import Enum
from dataclasses import dataclass, field, asdict
from collections import defaultdict
import random
import uuid
from contextlib import asynccontextmanager
import structlog

logger = structlog.get_logger(__name__)

class ShardingStrategy(Enum):
    HASH = "hash"
    RANGE = "range"
    DIRECTORY = "directory"
    CONSISTENT_HASH = "consistent_hash"
    GEOGRAPHIC = "geographic"

class ConsistencyLevel(Enum):
    EVENTUAL = "eventual"
    STRONG = "strong"
    BOUNDED_STALENESS = "bounded_staleness"

class ReplicationMode(Enum):
    SYNCHRONOUS = "synchronous"
    ASYNCHRONOUS = "asynchronous"
    SEMI_SYNCHRONOUS = "semi_synchronous"

class ShardState(Enum):
    ACTIVE = "active"
    MIGRATING = "migrating"
    READONLY = "readonly"
    OFFLINE = "offline"

@dataclass
class ShardConfig:
    shard_id: str
    host: str
    port: int
    database: str
    username: str
    password: str
    min_connections: int = 10
    max_connections: int = 100
    state: ShardState = ShardState.ACTIVE
    weight: int = 100
    tags: Dict[str, str] = field(default_factory=dict)
    range_start: Optional[Any] = None
    range_end: Optional[Any] = None
    read_replicas: List['ReplicaConfig'] = field(default_factory=list)

@dataclass
class ReplicaConfig:
    replica_id: str
    host: str
    port: int
    database: str
    username: str
    password: str
    lag_threshold_ms: int = 1000
    priority: int = 100
    replication_mode: ReplicationMode = ReplicationMode.ASYNCHRONOUS

@dataclass
class ShardKey:
    table: str
    column: str
    value: Any
    strategy: ShardingStrategy = ShardingStrategy.HASH

class ConnectionPool:
    def __init__(self, config: ShardConfig):
        self.config = config
        self.pool = None
        self.replica_pools = {}
        self.stats = {
            'total_connections': 0,
            'active_connections': 0,
            'queries_executed': 0,
            'errors': 0,
            'avg_query_time': 0
        }
        self.last_health_check = datetime.utcnow()
        self.healthy = True
    
    async def initialize(self):
        """Initialize connection pool"""
        try:
            dsn = f"postgresql://{self.config.username}:{self.config.password}@{self.config.host}:{self.config.port}/{self.config.database}"
            
            self.pool = await asyncpg.create_pool(
                dsn,
                min_size=self.config.min_connections,
                max_size=self.config.max_connections,
                command_timeout=30
            )
            
            # Initialize replica pools
            for replica in self.config.read_replicas:
                await self._initialize_replica_pool(replica)
            
            logger.info(f"Connection pool initialized for shard {self.config.shard_id}")
            self.healthy = True
            
        except Exception as e:
            logger.error(f"Failed to initialize connection pool for shard {self.config.shard_id}: {e}")
            self.healthy = False
            raise
    
    async def _initialize_replica_pool(self, replica: ReplicaConfig):
        """Initialize read replica connection pool"""
        try:
            dsn = f"postgresql://{replica.username}:{replica.password}@{replica.host}:{replica.port}/{replica.database}"
            
            pool = await asyncpg.create_pool(
                dsn,
                min_size=5,
                max_size=50,
                command_timeout=30
            )
            
            self.replica_pools[replica.replica_id] = pool
            logger.info(f"Replica pool initialized: {replica.replica_id}")
            
        except Exception as e:
            logger.error(f"Failed to initialize replica pool {replica.replica_id}: {e}")
    
    @asynccontextmanager
    async def acquire_connection(self, read_only: bool = False):
        """Acquire database connection"""
        pool = self._select_pool(read_only)
        
        if not pool:
            raise Exception("No available connection pool")
        
        async with pool.acquire() as connection:
            self.stats['active_connections'] += 1
            try:
                yield connection
            finally:
                self.stats['active_connections'] -= 1
    
    def _select_pool(self, read_only: bool = False):
        """Select appropriate connection pool"""
        if read_only and self.replica_pools:
            # Select best replica based on lag and priority
            best_replica_id = self._select_best_replica()
            if best_replica_id:
                return self.replica_pools[best_replica_id]
        
        return self.pool
    
    def _select_best_replica(self) -> Optional[str]:
        """Select best read replica"""
        available_replicas = []
        
        for replica in self.config.read_replicas:
            if replica.replica_id in self.replica_pools:
                available_replicas.append(replica)
        
        if not available_replicas:
            return None
        
        # Simple priority-based selection
        return max(available_replicas, key=lambda r: r.priority).replica_id
    
    async def execute_query(self, query: str, params: Tuple = (), read_only: bool = False) -> Any:
        """Execute database query"""
        start_time = time.time()
        
        try:
            async with self.acquire_connection(read_only) as connection:
                if query.strip().upper().startswith('SELECT'):
                    result = await connection.fetch(query, *params)
                else:
                    result = await connection.execute(query, *params)
                
                self.stats['queries_executed'] += 1
                query_time = (time.time() - start_time) * 1000
                self._update_avg_query_time(query_time)
                
                return result
                
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"Query execution failed on shard {self.config.shard_id}: {e}")
            raise
    
    def _update_avg_query_time(self, query_time: float):
        """Update average query time"""
        current_avg = self.stats['avg_query_time']
        total_queries = self.stats['queries_executed']
        
        if total_queries == 1:
            self.stats['avg_query_time'] = query_time
        else:
            # Weighted average
            self.stats['avg_query_time'] = (current_avg * (total_queries - 1) + query_time) / total_queries
    
    async def health_check(self) -> bool:
        """Check connection pool health"""
        try:
            async with self.acquire_connection() as connection:
                await connection.fetchval("SELECT 1")
            
            self.healthy = True
            self.last_health_check = datetime.utcnow()
            return True
            
        except Exception as e:
            logger.error(f"Health check failed for shard {self.config.shard_id}: {e}")
            self.healthy = False
            return False
    
    async def close(self):
        """Close connection pools"""
        if self.pool:
            await self.pool.close()
        
        for pool in self.replica_pools.values():
            await pool.close()

class QueryRouter:
    def __init__(self, sharding_strategy: ShardingStrategy):
        self.sharding_strategy = sharding_strategy
        self.shard_map = {}
        self.hash_ring = {}
        self.directory_map = {}
    
    def route_query(self, shard_key: ShardKey, shards: List[ShardConfig]) -> List[str]:
        """Route query to appropriate shards"""
        if self.sharding_strategy == ShardingStrategy.HASH:
            return [self._hash_route(shard_key, shards)]
        elif self.sharding_strategy == ShardingStrategy.RANGE:
            return self._range_route(shard_key, shards)
        elif self.sharding_strategy == ShardingStrategy.CONSISTENT_HASH:
            return [self._consistent_hash_route(shard_key, shards)]
        elif self.sharding_strategy == ShardingStrategy.DIRECTORY:
            return self._directory_route(shard_key, shards)
        else:
            return [shards[0].shard_id] if shards else []
    
    def _hash_route(self, shard_key: ShardKey, shards: List[ShardConfig]) -> str:
        """Hash-based routing"""
        if not shards:
            raise ValueError("No shards available")
        
        hash_value = hashlib.md5(str(shard_key.value).encode()).hexdigest()
        shard_index = int(hash_value, 16) % len(shards)
        return shards[shard_index].shard_id
    
    def _range_route(self, shard_key: ShardKey, shards: List[ShardConfig]) -> List[str]:
        """Range-based routing"""
        matching_shards = []
        
        for shard in shards:
            if (shard.range_start is None or shard_key.value >= shard.range_start) and \
               (shard.range_end is None or shard_key.value < shard.range_end):
                matching_shards.append(shard.shard_id)
        
        return matching_shards if matching_shards else [shards[0].shard_id]
    
    def _consistent_hash_route(self, shard_key: ShardKey, shards: List[ShardConfig]) -> str:
        """Consistent hash-based routing"""
        if not shards:
            raise ValueError("No shards available")
        
        # Build hash ring if not exists
        ring_key = id(shards)
        if ring_key not in self.hash_ring:
            self._build_hash_ring(shards, ring_key)
        
        # Find shard in ring
        key_hash = int(hashlib.md5(str(shard_key.value).encode()).hexdigest(), 16)
        return self._find_shard_in_ring(key_hash, ring_key)
    
    def _build_hash_ring(self, shards: List[ShardConfig], ring_key):
        """Build consistent hash ring"""
        ring = {}
        
        for shard in shards:
            for i in range(shard.weight):
                node_hash = hashlib.md5(f"{shard.shard_id}:{i}".encode()).hexdigest()
                ring[int(node_hash, 16)] = shard.shard_id
        
        self.hash_ring[ring_key] = dict(sorted(ring.items()))
    
    def _find_shard_in_ring(self, key_hash: int, ring_key) -> str:
        """Find shard in consistent hash ring"""
        ring = self.hash_ring[ring_key]
        
        for node_hash in sorted(ring.keys()):
            if key_hash <= node_hash:
                return ring[node_hash]
        
        # Wrap around to first node
        return ring[min(ring.keys())]
    
    def _directory_route(self, shard_key: ShardKey, shards: List[ShardConfig]) -> List[str]:
        """Directory-based routing"""
        # This would typically lookup from a directory service
        # For now, use simple mapping
        directory_key = f"{shard_key.table}:{shard_key.value}"
        
        if directory_key in self.directory_map:
            return [self.directory_map[directory_key]]
        
        # Default to first shard
        return [shards[0].shard_id] if shards else []

class DistributedTransaction:
    def __init__(self, transaction_id: str, sharding_manager: 'ShardingManager'):
        self.transaction_id = transaction_id
        self.sharding_manager = sharding_manager
        self.participants = set()
        self.state = "ACTIVE"
        self.operations = []
        self.start_time = datetime.utcnow()
    
    async def execute_query(self, query: str, shard_key: ShardKey, params: Tuple = ()):
        """Execute query within distributed transaction"""
        if self.state != "ACTIVE":
            raise Exception(f"Transaction {self.transaction_id} is not active")
        
        # Route query to appropriate shard
        shard_ids = self.sharding_manager.query_router.route_query(
            shard_key, 
            self.sharding_manager.get_active_shards()
        )
        
        results = []
        
        for shard_id in shard_ids:
            if shard_id not in self.participants:
                await self._begin_transaction_on_shard(shard_id)
                self.participants.add(shard_id)
            
            # Execute query on shard
            pool = self.sharding_manager.connection_pools[shard_id]
            result = await pool.execute_query(query, params)
            results.append(result)
            
            # Track operation for potential rollback
            self.operations.append({
                'shard_id': shard_id,
                'query': query,
                'params': params,
                'timestamp': datetime.utcnow()
            })
        
        return results
    
    async def _begin_transaction_on_shard(self, shard_id: str):
        """Begin transaction on specific shard"""
        pool = self.sharding_manager.connection_pools[shard_id]
        await pool.execute_query("BEGIN")
    
    async def commit(self) -> bool:
        """Commit distributed transaction using 2PC"""
        if self.state != "ACTIVE":
            raise Exception(f"Transaction {self.transaction_id} is not active")
        
        try:
            # Phase 1: Prepare
            prepare_results = await self._prepare_phase()
            
            if all(prepare_results.values()):
                # Phase 2: Commit
                await self._commit_phase()
                self.state = "COMMITTED"
                logger.info(f"Distributed transaction {self.transaction_id} committed successfully")
                return True
            else:
                # Abort transaction
                await self._abort_phase()
                self.state = "ABORTED"
                logger.warning(f"Distributed transaction {self.transaction_id} aborted")
                return False
                
        except Exception as e:
            logger.error(f"Error during distributed transaction commit: {e}")
            await self._abort_phase()
            self.state = "ABORTED"
            return False
    
    async def _prepare_phase(self) -> Dict[str, bool]:
        """Phase 1 of 2PC - Prepare"""
        prepare_results = {}
        
        for shard_id in self.participants:
            try:
                pool = self.sharding_manager.connection_pools[shard_id]
                await pool.execute_query("PREPARE TRANSACTION $1", (self.transaction_id,))
                prepare_results[shard_id] = True
            except Exception as e:
                logger.error(f"Prepare failed for shard {shard_id}: {e}")
                prepare_results[shard_id] = False
        
        return prepare_results
    
    async def _commit_phase(self):
        """Phase 2 of 2PC - Commit"""
        for shard_id in self.participants:
            try:
                pool = self.sharding_manager.connection_pools[shard_id]
                await pool.execute_query("COMMIT PREPARED $1", (self.transaction_id,))
            except Exception as e:
                logger.error(f"Commit failed for shard {shard_id}: {e}")
                # In production, you would need recovery mechanisms here
    
    async def _abort_phase(self):
        """Abort transaction on all participants"""
        for shard_id in self.participants:
            try:
                pool = self.sharding_manager.connection_pools[shard_id]
                await pool.execute_query("ROLLBACK PREPARED $1", (self.transaction_id,))
            except Exception as e:
                logger.error(f"Rollback failed for shard {shard_id}: {e}")

class DataMigrationManager:
    def __init__(self, sharding_manager: 'ShardingManager'):
        self.sharding_manager = sharding_manager
        self.active_migrations = {}
        self.migration_history = []
    
    async def migrate_shard_data(self, source_shard_id: str, target_shard_id: str,
                                table: str, condition: str = "") -> str:
        """Migrate data between shards"""
        migration_id = str(uuid.uuid4())
        
        migration_task = {
            'migration_id': migration_id,
            'source_shard': source_shard_id,
            'target_shard': target_shard_id,
            'table': table,
            'condition': condition,
            'status': 'RUNNING',
            'start_time': datetime.utcnow(),
            'progress': 0.0
        }
        
        self.active_migrations[migration_id] = migration_task
        
        try:
            await self._execute_migration(migration_task)
            migration_task['status'] = 'COMPLETED'
            migration_task['end_time'] = datetime.utcnow()
            
        except Exception as e:
            migration_task['status'] = 'FAILED'
            migration_task['error'] = str(e)
            logger.error(f"Migration {migration_id} failed: {e}")
        
        finally:
            self.migration_history.append(migration_task)
            del self.active_migrations[migration_id]
        
        return migration_id
    
    async def _execute_migration(self, migration_task: Dict[str, Any]):
        """Execute data migration"""
        source_pool = self.sharding_manager.connection_pools[migration_task['source_shard']]
        target_pool = self.sharding_manager.connection_pools[migration_task['target_shard']]
        
        # Get total rows to migrate
        count_query = f"SELECT COUNT(*) FROM {migration_task['table']}"
        if migration_task['condition']:
            count_query += f" WHERE {migration_task['condition']}"
        
        total_rows = await source_pool.execute_query(count_query, read_only=True)
        total_count = total_rows[0]['count']
        
        # Migrate data in batches
        batch_size = 1000
        offset = 0
        migrated_rows = 0
        
        while offset < total_count:
            # Read batch from source
            select_query = f"SELECT * FROM {migration_task['table']}"
            if migration_task['condition']:
                select_query += f" WHERE {migration_task['condition']}"
            select_query += f" LIMIT {batch_size} OFFSET {offset}"
            
            rows = await source_pool.execute_query(select_query, read_only=True)
            
            if not rows:
                break
            
            # Insert batch into target
            if rows:
                await self._insert_batch(target_pool, migration_task['table'], rows)
                migrated_rows += len(rows)
                
                # Update progress
                migration_task['progress'] = migrated_rows / total_count
                
            offset += batch_size
            
            # Small delay to avoid overwhelming the database
            await asyncio.sleep(0.1)
    
    async def _insert_batch(self, target_pool: ConnectionPool, table: str, rows: List[Dict]):
        """Insert batch of rows into target shard"""
        if not rows:
            return
        
        # Build bulk insert query
        columns = list(rows[0].keys())
        placeholders = ', '.join([f"${i+1}" for i in range(len(columns))])
        query = f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})"
        
        # Execute bulk insert
        for row in rows:
            values = tuple(row[col] for col in columns)
            await target_pool.execute_query(query, values)

class ReadReplicaManager:
    def __init__(self):
        self.replica_health = {}
        self.replica_lag = {}
        self.health_check_task = None
    
    async def initialize(self):
        """Initialize read replica manager"""
        self.health_check_task = asyncio.create_task(self._health_check_loop())
    
    async def _health_check_loop(self):
        """Continuously check replica health and lag"""
        while True:
            try:
                # Check replica health and lag
                # Implementation would check actual replica status
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Replica health check error: {e}")
                await asyncio.sleep(5)
    
    async def get_best_replica(self, replicas: List[ReplicaConfig]) -> Optional[ReplicaConfig]:
        """Get best available replica for read operations"""
        available_replicas = [r for r in replicas if self.replica_health.get(r.replica_id, True)]
        
        if not available_replicas:
            return None
        
        # Select replica with lowest lag and highest priority
        def replica_score(replica):
            lag = self.replica_lag.get(replica.replica_id, 0)
            return replica.priority - lag  # Higher priority, lower lag = higher score
        
        return max(available_replicas, key=replica_score)

class ShardingManager:
    def __init__(self, sharding_strategy: ShardingStrategy = ShardingStrategy.HASH):
        self.sharding_strategy = sharding_strategy
        self.shards = {}
        self.connection_pools = {}
        self.query_router = QueryRouter(sharding_strategy)
        self.replica_manager = ReadReplicaManager()
        self.migration_manager = DataMigrationManager(self)
        self.active_transactions = {}
        self.health_check_task = None
    
    async def initialize(self):
        """Initialize sharding manager"""
        await self.replica_manager.initialize()
        self.health_check_task = asyncio.create_task(self._health_check_loop())
        logger.info("Sharding manager initialized")
    
    async def add_shard(self, shard_config: ShardConfig):
        """Add new shard to the cluster"""
        self.shards[shard_config.shard_id] = shard_config
        
        # Initialize connection pool
        pool = ConnectionPool(shard_config)
        await pool.initialize()
        self.connection_pools[shard_config.shard_id] = pool
        
        logger.info(f"Shard {shard_config.shard_id} added successfully")
    
    async def remove_shard(self, shard_id: str):
        """Remove shard from cluster"""
        if shard_id in self.connection_pools:
            await self.connection_pools[shard_id].close()
            del self.connection_pools[shard_id]
        
        if shard_id in self.shards:
            del self.shards[shard_id]
        
        logger.info(f"Shard {shard_id} removed")
    
    def get_active_shards(self) -> List[ShardConfig]:
        """Get list of active shards"""
        return [shard for shard in self.shards.values() if shard.state == ShardState.ACTIVE]
    
    async def execute_query(self, query: str, shard_key: ShardKey, 
                           params: Tuple = (), read_only: bool = False) -> Any:
        """Execute query on appropriate shard"""
        shard_ids = self.query_router.route_query(shard_key, self.get_active_shards())
        
        if not shard_ids:
            raise ValueError("No available shards for query")
        
        # For read-only queries, use any shard
        # For write queries, execute on all relevant shards
        if read_only:
            shard_id = shard_ids[0]
            pool = self.connection_pools[shard_id]
            return await pool.execute_query(query, params, read_only=True)
        else:
            results = []
            for shard_id in shard_ids:
                pool = self.connection_pools[shard_id]
                result = await pool.execute_query(query, params, read_only=False)
                results.append(result)
            return results
    
    async def begin_distributed_transaction(self) -> DistributedTransaction:
        """Begin new distributed transaction"""
        transaction_id = str(uuid.uuid4())
        transaction = DistributedTransaction(transaction_id, self)
        self.active_transactions[transaction_id] = transaction
        return transaction
    
    async def _health_check_loop(self):
        """Health check loop for all shards"""
        while True:
            try:
                for shard_id, pool in self.connection_pools.items():
                    healthy = await pool.health_check()
                    if not healthy:
                        logger.warning(f"Shard {shard_id} health check failed")
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Health check loop error: {e}")
                await asyncio.sleep(10)
    
    async def get_cluster_stats(self) -> Dict[str, Any]:
        """Get cluster statistics"""
        stats = {
            'total_shards': len(self.shards),
            'active_shards': len(self.get_active_shards()),
            'total_connections': 0,
            'active_connections': 0,
            'total_queries': 0,
            'total_errors': 0,
            'shard_stats': {}
        }
        
        for shard_id, pool in self.connection_pools.items():
            shard_stats = pool.stats.copy()
            stats['shard_stats'][shard_id] = shard_stats
            stats['total_connections'] += shard_stats['total_connections']
            stats['active_connections'] += shard_stats['active_connections']
            stats['total_queries'] += shard_stats['queries_executed']
            stats['total_errors'] += shard_stats['errors']
        
        return stats
    
    async def shutdown(self):
        """Shutdown sharding manager"""
        if self.health_check_task:
            self.health_check_task.cancel()
        
        for pool in self.connection_pools.values():
            await pool.close()
        
        logger.info("Sharding manager shutdown completed")

# Global sharding manager instance
_sharding_manager_instance = None

async def get_sharding_manager(strategy: ShardingStrategy = ShardingStrategy.HASH) -> ShardingManager:
    """Get or create sharding manager"""
    global _sharding_manager_instance
    
    if _sharding_manager_instance is None:
        _sharding_manager_instance = ShardingManager(strategy)
        await _sharding_manager_instance.initialize()
    
    return _sharding_manager_instance

async def initialize_database_cluster(shards: List[ShardConfig], 
                                    strategy: ShardingStrategy = ShardingStrategy.HASH) -> ShardingManager:
    """Initialize database cluster with shards"""
    manager = ShardingManager(strategy)
    await manager.initialize()
    
    for shard_config in shards:
        await manager.add_shard(shard_config)
    
    return manager