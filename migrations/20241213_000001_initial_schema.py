"""
Migration: Initial Schema
Description: Create initial database tables for BLNCS
Type: schema
Created: 2024-12-13T00:00:01.000000
"""

from blncs.core.database_migration import Migration as BaseMigration, MigrationType


class Migration(BaseMigration):
    """Migration: Initial Schema"""
    
    def __init__(self):
        super().__init__(
            migration_id="20241213_000001_initial_schema",
            version="20241213_000001",
            name="Initial Schema",
            description="Create initial database tables for BLNCS"
        )
        self.migration_type = MigrationType.SCHEMA
    
    def up(self, db_connection):
        """Apply the migration"""
        cursor = db_connection.cursor()
        
        # Lightning Network nodes table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS lightning_nodes (
                node_id TEXT PRIMARY KEY,
                alias TEXT,
                public_key TEXT,
                addresses TEXT,
                color TEXT,
                features TEXT,
                last_update TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Lightning Network channels table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS lightning_channels (
                channel_id TEXT PRIMARY KEY,
                node1_id TEXT NOT NULL,
                node2_id TEXT NOT NULL,
                capacity INTEGER NOT NULL,
                local_balance INTEGER,
                remote_balance INTEGER,
                fee_rate REAL,
                base_fee INTEGER,
                time_lock_delta INTEGER,
                min_htlc INTEGER,
                max_htlc INTEGER,
                is_active BOOLEAN DEFAULT 1,
                last_update TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (node1_id) REFERENCES lightning_nodes (node_id),
                FOREIGN KEY (node2_id) REFERENCES lightning_nodes (node_id)
            );
        """)
        
        # Payment routing history
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payment_routes (
                route_id TEXT PRIMARY KEY,
                source_node TEXT NOT NULL,
                destination_node TEXT NOT NULL,
                amount_msat INTEGER NOT NULL,
                total_fee INTEGER,
                route_path TEXT,
                success_probability REAL,
                execution_time_ms INTEGER,
                success BOOLEAN,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Channel rebalancing operations
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rebalance_operations (
                operation_id TEXT PRIMARY KEY,
                source_channel_id TEXT NOT NULL,
                target_channel_id TEXT NOT NULL,
                amount INTEGER NOT NULL,
                strategy TEXT,
                success BOOLEAN,
                execution_time_ms INTEGER,
                fees_paid INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (source_channel_id) REFERENCES lightning_channels (channel_id),
                FOREIGN KEY (target_channel_id) REFERENCES lightning_channels (channel_id)
            );
        """)
        
        
        # System metrics history
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_metrics (
                metric_id TEXT PRIMARY KEY,
                metric_type TEXT NOT NULL,
                metric_name TEXT NOT NULL,
                value REAL NOT NULL,
                unit TEXT,
                tags TEXT,
                timestamp TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # System alerts
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_alerts (
                alert_id TEXT PRIMARY KEY,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                source TEXT,
                threshold_value REAL,
                actual_value REAL,
                acknowledged BOOLEAN DEFAULT 0,
                resolved BOOLEAN DEFAULT 0,
                timestamp TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Configuration settings
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS configuration (
                config_key TEXT PRIMARY KEY,
                config_value TEXT NOT NULL,
                config_type TEXT DEFAULT 'string',
                description TEXT,
                category TEXT,
                is_sensitive BOOLEAN DEFAULT 0,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Backup metadata
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS backup_metadata (
                backup_id TEXT PRIMARY KEY,
                backup_type TEXT NOT NULL,
                file_path TEXT NOT NULL,
                size_bytes INTEGER,
                file_count INTEGER,
                checksum TEXT,
                compression BOOLEAN DEFAULT 0,
                encryption BOOLEAN DEFAULT 0,
                description TEXT,
                status TEXT DEFAULT 'completed',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        db_connection.commit()
    
    def down(self, db_connection):
        """Rollback the migration"""
        cursor = db_connection.cursor()
        
        # Drop tables in reverse dependency order
        tables = [
            'backup_metadata',
            'configuration',
            'system_alerts',
            'system_metrics',
            'rebalance_operations',
            'payment_routes',
            'lightning_channels',
            'lightning_nodes'
        ]
        
        for table in tables:
            cursor.execute(f"DROP TABLE IF EXISTS {table};")
        
        db_connection.commit()
    
    def validate(self, db_connection) -> bool:
        """Validate migration can be applied"""
        cursor = db_connection.cursor()
        
        # Check if tables don't already exist
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='lightning_nodes'
        """)
        
        # If table exists, migration might already be applied
        if cursor.fetchone():
            return False
        
        return True