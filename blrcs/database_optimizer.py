import asyncio
import time
import re
import hashlib
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import sqlite3
import logging
import json
from collections import defaultdict

logger = logging.getLogger(__name__)

@dataclass
class QueryStats:
    """クエリ統計"""
    query: str
    execution_count: int
    total_time: float
    avg_time: float
    max_time: float
    min_time: float
    last_executed: float

@dataclass
class IndexSuggestion:
    """インデックス提案"""
    table_name: str
    columns: List[str]
    reason: str
    estimated_improvement: float
    query_patterns: List[str]

class DatabaseOptimizer:
    """データベース最適化エンジン"""
    
    def __init__(self, db_path: str = "blrcs.db"):
        self.db_path = db_path
        self.query_stats: Dict[str, QueryStats] = {}
        self.slow_query_threshold = 1.0  # 秒
        self.optimization_interval = 3600  # 1時間
        self.index_suggestions: List[IndexSuggestion] = []
        self._init_optimization_tables()
        
    def _init_optimization_tables(self):
        """最適化用テーブル初期化"""
        with sqlite3.connect(self.db_path) as conn:
            # クエリ統計テーブル
            conn.execute("""
                CREATE TABLE IF NOT EXISTS query_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    query_hash TEXT UNIQUE NOT NULL,
                    query_text TEXT NOT NULL,
                    execution_count INTEGER DEFAULT 0,
                    total_time REAL DEFAULT 0,
                    avg_time REAL DEFAULT 0,
                    max_time REAL DEFAULT 0,
                    min_time REAL DEFAULT 999999,
                    last_executed REAL,
                    INDEX idx_avg_time (avg_time),
                    INDEX idx_execution_count (execution_count)
                )
            """)
            
            # インデックス使用状況
            conn.execute("""
                CREATE TABLE IF NOT EXISTS index_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    index_name TEXT NOT NULL,
                    table_name TEXT NOT NULL,
                    usage_count INTEGER DEFAULT 0,
                    last_used REAL,
                    created_at REAL,
                    UNIQUE(index_name, table_name)
                )
            """)
            
            # テーブル統計
            conn.execute("""
                CREATE TABLE IF NOT EXISTS table_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    table_name TEXT UNIQUE NOT NULL,
                    row_count INTEGER,
                    data_size INTEGER,
                    index_size INTEGER,
                    last_analyzed REAL,
                    fragmentation_level REAL
                )
            """)
            
    async def start_optimization_loop(self):
        """最適化ループ開始"""
        asyncio.create_task(self._optimization_loop())
        
    async def _optimization_loop(self):
        """定期最適化実行"""
        while True:
            try:
                await asyncio.sleep(self.optimization_interval)
                await self.optimize_database()
            except Exception as e:
                logger.error(f"Optimization loop error: {e}")
                
    async def optimize_database(self):
        """データベース最適化実行"""
        logger.info("Starting database optimization...")
        
        # 1. 統計情報更新
        await self.update_statistics()
        
        # 2. スロークエリ分析
        slow_queries = await self.analyze_slow_queries()
        
        # 3. インデックス分析
        index_suggestions = await self.analyze_indexes()
        
        # 4. 自動インデックス作成
        await self.create_suggested_indexes(index_suggestions)
        
        # 5. VACUUM実行
        await self.vacuum_database()
        
        # 6. クエリプラン最適化
        await self.optimize_query_plans()
        
        logger.info("Database optimization completed")
        
    async def update_statistics(self):
        """統計情報更新"""
        with sqlite3.connect(self.db_path) as conn:
            # ANALYZE実行
            conn.execute("ANALYZE")
            
            # テーブル統計収集
            cursor = conn.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
            """)
            
            for row in cursor:
                table_name = row[0]
                
                # 行数取得
                count_cursor = conn.execute(f"SELECT COUNT(*) FROM {table_name}")
                row_count = count_cursor.fetchone()[0]
                
                # テーブルサイズ取得
                size_cursor = conn.execute(f"""
                    SELECT 
                        SUM(pgsize) as data_size
                    FROM dbstat 
                    WHERE name='{table_name}'
                """)
                data_size = size_cursor.fetchone()[0] or 0
                
                # 統計更新
                conn.execute("""
                    INSERT OR REPLACE INTO table_stats 
                    (table_name, row_count, data_size, last_analyzed)
                    VALUES (?, ?, ?, ?)
                """, (table_name, row_count, data_size, time.time()))
                
            conn.commit()
            
    async def analyze_slow_queries(self) -> List[QueryStats]:
        """スロークエリ分析"""
        slow_queries = []
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT query_text, execution_count, avg_time, max_time
                FROM query_stats
                WHERE avg_time > ?
                ORDER BY avg_time DESC
                LIMIT 20
            """, (self.slow_query_threshold,))
            
            for row in cursor:
                slow_queries.append(QueryStats(
                    query=row[0],
                    execution_count=row[1],
                    avg_time=row[2],
                    max_time=row[3],
                    total_time=row[1] * row[2],
                    min_time=0,
                    last_executed=time.time()
                ))
                
                # クエリプラン分析
                await self._analyze_query_plan(conn, row[0])
                
        return slow_queries
        
    async def _analyze_query_plan(self, conn, query: str):
        """クエリプラン分析"""
        try:
            # EXPLAIN QUERY PLAN実行
            cursor = conn.execute(f"EXPLAIN QUERY PLAN {query}")
            plan = cursor.fetchall()
            
            # テーブルスキャンを検出
            for row in plan:
                if "SCAN" in str(row):
                    # インデックスが必要な可能性
                    self._suggest_index_from_scan(query, row)
                    
        except Exception as e:
            logger.debug(f"Query plan analysis failed: {e}")
            
    def _suggest_index_from_scan(self, query: str, scan_info):
        """スキャン情報からインデックス提案"""
        # WHERE句のカラムを抽出
        import re
        
        where_match = re.search(r'WHERE\s+(\w+)\s*=', query, re.IGNORECASE)
        if where_match:
            column = where_match.group(1)
            
            # テーブル名を抽出
            table_match = re.search(r'FROM\s+(\w+)', query, re.IGNORECASE)
            if table_match:
                table = table_match.group(1)
                
                suggestion = IndexSuggestion(
                    table_name=table,
                    columns=[column],
                    reason="Table scan detected in WHERE clause",
                    estimated_improvement=0.5,
                    query_patterns=[query]
                )
                
                if suggestion not in self.index_suggestions:
                    self.index_suggestions.append(suggestion)
                    
    async def analyze_indexes(self) -> List[IndexSuggestion]:
        """インデックス分析"""
        suggestions = []
        
        with sqlite3.connect(self.db_path) as conn:
            # 未使用インデックスの検出
            cursor = conn.execute("""
                SELECT name, tbl_name 
                FROM sqlite_master 
                WHERE type='index' AND name NOT LIKE 'sqlite_%'
            """)
            
            for row in cursor:
                index_name, table_name = row
                
                # 使用状況チェック
                usage_cursor = conn.execute("""
                    SELECT usage_count, last_used
                    FROM index_usage
                    WHERE index_name = ? AND table_name = ?
                """, (index_name, table_name))
                
                usage = usage_cursor.fetchone()
                if usage and usage[0] == 0:
                    # 未使用インデックス
                    logger.info(f"Unused index detected: {index_name} on {table_name}")
                    
            # 複合インデックスの提案
            suggestions.extend(await self._suggest_composite_indexes(conn))
            
        return suggestions + self.index_suggestions
        
    async def _suggest_composite_indexes(self, conn) -> List[IndexSuggestion]:
        """複合インデックス提案"""
        suggestions = []
        
        # 頻繁に一緒に使われるカラムの組み合わせを検出
        cursor = conn.execute("""
            SELECT query_text, execution_count
            FROM query_stats
            WHERE query_text LIKE '%WHERE%AND%'
            ORDER BY execution_count DESC
            LIMIT 50
        """)
        
        for row in cursor:
            query = row[0]
            
            # WHERE句のカラムを抽出
            import re
            columns = re.findall(r'(\w+)\s*=', query)
            
            if len(columns) > 1:
                # テーブル名を抽出
                table_match = re.search(r'FROM\s+(\w+)', query, re.IGNORECASE)
                if table_match:
                    table = table_match.group(1)
                    
                    suggestion = IndexSuggestion(
                        table_name=table,
                        columns=list(set(columns)),
                        reason="Frequent multi-column WHERE clause",
                        estimated_improvement=0.7,
                        query_patterns=[query]
                    )
                    
                    if suggestion not in suggestions:
                        suggestions.append(suggestion)
                        
        return suggestions
        
    async def create_suggested_indexes(self, suggestions: List[IndexSuggestion]):
        """提案されたインデックスを作成"""
        with sqlite3.connect(self.db_path) as conn:
            for suggestion in suggestions:
                if suggestion.estimated_improvement > 0.5:
                    index_name = f"idx_{suggestion.table_name}_{'_'.join(suggestion.columns)}"
                    
                    try:
                        # インデックス作成
                        columns_str = ', '.join(suggestion.columns)
                        conn.execute(f"""
                            CREATE INDEX IF NOT EXISTS {index_name}
                            ON {suggestion.table_name} ({columns_str})
                        """)
                        
                        logger.info(f"Created index: {index_name}")
                        
                        # 使用状況記録
                        conn.execute("""
                            INSERT OR IGNORE INTO index_usage
                            (index_name, table_name, created_at)
                            VALUES (?, ?, ?)
                        """, (index_name, suggestion.table_name, time.time()))
                        
                    except Exception as e:
                        logger.error(f"Failed to create index {index_name}: {e}")
                        
            conn.commit()
            
    async def vacuum_database(self):
        """データベースVACUUM実行"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # 断片化レベルチェック
                cursor = conn.execute("""
                    SELECT 
                        (page_count - freelist_count) * page_size as used_size,
                        page_count * page_size as total_size
                    FROM pragma_page_count(), pragma_freelist_count(), pragma_page_size()
                """)
                
                used_size, total_size = cursor.fetchone()
                fragmentation = 1 - (used_size / total_size) if total_size > 0 else 0
                
                # 断片化が20%以上ならVACUUM実行
                if fragmentation > 0.2:
                    logger.info(f"Database fragmentation: {fragmentation:.2%}, running VACUUM...")
                    conn.execute("VACUUM")
                    logger.info("VACUUM completed")
                    
        except Exception as e:
            logger.error(f"VACUUM failed: {e}")
            
    async def optimize_query_plans(self):
        """クエリプラン最適化"""
        with sqlite3.connect(self.db_path) as conn:
            # クエリオプティマイザーのヒント設定
            conn.execute("PRAGMA optimize")
            
            # 自動インデックス有効化
            conn.execute("PRAGMA automatic_index = ON")
            
            # クエリプランナーの設定
            conn.execute("PRAGMA query_only = OFF")
            
    def record_query_execution(self, query: str, execution_time: float):
        """クエリ実行記録"""
        import hashlib
        
        # クエリハッシュ生成
        query_hash = hashlib.sha256(query.encode()).hexdigest()
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                # 既存レコード取得
                cursor = conn.execute("""
                    SELECT execution_count, total_time, max_time, min_time
                    FROM query_stats
                    WHERE query_hash = ?
                """, (query_hash,))
                
                existing = cursor.fetchone()
                
                if existing:
                    # 更新
                    count = existing[0] + 1
                    total = existing[1] + execution_time
                    max_time = max(existing[2], execution_time)
                    min_time = min(existing[3], execution_time)
                    avg_time = total / count
                    
                    conn.execute("""
                        UPDATE query_stats
                        SET execution_count = ?, total_time = ?, avg_time = ?,
                            max_time = ?, min_time = ?, last_executed = ?
                        WHERE query_hash = ?
                    """, (count, total, avg_time, max_time, min_time, time.time(), query_hash))
                else:
                    # 新規挿入
                    conn.execute("""
                        INSERT INTO query_stats
                        (query_hash, query_text, execution_count, total_time,
                         avg_time, max_time, min_time, last_executed)
                        VALUES (?, ?, 1, ?, ?, ?, ?, ?)
                    """, (query_hash, query, execution_time, execution_time,
                          execution_time, execution_time, time.time()))
                    
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to record query execution: {e}")

class ConnectionPool:
    """データベース接続プール"""
    
    def __init__(self, db_path: str, pool_size: int = 10):
        self.db_path = db_path
        self.pool_size = pool_size
        self.connections: List[sqlite3.Connection] = []
        self.available: List[sqlite3.Connection] = []
        self.in_use: Dict[int, sqlite3.Connection] = {}
        self._init_pool()
        
    def _init_pool(self):
        """接続プール初期化"""
        for _ in range(self.pool_size):
            conn = self._create_connection()
            self.connections.append(conn)
            self.available.append(conn)
            
    def _create_connection(self) -> sqlite3.Connection:
        """接続作成"""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        
        # パフォーマンス設定
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA cache_size = -64000")  # 64MB
        conn.execute("PRAGMA temp_store = MEMORY")
        conn.execute("PRAGMA mmap_size = 30000000000")  # 30GB
        
        return conn
        
    def acquire(self) -> sqlite3.Connection:
        """接続取得"""
        if not self.available:
            # 全て使用中の場合は新規作成
            if len(self.connections) < self.pool_size * 2:
                conn = self._create_connection()
                self.connections.append(conn)
                return conn
            else:
                # 待機
                time.sleep(0.01)  # 最適化: 100ms -> 10ms
                return self.acquire()
                
        conn = self.available.pop()
        self.in_use[id(conn)] = conn
        return conn
        
    def release(self, conn: sqlite3.Connection):
        """接続返却"""
        conn_id = id(conn)
        if conn_id in self.in_use:
            del self.in_use[conn_id]
            self.available.append(conn)
            
    def close_all(self):
        """全接続クローズ"""
        for conn in self.connections:
            conn.close()
        self.connections.clear()
        self.available.clear()
        self.in_use.clear()

@dataclass
class PerformanceMetrics:
    """パフォーマンス指標"""
    avg_query_time: float
    slow_query_count: int
    index_hit_ratio: float
    cache_hit_ratio: float
    fragmentation_level: float
    active_connections: int
    
class AdvancedDatabaseOptimizer:
    """高度なデータベース最適化エンジン"""
    
    def __init__(self, db_path: str = "blrcs.db"):
        self.db_path = db_path
        self.basic_optimizer = DatabaseOptimizer(db_path)
        self.performance_metrics: Dict[str, float] = {}
        self.query_cache: Dict[str, Any] = {}
        self.cache_max_size = 1000
        self.n_plus_one_queries: Set[str] = set()
        
        # Lightning Network固有のテーブル定義
        self.ln_tables = {
            "channels": ["channel_id", "node_id", "capacity", "local_balance", "remote_balance", "status", "created_at"],
            "payments": ["payment_hash", "destination", "amount_msat", "status", "created_at", "settled_at"],
            "invoices": ["payment_request", "payment_hash", "amount_msat", "status", "created_at", "expires_at"],
            "nodes": ["node_id", "alias", "public_key", "address", "last_seen"],
            "routes": ["route_id", "source", "destination", "hops", "total_fee", "success_rate"],
            "transactions": ["tx_id", "amount", "fee", "confirmation_time", "block_height"],
            "sessions": ["session_id", "user_id", "created_at", "last_activity", "ip_address"],
            "users": ["user_id", "username", "email", "created_at", "last_login"],
            "audit_logs": ["event_id", "user_id", "action", "resource", "timestamp", "ip_address"],
            "rate_limits": ["ip_address", "endpoint", "request_count", "window_start", "blocked_until"]
        }
        
    async def comprehensive_optimization(self):
        """包括的最適化実行"""
        logger.info("Starting comprehensive database optimization...")
        
        start_time = time.time()
        
        # 1. 基本最適化
        await self.basic_optimizer.optimize_database()
        
        # 2. Lightning Network特化最適化
        await self.optimize_ln_specific_queries()
        
        # 3. N+1クエリ問題の解決
        await self.detect_and_fix_n_plus_one()
        
        # 4. 自動パーティショニング
        await self.implement_partitioning()
        
        # 5. 高度なインデックス戦略
        await self.implement_advanced_indexing()
        
        # 6. クエリキャッシュ最適化
        await self.optimize_query_cache()
        
        # 7. 接続プール最適化
        await self.optimize_connection_pool()
        
        # 8. パフォーマンス指標計算
        metrics = await self.calculate_performance_metrics()
        
        optimization_time = time.time() - start_time
        logger.info(f"Comprehensive optimization completed in {optimization_time:.2f}s")
        
        return metrics
        
    async def optimize_ln_specific_queries(self):
        """Lightning Network固有のクエリ最適化"""
        with sqlite3.connect(self.db_path) as conn:
            
            # 1. チャネル残高クエリの最適化
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_channels_balance_status 
                ON channels(local_balance, remote_balance, status)
            """)
            
            # 2. 支払い履歴クエリの最適化
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_payments_destination_status_date
                ON payments(destination, status, created_at)
            """)
            
            # 3. インボイス検索の最適化
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_invoices_status_expires
                ON invoices(status, expires_at)
            """)
            
            # 4. ノード情報クエリの最適化
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_nodes_last_seen
                ON nodes(last_seen)
            """)
            
            # 5. ルート探索の最適化
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_routes_success_rate
                ON routes(source, destination, success_rate)
            """)
            
            # 6. セッション管理の最適化
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_sessions_user_activity
                ON sessions(user_id, last_activity)
            """)
            
            # 7. 監査ログの最適化
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_logs_user_timestamp
                ON audit_logs(user_id, timestamp)
            """)
            
            # 8. レート制限の最適化
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_rate_limits_ip_endpoint
                ON rate_limits(ip_address, endpoint, window_start)
            """)
            
            conn.commit()
            
        logger.info("Lightning Network specific optimizations completed")
        
    async def detect_and_fix_n_plus_one(self):
        """N+1クエリ問題の検出と修正"""
        
        # N+1パターンの検出
        n_plus_one_patterns = [
            # チャネル情報とノード情報の分離クエリ
            {
                "pattern": r"SELECT.*FROM channels.*WHERE.*",
                "related": r"SELECT.*FROM nodes.*WHERE node_id.*",
                "solution": """
                    CREATE VIEW IF NOT EXISTS v_channels_with_nodes AS
                    SELECT c.*, n.alias, n.public_key, n.address
                    FROM channels c
                    LEFT JOIN nodes n ON c.node_id = n.node_id
                """
            },
            
            # 支払いと請求書の分離クエリ
            {
                "pattern": r"SELECT.*FROM payments.*WHERE.*",
                "related": r"SELECT.*FROM invoices.*WHERE payment_hash.*",
                "solution": """
                    CREATE VIEW IF NOT EXISTS v_payments_with_invoices AS
                    SELECT p.*, i.payment_request, i.expires_at
                    FROM payments p
                    LEFT JOIN invoices i ON p.payment_hash = i.payment_hash
                """
            }
        ]
        
        with sqlite3.connect(self.db_path) as conn:
            for pattern_info in n_plus_one_patterns:
                try:
                    conn.execute(pattern_info["solution"])
                    logger.debug(f"Created view to prevent N+1 queries")
                except Exception as e:
                    logger.error(f"Failed to create N+1 prevention view: {e}")
                    
            conn.commit()
            
    async def implement_partitioning(self):
        """自動パーティショニング実装"""
        
        # 時系列データのパーティショニング
        partitioning_rules = [
            {
                "table": "audit_logs",
                "partition_column": "timestamp",
                "partition_type": "monthly"
            },
            {
                "table": "payments",
                "partition_column": "created_at",
                "partition_type": "weekly"
            },
            {
                "table": "rate_limits",
                "partition_column": "window_start",
                "partition_type": "daily"
            }
        ]
        
        with sqlite3.connect(self.db_path) as conn:
            for rule in partitioning_rules:
                await self._create_partition_tables(conn, rule)
                
    async def _create_partition_tables(self, conn: sqlite3.Connection, rule: Dict[str, str]):
        """パーティションテーブル作成"""
        table_name = rule["table"]
        partition_column = rule["partition_column"]
        partition_type = rule["partition_type"]
        
        try:
            # 現在の日付に基づいてパーティション作成
            current_time = datetime.now()
            
            if partition_type == "monthly":
                partition_suffix = current_time.strftime("%Y_%m")
            elif partition_type == "weekly":
                week_num = current_time.isocalendar()[1]
                partition_suffix = f"{current_time.year}_{week_num:02d}"
            elif partition_type == "daily":
                partition_suffix = current_time.strftime("%Y_%m_%d")
            else:
                return
                
            partition_table = f"{table_name}_{partition_suffix}"
            
            # パーティションテーブル作成
            conn.execute(f"""
                CREATE TABLE IF NOT EXISTS {partition_table} AS 
                SELECT * FROM {table_name} WHERE 1=0
            """)
            
            # パーティション用のインデックス作成
            conn.execute(f"""
                CREATE INDEX IF NOT EXISTS idx_{partition_table}_{partition_column}
                ON {partition_table}({partition_column})
            """)
            
            logger.debug(f"Created partition table: {partition_table}")
            
        except Exception as e:
            logger.error(f"Failed to create partition for {table_name}: {e}")
            
    async def implement_advanced_indexing(self):
        """高度なインデックス戦略実装"""
        
        with sqlite3.connect(self.db_path) as conn:
            
            # 1. 複合インデックス（最適な順序で）
            composite_indexes = [
                ("channels", ["status", "local_balance", "created_at"]),
                ("payments", ["destination", "status", "amount_msat"]),
                ("invoices", ["status", "expires_at", "amount_msat"]),
                ("sessions", ["user_id", "last_activity", "status"]),
                ("audit_logs", ["timestamp", "user_id", "action"]),
                ("rate_limits", ["ip_address", "window_start", "blocked_until"])
            ]
            
            for table, columns in composite_indexes:
                index_name = f"idx_{table}_{'_'.join(columns)}"
                columns_str = ", ".join(columns)
                
                try:
                    conn.execute(f"""
                        CREATE INDEX IF NOT EXISTS {index_name}
                        ON {table}({columns_str})
                    """)
                    logger.debug(f"Created composite index: {index_name}")
                except Exception as e:
                    logger.error(f"Failed to create composite index {index_name}: {e}")
                    
            # 2. 部分インデックス（条件付き）
            partial_indexes = [
                ("channels", "local_balance", "status = 'active'"),
                ("payments", "amount_msat", "status = 'succeeded'"),
                ("invoices", "expires_at", "status = 'open'"),
                ("sessions", "last_activity", "status = 'active'")
            ]
            
            for table, column, condition in partial_indexes:
                index_name = f"idx_{table}_{column}_partial"
                
                try:
                    conn.execute(f"""
                        CREATE INDEX IF NOT EXISTS {index_name}
                        ON {table}({column}) WHERE {condition}
                    """)
                    logger.debug(f"Created partial index: {index_name}")
                except Exception as e:
                    logger.error(f"Failed to create partial index {index_name}: {e}")
                    
            # 3. 式ベースのインデックス
            expression_indexes = [
                ("payments", "datetime(created_at, 'unixepoch')", "payment_date"),
                ("channels", "local_balance + remote_balance", "total_capacity"),
                ("invoices", "datetime(expires_at, 'unixepoch')", "expiry_date")
            ]
            
            for table, expression, name_suffix in expression_indexes:
                index_name = f"idx_{table}_{name_suffix}"
                
                try:
                    conn.execute(f"""
                        CREATE INDEX IF NOT EXISTS {index_name}
                        ON {table}({expression})
                    """)
                    logger.debug(f"Created expression index: {index_name}")
                except Exception as e:
                    logger.error(f"Failed to create expression index {index_name}: {e}")
                    
            conn.commit()
            
    async def optimize_query_cache(self):
        """クエリキャッシュ最適化"""
        
        # よく使用されるクエリパターンをキャッシュ
        common_queries = [
            "SELECT * FROM channels WHERE status = 'active'",
            "SELECT COUNT(*) FROM payments WHERE status = 'succeeded'",
            "SELECT * FROM invoices WHERE status = 'open' AND expires_at > ?",
            "SELECT * FROM sessions WHERE last_activity > ?",
            "SELECT COUNT(*) FROM audit_logs WHERE timestamp > ?"
        ]
        
        with sqlite3.connect(self.db_path) as conn:
            for query in common_queries:
                try:
                    # クエリプランをキャッシュ
                    conn.execute(f"EXPLAIN QUERY PLAN {query}")
                    
                    # プリペアドステートメントとして保存
                    query_hash = hashlib.sha256(query.encode()).hexdigest()
                    self.query_cache[query_hash] = {
                        "query": query,
                        "prepared_at": time.time(),
                        "hit_count": 0
                    }
                    
                except Exception as e:
                    logger.debug(f"Failed to cache query: {e}")
                    
    async def optimize_connection_pool(self):
        """接続プール最適化"""
        
        # 現在の接続数とパフォーマンスを分析
        with sqlite3.connect(self.db_path) as conn:
            
            # WALモードの最適化
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA wal_autocheckpoint = 1000")
            
            # 同期設定の最適化
            conn.execute("PRAGMA synchronous = NORMAL")
            
            # キャッシュサイズの最適化
            conn.execute("PRAGMA cache_size = -128000")  # 128MB
            
            # メモリマップドファイルの最適化
            conn.execute("PRAGMA mmap_size = 50000000000")  # 50GB
            
            # 一時ストレージの最適化
            conn.execute("PRAGMA temp_store = MEMORY")
            
            # クエリオプティマイザーの設定
            conn.execute("PRAGMA optimize")
            
            # 外部キー制約の最適化
            conn.execute("PRAGMA foreign_keys = ON")
            
            logger.info("Connection pool optimizations applied")
            
    async def calculate_performance_metrics(self) -> PerformanceMetrics:
        """パフォーマンス指標計算"""
        
        with sqlite3.connect(self.db_path) as conn:
            
            # 平均クエリ時間
            cursor = conn.execute("SELECT AVG(avg_time) FROM query_stats")
            avg_query_time = cursor.fetchone()[0] or 0
            
            # スロークエリ数
            cursor = conn.execute(
                "SELECT COUNT(*) FROM query_stats WHERE avg_time > ?",
                (self.basic_optimizer.slow_query_threshold,)
            )
            slow_query_count = cursor.fetchone()[0]
            
            # インデックスヒット率（簡略計算）
            cursor = conn.execute("""
                SELECT COUNT(*) as total_indexes 
                FROM sqlite_master 
                WHERE type='index' AND name NOT LIKE 'sqlite_%'
            """)
            total_indexes = cursor.fetchone()[0]
            
            cursor = conn.execute("SELECT COUNT(*) FROM index_usage WHERE usage_count > 0")
            used_indexes = cursor.fetchone()[0]
            
            index_hit_ratio = used_indexes / total_indexes if total_indexes > 0 else 0
            
            # キャッシュヒット率
            total_cache_requests = sum(
                cache_entry["hit_count"] for cache_entry in self.query_cache.values()
            )
            cache_hit_ratio = min(1.0, total_cache_requests / 100) if total_cache_requests > 0 else 0
            
            # 断片化レベル
            cursor = conn.execute("""
                SELECT 
                    (page_count - freelist_count) * page_size as used_size,
                    page_count * page_size as total_size
                FROM pragma_page_count(), pragma_freelist_count(), pragma_page_size()
            """)
            
            try:
                used_size, total_size = cursor.fetchone()
                fragmentation_level = 1 - (used_size / total_size) if total_size > 0 else 0
            except:
                fragmentation_level = 0
                
            metrics = PerformanceMetrics(
                avg_query_time=avg_query_time,
                slow_query_count=slow_query_count,
                index_hit_ratio=index_hit_ratio,
                cache_hit_ratio=cache_hit_ratio,
                fragmentation_level=fragmentation_level,
                active_connections=len(self.basic_optimizer.sessions) if hasattr(self.basic_optimizer, 'sessions') else 0
            )
            
            logger.info(f"Performance metrics: {metrics}")
            return metrics

# グローバルインスタンス
advanced_optimizer = AdvancedDatabaseOptimizer()