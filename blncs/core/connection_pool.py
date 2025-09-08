"""
Lightning Network connection pooling and optimization
Efficient connection management for multiple Lightning operations.
"""

import time
import threading
from typing import Dict, Optional, Any, List
from queue import Queue, Empty
from dataclasses import dataclass
from datetime import datetime, timedelta

from .logger import get_logger
from .config import get_config
from .cache import get_cache


@dataclass
class ConnectionInfo:
    """接続情報"""
    host: str
    port: int
    created_at: datetime
    last_used: datetime
    active: bool = True
    failures: int = 0


class ConnectionPool:
    """Lightning Network接続プール"""
    
    def __init__(self, max_connections: int = 10):
        self.logger = get_logger(__name__)
        self.config = get_config()
        
        self.max_connections = max_connections
        self.connections: Dict[str, ConnectionInfo] = {}
        self.pool_lock = threading.RLock()
        
        # 接続プールの設定
        self.connection_timeout = self.config.get('performance.connection_timeout', 5)
        self.max_idle_time = self.config.get('performance.max_idle_time', 300)  # 5分
        self.cleanup_interval = self.config.get('performance.cleanup_interval', 60)   # 1分
        
        # クリーンアップスレッド
        self.cleanup_thread = None
        self.running = False
        self.start_cleanup_thread()
    
    def start_cleanup_thread(self) -> None:
        """クリーンアップスレッドを開始"""
        if not self.cleanup_thread or not self.cleanup_thread.is_alive():
            self.running = True
            self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
            self.cleanup_thread.start()
    
    def stop(self) -> None:
        """プールを停止"""
        self.running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=1)
    
    def _cleanup_loop(self) -> None:
        """アイドル接続のクリーンアップループ"""
        while self.running:
            try:
                self.cleanup_idle_connections()
                time.sleep(self.cleanup_interval)
            except Exception as e:
                self.logger.error(f"接続プールクリーンアップエラー: {e}")
                time.sleep(self.cleanup_interval)
    
    def get_connection_key(self, host: str, port: int) -> str:
        """接続キー生成"""
        return f"{host}:{port}"
    
    def get_connection(self, host: str, port: int) -> Optional[ConnectionInfo]:
        """接続を取得"""
        key = self.get_connection_key(host, port)
        
        with self.pool_lock:
            conn = self.connections.get(key)
            
            if conn and conn.active:
                conn.last_used = datetime.now()
                return conn
            
            # 新しい接続を作成
            if len(self.connections) >= self.max_connections:
                # 古い接続を削除
                self._remove_oldest_connection()
            
            conn = ConnectionInfo(
                host=host,
                port=port,
                created_at=datetime.now(),
                last_used=datetime.now(),
                active=True
            )
            
            self.connections[key] = conn
            self.logger.debug(f"新しい接続作成: {key}")
            return conn
    
    def release_connection(self, host: str, port: int, failed: bool = False) -> None:
        """接続を解放"""
        key = self.get_connection_key(host, port)
        
        with self.pool_lock:
            conn = self.connections.get(key)
            if conn:
                if failed:
                    conn.failures += 1
                    if conn.failures > 3:
                        conn.active = False
                        self.logger.warning(f"接続を無効化 (失敗多数): {key}")
                else:
                    conn.failures = 0  # 成功時はリセット
                
                conn.last_used = datetime.now()
    
    def _remove_oldest_connection(self) -> None:
        """最も古い接続を削除"""
        if not self.connections:
            return
        
        oldest_key = min(self.connections.keys(), 
                        key=lambda k: self.connections[k].last_used)
        
        del self.connections[oldest_key]
        self.logger.debug(f"古い接続を削除: {oldest_key}")
    
    def cleanup_idle_connections(self) -> None:
        """アイドル接続をクリーンアップ"""
        cutoff_time = datetime.now() - timedelta(seconds=self.max_idle_time)
        
        with self.pool_lock:
            keys_to_remove = []
            
            for key, conn in self.connections.items():
                if conn.last_used < cutoff_time or not conn.active:
                    keys_to_remove.append(key)
            
            for key in keys_to_remove:
                del self.connections[key]
                self.logger.debug(f"アイドル接続を削除: {key}")
    
    def get_pool_stats(self) -> Dict[str, Any]:
        """プール統計取得"""
        with self.pool_lock:
            active_connections = sum(1 for c in self.connections.values() if c.active)
            failed_connections = sum(1 for c in self.connections.values() if c.failures > 0)
            
            return {
                'total_connections': len(self.connections),
                'active_connections': active_connections,
                'failed_connections': failed_connections,
                'max_connections': self.max_connections,
                'pool_utilization': len(self.connections) / self.max_connections if self.max_connections > 0 else 0
            }


class RequestCache:
    """Lightning Network リクエストキャッシュ"""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        self.cache = get_cache()
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.hit_count = 0
        self.miss_count = 0
        
    def get_cache_key(self, method: str, *args, **kwargs) -> str:
        """キャッシュキー生成"""
        # 引数を正規化してハッシュ化
        import hashlib
        import json
        
        key_data = {
            'method': method,
            'args': args,
            'kwargs': {k: v for k, v in kwargs.items() if k not in ['timeout', 'max_retries']}
        }
        
        key_str = json.dumps(key_data, sort_keys=True, default=str)
        key_hash = hashlib.md5(key_str.encode()).hexdigest()
        
        return f"ln_request:{key_hash}"
    
    def get(self, method: str, *args, **kwargs) -> Optional[Any]:
        """キャッシュから取得"""
        key = self.get_cache_key(method, *args, **kwargs)
        result = self.cache.get(key)
        
        if result is not None:
            self.hit_count += 1
        else:
            self.miss_count += 1
        
        return result
    
    def set(self, method: str, result: Any, ttl: Optional[int] = None, *args, **kwargs) -> None:
        """キャッシュに保存"""
        key = self.get_cache_key(method, *args, **kwargs)
        actual_ttl = ttl or self.default_ttl
        
        self.cache.set(key, result, actual_ttl)
    
    def invalidate(self, method: str, *args, **kwargs) -> None:
        """キャッシュを無効化"""
        key = self.get_cache_key(method, *args, **kwargs)
        self.cache.delete(key)
    
    def invalidate_pattern(self, pattern: str) -> None:
        """パターンマッチでキャッシュを無効化"""
        # ここでは簡単な実装。実際にはRedisのような場合はより効率的に実装可能
        pass
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """キャッシュ統計取得"""
        total_requests = self.hit_count + self.miss_count
        hit_rate = self.hit_count / total_requests if total_requests > 0 else 0
        
        return {
            'hit_count': self.hit_count,
            'miss_count': self.miss_count,
            'total_requests': total_requests,
            'hit_rate': hit_rate,
            'cache_efficiency': hit_rate * 100
        }


# Global instances
_connection_pool = None
_request_cache = None

def get_connection_pool() -> ConnectionPool:
    """グローバル接続プール取得"""
    global _connection_pool
    if _connection_pool is None:
        config = get_config()
        max_conn = config.get('performance.max_connections', 10)
        _connection_pool = ConnectionPool(max_conn)
    return _connection_pool

def get_request_cache() -> RequestCache:
    """グローバルリクエストキャッシュ取得"""
    global _request_cache
    if _request_cache is None:
        config = get_config()
        max_size = config.get('performance.request_cache_size', 1000)
        _request_cache = RequestCache(max_size)
    return _request_cache