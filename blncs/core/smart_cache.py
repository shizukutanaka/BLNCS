#!/usr/bin/env python3
"""
Smart Caching and Memoization System - 計算の省力化
Intelligent caching with predictive preloading and automatic invalidation
"""

import asyncio
import threading
import time
import hashlib
import pickle
import json
import weakref
from typing import Dict, Any, Optional, Callable, Union, List, TypeVar, Generic
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import logging
import functools
import inspect
from collections import OrderedDict, defaultdict
import gc

# Use lightweight fallbacks instead of external dependencies
try:
    from blncs.utils.lightweight_fallbacks import get_system_monitor, psutil
    system_monitor = get_system_monitor()
except ImportError:
    psutil = None
    system_monitor = None

logger = logging.getLogger(__name__)

T = TypeVar('T')


class CacheStrategy(Enum):
    LRU = "lru"           # Least Recently Used
    LFU = "lfu"           # Least Frequently Used  
    TTL = "ttl"           # Time To Live
    ADAPTIVE = "adaptive"  # Adaptive based on usage patterns
    PREDICTIVE = "predictive"  # Predictive preloading


class CacheLevel(Enum):
    MEMORY = "memory"
    DISK = "disk"
    DISTRIBUTED = "distributed"


@dataclass
class CacheEntry:
    """キャッシュエントリー"""
    key: str
    value: Any
    created_at: datetime
    last_accessed: datetime
    access_count: int = 0
    ttl: Optional[float] = None
    size_bytes: int = 0
    hit_rate: float = 0.0
    prediction_score: float = 0.0
    
    def is_expired(self) -> bool:
        """期限切れかチェック"""
        if self.ttl is None:
            return False
        return time.time() - self.created_at.timestamp() > self.ttl
    
    def update_access(self):
        """アクセス情報を更新"""
        self.last_accessed = datetime.now()
        self.access_count += 1


class SmartCache:
    """
    スマートキャッシュシステム
    
    機能:
    - 複数レベルキャッシング (メモリ/ディスク)
    - アダプティブ戦略選択
    - 予測的プリロード
    - 自動サイズ管理
    - パフォーマンス最適化
    """
    
    def __init__(self, 
                 max_memory_size: int = 100 * 1024 * 1024,  # 100MB
                 max_entries: int = 10000,
                 default_ttl: float = 3600.0,
                 strategy: CacheStrategy = CacheStrategy.ADAPTIVE,
                 enable_disk_cache: bool = True,
                 enable_prediction: bool = True):
        
        self.max_memory_size = max_memory_size
        self.max_entries = max_entries
        self.default_ttl = default_ttl
        self.strategy = strategy
        self.enable_disk_cache = enable_disk_cache
        self.enable_prediction = enable_prediction
        
        # Cache storage
        self.memory_cache: Dict[str, CacheEntry] = {}
        self.access_order = OrderedDict()  # For LRU
        self.frequency_counter = defaultdict(int)  # For LFU
        
        # Statistics
        self.stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'total_size': 0,
            'memory_usage': 0
        }
        
        # Smart features
        self.usage_patterns = defaultdict(list)
        self.prediction_model = PredictionModel()
        self.adaptive_manager = AdaptiveManager(self)
        
        # Background tasks
        self._cleanup_task = None
        self._prediction_task = None
        self._running = False
        
        self.lock = threading.RLock()
    
    def start(self):
        """キャッシュシステム開始"""
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        if self.enable_prediction:
            self._prediction_task = asyncio.create_task(self._prediction_loop())
        logger.info("🚀 Smart Cache System started")
    
    def stop(self):
        """キャッシュシステム停止"""
        self._running = False
        if self._cleanup_task:
            self._cleanup_task.cancel()
        if self._prediction_task:
            self._prediction_task.cancel()
        logger.info("🛑 Smart Cache System stopped")
    
    def get(self, key: str) -> Optional[Any]:
        """値を取得"""
        with self.lock:
            # Memory cache check
            if key in self.memory_cache:
                entry = self.memory_cache[key]
                
                # Check expiration
                if entry.is_expired():
                    self._remove_entry(key)
                    self.stats['misses'] += 1
                    return None
                
                # Update access info
                entry.update_access()
                self._update_access_order(key)
                
                self.stats['hits'] += 1
                self._record_access_pattern(key)
                
                return entry.value
            
            # Disk cache check (if enabled)
            if self.enable_disk_cache:
                disk_value = self._get_from_disk(key)
                if disk_value is not None:
                    # Promote to memory cache
                    self.put(key, disk_value, promote_from_disk=True)
                    self.stats['hits'] += 1
                    return disk_value
            
            self.stats['misses'] += 1
            return None
    
    def put(self, 
            key: str, 
            value: Any, 
            ttl: Optional[float] = None,
            promote_from_disk: bool = False):
        """値を格納"""
        with self.lock:
            ttl = ttl or self.default_ttl
            
            # Calculate size
            size_bytes = self._calculate_size(value)
            
            # Create entry
            entry = CacheEntry(
                key=key,
                value=value,
                created_at=datetime.now(),
                last_accessed=datetime.now(),
                ttl=ttl,
                size_bytes=size_bytes
            )
            
            # Check if we need to evict
            if not promote_from_disk:
                self._ensure_capacity(size_bytes)
            
            # Store in memory
            if key in self.memory_cache:
                old_entry = self.memory_cache[key]
                self.stats['total_size'] -= old_entry.size_bytes
            
            self.memory_cache[key] = entry
            self.stats['total_size'] += size_bytes
            self._update_access_order(key)
            
            # Store to disk if enabled and valuable
            if self.enable_disk_cache and self._should_persist_to_disk(entry):
                self._put_to_disk(key, value)
            
            self._record_access_pattern(key, is_write=True)
    
    def delete(self, key: str) -> bool:
        """キーを削除"""
        with self.lock:
            if key in self.memory_cache:
                self._remove_entry(key)
                return True
            return False
    
    def clear(self):
        """全キャッシュをクリア"""
        with self.lock:
            self.memory_cache.clear()
            self.access_order.clear()
            self.frequency_counter.clear()
            self.stats['total_size'] = 0
            logger.info("🧹 Cache cleared")
    
    def get_stats(self) -> Dict[str, Any]:
        """統計情報を取得"""
        with self.lock:
            hit_rate = 0.0
            total_requests = self.stats['hits'] + self.stats['misses']
            if total_requests > 0:
                hit_rate = self.stats['hits'] / total_requests
            
            return {
                **self.stats,
                'hit_rate': hit_rate,
                'cache_entries': len(self.memory_cache),
                'memory_usage_mb': self.stats['total_size'] / (1024 * 1024),
                'system_memory_usage': psutil.Process().memory_info().rss / (1024 * 1024)
            }
    
    def _ensure_capacity(self, required_size: int):
        """容量を確保"""
        while (self.stats['total_size'] + required_size > self.max_memory_size or
               len(self.memory_cache) >= self.max_entries):
            
            if not self.memory_cache:
                break
            
            # Select eviction strategy
            if self.strategy == CacheStrategy.ADAPTIVE:
                self.strategy = self.adaptive_manager.get_best_strategy()
            
            victim_key = self._select_eviction_candidate()
            if victim_key:
                self._remove_entry(victim_key)
                self.stats['evictions'] += 1
            else:
                break
    
    def _select_eviction_candidate(self) -> Optional[str]:
        """立ち退き候補を選択"""
        if not self.memory_cache:
            return None
        
        if self.strategy == CacheStrategy.LRU:
            return next(iter(self.access_order))
        
        elif self.strategy == CacheStrategy.LFU:
            # Find least frequently used
            min_freq = float('inf')
            candidate = None
            for key, entry in self.memory_cache.items():
                if entry.access_count < min_freq:
                    min_freq = entry.access_count
                    candidate = key
            return candidate
        
        elif self.strategy == CacheStrategy.TTL:
            # Find expired or closest to expiration
            now = time.time()
            min_remaining_ttl = float('inf')
            candidate = None
            
            for key, entry in self.memory_cache.items():
                if entry.is_expired():
                    return key
                
                if entry.ttl:
                    remaining_ttl = entry.ttl - (now - entry.created_at.timestamp())
                    if remaining_ttl < min_remaining_ttl:
                        min_remaining_ttl = remaining_ttl
                        candidate = key
            
            return candidate or next(iter(self.access_order))
        
        elif self.strategy == CacheStrategy.PREDICTIVE:
            # Use prediction score
            min_score = float('inf')
            candidate = None
            for key, entry in self.memory_cache.items():
                if entry.prediction_score < min_score:
                    min_score = entry.prediction_score
                    candidate = key
            return candidate
        
        # Default to LRU
        return next(iter(self.access_order))
    
    def _remove_entry(self, key: str):
        """エントリーを削除"""
        if key in self.memory_cache:
            entry = self.memory_cache[key]
            self.stats['total_size'] -= entry.size_bytes
            del self.memory_cache[key]
        
        if key in self.access_order:
            del self.access_order[key]
        
        if key in self.frequency_counter:
            del self.frequency_counter[key]
    
    def _update_access_order(self, key: str):
        """アクセス順序を更新"""
        if key in self.access_order:
            del self.access_order[key]
        self.access_order[key] = True
        
        self.frequency_counter[key] += 1
    
    def _calculate_size(self, value: Any) -> int:
        """値のサイズを計算"""
        try:
            return len(pickle.dumps(value))
        except:
            return len(str(value).encode('utf-8'))
    
    def _record_access_pattern(self, key: str, is_write: bool = False):
        """アクセスパターンを記録"""
        if not self.enable_prediction:
            return
        
        pattern = {
            'timestamp': time.time(),
            'key': key,
            'action': 'write' if is_write else 'read'
        }
        
        self.usage_patterns[key].append(pattern)
        
        # Keep only recent patterns
        cutoff = time.time() - 3600  # 1 hour
        self.usage_patterns[key] = [
            p for p in self.usage_patterns[key] 
            if p['timestamp'] > cutoff
        ]
    
    def _should_persist_to_disk(self, entry: CacheEntry) -> bool:
        """ディスクに永続化すべきかチェック"""
        # Persist if frequently accessed or large
        return (entry.access_count > 5 or 
                entry.size_bytes > 1024 or
                entry.ttl and entry.ttl > 3600)
    
    def _get_from_disk(self, key: str) -> Optional[Any]:
        """ディスクから取得"""
        # Simplified disk cache - would use proper file storage
        return None
    
    def _put_to_disk(self, key: str, value: Any):
        """ディスクに格納"""
        # Simplified - would implement proper disk storage
        pass
    
    async def _cleanup_loop(self):
        """クリーンアップループ"""
        while self._running:
            try:
                await asyncio.sleep(60)  # Run every minute
                self._cleanup_expired()
                self._update_prediction_scores()
                
                # Memory pressure check
                memory_usage = psutil.Process().memory_info().rss / (1024 * 1024)
                if memory_usage > 500:  # 500MB threshold
                    self._aggressive_cleanup()
                
            except Exception as e:
                logger.error(f"Cache cleanup error: {e}")
    
    def _cleanup_expired(self):
        """期限切れエントリーをクリーンアップ"""
        with self.lock:
            expired_keys = []
            for key, entry in self.memory_cache.items():
                if entry.is_expired():
                    expired_keys.append(key)
            
            for key in expired_keys:
                self._remove_entry(key)
            
            if expired_keys:
                logger.debug(f"🧹 Cleaned up {len(expired_keys)} expired entries")
    
    def _aggressive_cleanup(self):
        """積極的クリーンアップ"""
        with self.lock:
            # Remove least valuable entries
            entries_by_value = sorted(
                self.memory_cache.items(),
                key=lambda x: x[1].access_count * x[1].hit_rate
            )
            
            # Remove bottom 25%
            remove_count = len(entries_by_value) // 4
            for key, _ in entries_by_value[:remove_count]:
                self._remove_entry(key)
            
            logger.info(f"🧹 Aggressive cleanup: removed {remove_count} entries")
    
    def _update_prediction_scores(self):
        """予測スコアを更新"""
        if not self.enable_prediction:
            return
        
        with self.lock:
            for key, entry in self.memory_cache.items():
                if key in self.usage_patterns:
                    patterns = self.usage_patterns[key]
                    entry.prediction_score = self.prediction_model.calculate_score(patterns)
    
    async def _prediction_loop(self):
        """予測ループ"""
        while self._running:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes
                await self._predictive_preload()
            except Exception as e:
                logger.error(f"Prediction loop error: {e}")
    
    async def _predictive_preload(self):
        """予測的プリロード"""
        # Analyze patterns and predict what might be needed
        predictions = self.prediction_model.predict_next_accesses(self.usage_patterns)
        
        for key, probability in predictions:
            if probability > 0.7 and key not in self.memory_cache:
                # Try to preload from disk or regenerate
                logger.debug(f"🔮 Predictive preload: {key} (probability: {probability:.2f})")


class PredictionModel:
    """アクセスパターン予測モデル"""
    
    def calculate_score(self, patterns: List[Dict]) -> float:
        """パターンから予測スコアを計算"""
        if not patterns:
            return 0.0
        
        now = time.time()
        recent_accesses = [p for p in patterns if now - p['timestamp'] < 3600]
        
        if not recent_accesses:
            return 0.0
        
        # Simple scoring based on frequency and recency
        frequency_score = len(recent_accesses) / 60  # accesses per hour
        recency_score = 1.0 / (now - recent_accesses[-1]['timestamp'] + 1)
        
        return min(1.0, frequency_score * recency_score)
    
    def predict_next_accesses(self, all_patterns: Dict[str, List]) -> List[tuple]:
        """次のアクセスを予測"""
        predictions = []
        
        for key, patterns in all_patterns.items():
            if len(patterns) < 3:
                continue
            
            # Simple time-based prediction
            recent_patterns = patterns[-10:]  # Last 10 accesses
            if len(recent_patterns) >= 2:
                intervals = []
                for i in range(1, len(recent_patterns)):
                    interval = recent_patterns[i]['timestamp'] - recent_patterns[i-1]['timestamp']
                    intervals.append(interval)
                
                if intervals:
                    avg_interval = sum(intervals) / len(intervals)
                    last_access = recent_patterns[-1]['timestamp']
                    expected_next = last_access + avg_interval
                    
                    now = time.time()
                    if abs(expected_next - now) < avg_interval * 0.5:
                        probability = 1.0 / (abs(expected_next - now) + 1)
                        predictions.append((key, probability))
        
        return sorted(predictions, key=lambda x: x[1], reverse=True)[:10]


class AdaptiveManager:
    """アダプティブ戦略管理"""
    
    def __init__(self, cache: SmartCache):
        self.cache = cache
        self.strategy_performance = {
            CacheStrategy.LRU: {'hits': 0, 'misses': 0},
            CacheStrategy.LFU: {'hits': 0, 'misses': 0},
            CacheStrategy.TTL: {'hits': 0, 'misses': 0}
        }
        self.current_strategy = CacheStrategy.LRU
        self.evaluation_window = 1000  # Evaluate every N requests
        self.request_count = 0
    
    def get_best_strategy(self) -> CacheStrategy:
        """最適戦略を選択"""
        self.request_count += 1
        
        if self.request_count % self.evaluation_window == 0:
            best_strategy = CacheStrategy.LRU
            best_hit_rate = 0.0
            
            for strategy, perf in self.strategy_performance.items():
                total = perf['hits'] + perf['misses']
                if total > 0:
                    hit_rate = perf['hits'] / total
                    if hit_rate > best_hit_rate:
                        best_hit_rate = hit_rate
                        best_strategy = strategy
            
            self.current_strategy = best_strategy
            logger.debug(f"🎯 Adaptive strategy selected: {best_strategy.value}")
        
        return self.current_strategy


# Decorator for function memoization
def memoize(ttl: Optional[float] = None,
           cache_key: Optional[Callable] = None,
           strategy: CacheStrategy = CacheStrategy.ADAPTIVE):
    """
    関数メモ化デコレーター
    
    使用例:
    @memoize(ttl=300, strategy=CacheStrategy.LRU)
    def expensive_calculation(x, y):
        return x ** y + complex_operation()
    """
    def decorator(func: Callable) -> Callable:
        cache = SmartCache(strategy=strategy)
        # Don't start cache during import to avoid event loop issues
        # cache.start()  # Will be started on first use
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Start cache on first use if needed
            if not cache._running:
                try:
                    cache.start()
                except RuntimeError:
                    pass  # Running outside async context
            
            # Generate cache key
            if cache_key:
                key = cache_key(*args, **kwargs)
            else:
                key = _generate_key(func.__name__, args, kwargs)
            
            # Try to get from cache
            result = cache.get(key)
            if result is not None:
                return result
            
            # Compute and cache result
            result = func(*args, **kwargs)
            cache.put(key, result, ttl=ttl)
            return result
        
        wrapper._cache = cache
        return wrapper
    
    return decorator


def _generate_key(func_name: str, args: tuple, kwargs: dict) -> str:
    """キャッシュキーを生成"""
    key_data = {
        'function': func_name,
        'args': args,
        'kwargs': sorted(kwargs.items())
    }
    
    key_str = json.dumps(key_data, default=str, sort_keys=True)
    return hashlib.sha256(key_str.encode()).hexdigest()[:16]


# Global cache instance
_global_cache: Optional[SmartCache] = None


def get_cache() -> SmartCache:
    """グローバルキャッシュを取得"""
    global _global_cache
    if _global_cache is None:
        _global_cache = SmartCache()
        _global_cache.start()
    return _global_cache


# Convenient cache functions
def cached_get(key: str) -> Optional[Any]:
    """グローバルキャッシュから取得"""
    return get_cache().get(key)


def cached_put(key: str, value: Any, ttl: Optional[float] = None):
    """グローバルキャッシュに格納"""
    get_cache().put(key, value, ttl=ttl)


def cached_delete(key: str) -> bool:
    """グローバルキャッシュから削除"""
    return get_cache().delete(key)


def cache_stats() -> Dict[str, Any]:
    """グローバルキャッシュ統計"""
    return get_cache().get_stats()


# Built-in cached functions
# @memoize(ttl=60, strategy=CacheStrategy.LRU)  # Disabled during import to avoid event loop issues
def cached_system_info():
    """システム情報のキャッシュ版"""
    import psutil
    return {
        'cpu_percent': psutil.cpu_percent(interval=1),
        'memory': psutil.virtual_memory()._asdict(),
        'disk': psutil.disk_usage('/')._asdict()
    }


@memoize(ttl=300, strategy=CacheStrategy.LFU)  
def cached_network_info():
    """ネットワーク情報のキャッシュ版"""
    import psutil
    return {
        'connections': len(psutil.net_connections()),
        'io_counters': psutil.net_io_counters()._asdict()
    }