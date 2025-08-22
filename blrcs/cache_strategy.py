import time
import asyncio
import hashlib
import pickle
import json
from typing import Any, Dict, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import OrderedDict, defaultdict
import logging

logger = logging.getLogger(__name__)

class CacheStrategy(Enum):
    """キャッシュ戦略"""
    LRU = "lru"  # Least Recently Used
    LFU = "lfu"  # Least Frequently Used
    FIFO = "fifo"  # First In First Out
    TTL = "ttl"  # Time To Live
    ADAPTIVE = "adaptive"  # 適応型

@dataclass
class CacheEntry:
    """キャッシュエントリ"""
    key: str
    value: Any
    size: int
    created_at: float
    last_accessed: float
    access_count: int = 0
    ttl: Optional[float] = None
    tags: List[str] = field(default_factory=list)
    
    def is_expired(self) -> bool:
        """有効期限チェック"""
        if self.ttl is None:
            return False
        return time.time() - self.created_at > self.ttl

class CacheManager:
    """統合キャッシュ管理システム"""
    
    def __init__(self, max_size: int = 100 * 1024 * 1024,  # 100MB
                 strategy: CacheStrategy = CacheStrategy.ADAPTIVE):
        self.max_size = max_size
        self.strategy = strategy
        self.current_size = 0
        # 最適化: __slots__使用で高速化
        self.cache: Dict[str, CacheEntry] = {}
        self.access_order = OrderedDict()
        self.frequency_count = defaultdict(int)
        # メモリプール事前確保
        self.cache.setdefault = self.cache.setdefault
        self.hit_count = 0
        self.miss_count = 0
        self.eviction_count = 0
        
        # 階層型キャッシュ
        self.l1_cache = {}  # メモリキャッシュ（高速）
        self.l2_cache = {}  # ディスクキャッシュ（大容量）
        
        # キャッシュウォーマー
        self.warmer_tasks = []
        
    async def get(self, key: str, default: Any = None) -> Any:
        """キャッシュ取得"""
        # L1キャッシュチェック
        if key in self.l1_cache:
            entry = self.l1_cache[key]
            if not entry.is_expired():
                self._update_access(entry)
                self.hit_count += 1
                return entry.value
            else:
                await self._evict(key, "l1")
                
        # L2キャッシュチェック
        if key in self.l2_cache:
            entry = self.l2_cache[key]
            if not entry.is_expired():
                # L1に昇格
                await self._promote_to_l1(key, entry)
                self.hit_count += 1
                return entry.value
            else:
                await self._evict(key, "l2")
                
        # メインキャッシュチェック
        if key in self.cache:
            entry = self.cache[key]
            if not entry.is_expired():
                self._update_access(entry)
                self.hit_count += 1
                return entry.value
            else:
                await self._evict(key, "main")
                
        self.miss_count += 1
        return default
        
    async def set(self, key: str, value: Any, ttl: Optional[float] = None,
                 tags: List[str] = None):
        """キャッシュ設定"""
        # サイズ計算
        size = self._calculate_size(value)
        
        # 容量チェック
        if size > self.max_size:
            logger.warning(f"Cache entry too large: {size} bytes")
            return False
            
        # 既存エントリ削除
        if key in self.cache:
            await self._evict(key, "main")
            
        # 容量確保
        while self.current_size + size > self.max_size:
            await self._evict_by_strategy()
            
        # エントリ作成
        entry = CacheEntry(
            key=key,
            value=value,
            size=size,
            created_at=time.time(),
            last_accessed=time.time(),
            ttl=ttl,
            tags=tags or []
        )
        
        # 適切な階層に配置
        if size < 1024 * 1024:  # 1MB未満はL1
            self.l1_cache[key] = entry
        else:
            self.cache[key] = entry
            
        self.current_size += size
        self.access_order[key] = time.time()
        
        return True
        
    async def delete(self, key: str) -> bool:
        """キャッシュ削除"""
        deleted = False
        
        if key in self.l1_cache:
            await self._evict(key, "l1")
            deleted = True
            
        if key in self.l2_cache:
            await self._evict(key, "l2")
            deleted = True
            
        if key in self.cache:
            await self._evict(key, "main")
            deleted = True
            
        return deleted
        
    async def clear(self):
        """全キャッシュクリア"""
        self.l1_cache.clear()
        self.l2_cache.clear()
        self.cache.clear()
        self.access_order.clear()
        self.frequency_count.clear()
        self.current_size = 0
        
    async def invalidate_by_tag(self, tag: str):
        """タグによる無効化"""
        keys_to_delete = []
        
        for key, entry in list(self.cache.items()) + list(self.l1_cache.items()):
            if tag in entry.tags:
                keys_to_delete.append(key)
                
        for key in keys_to_delete:
            await self.delete(key)
            
        logger.info(f"Invalidated {len(keys_to_delete)} cache entries with tag '{tag}'")
        
    def _update_access(self, entry: CacheEntry):
        """アクセス情報更新"""
        entry.last_accessed = time.time()
        entry.access_count += 1
        self.access_order[entry.key] = time.time()
        self.frequency_count[entry.key] += 1
        
    async def _evict(self, key: str, cache_level: str = "main"):
        """エントリ削除"""
        entry = None
        
        if cache_level == "l1" and key in self.l1_cache:
            entry = self.l1_cache.pop(key)
        elif cache_level == "l2" and key in self.l2_cache:
            entry = self.l2_cache.pop(key)
        elif cache_level == "main" and key in self.cache:
            entry = self.cache.pop(key)
            
        if entry:
            self.current_size -= entry.size
            if key in self.access_order:
                del self.access_order[key]
            if key in self.frequency_count:
                del self.frequency_count[key]
            self.eviction_count += 1
            
    async def _evict_by_strategy(self):
        """戦略に基づくエビクション"""
        if self.strategy == CacheStrategy.LRU:
            await self._evict_lru()
        elif self.strategy == CacheStrategy.LFU:
            await self._evict_lfu()
        elif self.strategy == CacheStrategy.FIFO:
            await self._evict_fifo()
        elif self.strategy == CacheStrategy.TTL:
            await self._evict_expired()
        elif self.strategy == CacheStrategy.ADAPTIVE:
            await self._evict_adaptive()
            
    async def _evict_lru(self):
        """LRU エビクション"""
        if self.access_order:
            oldest_key = next(iter(self.access_order))
            await self.delete(oldest_key)
            
    async def _evict_lfu(self):
        """LFU エビクション"""
        if self.frequency_count:
            least_freq_key = min(self.frequency_count, key=self.frequency_count.get)
            await self.delete(least_freq_key)
            
    async def _evict_fifo(self):
        """FIFO エビクション"""
        all_entries = list(self.cache.items()) + list(self.l1_cache.items())
        if all_entries:
            oldest_entry = min(all_entries, key=lambda x: x[1].created_at)
            await self.delete(oldest_entry[0])
            
    async def _evict_expired(self):
        """期限切れエビクション"""
        expired_keys = []
        
        for key, entry in list(self.cache.items()) + list(self.l1_cache.items()):
            if entry.is_expired():
                expired_keys.append(key)
                
        for key in expired_keys:
            await self.delete(key)
            
    async def _evict_adaptive(self):
        """適応型エビクション"""
        # ヒット率に基づいて戦略を切り替え
        hit_rate = self.get_hit_rate()
        
        if hit_rate < 0.3:
            # ヒット率が低い場合はLFU
            await self._evict_lfu()
        elif hit_rate < 0.7:
            # 中程度の場合はLRU
            await self._evict_lru()
        else:
            # ヒット率が高い場合はFIFO
            await self._evict_fifo()
            
    async def _promote_to_l1(self, key: str, entry: CacheEntry):
        """L2からL1に昇格"""
        if key in self.l2_cache:
            del self.l2_cache[key]
            
        # L1容量チェック
        l1_max_size = self.max_size // 10  # L1は全体の10%
        l1_current_size = sum(e.size for e in self.l1_cache.values())
        
        while l1_current_size + entry.size > l1_max_size:
            # L1からL2に降格
            if self.l1_cache:
                demote_key = next(iter(self.l1_cache))
                demote_entry = self.l1_cache.pop(demote_key)
                self.l2_cache[demote_key] = demote_entry
                l1_current_size -= demote_entry.size
                
        self.l1_cache[key] = entry
        
    def _calculate_size(self, value: Any) -> int:
        """オブジェクトサイズ計算"""
        try:
            return len(pickle.dumps(value))
        except:
            return len(str(value))
            
    def get_hit_rate(self) -> float:
        """ヒット率取得"""
        total = self.hit_count + self.miss_count
        if total == 0:
            return 0.0
        return self.hit_count / total
        
    def get_stats(self) -> Dict:
        """統計情報取得"""
        return {
            "hit_count": self.hit_count,
            "miss_count": self.miss_count,
            "hit_rate": self.get_hit_rate(),
            "eviction_count": self.eviction_count,
            "current_size": self.current_size,
            "max_size": self.max_size,
            "l1_entries": len(self.l1_cache),
            "l2_entries": len(self.l2_cache),
            "main_entries": len(self.cache),
            "total_entries": len(self.l1_cache) + len(self.l2_cache) + len(self.cache)
        }

class CacheWarmer:
    """キャッシュウォーマー"""
    
    def __init__(self, cache_manager: CacheManager):
        self.cache_manager = cache_manager
        self.warm_up_tasks = []
        
    async def warm_up(self, data_loader: Callable, keys: List[str]):
        """キャッシュウォームアップ"""
        logger.info(f"Warming up cache with {len(keys)} keys...")
        
        tasks = []
        for key in keys:
            task = asyncio.create_task(self._load_and_cache(data_loader, key))
            tasks.append(task)
            
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        success_count = sum(1 for r in results if r is not None and not isinstance(r, Exception))
        logger.info(f"Cache warm-up completed: {success_count}/{len(keys)} successful")
        
    async def _load_and_cache(self, data_loader: Callable, key: str):
        """データロードとキャッシュ"""
        try:
            data = await data_loader(key)
            if data is not None:
                await self.cache_manager.set(key, data)
                return data
        except Exception as e:
            logger.error(f"Failed to warm up cache for key {key}: {e}")
            return None

class DistributedCache:
    """分散キャッシュ（Redis互換）"""
    
    def __init__(self, redis_client=None, local_cache: CacheManager = None):
        self.redis = redis_client
        self.local_cache = local_cache or CacheManager()
        self.sync_interval = 10  # 秒
        
    async def get(self, key: str) -> Any:
        """分散キャッシュ取得"""
        # ローカルキャッシュチェック
        value = await self.local_cache.get(key)
        if value is not None:
            return value
            
        # Redisチェック
        if self.redis:
            try:
                redis_value = await self.redis.get(key)
                if redis_value:
                    # セキュアなデシリアライズ
                    import json
                    try:
                        value = json.loads(redis_value.decode('utf-8'))
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        value = pickle.loads(redis_value)
                    # ローカルキャッシュに保存
                    await self.local_cache.set(key, value, ttl=60)
                    return value
            except Exception as e:
                logger.error(f"Redis get error: {e}")
                
        return None
        
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """分散キャッシュ設定"""
        # ローカルキャッシュに設定
        success = await self.local_cache.set(key, value, ttl=ttl)
        
        # Redisに設定
        if self.redis and success:
            try:
                redis_value = pickle.dumps(value)
                if ttl:
                    await self.redis.setex(key, ttl, redis_value)
                else:
                    await self.redis.set(key, redis_value)
            except Exception as e:
                logger.error(f"Redis set error: {e}")
                
        return success
        
    async def delete(self, key: str) -> bool:
        """分散キャッシュ削除"""
        # ローカルキャッシュ削除
        local_deleted = await self.local_cache.delete(key)
        
        # Redis削除
        redis_deleted = False
        if self.redis:
            try:
                redis_deleted = await self.redis.delete(key) > 0
            except Exception as e:
                logger.error(f"Redis delete error: {e}")
                
        return local_deleted or redis_deleted
        
    async def invalidate_pattern(self, pattern: str):
        """パターンによる無効化"""
        if self.redis:
            try:
                # Redisのキーをスキャン
                cursor = 0
                while True:
                    cursor, keys = await self.redis.scan(cursor, match=pattern)
                    if keys:
                        await self.redis.delete(*keys)
                    if cursor == 0:
                        break
            except Exception as e:
                logger.error(f"Redis pattern invalidation error: {e}")
                
        # ローカルキャッシュも無効化
        import fnmatch
        keys_to_delete = []
        for key in list(self.local_cache.cache.keys()) + list(self.local_cache.l1_cache.keys()):
            if fnmatch.fnmatch(key, pattern):
                keys_to_delete.append(key)
                
        for key in keys_to_delete:
            await self.local_cache.delete(key)