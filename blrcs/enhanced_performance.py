"""強化されたパフォーマンス監視・最適化システム"""

import time
import asyncio
import psutil
import threading
import multiprocessing
import gc
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import logging
from collections import defaultdict, deque
import weakref
import signal
import sys

logger = logging.getLogger(__name__)

class PerformanceLevel(Enum):
    """パフォーマンスレベル"""
    EXCELLENT = "excellent"
    GOOD = "good"
    DEGRADED = "degraded"
    CRITICAL = "critical"

@dataclass
class PerformanceMetrics:
    """パフォーマンス指標"""
    timestamp: float
    cpu_percent: float
    memory_percent: float
    memory_available: int
    disk_io_read: int
    disk_io_write: int
    network_sent: int
    network_recv: int
    response_time: float
    active_connections: int
    queue_size: int
    error_rate: float

@dataclass
class ResourceAlert:
    """リソースアラート"""
    timestamp: float
    resource_type: str
    level: PerformanceLevel
    current_value: float
    threshold: float
    message: str

class AdaptiveRateLimiter:
    """適応的レート制限"""
    
    def __init__(self):
        self.buckets = defaultdict(lambda: {
            'tokens': 100,
            'last_refill': time.time(),
            'capacity': 100,
            'refill_rate': 10,
            'burst_allowed': False,
            'violations': 0
        })
        
        # 動的調整パラメータ
        self.base_capacity = 100
        self.base_refill_rate = 10
        self.adaptation_factor = 0.1
        self.violation_penalty = 0.8
        self.recovery_bonus = 1.2
        
    async def check_rate_limit(self, 
                             client_id: str, 
                             endpoint: str = "default",
                             current_load: float = 0.5) -> Tuple[bool, Optional[str]]:
        """適応的レート制限チェック"""
        bucket_key = f"{client_id}:{endpoint}"
        bucket = self.buckets[bucket_key]
        
        current_time = time.time()
        time_passed = current_time - bucket['last_refill']
        
        # 現在のシステム負荷に基づいて容量を調整
        load_factor = 1.0 - (current_load * 0.5)  # 負荷が高いほど制限を厳しく
        adjusted_capacity = int(self.base_capacity * load_factor)
        adjusted_refill_rate = self.base_refill_rate * load_factor
        
        # トークン補充
        tokens_to_add = time_passed * adjusted_refill_rate
        bucket['tokens'] = min(adjusted_capacity, bucket['tokens'] + tokens_to_add)
        bucket['last_refill'] = current_time
        bucket['capacity'] = adjusted_capacity
        bucket['refill_rate'] = adjusted_refill_rate
        
        # レート制限チェック
        if bucket['tokens'] >= 1:
            bucket['tokens'] -= 1
            
            # 違反回復時のボーナス
            if bucket['violations'] > 0:
                bucket['violations'] = max(0, bucket['violations'] - 1)
                if bucket['violations'] == 0:
                    bucket['capacity'] = int(bucket['capacity'] * self.recovery_bonus)
                    
            return True, None
        else:
            # レート制限違反
            bucket['violations'] += 1
            
            # 違反ペナルティ
            if bucket['violations'] > 5:
                bucket['capacity'] = int(bucket['capacity'] * self.violation_penalty)
                bucket['refill_rate'] *= self.violation_penalty
                
            retry_after = int((1 - bucket['tokens']) / adjusted_refill_rate)
            return False, f"Rate limit exceeded. Retry after {retry_after} seconds"

    def get_bucket_status(self, client_id: str, endpoint: str = "default") -> Dict[str, Any]:
        """バケット状態取得"""
        bucket_key = f"{client_id}:{endpoint}"
        bucket = self.buckets[bucket_key]
        
        return {
            'tokens': bucket['tokens'],
            'capacity': bucket['capacity'],
            'refill_rate': bucket['refill_rate'],
            'violations': bucket['violations'],
            'burst_allowed': bucket['burst_allowed']
        }

class MemoryOptimizer:
    """メモリ最適化"""
    
    def __init__(self):
        self.memory_threshold = 0.8  # 80%
        self.gc_thresholds = (700, 10, 10)
        self.object_pools = {}
        self.weak_references = weakref.WeakSet()
        
        # メモリ監視開始
        self._start_monitoring()
        
    def _start_monitoring(self):
        """メモリ監視開始"""
        def monitor_memory():
            while True:
                try:
                    memory_percent = psutil.virtual_memory().percent / 100.0
                    
                    if memory_percent > self.memory_threshold:
                        self._emergency_cleanup()
                        
                    time.sleep(10)  # 10秒間隔
                except Exception as e:
                    logger.error(f"Memory monitoring error: {e}")
                    time.sleep(60)
                    
        thread = threading.Thread(target=monitor_memory, daemon=True)
        thread.start()
        
    def _emergency_cleanup(self):
        """緊急メモリクリーンアップ"""
        logger.warning("Emergency memory cleanup initiated")
        
        # 1. ガベージコレクション強制実行
        collected = gc.collect()
        logger.info(f"Garbage collection freed {collected} objects")
        
        # 2. オブジェクトプールクリア
        for pool_name, pool in self.object_pools.items():
            cleared = len(pool)
            pool.clear()
            logger.info(f"Cleared {cleared} objects from pool '{pool_name}'")
            
        # 3. 弱参照オブジェクトのクリーンアップ
        self.weak_references.clear()
        
        # 4. キャッシュクリア（他のモジュールに通知）
        self._notify_cache_clear()

    def _notify_cache_clear(self):
        """キャッシュクリア通知"""
        # 他のモジュールのキャッシュをクリア
        try:
            import blrcs.cache_strategy
            if hasattr(blrcs.cache_strategy, 'cache_manager'):
                asyncio.create_task(blrcs.cache_strategy.cache_manager.clear_all())
        except ImportError:
            pass

    def optimize_gc(self):
        """ガベージコレクション最適化"""
        # カスタムGCしきい値設定
        gc.set_threshold(*self.gc_thresholds)
        
        # デバッグ情報収集（開発時のみ）
        if logger.isEnabledFor(logging.DEBUG):
            gc.set_debug(gc.DEBUG_STATS)

    def create_object_pool(self, name: str, factory: Callable, max_size: int = 100):
        """オブジェクトプール作成"""
        if name not in self.object_pools:
            self.object_pools[name] = deque(maxlen=max_size)
            
    def get_from_pool(self, name: str, factory: Callable):
        """プールからオブジェクト取得"""
        pool = self.object_pools.get(name)
        if pool and pool:
            return pool.popleft()
        else:
            return factory()
            
    def return_to_pool(self, name: str, obj: Any):
        """オブジェクトをプールに返却"""
        pool = self.object_pools.get(name)
        if pool is not None and len(pool) < pool.maxlen:
            # オブジェクトリセット（必要に応じて）
            if hasattr(obj, 'reset'):
                obj.reset()
            pool.append(obj)

class CPUOptimizer:
    """CPU最適化"""
    
    def __init__(self):
        self.cpu_threshold = 0.8  # 80%
        self.process_priority = {
            'high': [],
            'normal': [],
            'low': []
        }
        self.affinity_set = False
        
    def optimize_process_priority(self):
        """プロセス優先度最適化"""
        try:
            process = psutil.Process()
            
            # プロセス優先度設定
            if sys.platform == 'win32':
                process.nice(psutil.HIGH_PRIORITY_CLASS)
            else:
                process.nice(-5)  # Unix系での高優先度
                
            logger.info("Process priority optimized")
        except Exception as e:
            logger.warning(f"Failed to optimize process priority: {e}")

    def optimize_cpu_affinity(self):
        """CPU親和性最適化"""
        if self.affinity_set:
            return
            
        try:
            cpu_count = psutil.cpu_count()
            if cpu_count > 1:
                # 最後のCPUコアをシステム用に残す
                available_cpus = list(range(cpu_count - 1))
                psutil.Process().cpu_affinity(available_cpus)
                self.affinity_set = True
                logger.info(f"CPU affinity set to cores: {available_cpus}")
        except Exception as e:
            logger.warning(f"Failed to set CPU affinity: {e}")

    def balance_workload(self, tasks: List[Callable], max_workers: int = None):
        """ワークロード分散"""
        if not max_workers:
            max_workers = min(psutil.cpu_count(), len(tasks))
            
        # CPU使用率に基づいて動的にワーカー数調整
        cpu_percent = psutil.cpu_percent(interval=1)
        if cpu_percent > self.cpu_threshold:
            max_workers = max(1, max_workers // 2)
            
        return max_workers

class IOOptimizer:
    """I/O最適化"""
    
    def __init__(self):
        self.read_cache = {}
        self.write_buffer = []
        self.buffer_size = 1024 * 1024  # 1MB
        self.flush_interval = 5  # 5秒
        
        # 定期フラッシュ開始
        self._start_periodic_flush()
        
    def _start_periodic_flush(self):
        """定期フラッシュ開始"""
        def periodic_flush():
            while True:
                try:
                    if self.write_buffer:
                        self._flush_write_buffer()
                    time.sleep(self.flush_interval)
                except Exception as e:
                    logger.error(f"Periodic flush error: {e}")
                    
        thread = threading.Thread(target=periodic_flush, daemon=True)
        thread.start()

    def optimize_file_operations(self, file_path: str, operation: str):
        """ファイル操作最適化"""
        if operation == 'read':
            return self._optimized_read(file_path)
        elif operation == 'write':
            return self._optimized_write
        else:
            return None

    def _optimized_read(self, file_path: str):
        """最適化読み込み"""
        if file_path in self.read_cache:
            return self.read_cache[file_path]
            
        try:
            with open(file_path, 'rb', buffering=self.buffer_size) as f:
                data = f.read()
                self.read_cache[file_path] = data
                return data
        except Exception as e:
            logger.error(f"Optimized read error for {file_path}: {e}")
            return None

    def _optimized_write(self, file_path: str, data: bytes):
        """最適化書き込み"""
        self.write_buffer.append((file_path, data))
        
        # バッファサイズ制限チェック
        total_size = sum(len(data) for _, data in self.write_buffer)
        if total_size >= self.buffer_size:
            self._flush_write_buffer()

    def _flush_write_buffer(self):
        """書き込みバッファフラッシュ"""
        if not self.write_buffer:
            return
            
        try:
            # ファイルごとにグループ化
            file_groups = defaultdict(list)
            for file_path, data in self.write_buffer:
                file_groups[file_path].append(data)
                
            # バッチ書き込み
            for file_path, data_list in file_groups.items():
                with open(file_path, 'ab', buffering=self.buffer_size) as f:
                    for data in data_list:
                        f.write(data)
                        
            self.write_buffer.clear()
            logger.debug("Write buffer flushed")
            
        except Exception as e:
            logger.error(f"Write buffer flush error: {e}")

class PerformanceMonitor:
    """包括的パフォーマンス監視"""
    
    def __init__(self):
        self.metrics_history = deque(maxlen=1000)  # 最新1000件
        self.alerts = deque(maxlen=100)
        self.monitoring_active = False
        
        # しきい値設定
        self.thresholds = {
            'cpu_percent': 80.0,
            'memory_percent': 85.0,
            'disk_io_rate': 100_000_000,  # 100MB/s
            'network_rate': 50_000_000,   # 50MB/s
            'response_time': 5.0,         # 5秒
            'error_rate': 0.1             # 10%
        }
        
        # 前回の値（差分計算用）
        self.previous_metrics = None
        
    async def start_monitoring(self, interval: float = 10.0):
        """監視開始"""
        self.monitoring_active = True
        
        while self.monitoring_active:
            try:
                metrics = await self._collect_metrics()
                self.metrics_history.append(metrics)
                
                # アラートチェック
                alerts = self._check_alerts(metrics)
                self.alerts.extend(alerts)
                
                # パフォーマンスレベル評価
                level = self._evaluate_performance_level(metrics)
                
                if level in [PerformanceLevel.DEGRADED, PerformanceLevel.CRITICAL]:
                    await self._trigger_optimization(level, metrics)
                    
                await asyncio.sleep(interval)
                
            except Exception as e:
                logger.error(f"Performance monitoring error: {e}")
                await asyncio.sleep(interval)

    async def _collect_metrics(self) -> PerformanceMetrics:
        """メトリクス収集"""
        # CPU・メモリ情報
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        
        # ディスクI/O
        disk_io = psutil.disk_io_counters()
        disk_read = disk_io.read_bytes if disk_io else 0
        disk_write = disk_io.write_bytes if disk_io else 0
        
        # ネットワークI/O
        network_io = psutil.net_io_counters()
        network_sent = network_io.bytes_sent if network_io else 0
        network_recv = network_io.bytes_recv if network_io else 0
        
        # レスポンス時間測定（サンプル）
        start_time = time.time()
        await asyncio.sleep(0.001)  # 1ms待機
        response_time = time.time() - start_time
        
        return PerformanceMetrics(
            timestamp=time.time(),
            cpu_percent=cpu_percent,
            memory_percent=memory.percent,
            memory_available=memory.available,
            disk_io_read=disk_read,
            disk_io_write=disk_write,
            network_sent=network_sent,
            network_recv=network_recv,
            response_time=response_time,
            active_connections=len(psutil.net_connections()),
            queue_size=0,  # アプリケーション固有
            error_rate=0.0  # アプリケーション固有
        )

    def _check_alerts(self, metrics: PerformanceMetrics) -> List[ResourceAlert]:
        """アラートチェック"""
        alerts = []
        
        # CPU使用率チェック
        if metrics.cpu_percent > self.thresholds['cpu_percent']:
            level = PerformanceLevel.CRITICAL if metrics.cpu_percent > 95 else PerformanceLevel.DEGRADED
            alerts.append(ResourceAlert(
                timestamp=metrics.timestamp,
                resource_type="CPU",
                level=level,
                current_value=metrics.cpu_percent,
                threshold=self.thresholds['cpu_percent'],
                message=f"High CPU usage: {metrics.cpu_percent:.1f}%"
            ))
            
        # メモリ使用率チェック
        if metrics.memory_percent > self.thresholds['memory_percent']:
            level = PerformanceLevel.CRITICAL if metrics.memory_percent > 95 else PerformanceLevel.DEGRADED
            alerts.append(ResourceAlert(
                timestamp=metrics.timestamp,
                resource_type="Memory",
                level=level,
                current_value=metrics.memory_percent,
                threshold=self.thresholds['memory_percent'],
                message=f"High memory usage: {metrics.memory_percent:.1f}%"
            ))
            
        # レスポンス時間チェック
        if metrics.response_time > self.thresholds['response_time']:
            level = PerformanceLevel.CRITICAL if metrics.response_time > 10 else PerformanceLevel.DEGRADED
            alerts.append(ResourceAlert(
                timestamp=metrics.timestamp,
                resource_type="Response Time",
                level=level,
                current_value=metrics.response_time,
                threshold=self.thresholds['response_time'],
                message=f"Slow response time: {metrics.response_time:.2f}s"
            ))
            
        return alerts

    def _evaluate_performance_level(self, metrics: PerformanceMetrics) -> PerformanceLevel:
        """パフォーマンスレベル評価"""
        critical_count = 0
        degraded_count = 0
        
        if metrics.cpu_percent > 95:
            critical_count += 1
        elif metrics.cpu_percent > 80:
            degraded_count += 1
            
        if metrics.memory_percent > 95:
            critical_count += 1
        elif metrics.memory_percent > 85:
            degraded_count += 1
            
        if metrics.response_time > 10:
            critical_count += 1
        elif metrics.response_time > 5:
            degraded_count += 1
            
        if critical_count > 0:
            return PerformanceLevel.CRITICAL
        elif degraded_count > 1:
            return PerformanceLevel.DEGRADED
        elif degraded_count > 0:
            return PerformanceLevel.GOOD
        else:
            return PerformanceLevel.EXCELLENT

    async def _trigger_optimization(self, level: PerformanceLevel, metrics: PerformanceMetrics):
        """最適化トリガー"""
        logger.warning(f"Performance level: {level.value}, triggering optimization")
        
        if level == PerformanceLevel.CRITICAL:
            # 緊急最適化
            await self._emergency_optimization(metrics)
        else:
            # 通常最適化
            await self._routine_optimization(metrics)

    async def _emergency_optimization(self, metrics: PerformanceMetrics):
        """緊急最適化"""
        # メモリクリーンアップ
        if metrics.memory_percent > 90:
            gc.collect()
            
        # CPU負荷軽減
        if metrics.cpu_percent > 90:
            # 低優先度タスクの一時停止など
            pass
            
        logger.info("Emergency optimization completed")

    async def _routine_optimization(self, metrics: PerformanceMetrics):
        """通常最適化"""
        # ガベージコレクション
        if metrics.memory_percent > 80:
            gc.collect()
            
        logger.info("Routine optimization completed")

    def stop_monitoring(self):
        """監視停止"""
        self.monitoring_active = False

    def get_performance_report(self) -> Dict[str, Any]:
        """パフォーマンスレポート取得"""
        if not self.metrics_history:
            return {"error": "No metrics available"}
            
        recent_metrics = list(self.metrics_history)[-100:]  # 直近100件
        
        # 統計計算
        avg_cpu = sum(m.cpu_percent for m in recent_metrics) / len(recent_metrics)
        avg_memory = sum(m.memory_percent for m in recent_metrics) / len(recent_metrics)
        avg_response_time = sum(m.response_time for m in recent_metrics) / len(recent_metrics)
        
        max_cpu = max(m.cpu_percent for m in recent_metrics)
        max_memory = max(m.memory_percent for m in recent_metrics)
        max_response_time = max(m.response_time for m in recent_metrics)
        
        return {
            "period": {
                "start": datetime.fromtimestamp(recent_metrics[0].timestamp).isoformat(),
                "end": datetime.fromtimestamp(recent_metrics[-1].timestamp).isoformat(),
                "samples": len(recent_metrics)
            },
            "averages": {
                "cpu_percent": round(avg_cpu, 2),
                "memory_percent": round(avg_memory, 2),
                "response_time": round(avg_response_time, 4)
            },
            "maximums": {
                "cpu_percent": round(max_cpu, 2),
                "memory_percent": round(max_memory, 2),
                "response_time": round(max_response_time, 4)
            },
            "current_level": self._evaluate_performance_level(recent_metrics[-1]).value,
            "active_alerts": len([a for a in self.alerts if time.time() - a.timestamp < 300]),
            "total_alerts": len(self.alerts)
        }

# グローバルインスタンス
memory_optimizer = MemoryOptimizer()
cpu_optimizer = CPUOptimizer()
io_optimizer = IOOptimizer()
performance_monitor = PerformanceMonitor()
adaptive_rate_limiter = AdaptiveRateLimiter()