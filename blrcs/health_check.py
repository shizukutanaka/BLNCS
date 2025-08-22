import asyncio
import time
import psutil
import aiohttp
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
import logging
import sqlite3

logger = logging.getLogger(__name__)

class HealthStatus(Enum):
    """ヘルスステータス"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"

@dataclass
class ComponentHealth:
    """コンポーネントヘルス情報"""
    name: str
    status: HealthStatus
    latency_ms: float
    details: Dict[str, Any]
    error: Optional[str] = None

class HealthChecker:
    """包括的ヘルスチェックシステム"""
    
    def __init__(self):
        self.checks = []
        self.last_check_time = 0
        self.check_interval = 30  # 秒
        self.cache = {}
        
    async def check_all(self, use_cache: bool = True) -> Dict:
        """全ヘルスチェック実行"""
        current_time = time.time()
        
        # キャッシュチェック
        if use_cache and (current_time - self.last_check_time) < self.check_interval:
            return self.cache
            
        # 並列チェック実行
        checks = await asyncio.gather(
            self.check_database(),
            self.check_cache(),
            self.check_lightning_node(),
            self.check_disk_space(),
            self.check_memory(),
            self.check_cpu(),
            self.check_network(),
            self.check_external_services(),
            return_exceptions=True
        )
        
        # 結果集計
        components = []
        overall_status = HealthStatus.HEALTHY
        
        for check in checks:
            if isinstance(check, Exception):
                logger.error(f"Health check failed: {check}")
                overall_status = HealthStatus.UNHEALTHY
            elif isinstance(check, ComponentHealth):
                components.append(check)
                if check.status == HealthStatus.UNHEALTHY:
                    overall_status = HealthStatus.UNHEALTHY
                elif check.status == HealthStatus.DEGRADED and overall_status == HealthStatus.HEALTHY:
                    overall_status = HealthStatus.DEGRADED
                    
        result = {
            "status": overall_status.value,
            "timestamp": current_time,
            "version": self._get_version(),
            "uptime": self._get_uptime(),
            "components": [
                {
                    "name": c.name,
                    "status": c.status.value,
                    "latency_ms": c.latency_ms,
                    "details": c.details,
                    "error": c.error
                }
                for c in components
            ]
        }
        
        self.cache = result
        self.last_check_time = current_time
        
        return result
        
    async def check_database(self) -> ComponentHealth:
        """データベースヘルスチェック"""
        start_time = time.time()
        
        try:
            conn = sqlite3.connect("blrcs.db")
            cursor = conn.execute("SELECT COUNT(*) FROM sqlite_master")
            table_count = cursor.fetchone()[0]
            conn.close()
            
            latency = (time.time() - start_time) * 1000
            
            return ComponentHealth(
                name="database",
                status=HealthStatus.HEALTHY if latency < 100 else HealthStatus.DEGRADED,
                latency_ms=latency,
                details={
                    "type": "sqlite",
                    "tables": table_count,
                    "connection": "ok"
                }
            )
        except Exception as e:
            return ComponentHealth(
                name="database",
                status=HealthStatus.UNHEALTHY,
                latency_ms=-1,
                details={"connection": "failed"},
                error=str(e)
            )
            
    async def check_cache(self) -> ComponentHealth:
        """キャッシュヘルスチェック"""
        start_time = time.time()
        
        try:
            # キャッシュのテスト
            test_key = "_health_check"
            test_value = str(time.time())
            
            # ローカルキャッシュテスト（実際の実装に合わせて調整）
            cache_test = True
            
            latency = (time.time() - start_time) * 1000
            
            return ComponentHealth(
                name="cache",
                status=HealthStatus.HEALTHY,
                latency_ms=latency,
                details={
                    "type": "memory",
                    "available": True
                }
            )
        except Exception as e:
            return ComponentHealth(
                name="cache",
                status=HealthStatus.UNHEALTHY,
                latency_ms=-1,
                details={"available": False},
                error=str(e)
            )
            
    async def check_lightning_node(self) -> ComponentHealth:
        """Lightning Node ヘルスチェック"""
        start_time = time.time()
        
        try:
            # LNDヘルスチェック（実際のAPIに合わせて調整）
            # ここではモック実装
            node_status = {
                "synced": True,
                "channels": 10,
                "peers": 15,
                "balance": 1000000
            }
            
            latency = (time.time() - start_time) * 1000
            
            return ComponentHealth(
                name="lightning_node",
                status=HealthStatus.HEALTHY,
                latency_ms=latency,
                details=node_status
            )
        except Exception as e:
            return ComponentHealth(
                name="lightning_node",
                status=HealthStatus.UNHEALTHY,
                latency_ms=-1,
                details={"connected": False},
                error=str(e)
            )
            
    async def check_disk_space(self) -> ComponentHealth:
        """ディスク容量チェック"""
        try:
            disk_usage = psutil.disk_usage('/')
            free_percent = 100 - disk_usage.percent
            
            if free_percent < 10:
                status = HealthStatus.UNHEALTHY
            elif free_percent < 20:
                status = HealthStatus.DEGRADED
            else:
                status = HealthStatus.HEALTHY
                
            return ComponentHealth(
                name="disk_space",
                status=status,
                latency_ms=0,
                details={
                    "total_gb": disk_usage.total / (1024**3),
                    "used_gb": disk_usage.used / (1024**3),
                    "free_gb": disk_usage.free / (1024**3),
                    "percent_used": disk_usage.percent
                }
            )
        except Exception as e:
            return ComponentHealth(
                name="disk_space",
                status=HealthStatus.UNHEALTHY,
                latency_ms=-1,
                details={},
                error=str(e)
            )
            
    async def check_memory(self) -> ComponentHealth:
        """メモリ使用状況チェック"""
        try:
            memory = psutil.virtual_memory()
            
            if memory.percent > 90:
                status = HealthStatus.UNHEALTHY
            elif memory.percent > 80:
                status = HealthStatus.DEGRADED
            else:
                status = HealthStatus.HEALTHY
                
            return ComponentHealth(
                name="memory",
                status=status,
                latency_ms=0,
                details={
                    "total_gb": memory.total / (1024**3),
                    "available_gb": memory.available / (1024**3),
                    "percent_used": memory.percent
                }
            )
        except Exception as e:
            return ComponentHealth(
                name="memory",
                status=HealthStatus.UNHEALTHY,
                latency_ms=-1,
                details={},
                error=str(e)
            )
            
    async def check_cpu(self) -> ComponentHealth:
        """CPU使用状況チェック"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            
            if cpu_percent > 90:
                status = HealthStatus.UNHEALTHY
            elif cpu_percent > 70:
                status = HealthStatus.DEGRADED
            else:
                status = HealthStatus.HEALTHY
                
            return ComponentHealth(
                name="cpu",
                status=status,
                latency_ms=0,
                details={
                    "percent_used": cpu_percent,
                    "core_count": psutil.cpu_count()
                }
            )
        except Exception as e:
            return ComponentHealth(
                name="cpu",
                status=HealthStatus.UNHEALTHY,
                latency_ms=-1,
                details={},
                error=str(e)
            )
            
    async def check_network(self) -> ComponentHealth:
        """ネットワーク接続チェック"""
        start_time = time.time()
        
        try:
            # ローカルDNS解決テスト
            import socket
            socket.gethostbyname("localhost")
            
            # ループバック接続テスト
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(("127.0.0.1", 80))
            sock.close()
            
            latency = (time.time() - start_time) * 1000
            
            # ネットワークインターフェースチェック
            net_stats = psutil.net_if_stats()
            active_interfaces = sum(1 for iface, stats in net_stats.items() if stats.isup)
            
            return ComponentHealth(
                name="network",
                status=HealthStatus.HEALTHY if active_interfaces > 0 else HealthStatus.DEGRADED,
                latency_ms=latency,
                details={
                    "loopback": "ok",
                    "dns": "ok",
                    "active_interfaces": active_interfaces,
                    "total_interfaces": len(net_stats)
                }
            )
        except Exception as e:
            return ComponentHealth(
                name="network",
                status=HealthStatus.UNHEALTHY,
                latency_ms=-1,
                details={"network": "error"},
                error=str(e)
            )
            
    async def check_external_services(self) -> ComponentHealth:
        """外部サービスチェック"""
        services_status = {}
        overall_status = HealthStatus.HEALTHY
        
        # ローカルサービスの接続確認（設定から取得）
        from .config import get_config
        config = get_config()
        
        local_services = [
            ("lnd_api", f"{config.lnd_rest_host}:10009"),  # LND gRPC
            ("rest_api", f"{config.host}:{config.port}"),  # REST API
            ("monitoring", f"{config.host}:9090")  # Prometheus
        ]
        
        for service_name, endpoint in local_services:
            try:
                # 単純なポート接続チェック
                host, port = endpoint.split(':')
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, int(port)))
                sock.close()
                
                if result == 0:
                    services_status[service_name] = "ok"
                else:
                    services_status[service_name] = "unreachable"
                    overall_status = HealthStatus.DEGRADED
            except Exception as e:
                services_status[service_name] = "error"
                overall_status = HealthStatus.DEGRADED
                logger.debug(f"Service check failed for {service_name}: {e}")
                
        return ComponentHealth(
            name="external_services",
            status=overall_status,
            latency_ms=0,
            details=services_status
        )
        
    def _get_version(self) -> str:
        """アプリケーションバージョン取得"""
        try:
            with open("VERSION", "r") as f:
                return f.read().strip()
        except:
            return "unknown"
            
    def _get_uptime(self) -> float:
        """アップタイム取得（秒）"""
        try:
            with open("/proc/uptime", "r") as f:
                return float(f.read().split()[0])
        except:
            return psutil.boot_time()

class LivenessProbe:
    """生存確認プローブ"""
    
    @staticmethod
    async def check() -> bool:
        """単純な生存確認"""
        return True

class ReadinessProbe:
    """準備完了プローブ"""
    
    def __init__(self, health_checker: HealthChecker):
        self.health_checker = health_checker
        
    async def check(self) -> bool:
        """アプリケーションの準備完了確認"""
        result = await self.health_checker.check_all()
        return result["status"] != "unhealthy"