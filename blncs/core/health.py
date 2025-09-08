"""
BLNCS Health Check Functionality
Lightweight system health monitoring.
"""

import os
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# psutil is treated as an optional dependency for lightweight operation
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from .logger import get_logger
from .config import get_config
from .connection_pool import ConnectionPool
from ..lightning.client import LightningClient


class HealthChecker:
    """Lightweight system health checker"""
    
    def __init__(self) -> None:
        self.logger = get_logger(__name__)
        self.config = get_config()
        
    def check_system_resources(self) -> Dict[str, Any]:
        """Check system resources"""
        if not PSUTIL_AVAILABLE:
            return {
                'error': 'psutil not available',
                'status': 'warning',
                'message': 'psutil is required for system resource checks'
            }
        
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory usage
            memory = psutil.virtual_memory()
            
            # Disk usage
            disk = psutil.disk_usage('/')
            
            return {
                'cpu': {
                    'percent': cpu_percent,
                    'status': 'healthy' if cpu_percent < 80 else 'warning' if cpu_percent < 95 else 'critical'
                },
                'memory': {
                    'percent': memory.percent,
                    'available_mb': memory.available / 1024 / 1024,
                    'status': 'healthy' if memory.percent < 80 else 'warning' if memory.percent < 95 else 'critical'
                },
                'disk': {
                    'percent': (disk.used / disk.total) * 100,
                    'free_gb': disk.free / 1024 / 1024 / 1024,
                    'status': 'healthy' if disk.free > 1024**3 else 'warning' if disk.free > 500*1024**2 else 'critical'
                }
            }
        except Exception as e:
            self.logger.error(f"System resource check error: {e}")
            return {'error': str(e)}
    
    def check_lightning_node(self) -> Dict[str, Any]:
        """Check Lightning node connection status"""
        try:
            client = LightningClient(self.config.data)
            # Connection test
            start_time = time.time()
            info = client.get_info()
            response_time = time.time() - start_time
            
            # Auto-reconnect logic is handled by connection pool
            
            return {
                'connected': True,
                'response_time_ms': round(response_time * 1000, 2),
                'node_alias': info.get('alias', 'Unknown'),
                'synced_to_chain': info.get('synced_to_chain', False),
                'synced_to_graph': info.get('synced_to_graph', False),
                'status': 'healthy' if info.get('synced_to_chain') else 'warning'
            }
        except Exception as e:
            # Connection failure - pool will handle retry
            
            return {
                'connected': False,
                'error': str(e),
                'status': 'critical',
                'auto_retry_active': True
            }
    
    def check_file_system(self) -> Dict[str, Any]:
        """Check file system status"""
        checks = {}
        
        # Check existence of important directories
        important_dirs = ['config', 'data', 'logs']
        for dir_name in important_dirs:
            dir_path = Path(dir_name)
            checks[f'{dir_name}_exists'] = dir_path.exists()
        
        # Check configuration file
        config_file = Path("config/config.yaml")
        checks['config_file_exists'] = config_file.exists()
        
        if config_file.exists():
            checks['config_file_readable'] = config_file.is_file() and os.access(config_file, os.R_OK)
        
        # データディレクトリの書き込み権限確認
        data_dir = Path("data")
        if data_dir.exists():
            checks['data_dir_writable'] = os.access(data_dir, os.W_OK)
        
        # 履歴ファイルの確認
        history_file = data_dir / "transaction_history.json"
        if history_file.exists():
            stat = history_file.stat()
            checks['history_file_size_mb'] = round(stat.st_size / 1024 / 1024, 2)
        
        # 全体の状態を判定
        all_critical_checks = [
            checks.get('config_exists', False),
            checks.get('data_exists', False),
            checks.get('config_file_readable', True)
        ]
        
        checks['filesystem_status'] = 'healthy' if all(all_critical_checks) else 'warning'
        
        return checks
    
    def check_network_connectivity(self) -> Dict[str, Any]:
        """ネットワーク接続性をチェック"""
        try:
            import socket
            
            # DNS解決テスト
            start_time = time.time()
            socket.gethostbyname('google.com')
            dns_time = time.time() - start_time
            
            # Lightning ノードへの接続テスト
            ln_config = self.config.get('lightning', {})
            ln_host = ln_config.get('host', 'localhost')
            ln_port = ln_config.get('port', 8080)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            start_time = time.time()
            result = sock.connect_ex((ln_host, ln_port))
            connect_time = time.time() - start_time
            sock.close()
            
            return {
                'internet_available': True,
                'dns_response_time_ms': round(dns_time * 1000, 2),
                'lightning_port_open': result == 0,
                'lightning_connect_time_ms': round(connect_time * 1000, 2),
                'status': 'healthy' if result == 0 else 'warning'
            }
            
        except Exception as e:
            return {
                'internet_available': False,
                'error': str(e),
                'status': 'critical'
            }
    
    def run_full_health_check(self) -> Dict[str, Any]:
        """完全なヘルスチェックを実行"""
        self.logger.info("フルヘルスチェックを開始...")
        
        health_report = {
            'timestamp': datetime.now().isoformat(),
            'overall_status': 'unknown',
            'checks': {}
        }
        
        # 各チェックを実行
        checks = [
            ('system_resources', self.check_system_resources),
            ('lightning_node', self.check_lightning_node),
            ('file_system', self.check_file_system),
            ('network', self.check_network_connectivity)
        ]
        
        status_scores = {'healthy': 2, 'warning': 1, 'critical': 0, 'unknown': 0}
        total_score = 0
        max_possible_score = 0
        
        for check_name, check_func in checks:
            try:
                result = check_func()
                health_report['checks'][check_name] = result
                
                # ステータススコアを計算
                status = result.get('status', 'unknown')
                total_score += status_scores.get(status, 0)
                max_possible_score += 2
                
            except Exception as e:
                self.logger.error(f"{check_name} チェック中にエラー: {e}")
                health_report['checks'][check_name] = {
                    'error': str(e),
                    'status': 'critical'
                }
                max_possible_score += 2
        
        # 全体的なステータスを決定
        if max_possible_score > 0:
            health_ratio = total_score / max_possible_score
            if health_ratio >= 0.8:
                health_report['overall_status'] = 'healthy'
            elif health_ratio >= 0.5:
                health_report['overall_status'] = 'warning'
            else:
                health_report['overall_status'] = 'critical'
        
        health_report['health_score'] = f"{total_score}/{max_possible_score}"
        
        self.logger.info(f"ヘルスチェック完了: {health_report['overall_status']} ({health_report['health_score']})")
        return health_report
    
    def get_quick_status(self) -> Dict[str, Any]:
        """クイックステータスチェック（軽量版）"""
        try:
            # Lightning ノードの簡単なチェック
            ln_status = 'unknown'
            try:
                client = LightningClient(self.config.data)
                client.get_info()
                ln_status = 'connected'
            except:
                ln_status = 'disconnected'
            
            result = {
                'timestamp': datetime.now().isoformat(),
                'lightning_node': ln_status,
            }
            
            # psutilが利用可能な場合のみシステムリソース情報を追加
            if PSUTIL_AVAILABLE:
                cpu = psutil.cpu_percent(interval=0.1)
                memory = psutil.virtual_memory()
                result['cpu_percent'] = cpu
                result['memory_percent'] = memory.percent
                result['status'] = 'healthy' if cpu < 90 and memory.percent < 90 and ln_status == 'connected' else 'warning'
            else:
                result['status'] = 'healthy' if ln_status == 'connected' else 'warning'
                result['note'] = 'psutil not available - limited system info'
            
            return result
            
        except Exception as e:
            return {
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'status': 'critical'
            }


def get_health_checker() -> HealthChecker:
    """ヘルスチェッカーインスタンスを取得"""
    return HealthChecker()