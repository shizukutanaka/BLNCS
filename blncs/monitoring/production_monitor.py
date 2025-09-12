"""
Production Monitoring and Alerting System for BLNCS
Comprehensive monitoring with real-time alerts, metrics collection, and dashboards.
"""

import asyncio
import time
import threading
import json
import smtplib
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable, Union
from dataclasses import dataclass, field
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
import queue
import statistics
from collections import defaultdict, deque
import psutil
import socket
import subprocess
import os

try:
    from ..core.database import get_database
    from ..core.config_enhanced import get_config_manager
    from ..lightning.client import create_client, LightningError
    from ..utils.lightweight_fallbacks import get_system_monitor
except ImportError:
    # Fallback for standalone testing
    pass


@dataclass
class Alert:
    """Alert definition"""
    id: str
    level: str  # INFO, WARNING, ERROR, CRITICAL
    title: str
    message: str
    source: str
    timestamp: datetime = field(default_factory=datetime.now)
    acknowledged: bool = False
    resolved: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass  
class Metric:
    """Metric data point"""
    name: str
    value: Union[int, float]
    timestamp: datetime = field(default_factory=datetime.now)
    tags: Dict[str, str] = field(default_factory=dict)
    unit: Optional[str] = None


@dataclass
class HealthCheck:
    """Health check definition"""
    name: str
    check_function: Callable[[], bool]
    interval_seconds: int = 60
    timeout_seconds: int = 30
    critical: bool = False
    last_check: Optional[datetime] = None
    last_result: Optional[bool] = None
    failure_count: int = 0
    max_failures: int = 3


class MetricsCollector:
    """Collects system and application metrics"""
    
    def __init__(self):
        self.metrics_queue = queue.Queue()
        self.collection_thread = None
        self.running = False
        self.collectors = {
            'system': self.collect_system_metrics,
            'lightning': self.collect_lightning_metrics,
            'database': self.collect_database_metrics,
            'application': self.collect_application_metrics
        }
    
    def start(self):
        """Start metrics collection"""
        self.running = True
        self.collection_thread = threading.Thread(target=self._collection_loop)
        self.collection_thread.daemon = True
        self.collection_thread.start()
    
    def stop(self):
        """Stop metrics collection"""
        self.running = False
        if self.collection_thread:
            self.collection_thread.join()
    
    def _collection_loop(self):
        """Main collection loop"""
        while self.running:
            try:
                # Collect all metrics
                for collector_name, collector_func in self.collectors.items():
                    try:
                        metrics = collector_func()
                        for metric in metrics:
                            self.metrics_queue.put(metric)
                    except Exception as e:
                        logging.error(f"Error in {collector_name} collector: {e}")
                
                time.sleep(30)  # Collect every 30 seconds
                
            except Exception as e:
                logging.error(f"Error in metrics collection loop: {e}")
                time.sleep(60)  # Wait longer on error
    
    def collect_system_metrics(self) -> List[Metric]:
        """Collect system performance metrics"""
        metrics = []
        
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            metrics.append(Metric('system_cpu_percent', cpu_percent, unit='percent'))
            
            # Memory metrics
            memory = psutil.virtual_memory()
            metrics.append(Metric('system_memory_percent', memory.percent, unit='percent'))
            metrics.append(Metric('system_memory_used', memory.used, unit='bytes'))
            metrics.append(Metric('system_memory_available', memory.available, unit='bytes'))
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            metrics.append(Metric('system_disk_percent', disk.percent, unit='percent'))
            metrics.append(Metric('system_disk_used', disk.used, unit='bytes'))
            metrics.append(Metric('system_disk_free', disk.free, unit='bytes'))
            
            # Network metrics
            network = psutil.net_io_counters()
            metrics.append(Metric('system_network_bytes_sent', network.bytes_sent, unit='bytes'))
            metrics.append(Metric('system_network_bytes_recv', network.bytes_recv, unit='bytes'))
            
            # Load average (Unix systems)
            try:
                load_avg = os.getloadavg()
                metrics.append(Metric('system_load_1min', load_avg[0]))
                metrics.append(Metric('system_load_5min', load_avg[1]))
                metrics.append(Metric('system_load_15min', load_avg[2]))
            except (OSError, AttributeError):
                pass  # Not available on Windows
            
        except Exception as e:
            logging.error(f"Error collecting system metrics: {e}")
        
        return metrics
    
    def collect_lightning_metrics(self) -> List[Metric]:
        """Collect Lightning Network metrics"""
        metrics = []
        
        try:
            config = get_config_manager()
            client = create_client(
                host=config.get('lightning.host', 'localhost'),
                port=config.get('lightning.port', 8080),
                enhanced=True
            )
            
            if client.connect():
                # Node info metrics
                info = client.get_info()
                metrics.append(Metric('lightning_num_active_channels', info.get('num_active_channels', 0)))
                metrics.append(Metric('lightning_num_peers', info.get('num_peers', 0)))
                metrics.append(Metric('lightning_block_height', info.get('block_height', 0)))
                metrics.append(Metric('lightning_synced_to_chain', 1 if info.get('synced_to_chain') else 0))
                
                # Balance metrics
                balance = client.get_balance()
                metrics.append(Metric('lightning_wallet_balance', int(balance.get('confirmed_balance', 0)), unit='satoshis'))
                
                # Channel metrics
                if hasattr(client, 'get_channel_balance'):
                    channel_balance = client.get_channel_balance()
                    metrics.append(Metric('lightning_channel_balance', int(channel_balance.get('balance', 0)), unit='satoshis'))
                
                client.disconnect()
            
        except Exception as e:
            logging.error(f"Error collecting Lightning metrics: {e}")
            metrics.append(Metric('lightning_connection_error', 1))
        
        return metrics
    
    def collect_database_metrics(self) -> List[Metric]:
        """Collect database performance metrics"""
        metrics = []
        
        try:
            db = get_database()
            stats = db.get_database_stats()
            
            metrics.append(Metric('database_size_mb', stats.get('database_size_mb', 0), unit='megabytes'))
            metrics.append(Metric('database_available_connections', stats.get('available_connections', 0)))
            metrics.append(Metric('database_total_queries', stats.get('total_queries_tracked', 0)))
            
            # Table row counts
            table_counts = stats.get('table_row_counts', {})
            for table, count in table_counts.items():
                metrics.append(Metric(f'database_table_rows_{table}', count, tags={'table': table}))
            
        except Exception as e:
            logging.error(f"Error collecting database metrics: {e}")
        
        return metrics
    
    def collect_application_metrics(self) -> List[Metric]:
        """Collect BLNCS application metrics"""
        metrics = []
        
        try:
            # Process metrics
            process = psutil.Process()
            metrics.append(Metric('app_memory_percent', process.memory_percent(), unit='percent'))
            metrics.append(Metric('app_cpu_percent', process.cpu_percent(), unit='percent'))
            
            # File descriptor count (Unix)
            try:
                metrics.append(Metric('app_open_files', process.num_fds()))
            except AttributeError:
                pass  # Not available on Windows
            
            # Thread count
            metrics.append(Metric('app_thread_count', process.num_threads()))
            
            # Uptime
            create_time = datetime.fromtimestamp(process.create_time())
            uptime_seconds = (datetime.now() - create_time).total_seconds()
            metrics.append(Metric('app_uptime_seconds', uptime_seconds, unit='seconds'))
            
        except Exception as e:
            logging.error(f"Error collecting application metrics: {e}")
        
        return metrics
    
    def get_metrics(self, timeout: float = 1.0) -> List[Metric]:
        """Get collected metrics"""
        metrics = []
        end_time = time.time() + timeout
        
        while time.time() < end_time and not self.metrics_queue.empty():
            try:
                metric = self.metrics_queue.get_nowait()
                metrics.append(metric)
            except queue.Empty:
                break
        
        return metrics


class AlertManager:
    """Manages alerts and notifications"""
    
    def __init__(self):
        self.alerts: Dict[str, Alert] = {}
        self.alert_rules = {}
        self.notification_channels = {}
        self.alert_history = deque(maxlen=1000)
        self.suppression_rules = {}
    
    def add_alert_rule(self, rule_id: str, condition: Callable[[List[Metric]], bool],
                      level: str, title: str, message_template: str):
        """Add alert rule"""
        self.alert_rules[rule_id] = {
            'condition': condition,
            'level': level,
            'title': title,
            'message_template': message_template
        }
    
    def add_notification_channel(self, channel_id: str, channel_type: str, config: Dict[str, Any]):
        """Add notification channel"""
        if channel_type == 'email':
            self.notification_channels[channel_id] = EmailNotificationChannel(config)
        elif channel_type == 'webhook':
            self.notification_channels[channel_id] = WebhookNotificationChannel(config)
        elif channel_type == 'slack':
            self.notification_channels[channel_id] = SlackNotificationChannel(config)
    
    def evaluate_metrics(self, metrics: List[Metric]):
        """Evaluate metrics against alert rules"""
        for rule_id, rule in self.alert_rules.items():
            try:
                if rule['condition'](metrics):
                    self.fire_alert(rule_id, rule)
            except Exception as e:
                logging.error(f"Error evaluating alert rule {rule_id}: {e}")
    
    def fire_alert(self, rule_id: str, rule: Dict[str, Any]):
        """Fire an alert"""
        alert = Alert(
            id=rule_id,
            level=rule['level'],
            title=rule['title'],
            message=rule['message_template'],
            source='monitoring_system'
        )
        
        # Check suppression
        if self.is_suppressed(alert):
            return
        
        # Store alert
        self.alerts[alert.id] = alert
        self.alert_history.append(alert)
        
        # Send notifications
        self.send_notifications(alert)
        
        logging.warning(f"Alert fired: {alert.title}")
    
    def is_suppressed(self, alert: Alert) -> bool:
        """Check if alert should be suppressed"""
        # Simple time-based suppression
        for existing_alert in self.alert_history:
            if (existing_alert.id == alert.id and 
                not existing_alert.resolved and
                (alert.timestamp - existing_alert.timestamp).total_seconds() < 300):  # 5 minutes
                return True
        return False
    
    def send_notifications(self, alert: Alert):
        """Send alert notifications"""
        for channel_id, channel in self.notification_channels.items():
            try:
                channel.send_alert(alert)
            except Exception as e:
                logging.error(f"Failed to send alert via {channel_id}: {e}")
    
    def acknowledge_alert(self, alert_id: str, user: str = "system"):
        """Acknowledge an alert"""
        if alert_id in self.alerts:
            self.alerts[alert_id].acknowledged = True
            logging.info(f"Alert {alert_id} acknowledged by {user}")
    
    def resolve_alert(self, alert_id: str, user: str = "system"):
        """Resolve an alert"""
        if alert_id in self.alerts:
            self.alerts[alert_id].resolved = True
            logging.info(f"Alert {alert_id} resolved by {user}")
    
    def get_active_alerts(self) -> List[Alert]:
        """Get currently active alerts"""
        return [alert for alert in self.alerts.values() 
               if not alert.resolved]
    
    def get_alert_summary(self) -> Dict[str, Any]:
        """Get alert summary statistics"""
        active_alerts = self.get_active_alerts()
        
        level_counts = defaultdict(int)
        for alert in active_alerts:
            level_counts[alert.level] += 1
        
        return {
            'total_active': len(active_alerts),
            'by_level': dict(level_counts),
            'total_alerts_today': len([a for a in self.alert_history 
                                     if a.timestamp.date() == datetime.now().date()])
        }


class NotificationChannel:
    """Base class for notification channels"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
    
    def send_alert(self, alert: Alert):
        """Send alert notification"""
        raise NotImplementedError


class EmailNotificationChannel(NotificationChannel):
    """Email notification channel"""
    
    def send_alert(self, alert: Alert):
        """Send email notification"""
        try:
            smtp_config = self.config.get('smtp', {})
            
            msg = MIMEMultipart()
            msg['From'] = smtp_config.get('from_address')
            msg['To'] = ', '.join(self.config.get('recipients', []))
            msg['Subject'] = f"[BLNCS] {alert.level}: {alert.title}"
            
            body = f"""
Alert Details:
--------------
Level: {alert.level}
Title: {alert.title}
Message: {alert.message}
Source: {alert.source}
Time: {alert.timestamp}

Alert ID: {alert.id}
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(smtp_config.get('host', 'localhost'), 
                                smtp_config.get('port', 587))
            
            if smtp_config.get('use_tls', True):
                server.starttls()
            
            if smtp_config.get('username'):
                server.login(smtp_config['username'], smtp_config['password'])
            
            server.send_message(msg)
            server.quit()
            
        except Exception as e:
            logging.error(f"Failed to send email alert: {e}")


class WebhookNotificationChannel(NotificationChannel):
    """Webhook notification channel"""
    
    def send_alert(self, alert: Alert):
        """Send webhook notification"""
        try:
            import requests
            
            payload = {
                'alert_id': alert.id,
                'level': alert.level,
                'title': alert.title,
                'message': alert.message,
                'source': alert.source,
                'timestamp': alert.timestamp.isoformat(),
                'metadata': alert.metadata
            }
            
            response = requests.post(
                self.config['webhook_url'],
                json=payload,
                timeout=10,
                headers=self.config.get('headers', {})
            )
            response.raise_for_status()
            
        except Exception as e:
            logging.error(f"Failed to send webhook alert: {e}")


class SlackNotificationChannel(NotificationChannel):
    """Slack notification channel"""
    
    def send_alert(self, alert: Alert):
        """Send Slack notification"""
        try:
            import requests
            
            color_map = {
                'INFO': 'good',
                'WARNING': 'warning', 
                'ERROR': 'danger',
                'CRITICAL': 'danger'
            }
            
            payload = {
                'text': f"BLNCS Alert: {alert.title}",
                'attachments': [{
                    'color': color_map.get(alert.level, 'warning'),
                    'fields': [
                        {'title': 'Level', 'value': alert.level, 'short': True},
                        {'title': 'Source', 'value': alert.source, 'short': True},
                        {'title': 'Time', 'value': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'), 'short': True},
                        {'title': 'Message', 'value': alert.message, 'short': False}
                    ]
                }]
            }
            
            response = requests.post(
                self.config['webhook_url'],
                json=payload,
                timeout=10
            )
            response.raise_for_status()
            
        except Exception as e:
            logging.error(f"Failed to send Slack alert: {e}")


class HealthChecker:
    """System health checker"""
    
    def __init__(self):
        self.checks: Dict[str, HealthCheck] = {}
        self.running = False
        self.check_thread = None
    
    def add_check(self, check: HealthCheck):
        """Add health check"""
        self.checks[check.name] = check
    
    def start(self):
        """Start health checking"""
        self.running = True
        self.check_thread = threading.Thread(target=self._check_loop)
        self.check_thread.daemon = True
        self.check_thread.start()
    
    def stop(self):
        """Stop health checking"""
        self.running = False
        if self.check_thread:
            self.check_thread.join()
    
    def _check_loop(self):
        """Main health check loop"""
        while self.running:
            try:
                for check in self.checks.values():
                    if self._should_run_check(check):
                        self._run_check(check)
                
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                logging.error(f"Error in health check loop: {e}")
                time.sleep(60)
    
    def _should_run_check(self, check: HealthCheck) -> bool:
        """Check if health check should run"""
        if not check.last_check:
            return True
        
        elapsed = (datetime.now() - check.last_check).total_seconds()
        return elapsed >= check.interval_seconds
    
    def _run_check(self, check: HealthCheck):
        """Run individual health check"""
        try:
            check.last_check = datetime.now()
            result = check.check_function()
            
            if result:
                check.failure_count = 0
                check.last_result = True
            else:
                check.failure_count += 1
                check.last_result = False
                
                if check.failure_count >= check.max_failures:
                    logging.error(f"Health check failed: {check.name}")
                    # Could fire alert here
            
        except Exception as e:
            logging.error(f"Error running health check {check.name}: {e}")
            check.failure_count += 1
            check.last_result = False
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get overall health status"""
        total_checks = len(self.checks)
        passing_checks = sum(1 for check in self.checks.values() 
                           if check.last_result is True)
        
        critical_failing = sum(1 for check in self.checks.values()
                              if check.critical and check.last_result is False)
        
        return {
            'overall_healthy': critical_failing == 0,
            'total_checks': total_checks,
            'passing_checks': passing_checks,
            'failing_checks': total_checks - passing_checks,
            'critical_failing': critical_failing,
            'checks': {name: {
                'last_result': check.last_result,
                'last_check': check.last_check.isoformat() if check.last_check else None,
                'failure_count': check.failure_count,
                'critical': check.critical
            } for name, check in self.checks.items()}
        }


class ProductionMonitor:
    """Main production monitoring system"""
    
    def __init__(self):
        self.metrics_collector = MetricsCollector()
        self.alert_manager = AlertManager()
        self.health_checker = HealthChecker()
        self.running = False
        self.main_thread = None
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('blncs_monitor.log'),
                logging.StreamHandler()
            ]
        )
        
        self.setup_default_rules()
        self.setup_health_checks()
    
    def setup_default_rules(self):
        """Setup default alert rules"""
        # High CPU usage
        self.alert_manager.add_alert_rule(
            'high_cpu_usage',
            lambda metrics: any(m.name == 'system_cpu_percent' and m.value > 90 for m in metrics),
            'WARNING',
            'High CPU Usage',
            'System CPU usage is above 90%'
        )
        
        # High memory usage
        self.alert_manager.add_alert_rule(
            'high_memory_usage',
            lambda metrics: any(m.name == 'system_memory_percent' and m.value > 85 for m in metrics),
            'WARNING',
            'High Memory Usage',
            'System memory usage is above 85%'
        )
        
        # Low disk space
        self.alert_manager.add_alert_rule(
            'low_disk_space',
            lambda metrics: any(m.name == 'system_disk_percent' and m.value > 90 for m in metrics),
            'CRITICAL',
            'Low Disk Space',
            'System disk usage is above 90%'
        )
        
        # Lightning connection error
        self.alert_manager.add_alert_rule(
            'lightning_connection_error',
            lambda metrics: any(m.name == 'lightning_connection_error' for m in metrics),
            'ERROR',
            'Lightning Connection Failed',
            'Unable to connect to Lightning node'
        )
    
    def setup_health_checks(self):
        """Setup health checks"""
        # Lightning node connectivity
        def check_lightning():
            try:
                config = get_config_manager()
                client = create_client(
                    host=config.get('lightning.host', 'localhost'),
                    port=config.get('lightning.port', 8080)
                )
                result = client.connect()
                if result:
                    client.disconnect()
                return result
            except:
                return False
        
        self.health_checker.add_check(HealthCheck(
            name='lightning_connectivity',
            check_function=check_lightning,
            interval_seconds=60,
            critical=True
        ))
        
        # Database connectivity
        def check_database():
            try:
                db = get_database()
                # Simple test query
                result = db.execute("SELECT 1")
                return len(result) > 0
            except:
                return False
        
        self.health_checker.add_check(HealthCheck(
            name='database_connectivity',
            check_function=check_database,
            interval_seconds=30,
            critical=True
        ))
    
    def start(self):
        """Start monitoring system"""
        logging.info("Starting BLNCS Production Monitor")
        
        self.running = True
        
        # Start subsystems
        self.metrics_collector.start()
        self.health_checker.start()
        
        # Start main monitoring loop
        self.main_thread = threading.Thread(target=self._monitoring_loop)
        self.main_thread.daemon = True
        self.main_thread.start()
    
    def stop(self):
        """Stop monitoring system"""
        logging.info("Stopping BLNCS Production Monitor")
        
        self.running = False
        
        # Stop subsystems
        self.metrics_collector.stop()
        self.health_checker.stop()
        
        if self.main_thread:
            self.main_thread.join()
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Get collected metrics
                metrics = self.metrics_collector.get_metrics()
                
                if metrics:
                    # Store metrics in database
                    self._store_metrics(metrics)
                    
                    # Evaluate alert rules
                    self.alert_manager.evaluate_metrics(metrics)
                
                time.sleep(30)  # Main loop every 30 seconds
                
            except Exception as e:
                logging.error(f"Error in monitoring loop: {e}")
                time.sleep(60)
    
    def _store_metrics(self, metrics: List[Metric]):
        """Store metrics in database"""
        try:
            db = get_database()
            for metric in metrics:
                db.record_metric(
                    metric.name,
                    metric.value,
                    {'unit': metric.unit, **metric.tags}
                )
        except Exception as e:
            logging.error(f"Failed to store metrics: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get monitoring system status"""
        return {
            'running': self.running,
            'health': self.health_checker.get_health_status(),
            'alerts': self.alert_manager.get_alert_summary(),
            'uptime': time.time() - (hasattr(self, 'start_time') and self.start_time or time.time())
        }


# Global monitor instance
_monitor: Optional[ProductionMonitor] = None

def get_production_monitor() -> ProductionMonitor:
    """Get global production monitor"""
    global _monitor
    if _monitor is None:
        _monitor = ProductionMonitor()
    return _monitor


def main():
    """CLI entry point for monitoring system"""
    import argparse
    import signal
    
    parser = argparse.ArgumentParser(description="BLNCS Production Monitor")
    parser.add_argument('--config', type=str, help='Configuration file path')
    parser.add_argument('--daemon', action='store_true', help='Run as daemon')
    
    args = parser.parse_args()
    
    monitor = get_production_monitor()
    
    # Setup signal handlers
    def signal_handler(sig, frame):
        print("\nShutting down monitor...")
        monitor.stop()
        exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start monitoring
    monitor.start()
    
    print("BLNCS Production Monitor started")
    print("Press Ctrl+C to stop")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()


if __name__ == "__main__":
    main()