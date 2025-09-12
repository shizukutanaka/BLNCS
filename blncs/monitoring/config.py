#!/usr/bin/env python3
"""
BLNCS Production Monitoring Configuration
Centralized configuration management for monitoring and alerting.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from datetime import timedelta

logger = logging.getLogger(__name__)


@dataclass
class MetricThreshold:
    """Configuration for metric threshold alerting"""
    name: str
    warning_threshold: float
    critical_threshold: float
    comparison: str = "greater"  # greater, less, equal
    enabled: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AlertChannel:
    """Configuration for alert notification channels"""
    type: str  # email, webhook, slack, console
    name: str
    config: Dict[str, Any]
    enabled: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MonitoringConfig:
    """Main monitoring configuration"""
    # Collection intervals (seconds)
    system_metrics_interval: int = 30
    lightning_metrics_interval: int = 60
    database_metrics_interval: int = 120
    application_metrics_interval: int = 45
    
    # Retention settings
    metrics_retention_days: int = 30
    alerts_retention_days: int = 90
    
    # Alert settings
    alert_cooldown_minutes: int = 15
    max_alerts_per_hour: int = 10
    
    # Health check settings
    health_check_interval: int = 30
    health_check_timeout: int = 10
    
    # Storage settings
    metrics_storage_path: str = "data/metrics"
    alerts_storage_path: str = "data/alerts"
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MonitoringConfigManager:
    """Manages monitoring configuration with validation and hot-reload"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = Path(config_path or "config/monitoring.json")
        self.config = MonitoringConfig()
        self.thresholds: Dict[str, MetricThreshold] = {}
        self.alert_channels: Dict[str, AlertChannel] = {}
        self.load_config()
        
    def load_config(self):
        """Load configuration from file"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Load main config
                if 'monitoring' in data:
                    self.config = MonitoringConfig(**data['monitoring'])
                
                # Load thresholds
                if 'thresholds' in data:
                    self.thresholds = {
                        name: MetricThreshold(**threshold_data)
                        for name, threshold_data in data['thresholds'].items()
                    }
                
                # Load alert channels
                if 'alert_channels' in data:
                    self.alert_channels = {
                        name: AlertChannel(**channel_data)
                        for name, channel_data in data['alert_channels'].items()
                    }
                
                logger.info(f"Monitoring configuration loaded from {self.config_path}")
            else:
                self._create_default_config()
                
        except Exception as e:
            logger.error(f"Failed to load monitoring config: {e}")
            self._create_default_config()
    
    def _create_default_config(self):
        """Create default monitoring configuration"""
        logger.info("Creating default monitoring configuration")
        
        # Default thresholds
        self.thresholds = {
            'cpu_usage': MetricThreshold(
                name='cpu_usage',
                warning_threshold=70.0,
                critical_threshold=90.0,
                comparison='greater'
            ),
            'memory_usage': MetricThreshold(
                name='memory_usage',
                warning_threshold=80.0,
                critical_threshold=95.0,
                comparison='greater'
            ),
            'disk_usage': MetricThreshold(
                name='disk_usage',
                warning_threshold=85.0,
                critical_threshold=95.0,
                comparison='greater'
            ),
            'lightning_channels_offline': MetricThreshold(
                name='lightning_channels_offline',
                warning_threshold=1.0,
                critical_threshold=3.0,
                comparison='greater'
            ),
            'database_query_time': MetricThreshold(
                name='database_query_time',
                warning_threshold=1000.0,  # ms
                critical_threshold=5000.0,
                comparison='greater'
            ),
            'application_response_time': MetricThreshold(
                name='application_response_time',
                warning_threshold=2000.0,  # ms
                critical_threshold=10000.0,
                comparison='greater'
            )
        }
        
        # Default alert channels
        self.alert_channels = {
            'console': AlertChannel(
                type='console',
                name='Console Alerts',
                config={},
                enabled=True
            ),
            'email': AlertChannel(
                type='email',
                name='Email Alerts',
                config={
                    'smtp_server': 'smtp.gmail.com',
                    'smtp_port': 587,
                    'username': '',
                    'password': '',
                    'from_email': '',
                    'to_emails': []
                },
                enabled=False
            ),
            'webhook': AlertChannel(
                type='webhook',
                name='Webhook Alerts',
                config={
                    'url': '',
                    'method': 'POST',
                    'headers': {
                        'Content-Type': 'application/json'
                    },
                    'timeout': 30
                },
                enabled=False
            )
        }
        
        self.save_config()
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            
            config_data = {
                'monitoring': self.config.to_dict(),
                'thresholds': {
                    name: threshold.to_dict()
                    for name, threshold in self.thresholds.items()
                },
                'alert_channels': {
                    name: channel.to_dict()
                    for name, channel in self.alert_channels.items()
                }
            }
            
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Monitoring configuration saved to {self.config_path}")
            
        except Exception as e:
            logger.error(f"Failed to save monitoring config: {e}")
    
    def get_threshold(self, metric_name: str) -> Optional[MetricThreshold]:
        """Get threshold configuration for a metric"""
        return self.thresholds.get(metric_name)
    
    def set_threshold(self, metric_name: str, threshold: MetricThreshold):
        """Set threshold configuration for a metric"""
        self.thresholds[metric_name] = threshold
        self.save_config()
    
    def get_alert_channel(self, channel_name: str) -> Optional[AlertChannel]:
        """Get alert channel configuration"""
        return self.alert_channels.get(channel_name)
    
    def set_alert_channel(self, channel_name: str, channel: AlertChannel):
        """Set alert channel configuration"""
        self.alert_channels[channel_name] = channel
        self.save_config()
    
    def get_enabled_alert_channels(self) -> List[AlertChannel]:
        """Get all enabled alert channels"""
        return [
            channel for channel in self.alert_channels.values()
            if channel.enabled
        ]
    
    def validate_config(self) -> List[str]:
        """Validate current configuration and return any issues"""
        issues = []
        
        # Validate intervals
        if self.config.system_metrics_interval < 5:
            issues.append("System metrics interval should be at least 5 seconds")
        
        if self.config.lightning_metrics_interval < 10:
            issues.append("Lightning metrics interval should be at least 10 seconds")
        
        # Validate thresholds
        for name, threshold in self.thresholds.items():
            if threshold.warning_threshold >= threshold.critical_threshold:
                issues.append(f"Warning threshold for {name} should be less than critical threshold")
        
        # Validate alert channels
        for name, channel in self.alert_channels.items():
            if channel.enabled:
                if channel.type == 'email':
                    config = channel.config
                    if not config.get('smtp_server'):
                        issues.append(f"Email channel {name} missing SMTP server")
                    if not config.get('to_emails'):
                        issues.append(f"Email channel {name} missing recipient emails")
                elif channel.type == 'webhook':
                    if not channel.config.get('url'):
                        issues.append(f"Webhook channel {name} missing URL")
        
        return issues
    
    def reload_config(self):
        """Reload configuration from file"""
        logger.info("Reloading monitoring configuration")
        self.load_config()


# Global configuration instance
config_manager = MonitoringConfigManager()


def get_config() -> MonitoringConfig:
    """Get the current monitoring configuration"""
    return config_manager.config


def get_threshold(metric_name: str) -> Optional[MetricThreshold]:
    """Get threshold for a specific metric"""
    return config_manager.get_threshold(metric_name)


def get_alert_channels() -> List[AlertChannel]:
    """Get all enabled alert channels"""
    return config_manager.get_enabled_alert_channels()


if __name__ == "__main__":
    # Test configuration loading
    import tempfile
    
    with tempfile.TemporaryDirectory() as temp_dir:
        config_path = Path(temp_dir) / "test_monitoring.json"
        test_config = MonitoringConfigManager(str(config_path))
        
        print("Default configuration created:")
        print(f"System metrics interval: {test_config.config.system_metrics_interval}s")
        print(f"Number of thresholds: {len(test_config.thresholds)}")
        print(f"Number of alert channels: {len(test_config.alert_channels)}")
        
        # Validate configuration
        issues = test_config.validate_config()
        if issues:
            print(f"\nConfiguration issues found: {issues}")
        else:
            print("\nConfiguration validation passed")