"""
BLNCS CLI Commands Package
Organized command structure for maintainable CLI.
"""

from .info_commands import info, balance, status, health
from .channel_commands import channels
from .network_commands import network_test, lightning_ping, system_info
from .management_commands import analyze_channels, connectivity_check, fee_estimate, payment_debug, channel_summary
from .config_commands import config_management, config_get, config_set, config_list, env_template
from .liquidity_commands import liquidity
from .daily_commands import earnings, top_channels, fee_analysis, health_check, backup_data, rebalance_suggestions
from .simple_dashboard import dashboard, system_overview
from .database_commands import db_status, db_optimize, db_cleanup, db_maintenance, db_vacuum
from .fee_automation_commands import fee_automation_status, fee_automation_start, fee_automation_stop, fee_automation_history, fee_automation_test
from .rebalancer_commands import rebalancer_status, rebalancer_start, rebalancer_stop, rebalancer_history, rebalancer_analyze, rebalancer_add_target, rebalancer_remove_target
from .monitoring_commands import monitoring_status, monitoring_start, monitoring_stop, monitoring_alerts, monitoring_history, monitoring_ack, monitoring_resolve, monitoring_metrics
from .security_commands import security_status, security_start, security_stop, security_findings, security_resolve, security_false_positive, security_scan, security_harden
from .connection_commands import quick_connect, connection_scan, connection_reconnect, connection_setup, connection_history, connection_status
from .qr_commands import qr_create, qr_generate, qr_read, qr_scan, qr_list, qr_cleanup
from .discovery_commands import node_discover, node_recommend, node_cached, node_scan_local, node_info
from .update_commands import update_check, update_install, update_config, update_history, update_status, update_cleanup
from .backup_commands import backup_create, backup_list, backup_restore, backup_verify, backup_status, backup_auto, backup_encrypt, backup_cleanup
from .migration_commands import migrate

__all__ = [
    'info', 'balance', 'status', 'health', 'channels', 'network_test', 'lightning_ping', 'system_info',
    'analyze_channels', 'connectivity_check', 'fee_estimate', 'payment_debug', 'channel_summary',
    'config_management', 'config_get', 'config_set', 'config_list', 'env_template', 'liquidity',
    'earnings', 'top_channels', 'fee_analysis', 'health_check', 'backup_data', 'rebalance_suggestions',
    'dashboard', 'system_overview', 'db_status', 'db_optimize', 'db_cleanup', 'db_maintenance', 'db_vacuum',
    'fee_automation_status', 'fee_automation_start', 'fee_automation_stop', 'fee_automation_history', 'fee_automation_test',
    'rebalancer_status', 'rebalancer_start', 'rebalancer_stop', 'rebalancer_history', 'rebalancer_analyze', 'rebalancer_add_target', 'rebalancer_remove_target',
    'monitoring_status', 'monitoring_start', 'monitoring_stop', 'monitoring_alerts', 'monitoring_history', 'monitoring_ack', 'monitoring_resolve', 'monitoring_metrics',
    'security_status', 'security_start', 'security_stop', 'security_findings', 'security_resolve', 'security_false_positive', 'security_scan', 'security_harden',
    'quick_connect', 'connection_scan', 'connection_reconnect', 'connection_setup', 'connection_history', 'connection_status',
    'qr_create', 'qr_generate', 'qr_read', 'qr_scan', 'qr_list', 'qr_cleanup',
    'node_discover', 'node_recommend', 'node_cached', 'node_scan_local', 'node_info',
    'update_check', 'update_install', 'update_config', 'update_history', 'update_status', 'update_cleanup',
    'backup_create', 'backup_list', 'backup_restore', 'backup_verify', 'backup_status', 'backup_auto', 'backup_encrypt', 'backup_cleanup',
    'migrate'
]