"""
BLNCS CLI Commands Package
Lightweight command structure - only essential commands loaded.
"""

# Import only essential lightweight commands - lazy loading for others
# Basic commands are imported on demand to reduce startup time

# Essential commands only - lightweight version without database dependencies

# Essential commands only - lightweight version without database dependencies
__all__ = [
    'info', 'balance', 'channels', 'system_info', 'health_check',
    'config_get', 'config_set', 'lightning_ping', 'connectivity_check',
    'dashboard', 'status', 'setup', 'validate_config',
    'create_invoice', 'pay_invoice', 'estimate_fee', 'payment_history', 'test_payment',
    'create_backup', 'restore_backup', 'list_backups',
    'analyze_fees', 'optimize_fees', 'fee_report', 'estimate_routing_fee', 'fee_policy_wizard',
    'transaction_history', 'transaction_stats', 'sync_history', 'export_history', 'payment_patterns',
    'discover_nodes', 'score_node', 'recommend_nodes', 'analyze_network',
    'monitoring_status', 'monitoring_start', 'monitoring_stop', 'monitoring_alerts',
    'monitoring_history', 'monitoring_ack', 'monitoring_resolve', 'monitoring_metrics',
    'alert_status', 'alert_list', 'alert_history', 'alert_ack', 'alert_resolve',
    'alert_channels', 'alert_add_channel', 'alert_test_channel', 'alert_rules',
    'export_all', 'export_summary', 'export_from_backup',
    'analyze_routes', 'routing_performance', 'routing_suggestions', 'routing_stress_test',
    'security_status', 'security_start', 'security_stop', 'security_findings',
    'security_resolve', 'security_false_positive', 'security_scan', 'security_harden',
    'network_topology', 'network_hubs', 'network_node_analysis', 'network_paths',
    'network_changes', 'network_benchmarks', 'network_export',
    'predict_liquidity', 'predict_revenue', 'predict_failures', 'predict_market_trends',
    'optimize_predictions', 'prediction_dashboard'
]