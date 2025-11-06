"""
Sample API Extension Plugin: Advanced Metrics API
Provides extended metrics and analytics endpoints.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import json

from blncs.core.plugin_system import ApiExtensionPlugin, PluginMetadata


class MetricsApiPlugin(ApiExtensionPlugin):
    """
    Advanced metrics API extension providing detailed system analytics,
    custom dashboards, and real-time monitoring endpoints.
    """
    
    def __init__(self):
        metadata = PluginMetadata(
            name="Advanced Metrics API",
            version="1.1.0",
            description="Extended metrics and analytics API endpoints",
            author="BLNCS Team",
            category="api_extension",
            tags=["api", "metrics", "analytics", "monitoring"],
            dependencies=[],
            min_api_version="1.0.0"
        )
        super().__init__(metadata)
        
        # Metrics storage
        self.metrics_history: List[Dict] = []
        self.custom_dashboards: Dict[str, Dict] = {}
        self.alert_rules: List[Dict] = []
        
        # Initialize default dashboards
        self._init_default_dashboards()
    
    def get_endpoints(self) -> Dict[str, callable]:
        """Return available API endpoints"""
        return {
            '/api/metrics/advanced/summary': self.get_metrics_summary,
            '/api/metrics/advanced/timeline': self.get_metrics_timeline,
            '/api/metrics/advanced/custom/{dashboard_id}': self.get_custom_dashboard,
            '/api/metrics/advanced/alerts': self.get_active_alerts,
            '/api/metrics/advanced/export': self.export_metrics,
            '/api/dashboards/create': self.create_dashboard,
            '/api/dashboards/list': self.list_dashboards,
            '/api/dashboards/{dashboard_id}': self.get_dashboard,
            '/api/alerts/rules': self.get_alert_rules,
            '/api/alerts/create': self.create_alert_rule,
            '/api/system/health/detailed': self.get_detailed_health
        }
    
    def get_metrics_summary(self, request_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Get comprehensive metrics summary"""
        try:
            timeframe = request_data.get('timeframe', '24h') if request_data else '24h'
            categories = request_data.get('categories', []) if request_data else []
            
            # Calculate timeframe
            cutoff_time = self._get_cutoff_time(timeframe)
            
            # Filter metrics by timeframe
            recent_metrics = [
                m for m in self.metrics_history 
                if datetime.fromisoformat(m.get('timestamp', '2024-01-01T00:00:00')) > cutoff_time
            ]
            
            # Generate summary by category
            summary = {
                'plugin': self.metadata.name,
                'endpoint': '/api/metrics/advanced/summary',
                'timeframe': timeframe,
                'timestamp': datetime.now().isoformat(),
                'total_data_points': len(recent_metrics),
                'categories': {}
            }
            
            # Performance metrics
            if not categories or 'performance' in categories:
                perf_metrics = [m for m in recent_metrics if m.get('category') == 'performance']
                summary['categories']['performance'] = self._summarize_performance_metrics(perf_metrics)
            
            # Network metrics
            if not categories or 'network' in categories:
                network_metrics = [m for m in recent_metrics if m.get('category') == 'network']
                summary['categories']['network'] = self._summarize_network_metrics(network_metrics)
            
            # Financial metrics
            if not categories or 'financial' in categories:
                financial_metrics = [m for m in recent_metrics if m.get('category') == 'financial']
                summary['categories']['financial'] = self._summarize_financial_metrics(financial_metrics)
            
            # System metrics
            if not categories or 'system' in categories:
                system_metrics = [m for m in recent_metrics if m.get('category') == 'system']
                summary['categories']['system'] = self._summarize_system_metrics(system_metrics)
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Metrics summary failed: {e}")
            return {'error': str(e), 'plugin': self.metadata.name}
    
    def get_metrics_timeline(self, request_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Get metrics data over time for charting"""
        try:
            timeframe = request_data.get('timeframe', '24h') if request_data else '24h'
            metric_types = request_data.get('metric_types', []) if request_data else []
            granularity = request_data.get('granularity', 'hour') if request_data else 'hour'
            
            cutoff_time = self._get_cutoff_time(timeframe)
            
            # Filter and organize metrics
            filtered_metrics = [
                m for m in self.metrics_history 
                if datetime.fromisoformat(m.get('timestamp', '2024-01-01T00:00:00')) > cutoff_time
            ]
            
            if metric_types:
                filtered_metrics = [
                    m for m in filtered_metrics 
                    if m.get('metric_type') in metric_types
                ]
            
            # Group by time intervals
            timeline_data = self._group_metrics_by_time(filtered_metrics, granularity)
            
            return {
                'plugin': self.metadata.name,
                'endpoint': '/api/metrics/advanced/timeline',
                'timeframe': timeframe,
                'granularity': granularity,
                'metric_types': metric_types or 'all',
                'timestamp': datetime.now().isoformat(),
                'data_points': len(timeline_data),
                'timeline': timeline_data
            }
            
        except Exception as e:
            self.logger.error(f"Timeline generation failed: {e}")
            return {'error': str(e), 'plugin': self.metadata.name}
    
    def get_custom_dashboard(self, request_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Get custom dashboard data"""
        try:
            dashboard_id = request_data.get('dashboard_id', 'default') if request_data else 'default'
            
            if dashboard_id not in self.custom_dashboards:
                return {
                    'error': f'Dashboard {dashboard_id} not found',
                    'available_dashboards': list(self.custom_dashboards.keys()),
                    'plugin': self.metadata.name
                }
            
            dashboard_config = self.custom_dashboards[dashboard_id]
            
            # Generate dashboard data based on configuration
            dashboard_data = {
                'plugin': self.metadata.name,
                'dashboard_id': dashboard_id,
                'dashboard_name': dashboard_config['name'],
                'timestamp': datetime.now().isoformat(),
                'widgets': []
            }
            
            # Process each widget
            for widget in dashboard_config.get('widgets', []):
                widget_data = self._generate_widget_data(widget)
                dashboard_data['widgets'].append(widget_data)
            
            return dashboard_data
            
        except Exception as e:
            self.logger.error(f"Dashboard generation failed: {e}")
            return {'error': str(e), 'plugin': self.metadata.name}
    
    def get_active_alerts(self, request_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Get currently active alerts"""
        try:
            severity_filter = request_data.get('severity') if request_data else None
            
            # Simulate active alerts (in real implementation, would check actual conditions)
            active_alerts = []
            
            # Check each alert rule
            for rule in self.alert_rules:
                if self._evaluate_alert_rule(rule):
                    alert = {
                        'rule_id': rule['id'],
                        'name': rule['name'],
                        'severity': rule['severity'],
                        'message': rule['message'],
                        'triggered_at': datetime.now().isoformat(),
                        'threshold': rule['threshold'],
                        'current_value': rule.get('current_value', 'unknown')
                    }
                    
                    if not severity_filter or alert['severity'] == severity_filter:
                        active_alerts.append(alert)
            
            return {
                'plugin': self.metadata.name,
                'endpoint': '/api/metrics/advanced/alerts',
                'timestamp': datetime.now().isoformat(),
                'active_alerts_count': len(active_alerts),
                'severity_filter': severity_filter,
                'alerts': active_alerts
            }
            
        except Exception as e:
            self.logger.error(f"Alert retrieval failed: {e}")
            return {'error': str(e), 'plugin': self.metadata.name}
    
    def create_dashboard(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new custom dashboard"""
        try:
            dashboard_id = request_data.get('dashboard_id')
            dashboard_name = request_data.get('name')
            widgets = request_data.get('widgets', [])
            
            if not dashboard_id or not dashboard_name:
                return {
                    'error': 'dashboard_id and name are required',
                    'plugin': self.metadata.name
                }
            
            # Validate widgets
            for widget in widgets:
                if not self._validate_widget_config(widget):
                    return {
                        'error': f'Invalid widget configuration: {widget}',
                        'plugin': self.metadata.name
                    }
            
            # Create dashboard
            self.custom_dashboards[dashboard_id] = {
                'id': dashboard_id,
                'name': dashboard_name,
                'widgets': widgets,
                'created_at': datetime.now().isoformat(),
                'created_by': 'api'
            }
            
            return {
                'plugin': self.metadata.name,
                'message': f'Dashboard {dashboard_id} created successfully',
                'dashboard_id': dashboard_id,
                'widgets_count': len(widgets)
            }
            
        except Exception as e:
            self.logger.error(f"Dashboard creation failed: {e}")
            return {'error': str(e), 'plugin': self.metadata.name}
    
    def get_detailed_health(self, request_data: Dict[str, Any] = None) -> Dict[str, Any]:
        """Get detailed system health information"""
        try:
            include_predictions = request_data.get('include_predictions', True) if request_data else True
            
            # Comprehensive health check
            health_data = {
                'plugin': self.metadata.name,
                'endpoint': '/api/system/health/detailed',
                'timestamp': datetime.now().isoformat(),
                'overall_status': 'healthy',
                'components': {}
            }
            
            # Lightning Network health
            health_data['components']['lightning_network'] = {
                'status': 'operational',
                'active_channels': 156,
                'total_capacity': 2500000,
                'success_rate': 0.94,
                'avg_fee_rate': 0.5,
                'last_payment': '2024-12-13T10:30:00'
            }
            
            # API health
            health_data['components']['api_server'] = {
                'status': 'operational',
                'uptime_hours': 72,
                'requests_per_minute': 45,
                'error_rate': 0.02,
                'response_time_ms': 150
            }
            
            # Database health
            health_data['components']['database'] = {
                'status': 'operational',
                'connections_active': 8,
                'query_time_avg_ms': 25,
                'disk_usage_percent': 45,
                'last_backup': '2024-12-13T06:00:00'
            }
            
            # ML system health
            health_data['components']['ml_system'] = {
                'status': 'operational',
                'models_loaded': 3,
                'prediction_accuracy': 0.87,
                'inference_time_ms': 45,
                'last_training': '2024-12-12T18:00:00'
            }
            
            # Add predictions if requested
            if include_predictions:
                health_data['predictions'] = {
                    'system_load_next_hour': 'normal',
                    'payment_success_rate_trend': 'stable',
                    'channel_rebalance_needed': False,
                    'maintenance_window_optimal': '2024-12-14T03:00:00'
                }
            
            return health_data
            
        except Exception as e:
            self.logger.error(f"Detailed health check failed: {e}")
            return {'error': str(e), 'plugin': self.metadata.name}
    
    def _init_default_dashboards(self):
        """Initialize default dashboard configurations"""
        self.custom_dashboards = {
            'lightning_overview': {
                'id': 'lightning_overview',
                'name': 'Lightning Network Overview',
                'widgets': [
                    {'type': 'metric', 'title': 'Active Channels', 'metric': 'active_channels'},
                    {'type': 'chart', 'title': 'Payment Volume', 'metric': 'payment_volume', 'timeframe': '24h'},
                    {'type': 'gauge', 'title': 'Success Rate', 'metric': 'success_rate'},
                    {'type': 'table', 'title': 'Recent Payments', 'metric': 'recent_payments', 'limit': 10}
                ]
            },
            'performance_dashboard': {
                'id': 'performance_dashboard',
                'name': 'System Performance',
                'widgets': [
                    {'type': 'chart', 'title': 'Response Times', 'metric': 'response_time', 'timeframe': '1h'},
                    {'type': 'metric', 'title': 'CPU Usage', 'metric': 'cpu_usage'},
                    {'type': 'metric', 'title': 'Memory Usage', 'metric': 'memory_usage'},
                    {'type': 'chart', 'title': 'Database Queries', 'metric': 'db_queries', 'timeframe': '24h'}
                ]
            }
        }
        
        # Initialize default alert rules
        self.alert_rules = [
            {
                'id': 'high_failure_rate',
                'name': 'High Payment Failure Rate',
                'metric': 'payment_success_rate',
                'threshold': 0.85,
                'operator': 'less_than',
                'severity': 'warning',
                'message': 'Payment success rate has dropped below 85%'
            },
            {
                'id': 'high_fees',
                'name': 'High Average Fees',
                'metric': 'avg_fee_rate',
                'threshold': 1.5,
                'operator': 'greater_than',
                'severity': 'info',
                'message': 'Average fee rate is above 1.5%'
            }
        ]
    
    def _get_cutoff_time(self, timeframe: str) -> datetime:
        """Convert timeframe to cutoff datetime"""
        now = datetime.now()
        if timeframe == '1h':
            return now - timedelta(hours=1)
        elif timeframe == '24h':
            return now - timedelta(hours=24)
        elif timeframe == '7d':
            return now - timedelta(days=7)
        elif timeframe == '30d':
            return now - timedelta(days=30)
        else:
            return now - timedelta(hours=24)
    
    def _summarize_performance_metrics(self, metrics: List[Dict]) -> Dict:
        """Summarize performance metrics"""
        if not metrics:
            return {'status': 'no_data', 'message': 'No performance metrics available'}
        
        # Extract performance values
        response_times = [m.get('response_time', 0) for m in metrics if m.get('response_time')]
        cpu_usage = [m.get('cpu_usage', 0) for m in metrics if m.get('cpu_usage')]
        
        return {
            'avg_response_time': sum(response_times) / len(response_times) if response_times else 0,
            'max_response_time': max(response_times) if response_times else 0,
            'avg_cpu_usage': sum(cpu_usage) / len(cpu_usage) if cpu_usage else 0,
            'data_points': len(metrics),
            'status': 'optimal' if (sum(response_times) / len(response_times) if response_times else 0) < 200 else 'degraded'
        }
    
    def _generate_widget_data(self, widget_config: Dict) -> Dict:
        """Generate data for a dashboard widget"""
        widget_type = widget_config.get('type', 'metric')
        
        # Generate sample data based on widget type
        if widget_type == 'metric':
            return {
                'type': 'metric',
                'title': widget_config.get('title', 'Metric'),
                'value': 42,  # Sample value
                'unit': widget_config.get('unit', ''),
                'change': '+5.2%',
                'trend': 'up'
            }
        elif widget_type == 'chart':
            return {
                'type': 'chart',
                'title': widget_config.get('title', 'Chart'),
                'data_points': [
                    {'x': '10:00', 'y': 45},
                    {'x': '11:00', 'y': 52},
                    {'x': '12:00', 'y': 38},
                    {'x': '13:00', 'y': 61},
                    {'x': '14:00', 'y': 44}
                ]
            }
        elif widget_type == 'gauge':
            return {
                'type': 'gauge',
                'title': widget_config.get('title', 'Gauge'),
                'value': 0.87,
                'min': 0,
                'max': 1,
                'thresholds': [0.7, 0.9]
            }
        else:
            return {
                'type': widget_type,
                'title': widget_config.get('title', 'Widget'),
                'data': 'Sample data'
            }


# Plugin registration
def create_plugin():
    """Plugin factory function"""
    return MetricsApiPlugin()