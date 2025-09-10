"""
Grafana Dashboard Generation and Management
Automated creation and deployment of monitoring dashboards.
"""

import json
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import requests
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class PanelType(Enum):
    """Grafana panel types."""
    GRAPH = "graph"
    SINGLESTAT = "singlestat"
    STAT = "stat"
    GAUGE = "gauge"
    BAR_GAUGE = "bargauge"
    TABLE = "table"
    HEATMAP = "heatmap"
    ALERT_LIST = "alertlist"
    LOGS = "logs"
    TEXT = "text"

class VisualizationType(Enum):
    """Visualization types for panels."""
    LINES = "lines"
    BARS = "bars"
    POINTS = "points"
    AREA = "area"
    PIE = "pie"
    DONUT = "donut"

@dataclass
class Target:
    """Prometheus query target for panels."""
    expr: str
    legend_format: str = ""
    ref_id: str = "A"
    interval: str = ""
    instant: bool = False
    format: str = "time_series"

@dataclass
class Panel:
    """Grafana panel configuration."""
    title: str
    panel_type: PanelType
    targets: List[Target]
    x: int = 0
    y: int = 0
    width: int = 12
    height: int = 8
    unit: Optional[str] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    thresholds: List[Dict[str, Any]] = field(default_factory=list)
    alert: Optional[Dict[str, Any]] = None
    description: str = ""
    transparent: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert panel to Grafana JSON format."""
        panel_dict = {
            "id": hash(self.title) % 10000,  # Simple ID generation
            "title": self.title,
            "type": self.panel_type.value,
            "gridPos": {
                "x": self.x,
                "y": self.y,
                "w": self.width,
                "h": self.height
            },
            "targets": [self._target_to_dict(t) for t in self.targets],
            "options": {},
            "fieldConfig": {
                "defaults": {
                    "unit": self.unit or "short",
                    "min": self.min_value,
                    "max": self.max_value,
                    "thresholds": {
                        "steps": self.thresholds or [
                            {"color": "green", "value": None},
                            {"color": "red", "value": 80}
                        ]
                    }
                }
            },
            "description": self.description,
            "transparent": self.transparent
        }
        
        # Add panel-specific configuration
        if self.panel_type == PanelType.GRAPH:
            panel_dict.update({
                "legend": {"displayMode": "visible"},
                "tooltip": {"mode": "single", "sort": "none"}
            })
        elif self.panel_type == PanelType.STAT:
            panel_dict["options"] = {
                "reduceOptions": {
                    "values": False,
                    "calcs": ["lastNotNull"],
                    "fields": ""
                },
                "orientation": "auto",
                "textMode": "auto",
                "colorMode": "palette-classic"
            }
        elif self.panel_type == PanelType.GAUGE:
            panel_dict["options"] = {
                "reduceOptions": {
                    "values": False,
                    "calcs": ["lastNotNull"],
                    "fields": ""
                },
                "orientation": "auto",
                "showThresholdLabels": False,
                "showThresholdMarkers": True
            }
        
        # Add alert configuration if present
        if self.alert:
            panel_dict["alert"] = self.alert
        
        return panel_dict
    
    def _target_to_dict(self, target: Target) -> Dict[str, Any]:
        """Convert target to Grafana JSON format."""
        return {
            "expr": target.expr,
            "legendFormat": target.legend_format,
            "refId": target.ref_id,
            "interval": target.interval,
            "instant": target.instant,
            "format": target.format
        }

@dataclass
class Dashboard:
    """Grafana dashboard configuration."""
    title: str
    description: str
    tags: List[str] = field(default_factory=list)
    panels: List[Panel] = field(default_factory=list)
    time_from: str = "now-1h"
    time_to: str = "now"
    refresh: str = "5s"
    uid: Optional[str] = None
    folder_id: int = 0
    
    def add_panel(self, panel: Panel) -> None:
        """Add a panel to the dashboard."""
        self.panels.append(panel)
    
    def auto_layout(self) -> None:
        """Automatically layout panels in a grid."""
        x, y = 0, 0
        max_width = 24
        
        for panel in self.panels:
            if x + panel.width > max_width:
                x = 0
                y += panel.height
            
            panel.x = x
            panel.y = y
            x += panel.width
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert dashboard to Grafana JSON format."""
        return {
            "dashboard": {
                "id": None,
                "uid": self.uid,
                "title": self.title,
                "description": self.description,
                "tags": self.tags,
                "timezone": "UTC",
                "panels": [panel.to_dict() for panel in self.panels],
                "time": {
                    "from": self.time_from,
                    "to": self.time_to
                },
                "timepicker": {
                    "refresh_intervals": ["5s", "10s", "30s", "1m", "5m", "15m", "30m", "1h", "2h", "1d"],
                    "time_options": ["5m", "15m", "1h", "6h", "12h", "24h", "2d", "7d", "30d"]
                },
                "refresh": self.refresh,
                "schemaVersion": 37,
                "version": 1,
                "weekStart": ""
            },
            "folderId": self.folder_id,
            "overwrite": True
        }

class DashboardGenerator:
    """Generate predefined dashboards for BLNCS monitoring."""
    
    def __init__(self, prometheus_url: str = "http://localhost:9090"):
        """Initialize dashboard generator."""
        self.prometheus_url = prometheus_url
    
    def create_lightning_overview_dashboard(self) -> Dashboard:
        """Create Lightning Network overview dashboard."""
        dashboard = Dashboard(
            title="Lightning Network Overview",
            description="Overview of Lightning Network operations and performance",
            tags=["lightning", "blncs", "overview"],
            uid="blncs-lightning-overview"
        )
        
        # Payment statistics
        dashboard.add_panel(Panel(
            title="Payment Volume (24h)",
            panel_type=PanelType.STAT,
            targets=[Target(
                expr='increase(blncs_lightning_payments_total[24h])',
                legend_format="Total Payments"
            )],
            width=6,
            height=4,
            unit="short"
        ))
        
        dashboard.add_panel(Panel(
            title="Payment Success Rate",
            panel_type=PanelType.GAUGE,
            targets=[Target(
                expr='rate(blncs_lightning_payments_total{status="success"}[5m]) / rate(blncs_lightning_payments_total[5m])',
                legend_format="Success Rate"
            )],
            width=6,
            height=4,
            unit="percentunit",
            min_value=0,
            max_value=1,
            thresholds=[
                {"color": "red", "value": 0},
                {"color": "yellow", "value": 0.8},
                {"color": "green", "value": 0.95}
            ]
        ))
        
        # Payment amounts over time
        dashboard.add_panel(Panel(
            title="Payment Amounts Over Time",
            panel_type=PanelType.GRAPH,
            targets=[
                Target(
                    expr='rate(blncs_lightning_payment_amount_satoshis_sum[5m])',
                    legend_format="Outgoing Payments",
                ),
                Target(
                    expr='rate(blncs_lightning_payment_amount_satoshis_sum{direction="incoming"}[5m])',
                    legend_format="Incoming Payments",
                    ref_id="B"
                )
            ],
            width=12,
            height=6,
            unit="sat/s"
        ))
        
        # Channel statistics
        dashboard.add_panel(Panel(
            title="Active Channels",
            panel_type=PanelType.STAT,
            targets=[Target(
                expr='blncs_lightning_channels_total{state="active"}',
                legend_format="Active Channels"
            )],
            width=4,
            height=4,
            unit="short"
        ))
        
        dashboard.add_panel(Panel(
            title="Total Channel Capacity",
            panel_type=PanelType.STAT,
            targets=[Target(
                expr='sum(blncs_lightning_channel_balance_satoshis{balance_type="local"})',
                legend_format="Local Balance"
            )],
            width=4,
            height=4,
            unit="sat"
        ))
        
        dashboard.add_panel(Panel(
            title="Fee Revenue (24h)",
            panel_type=PanelType.STAT,
            targets=[Target(
                expr='increase(blncs_lightning_fee_revenue_satoshis_total[24h])',
                legend_format="Fee Revenue"
            )],
            width=4,
            height=4,
            unit="sat"
        ))
        
        # Channel balance distribution
        dashboard.add_panel(Panel(
            title="Channel Balance Distribution",
            panel_type=PanelType.GRAPH,
            targets=[
                Target(
                    expr='histogram_quantile(0.5, rate(blncs_lightning_channel_balance_satoshis_bucket[5m]))',
                    legend_format="50th percentile"
                ),
                Target(
                    expr='histogram_quantile(0.95, rate(blncs_lightning_channel_balance_satoshis_bucket[5m]))',
                    legend_format="95th percentile",
                    ref_id="B"
                )
            ],
            width=12,
            height=6,
            unit="sat"
        ))
        
        dashboard.auto_layout()
        return dashboard
    
    def create_system_performance_dashboard(self) -> Dashboard:
        """Create system performance dashboard."""
        dashboard = Dashboard(
            title="System Performance",
            description="System resource utilization and performance metrics",
            tags=["system", "blncs", "performance"],
            uid="blncs-system-performance"
        )
        
        # CPU Usage
        dashboard.add_panel(Panel(
            title="CPU Usage",
            panel_type=PanelType.GRAPH,
            targets=[Target(
                expr='blncs_system_cpu_usage_percent',
                legend_format="Core {{core}}"
            )],
            width=12,
            height=6,
            unit="percent",
            max_value=100
        ))
        
        # Memory Usage
        dashboard.add_panel(Panel(
            title="Memory Usage",
            panel_type=PanelType.GRAPH,
            targets=[
                Target(
                    expr='blncs_system_memory_usage_bytes{type="used"}',
                    legend_format="Used"
                ),
                Target(
                    expr='blncs_system_memory_usage_bytes{type="available"}',
                    legend_format="Available",
                    ref_id="B"
                )
            ],
            width=12,
            height=6,
            unit="bytes"
        ))
        
        # Disk Usage
        dashboard.add_panel(Panel(
            title="Disk Usage by Device",
            panel_type=PanelType.BAR_GAUGE,
            targets=[Target(
                expr='blncs_system_disk_usage_bytes{type="used"} / (blncs_system_disk_usage_bytes{type="used"} + blncs_system_disk_usage_bytes{type="free"})',
                legend_format="{{device}}"
            )],
            width=12,
            height=6,
            unit="percentunit",
            max_value=1
        ))
        
        # Network I/O
        dashboard.add_panel(Panel(
            title="Network I/O",
            panel_type=PanelType.GRAPH,
            targets=[
                Target(
                    expr='rate(blncs_system_network_io_bytes_total{direction="sent"}[5m])',
                    legend_format="{{interface}} sent"
                ),
                Target(
                    expr='rate(blncs_system_network_io_bytes_total{direction="received"}[5m])',
                    legend_format="{{interface}} received",
                    ref_id="B"
                )
            ],
            width=12,
            height=6,
            unit="bytes/s"
        ))
        
        dashboard.auto_layout()
        return dashboard
    
    def create_application_metrics_dashboard(self) -> Dashboard:
        """Create application-specific metrics dashboard."""
        dashboard = Dashboard(
            title="Application Metrics",
            description="BLNCS application performance and error metrics",
            tags=["application", "blncs", "errors"],
            uid="blncs-application-metrics"
        )
        
        # HTTP Request Rate
        dashboard.add_panel(Panel(
            title="HTTP Request Rate",
            panel_type=PanelType.GRAPH,
            targets=[Target(
                expr='rate(blncs_http_requests_total[5m])',
                legend_format="{{method}} {{endpoint}}"
            )],
            width=12,
            height=6,
            unit="reqps"
        ))
        
        # HTTP Response Times
        dashboard.add_panel(Panel(
            title="HTTP Response Times",
            panel_type=PanelType.GRAPH,
            targets=[
                Target(
                    expr='histogram_quantile(0.50, rate(blncs_http_request_duration_seconds_bucket[5m]))',
                    legend_format="50th percentile"
                ),
                Target(
                    expr='histogram_quantile(0.95, rate(blncs_http_request_duration_seconds_bucket[5m]))',
                    legend_format="95th percentile",
                    ref_id="B"
                ),
                Target(
                    expr='histogram_quantile(0.99, rate(blncs_http_request_duration_seconds_bucket[5m]))',
                    legend_format="99th percentile",
                    ref_id="C"
                )
            ],
            width=12,
            height=6,
            unit="s"
        ))
        
        # HTTP Status Codes
        dashboard.add_panel(Panel(
            title="HTTP Status Codes",
            panel_type=PanelType.GRAPH,
            targets=[
                Target(
                    expr='rate(blncs_http_requests_total{status=~"2.."}[5m])',
                    legend_format="2xx Success"
                ),
                Target(
                    expr='rate(blncs_http_requests_total{status=~"4.."}[5m])',
                    legend_format="4xx Client Error",
                    ref_id="B"
                ),
                Target(
                    expr='rate(blncs_http_requests_total{status=~"5.."}[5m])',
                    legend_format="5xx Server Error",
                    ref_id="C"
                )
            ],
            width=12,
            height=6,
            unit="reqps"
        ))
        
        # Database Connections
        dashboard.add_panel(Panel(
            title="Database Connections",
            panel_type=PanelType.STAT,
            targets=[Target(
                expr='blncs_database_connections_total',
                legend_format="{{state}}"
            )],
            width=6,
            height=4,
            unit="short"
        ))
        
        # Application Uptime
        dashboard.add_panel(Panel(
            title="Application Uptime",
            panel_type=PanelType.STAT,
            targets=[Target(
                expr='time() - process_start_time_seconds',
                legend_format="Uptime"
            )],
            width=6,
            height=4,
            unit="s"
        ))
        
        dashboard.auto_layout()
        return dashboard
    
    def create_alerting_dashboard(self) -> Dashboard:
        """Create alerting and monitoring dashboard."""
        dashboard = Dashboard(
            title="Alerts & Monitoring",
            description="Current alerts and monitoring system status",
            tags=["alerts", "blncs", "monitoring"],
            uid="blncs-alerts-monitoring"
        )
        
        # Active Alerts
        dashboard.add_panel(Panel(
            title="Active Alerts",
            panel_type=PanelType.ALERT_LIST,
            targets=[],
            width=12,
            height=8
        ))
        
        # Alert Rate
        dashboard.add_panel(Panel(
            title="Alert Rate",
            panel_type=PanelType.GRAPH,
            targets=[Target(
                expr='rate(alertmanager_alerts_total[5m])',
                legend_format="{{severity}}"
            )],
            width=12,
            height=6,
            unit="alerts/s"
        ))
        
        dashboard.auto_layout()
        return dashboard

class GrafanaClient:
    """Client for interacting with Grafana API."""
    
    def __init__(self, base_url: str, api_key: str):
        """Initialize Grafana client."""
        self.base_url = base_url.rstrip('/')
        self.headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
    
    def create_dashboard(self, dashboard: Dashboard) -> Dict[str, Any]:
        """Create or update a dashboard in Grafana."""
        url = f"{self.base_url}/api/dashboards/db"
        
        try:
            response = self.session.post(url, json=dashboard.to_dict(), timeout=30)
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Created/updated dashboard: {dashboard.title} (ID: {result.get('id')})")
            return result
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create dashboard {dashboard.title}: {e}")
            raise
    
    def delete_dashboard(self, uid: str) -> None:
        """Delete a dashboard by UID."""
        url = f"{self.base_url}/api/dashboards/uid/{uid}"
        
        try:
            response = self.session.delete(url, timeout=30)
            response.raise_for_status()
            
            logger.info(f"Deleted dashboard: {uid}")
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to delete dashboard {uid}: {e}")
            raise
    
    def get_dashboard(self, uid: str) -> Dict[str, Any]:
        """Get dashboard by UID."""
        url = f"{self.base_url}/api/dashboards/uid/{uid}"
        
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to get dashboard {uid}: {e}")
            raise
    
    def list_dashboards(self) -> List[Dict[str, Any]]:
        """List all dashboards."""
        url = f"{self.base_url}/api/search?type=dash-db"
        
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to list dashboards: {e}")
            raise
    
    def create_folder(self, title: str) -> Dict[str, Any]:
        """Create a dashboard folder."""
        url = f"{self.base_url}/api/folders"
        
        payload = {
            "title": title
        }
        
        try:
            response = self.session.post(url, json=payload, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Created folder: {title} (ID: {result.get('id')})")
            return result
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to create folder {title}: {e}")
            raise

def deploy_default_dashboards(grafana_url: str, api_key: str) -> None:
    """Deploy default BLNCS dashboards to Grafana."""
    client = GrafanaClient(grafana_url, api_key)
    generator = DashboardGenerator()
    
    # Create BLNCS folder
    try:
        folder = client.create_folder("BLNCS")
        folder_id = folder.get('id', 0)
    except Exception as e:
        logger.warning(f"Failed to create folder, using default: {e}")
        folder_id = 0
    
    # Create dashboards
    dashboards = [
        generator.create_lightning_overview_dashboard(),
        generator.create_system_performance_dashboard(),
        generator.create_application_metrics_dashboard(),
        generator.create_alerting_dashboard()
    ]
    
    for dashboard in dashboards:
        dashboard.folder_id = folder_id
        try:
            client.create_dashboard(dashboard)
        except Exception as e:
            logger.error(f"Failed to deploy dashboard {dashboard.title}: {e}")
    
    logger.info("Dashboard deployment completed")

def export_dashboards_to_files(output_dir: Path) -> None:
    """Export dashboard definitions to JSON files."""
    output_dir.mkdir(parents=True, exist_ok=True)
    generator = DashboardGenerator()
    
    dashboards = [
        ("lightning-overview", generator.create_lightning_overview_dashboard()),
        ("system-performance", generator.create_system_performance_dashboard()),
        ("application-metrics", generator.create_application_metrics_dashboard()),
        ("alerts-monitoring", generator.create_alerting_dashboard())
    ]
    
    for filename, dashboard in dashboards:
        file_path = output_dir / f"{filename}.json"
        with open(file_path, 'w') as f:
            json.dump(dashboard.to_dict(), f, indent=2)
        
        logger.info(f"Exported dashboard to: {file_path}")
    
    logger.info(f"Dashboard export completed to: {output_dir}")