"""
Advanced Data Visualization System for BLNCS

This module provides comprehensive data visualization including:
- Interactive charts and graphs with real-time updates
- 3D visualizations and geospatial mapping
- Custom dashboard widgets and layouts
- Advanced analytics and reporting
- Export capabilities for multiple formats
"""

import time
import json
import logging
import threading
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from collections import defaultdict
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)

@dataclass
class VisualizationConfig:
    """Visualization configuration."""
    chart_type: str  # line, bar, scatter, heatmap, 3d, geospatial
    title: str
    x_axis: str
    y_axis: str
    data_source: str
    refresh_interval: int = 30
    interactive: bool = True
    export_formats: List[str] = None  # png, pdf, svg, html

@dataclass
class DashboardLayout:
    """Dashboard layout configuration."""
    layout_id: str
    name: str
    grid_config: Dict[str, Any]  # Grid layout specifications
    widgets: List[Dict[str, Any]] = None
    responsive: bool = True
    theme: str = 'default'

class InteractiveChartEngine:
    """Interactive chart generation engine."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.InteractiveChartEngine")
        self.charts = {}
        self.data_cache = {}
        self.update_threads = {}

    def create_line_chart(self, data: pd.DataFrame, config: VisualizationConfig) -> go.Figure:
        """Create interactive line chart."""
        fig = go.Figure()

        # Add multiple lines if multiple columns
        for column in data.columns[1:]:  # Skip first column (usually time/index)
            fig.add_trace(go.Scatter(
                x=data.iloc[:, 0],
                y=data[column],
                mode='lines+markers',
                name=column,
                hovertemplate=f"{config.x_axis}: %{{x}}<br>{config.y_axis}: %{{y}}<extra></extra>"
            ))

        fig.update_layout(
            title=config.title,
            xaxis_title=config.x_axis,
            yaxis_title=config.y_axis,
            hovermode='x unified',
            template='plotly_white'
        )

        return fig

    def create_bar_chart(self, data: pd.DataFrame, config: VisualizationConfig) -> go.Figure:
        """Create interactive bar chart."""
        fig = go.Figure()

        for column in data.columns[1:]:
            fig.add_trace(go.Bar(
                x=data.iloc[:, 0],
                y=data[column],
                name=column
            ))

        fig.update_layout(
            title=config.title,
            xaxis_title=config.x_axis,
            yaxis_title=config.y_axis,
            template='plotly_white'
        )

        return fig

    def create_heatmap(self, data: pd.DataFrame, config: VisualizationConfig) -> go.Figure:
        """Create interactive heatmap."""
        # Assuming data has columns for x, y, and value
        fig = go.Figure(data=go.Heatmap(
            z=data.iloc[:, 2].values.reshape(int(np.sqrt(len(data))), int(np.sqrt(len(data)))),
            x=data.iloc[:, 0].unique(),
            y=data.iloc[:, 1].unique(),
            colorscale='Viridis',
            hoverongaps=False
        ))

        fig.update_layout(
            title=config.title,
            xaxis_title=config.x_axis,
            yaxis_title=config.y_axis,
            template='plotly_white'
        )

        return fig

    def create_3d_scatter(self, data: pd.DataFrame, config: VisualizationConfig) -> go.Figure:
        """Create 3D scatter plot."""
        fig = go.Figure(data=[go.Scatter3d(
            x=data.iloc[:, 0],
            y=data.iloc[:, 1],
            z=data.iloc[:, 2],
            mode='markers',
            marker=dict(
                size=5,
                color=data.iloc[:, 2],
                colorscale='Viridis',
                showscale=True
            ),
            hovertemplate=f"{config.x_axis}: %{{x}}<br>{config.y_axis}: %{{y}}<br>Value: %{{z}}<extra></extra>"
        )])

        fig.update_layout(
            title=config.title,
            scene=dict(
                xaxis_title=config.x_axis,
                yaxis_title=config.y_axis,
                zaxis_title='Value'
            ),
            template='plotly_white'
        )

        return fig

    def create_geospatial_map(self, data: pd.DataFrame, config: VisualizationConfig) -> go.Figure:
        """Create geospatial map visualization."""
        fig = go.Figure(data=go.Scattergeo(
            lat=data['latitude'],
            lon=data['longitude'],
            text=data['location'],
            mode='markers',
            marker=dict(
                size=data['intensity'] * 10,
                color=data['intensity'],
                colorscale='Reds',
                showscale=True,
                sizemode='diameter'
            ),
            hovertemplate="Location: %{text}<br>Intensity: %{marker.size}<extra></extra>"
        ))

        fig.update_layout(
            title=config.title,
            geo=dict(
                showframe=False,
                showcoastlines=True,
                projection_type='natural earth'
            ),
            template='plotly_white'
        )

        return fig

    def generate_chart(self, data: pd.DataFrame, config: VisualizationConfig) -> go.Figure:
        """Generate chart based on configuration."""
        chart_generators = {
            'line': self.create_line_chart,
            'bar': self.create_bar_chart,
            'heatmap': self.create_heatmap,
            '3d_scatter': self.create_3d_scatter,
            'geospatial': self.create_geospatial_map
        }

        generator = chart_generators.get(config.chart_type)
        if not generator:
            raise ValueError(f"Unsupported chart type: {config.chart_type}")

        return generator(data, config)

class DashboardWidgetManager:
    """Dashboard widget management."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.DashboardWidgetManager")
        self.widgets = {}
        self.layouts = {}
        self.widget_data = defaultdict(dict)

    def create_widget(self, widget_id: str, widget_type: str, config: Dict[str, Any]):
        """Create dashboard widget."""
        widget = {
            'id': widget_id,
            'type': widget_type,
            'config': config,
            'data': None,
            'last_updated': time.time(),
            'update_interval': config.get('update_interval', 30)
        }

        self.widgets[widget_id] = widget
        return widget

    def update_widget_data(self, widget_id: str, data: Any):
        """Update widget data."""
        if widget_id in self.widgets:
            self.widgets[widget_id]['data'] = data
            self.widgets[widget_id]['last_updated'] = time.time()

    def create_layout(self, layout_id: str, grid_config: Dict[str, Any], widgets: List[str]):
        """Create dashboard layout."""
        layout = DashboardLayout(
            layout_id=layout_id,
            name=f"Layout {layout_id}",
            grid_config=grid_config,
            widgets=widgets
        )

        self.layouts[layout_id] = layout
        return layout

    def get_layout_data(self, layout_id: str) -> Dict[str, Any]:
        """Get complete layout data."""
        if layout_id not in self.layouts:
            return {}

        layout = self.layouts[layout_id]
        layout_data = asdict(layout)

        # Add widget data
        widget_data = {}
        for widget_id in layout.widgets:
            if widget_id in self.widgets:
                widget_data[widget_id] = self.widgets[widget_id]

        layout_data['widgets_data'] = widget_data
        return layout_data

class AdvancedAnalyticsEngine:
    """Advanced analytics and reporting."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.AdvancedAnalyticsEngine")
        self.analytics_cache = {}
        self.cache_ttl = 3600  # 1 hour

    def calculate_statistics(self, data: pd.DataFrame) -> Dict[str, Any]:
        """Calculate comprehensive statistics."""
        stats = {}

        for column in data.columns:
            if data[column].dtype in ['int64', 'float64']:
                col_stats = {
                    'mean': data[column].mean(),
                    'median': data[column].median(),
                    'std': data[column].std(),
                    'min': data[column].min(),
                    'max': data[column].max(),
                    'q25': data[column].quantile(0.25),
                    'q75': data[column].quantile(0.75),
                    'skewness': data[column].skew(),
                    'kurtosis': data[column].kurtosis()
                }

                # Trend analysis
                if len(data) > 10:
                    col_stats['trend'] = self._calculate_trend(data[column])

                stats[column] = col_stats

        return stats

    def _calculate_trend(self, series: pd.Series) -> str:
        """Calculate trend direction."""
        # Simple linear regression slope
        x = np.arange(len(series))
        slope = np.polyfit(x, series.values, 1)[0]

        if slope > 0.1:
            return 'increasing'
        elif slope < -0.1:
            return 'decreasing'
        else:
            return 'stable'

    def detect_anomalies(self, data: pd.DataFrame, threshold: float = 3.0) -> Dict[str, List[int]]:
        """Detect anomalies using z-score method."""
        anomalies = {}

        for column in data.columns:
            if data[column].dtype in ['int64', 'float64']:
                z_scores = np.abs((data[column] - data[column].mean()) / data[column].std())
                anomaly_indices = np.where(z_scores > threshold)[0].tolist()
                if anomaly_indices:
                    anomalies[column] = anomaly_indices

        return anomalies

    def generate_report(self, data: pd.DataFrame, report_type: str = 'comprehensive') -> Dict[str, Any]:
        """Generate comprehensive report."""
        report = {
            'generated_at': time.time(),
            'data_points': len(data),
            'columns': list(data.columns),
            'statistics': self.calculate_statistics(data),
            'anomalies': self.detect_anomalies(data),
            'correlations': data.corr().to_dict() if len(data.columns) > 1 else {},
            'summary': self._generate_summary(data)
        }

        return report

    def _generate_summary(self, data: pd.DataFrame) -> str:
        """Generate data summary."""
        summary = f"Dataset contains {len(data)} rows and {len(data.columns)} columns. "

        numeric_columns = [col for col in data.columns if data[col].dtype in ['int64', 'float64']]
        if numeric_columns:
            summary += f"Numeric columns: {', '.join(numeric_columns)}. "

        # Add key insights
        if len(data) > 0:
            summary += "Data spans from " + str(data.index.min()) + " to " + str(data.index.max()) + ". "

        return summary

class ExportManager:
    """Export management for visualizations."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.ExportManager")
        self.supported_formats = ['png', 'pdf', 'svg', 'html', 'json']

    def export_chart(self, fig: go.Figure, filename: str, format: str, **kwargs):
        """Export chart to specified format."""
        if format not in self.supported_formats:
            raise ValueError(f"Unsupported format: {format}")

        try:
            if format == 'png':
                fig.write_image(filename, **kwargs)
            elif format == 'pdf':
                fig.write_image(filename, **kwargs)
            elif format == 'svg':
                fig.write_image(filename, **kwargs)
            elif format == 'html':
                fig.write_html(filename, **kwargs)
            elif format == 'json':
                # Export as JSON data
                with open(filename, 'w') as f:
                    json.dump(fig.to_dict(), f, indent=2)

            self.logger.info(f"Exported chart to {filename}.{format}")

        except Exception as e:
            self.logger.error(f"Export failed: {e}")
            raise

class DataVisualizationManager:
    """Main data visualization management system."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.DataVisualizationManager")
        self.chart_engine = InteractiveChartEngine()
        self.widget_manager = DashboardWidgetManager()
        self.analytics_engine = AdvancedAnalyticsEngine()
        self.export_manager = ExportManager()

        self.visualization_active = False
        self.update_threads = {}

    def create_visualization(self, data: pd.DataFrame, config: VisualizationConfig) -> str:
        """Create visualization from data."""
        try:
            fig = self.chart_engine.generate_chart(data, config)

            viz_id = f"viz_{int(time.time())}_{secrets.token_hex(4)}"
            self.charts[viz_id] = {
                'figure': fig,
                'config': config,
                'data': data,
                'created_at': time.time()
            }

            # Start auto-update if configured
            if config.refresh_interval > 0:
                self._start_auto_update(viz_id, config)

            self.logger.info(f"Created visualization: {viz_id}")
            return viz_id

        except Exception as e:
            self.logger.error(f"Failed to create visualization: {e}")
            raise

    def _start_auto_update(self, viz_id: str, config: VisualizationConfig):
        """Start automatic updates for visualization."""
        def update_loop():
            while self.visualization_active:
                try:
                    time.sleep(config.refresh_interval)

                    # Get fresh data (in real implementation, from data source)
                    fresh_data = self._get_fresh_data(config.data_source)

                    if fresh_data is not None:
                        # Update chart
                        fig = self.chart_engine.generate_chart(fresh_data, config)
                        self.charts[viz_id]['figure'] = fig
                        self.charts[viz_id]['data'] = fresh_data
                        self.charts[viz_id]['updated_at'] = time.time()

                except Exception as e:
                    self.logger.error(f"Visualization update error for {viz_id}: {e}")

        thread = threading.Thread(target=update_loop, daemon=True)
        self.update_threads[viz_id] = thread
        thread.start()

    def _get_fresh_data(self, data_source: str) -> Optional[pd.DataFrame]:
        """Get fresh data from source."""
        # In a real implementation, fetch from database, API, etc.
        # For demo, return None (no update)
        return None

    def create_dashboard(self, layout: DashboardLayout) -> str:
        """Create dashboard with layout."""
        dashboard_id = f"dashboard_{int(time.time())}_{secrets.token_hex(4)}"

        self.dashboards[dashboard_id] = {
            'layout': layout,
            'created_at': time.time(),
            'widgets': {}
        }

        # Initialize widgets
        for widget_id in layout.widgets:
            if widget_id in self.widgets:
                self.dashboards[dashboard_id]['widgets'][widget_id] = self.widgets[widget_id]

        self.logger.info(f"Created dashboard: {dashboard_id}")
        return dashboard_id

    def generate_analytics_report(self, data: pd.DataFrame) -> Dict[str, Any]:
        """Generate comprehensive analytics report."""
        return self.analytics_engine.generate_report(data)

    def export_visualization(self, viz_id: str, format: str, filename: str):
        """Export visualization."""
        if viz_id not in self.charts:
            raise ValueError(f"Visualization not found: {viz_id}")

        fig = self.charts[viz_id]['figure']
        self.export_manager.export_chart(fig, filename, format)

    def get_visualization_status(self) -> Dict[str, Any]:
        """Get visualization system status."""
        return {
            'active_visualizations': len(self.charts),
            'active_dashboards': len(self.dashboards),
            'active_widgets': len(self.widgets),
            'supported_formats': self.export_manager.supported_formats,
            'chart_types': ['line', 'bar', 'scatter', 'heatmap', '3d', 'geospatial']
        }

def create_data_visualization_system() -> DataVisualizationManager:
    """Factory function to create data visualization system."""
    return DataVisualizationManager()

# Example usage
if __name__ == "__main__":
    # Create visualization system
    viz_manager = create_data_visualization_system()

    # Sample data for visualization
    dates = pd.date_range(start='2023-01-01', periods=100, freq='D')
    data = pd.DataFrame({
        'date': dates,
        'cpu_usage': np.random.normal(50, 15, 100),
        'memory_usage': np.random.normal(60, 10, 100),
        'network_io': np.random.normal(1000, 200, 100)
    })

    # Create line chart configuration
    config = VisualizationConfig(
        chart_type='line',
        title='System Performance Metrics',
        x_axis='Date',
        y_axis='Usage (%)',
        data_source='system_metrics',
        refresh_interval=60,
        interactive=True,
        export_formats=['png', 'html']
    )

    # Create visualization
    viz_id = viz_manager.create_visualization(data, config)
    print(f"Created visualization: {viz_id}")

    # Create dashboard layout
    layout = viz_manager.widget_manager.create_layout(
        'main_dashboard',
        {
            'rows': 2,
            'columns': 2,
            'responsive': True
        },
        ['widget_1', 'widget_2']
    )

    # Create sample widgets
    widget1 = viz_manager.widget_manager.create_widget(
        'widget_1',
        'chart',
        {'chart_type': 'line', 'title': 'CPU Usage'}
    )

    widget2 = viz_manager.widget_manager.create_widget(
        'widget_2',
        'metric',
        {'metric': 'system_health', 'format': 'percentage'}
    )

    # Generate analytics report
    report = viz_manager.generate_analytics_report(data)
    print(f"Analytics report generated with {len(report['statistics'])} metrics")

    # Export visualization
    viz_manager.export_visualization(viz_id, 'html', 'system_metrics')

    # Get status
    status = viz_manager.get_visualization_status()
    print(f"Visualization status: {json.dumps(status, indent=2)}")

    print("Advanced data visualization system setup complete!")
