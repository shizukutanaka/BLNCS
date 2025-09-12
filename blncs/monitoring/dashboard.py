#!/usr/bin/env python3
"""
BLNCS Production Monitoring Dashboard
Real-time monitoring dashboard with metrics visualization.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import json
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import logging
from pathlib import Path
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.dates as mdates
from collections import defaultdict, deque

try:
    from .production_monitor import ProductionMonitor
    from .config import get_config, get_threshold
except ImportError:
    # For standalone testing
    import sys
    sys.path.append(str(Path(__file__).parent))
    from production_monitor import ProductionMonitor
    from config import get_config, get_threshold

logger = logging.getLogger(__name__)


class MetricsChart:
    """Real-time metrics chart widget"""
    
    def __init__(self, parent, title: str, metrics: List[str], max_points: int = 100):
        self.parent = parent
        self.title = title
        self.metrics = metrics
        self.max_points = max_points
        
        # Data storage
        self.timestamps = deque(maxlen=max_points)
        self.data = {metric: deque(maxlen=max_points) for metric in metrics}
        
        # Create matplotlib figure
        self.figure = Figure(figsize=(8, 4), dpi=100)
        self.ax = self.figure.add_subplot(111)
        self.ax.set_title(title)
        self.ax.grid(True, alpha=0.3)
        
        # Create canvas
        self.canvas = FigureCanvasTkAgg(self.figure, parent)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Initialize plot
        self.lines = {}
        colors = ['blue', 'red', 'green', 'orange', 'purple', 'brown']
        for i, metric in enumerate(metrics):
            color = colors[i % len(colors)]
            line, = self.ax.plot([], [], label=metric, color=color, linewidth=2)
            self.lines[metric] = line
        
        if len(metrics) > 1:
            self.ax.legend(loc='upper right')
        
        self.figure.tight_layout()
    
    def add_data_point(self, timestamp: datetime, values: Dict[str, float]):
        """Add new data point to chart"""
        self.timestamps.append(timestamp)
        
        for metric in self.metrics:
            value = values.get(metric, 0.0)
            self.data[metric].append(value)
        
        self.update_chart()
    
    def update_chart(self):
        """Update chart display"""
        if not self.timestamps:
            return
        
        # Update data
        for metric in self.metrics:
            self.lines[metric].set_data(list(self.timestamps), list(self.data[metric]))
        
        # Update axes
        if len(self.timestamps) > 1:
            self.ax.set_xlim(self.timestamps[0], self.timestamps[-1])
            
            # Set y-axis limits
            all_values = []
            for metric in self.metrics:
                all_values.extend(list(self.data[metric]))
            
            if all_values:
                min_val = min(all_values)
                max_val = max(all_values)
                margin = (max_val - min_val) * 0.1
                self.ax.set_ylim(min_val - margin, max_val + margin)
        
        # Format x-axis
        self.ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        self.ax.xaxis.set_major_locator(mdates.MinuteLocator(interval=1))
        
        self.figure.autofmt_xdate()
        self.canvas.draw()


class AlertsPanel:
    """Panel for displaying alerts and notifications"""
    
    def __init__(self, parent):
        self.parent = parent
        self.alerts = []
        
        # Create UI
        self.frame = ttk.LabelFrame(parent, text="Recent Alerts", padding="10")
        self.frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Alerts list
        self.alerts_text = scrolledtext.ScrolledText(
            self.frame,
            height=8,
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.alerts_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure text tags for different alert levels
        self.alerts_text.tag_configure("INFO", foreground="blue")
        self.alerts_text.tag_configure("WARNING", foreground="orange")
        self.alerts_text.tag_configure("CRITICAL", foreground="red")
        
        # Control buttons
        buttons_frame = ttk.Frame(self.frame)
        buttons_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Button(
            buttons_frame,
            text="Clear Alerts",
            command=self.clear_alerts
        ).pack(side=tk.LEFT)
        
        ttk.Button(
            buttons_frame,
            text="Export Alerts",
            command=self.export_alerts
        ).pack(side=tk.LEFT, padx=(5, 0))
    
    def add_alert(self, timestamp: datetime, level: str, message: str):
        """Add new alert to panel"""
        alert = {
            'timestamp': timestamp,
            'level': level,
            'message': message
        }
        self.alerts.append(alert)
        
        # Keep only last 100 alerts
        if len(self.alerts) > 100:
            self.alerts.pop(0)
        
        # Update display
        self.update_display()
    
    def update_display(self):
        """Update alerts display"""
        self.alerts_text.config(state=tk.NORMAL)
        self.alerts_text.delete(1.0, tk.END)
        
        # Show recent alerts (last 20)
        recent_alerts = self.alerts[-20:]
        for alert in recent_alerts:
            timestamp_str = alert['timestamp'].strftime('%H:%M:%S')
            level = alert['level']
            message = alert['message']
            
            alert_text = f"[{timestamp_str}] {level}: {message}\n"
            self.alerts_text.insert(tk.END, alert_text, level)
        
        self.alerts_text.config(state=tk.DISABLED)
        self.alerts_text.see(tk.END)
    
    def clear_alerts(self):
        """Clear all alerts"""
        self.alerts.clear()
        self.update_display()
    
    def export_alerts(self):
        """Export alerts to file"""
        try:
            filename = f"alerts_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w', encoding='utf-8') as f:
                alerts_data = []
                for alert in self.alerts:
                    alerts_data.append({
                        'timestamp': alert['timestamp'].isoformat(),
                        'level': alert['level'],
                        'message': alert['message']
                    })
                json.dump(alerts_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Alerts exported to {filename}")
            
        except Exception as e:
            logger.error(f"Failed to export alerts: {e}")


class StatusIndicators:
    """Status indicators panel"""
    
    def __init__(self, parent):
        self.parent = parent
        self.indicators = {}
        
        # Create UI
        self.frame = ttk.LabelFrame(parent, text="System Status", padding="10")
        self.frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Create status indicators
        indicators_frame = ttk.Frame(self.frame)
        indicators_frame.pack(fill=tk.X)
        
        # System status
        self.add_indicator(indicators_frame, "System", "UNKNOWN", 0, 0)
        self.add_indicator(indicators_frame, "Lightning", "UNKNOWN", 0, 1)
        self.add_indicator(indicators_frame, "Database", "UNKNOWN", 0, 2)
        self.add_indicator(indicators_frame, "Application", "UNKNOWN", 0, 3)
    
    def add_indicator(self, parent, name: str, status: str, row: int, col: int):
        """Add status indicator"""
        frame = ttk.Frame(parent)
        frame.grid(row=row, column=col, padx=10, pady=5, sticky="ew")
        
        # Status label
        ttk.Label(frame, text=name, font=("Arial", 10, "bold")).pack()
        
        # Status indicator
        status_var = tk.StringVar(value=status)
        status_label = ttk.Label(
            frame,
            textvariable=status_var,
            font=("Arial", 9),
            foreground="gray"
        )
        status_label.pack()
        
        self.indicators[name.lower()] = {
            'var': status_var,
            'label': status_label
        }
        
        # Make columns expand
        parent.columnconfigure(col, weight=1)
    
    def update_status(self, component: str, status: str, is_healthy: bool = True):
        """Update status indicator"""
        component = component.lower()
        if component in self.indicators:
            self.indicators[component]['var'].set(status)
            
            # Update color based on health
            color = "green" if is_healthy else "red"
            if status.upper() in ["UNKNOWN", "STARTING"]:
                color = "orange"
            
            self.indicators[component]['label'].config(foreground=color)


class MonitoringDashboard:
    """Main monitoring dashboard application"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("BLNCS Production Monitoring Dashboard")
        self.root.geometry("1200x800")
        
        # Initialize components
        self.monitor = ProductionMonitor()
        self.config = get_config()
        
        # Data storage
        self.metrics_history = defaultdict(lambda: deque(maxlen=100))
        self.running = False
        self.update_thread = None
        
        # UI components
        self.charts = {}
        self.alerts_panel = None
        self.status_indicators = None
        
        self.setup_ui()
        self.setup_monitoring()
    
    def setup_ui(self):
        """Setup dashboard UI"""
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Status indicators at top
        self.status_indicators = StatusIndicators(main_frame)
        
        # Create notebook for different chart tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # System metrics tab
        system_frame = ttk.Frame(notebook)
        notebook.add(system_frame, text="System Metrics")
        
        system_chart = MetricsChart(
            system_frame,
            "System Performance",
            ["cpu_percent", "memory_percent", "disk_percent"]
        )
        self.charts["system"] = system_chart
        
        # Lightning metrics tab
        lightning_frame = ttk.Frame(notebook)
        notebook.add(lightning_frame, text="Lightning Network")
        
        lightning_chart = MetricsChart(
            lightning_frame,
            "Lightning Network Status",
            ["channels_total", "channels_active", "balance_local"]
        )
        self.charts["lightning"] = lightning_chart
        
        # Database metrics tab
        database_frame = ttk.Frame(notebook)
        notebook.add(database_frame, text="Database")
        
        database_chart = MetricsChart(
            database_frame,
            "Database Performance",
            ["connections_active", "query_time_avg", "cache_hit_rate"]
        )
        self.charts["database"] = database_chart
        
        # Alerts tab
        alerts_frame = ttk.Frame(notebook)
        notebook.add(alerts_frame, text="Alerts")
        
        self.alerts_panel = AlertsPanel(alerts_frame)
        
        # Control panel at bottom
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(
            control_frame,
            text="Start Monitoring",
            command=self.start_monitoring
        ).pack(side=tk.LEFT)
        
        ttk.Button(
            control_frame,
            text="Stop Monitoring",
            command=self.stop_monitoring
        ).pack(side=tk.LEFT, padx=(5, 0))
        
        ttk.Button(
            control_frame,
            text="Export Data",
            command=self.export_data
        ).pack(side=tk.LEFT, padx=(5, 0))
        
        # Status label
        self.status_var = tk.StringVar(value="Monitoring stopped")
        ttk.Label(
            control_frame,
            textvariable=self.status_var
        ).pack(side=tk.RIGHT)
    
    def setup_monitoring(self):
        """Setup monitoring components"""
        try:
            self.monitor.start()
            logger.info("Production monitor started")
        except Exception as e:
            logger.error(f"Failed to start production monitor: {e}")
    
    def start_monitoring(self):
        """Start monitoring thread"""
        if not self.running:
            self.running = True
            self.status_var.set("Monitoring active")
            
            self.update_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
            self.update_thread.start()
            
            logger.info("Dashboard monitoring started")
    
    def stop_monitoring(self):
        """Stop monitoring thread"""
        self.running = False
        self.status_var.set("Monitoring stopped")
        logger.info("Dashboard monitoring stopped")
    
    def monitoring_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Collect metrics
                current_time = datetime.now()
                
                # Get system metrics
                system_metrics = self.monitor.metrics_collector.collect_system_metrics()
                self.update_chart("system", current_time, system_metrics)
                self.status_indicators.update_status(
                    "system",
                    f"CPU: {system_metrics.get('cpu_percent', 0):.1f}%",
                    system_metrics.get('cpu_percent', 0) < 90
                )
                
                # Get Lightning metrics
                lightning_metrics = self.monitor.metrics_collector.collect_lightning_metrics()
                self.update_chart("lightning", current_time, lightning_metrics)
                channels_active = lightning_metrics.get('channels_active', 0)
                channels_total = lightning_metrics.get('channels_total', 0)
                self.status_indicators.update_status(
                    "lightning",
                    f"Channels: {channels_active}/{channels_total}",
                    channels_active == channels_total
                )
                
                # Get database metrics
                database_metrics = self.monitor.metrics_collector.collect_database_metrics()
                self.update_chart("database", current_time, database_metrics)
                self.status_indicators.update_status(
                    "database",
                    f"Connections: {database_metrics.get('connections_active', 0)}",
                    True
                )
                
                # Check for alerts
                self.check_alerts(current_time, {
                    **system_metrics,
                    **lightning_metrics,
                    **database_metrics
                })
                
                # Sleep before next update
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(10)  # Wait longer on error
    
    def update_chart(self, chart_name: str, timestamp: datetime, metrics: Dict[str, Any]):
        """Update chart with new data"""
        if chart_name in self.charts:
            self.charts[chart_name].add_data_point(timestamp, metrics)
    
    def check_alerts(self, timestamp: datetime, metrics: Dict[str, Any]):
        """Check metrics against thresholds and generate alerts"""
        for metric_name, value in metrics.items():
            threshold = get_threshold(metric_name)
            if not threshold or not threshold.enabled:
                continue
            
            # Check threshold violation
            violation_level = None
            if threshold.comparison == "greater":
                if value >= threshold.critical_threshold:
                    violation_level = "CRITICAL"
                elif value >= threshold.warning_threshold:
                    violation_level = "WARNING"
            elif threshold.comparison == "less":
                if value <= threshold.critical_threshold:
                    violation_level = "CRITICAL"
                elif value <= threshold.warning_threshold:
                    violation_level = "WARNING"
            
            # Generate alert if threshold violated
            if violation_level:
                message = f"{metric_name} is {value} (threshold: {threshold.warning_threshold}/{threshold.critical_threshold})"
                self.alerts_panel.add_alert(timestamp, violation_level, message)
    
    def export_data(self):
        """Export monitoring data"""
        try:
            filename = f"monitoring_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            export_data = {
                'timestamp': datetime.now().isoformat(),
                'config': self.config.to_dict(),
                'charts_data': {}
            }
            
            # Export chart data
            for chart_name, chart in self.charts.items():
                export_data['charts_data'][chart_name] = {
                    'timestamps': [ts.isoformat() for ts in chart.timestamps],
                    'metrics': {
                        metric: list(data)
                        for metric, data in chart.data.items()
                    }
                }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Monitoring data exported to {filename}")
            
        except Exception as e:
            logger.error(f"Failed to export monitoring data: {e}")
    
    def run(self):
        """Run dashboard application"""
        try:
            # Start monitoring automatically
            self.start_monitoring()
            
            # Start GUI main loop
            self.root.mainloop()
            
        except KeyboardInterrupt:
            logger.info("Dashboard interrupted by user")
        except Exception as e:
            logger.error(f"Dashboard error: {e}")
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Cleanup resources"""
        logger.info("Cleaning up dashboard resources")
        self.stop_monitoring()
        
        try:
            self.monitor.stop()
        except:
            pass


def main():
    """Main entry point"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    try:
        dashboard = MonitoringDashboard()
        dashboard.run()
    except Exception as e:
        logger.error(f"Failed to start monitoring dashboard: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())