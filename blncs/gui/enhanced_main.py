"""
Enhanced BLNCS Main GUI Application
Modern, responsive interface with advanced features and real-time updates.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import time
import json
import queue
import logging
from typing import Dict, Any, Optional, Callable, List
from datetime import datetime, timedelta
from pathlib import Path
import asyncio
from dataclasses import dataclass

try:
    from ..core.config_enhanced import get_config_manager
    from ..lightning.client import create_client, LightningError, format_satoshis
    from ..core.database import get_database
    from ..core.observability import get_system_monitor
    from ..utils.lightweight_fallbacks import get_system_monitor as get_fallback_monitor
except ImportError:
    # Fallback imports for standalone testing
    import sys
    sys.path.append(str(Path(__file__).parent.parent))
    from core.config_enhanced import get_config_manager
    from lightning.client import create_client, LightningError, format_satoshis
    from core.database import get_database


@dataclass
class UIState:
    """Application UI state"""
    connected: bool = False
    node_info: Optional[Dict[str, Any]] = None
    balance: int = 0
    channels_count: int = 0
    last_update: Optional[datetime] = None
    theme: str = "light"


class EnhancedThemeManager:
    """Advanced theme management"""
    
    def __init__(self):
        self.themes = {
            'light': {
                'bg_primary': '#ffffff',
                'bg_secondary': '#f8fafc',
                'bg_accent': '#e2e8f0',
                'text_primary': '#0f172a',
                'text_secondary': '#64748b',
                'text_accent': '#3b82f6',
                'border': '#e2e8f0',
                'success': '#16a34a',
                'warning': '#d97706', 
                'error': '#dc2626',
                'button_primary': '#3b82f6',
                'button_hover': '#2563eb'
            },
            'dark': {
                'bg_primary': '#0f172a',
                'bg_secondary': '#1e293b',
                'bg_accent': '#334155',
                'text_primary': '#f8fafc',
                'text_secondary': '#cbd5e1',
                'text_accent': '#60a5fa',
                'border': '#475569',
                'success': '#22c55e',
                'warning': '#f59e0b',
                'error': '#ef4444',
                'button_primary': '#3b82f6',
                'button_hover': '#2563eb'
            },
            'bitcoin': {
                'bg_primary': '#fff7ed',
                'bg_secondary': '#fed7aa',
                'bg_accent': '#fdba74',
                'text_primary': '#1a1a1a',
                'text_secondary': '#525252',
                'text_accent': '#ea580c',
                'border': '#fed7aa',
                'success': '#16a34a',
                'warning': '#d97706',
                'error': '#dc2626',
                'button_primary': '#ea580c',
                'button_hover': '#c2410c'
            }
        }
        self.current_theme = 'light'
        self.style = None
    
    def set_theme(self, theme_name: str):
        """Set application theme"""
        if theme_name not in self.themes:
            return False
        
        self.current_theme = theme_name
        if self.style:
            self._apply_theme()
        return True
    
    def configure_style(self, style: ttk.Style):
        """Configure TTK style with current theme"""
        self.style = style
        self._apply_theme()
    
    def _apply_theme(self):
        """Apply current theme to TTK style"""
        theme = self.themes[self.current_theme]
        
        # Configure styles
        self.style.configure('Title.TLabel',
            background=theme['bg_primary'],
            foreground=theme['text_primary'],
            font=('Segoe UI', 18, 'bold'))
        
        self.style.configure('Subtitle.TLabel',
            background=theme['bg_primary'],
            foreground=theme['text_secondary'],
            font=('Segoe UI', 12))
        
        self.style.configure('Card.TFrame',
            background=theme['bg_secondary'],
            relief='flat',
            borderwidth=1)
        
        self.style.configure('Primary.TButton',
            background=theme['button_primary'],
            foreground='white',
            borderwidth=0,
            focuscolor='none',
            font=('Segoe UI', 10, 'bold'))
        
        self.style.map('Primary.TButton',
            background=[('active', theme['button_hover'])])
        
        self.style.configure('Success.TLabel',
            background=theme['bg_primary'],
            foreground=theme['success'])
        
        self.style.configure('Warning.TLabel', 
            background=theme['bg_primary'],
            foreground=theme['warning'])
        
        self.style.configure('Error.TLabel',
            background=theme['bg_primary'],
            foreground=theme['error'])
    
    def get_color(self, key: str) -> str:
        """Get color from current theme"""
        return self.themes[self.current_theme].get(key, '#000000')


class RealTimeChart:
    """Real-time data chart widget"""
    
    def __init__(self, parent, title: str, max_points: int = 50):
        self.parent = parent
        self.title = title
        self.max_points = max_points
        self.data_points: List[float] = []
        self.timestamps: List[datetime] = []
        
        self.frame = ttk.Frame(parent)
        self.canvas = tk.Canvas(self.frame, height=200, bg='white')
        self.canvas.pack(fill='both', expand=True)
        
        # Title
        self.canvas.create_text(10, 10, text=title, anchor='nw', font=('Segoe UI', 12, 'bold'))
    
    def add_data_point(self, value: float):
        """Add new data point"""
        self.data_points.append(value)
        self.timestamps.append(datetime.now())
        
        # Keep only max_points
        if len(self.data_points) > self.max_points:
            self.data_points.pop(0)
            self.timestamps.pop(0)
        
        self.update_chart()
    
    def update_chart(self):
        """Update chart display"""
        if not self.data_points:
            return
        
        self.canvas.delete("chart")
        
        width = self.canvas.winfo_width()
        height = self.canvas.winfo_height()
        
        if width <= 1 or height <= 1:
            return
        
        # Calculate chart area
        margin = 40
        chart_width = width - 2 * margin
        chart_height = height - 2 * margin - 30  # Space for title
        
        if chart_width <= 0 or chart_height <= 0:
            return
        
        # Calculate data ranges
        min_val = min(self.data_points)
        max_val = max(self.data_points)
        val_range = max_val - min_val if max_val != min_val else 1
        
        # Draw data points
        points = []
        for i, value in enumerate(self.data_points):
            x = margin + (i / max(len(self.data_points) - 1, 1)) * chart_width
            y = margin + 30 + chart_height - ((value - min_val) / val_range) * chart_height
            points.extend([x, y])
        
        if len(points) >= 4:  # Need at least 2 points
            self.canvas.create_line(points, fill='#3b82f6', width=2, tags="chart", smooth=True)
        
        # Draw axes
        self.canvas.create_line(margin, margin + 30, margin, margin + 30 + chart_height, 
                              fill='#64748b', tags="chart")
        self.canvas.create_line(margin, margin + 30 + chart_height, 
                              margin + chart_width, margin + 30 + chart_height,
                              fill='#64748b', tags="chart")
        
        # Add value labels
        if self.data_points:
            latest = self.data_points[-1]
            self.canvas.create_text(width - 10, 30, text=f"{latest:.2f}", 
                                  anchor='ne', font=('Segoe UI', 10), tags="chart")


class NotificationCenter:
    """In-app notification system"""
    
    def __init__(self, parent):
        self.parent = parent
        self.notifications = []
        
        # Create notification area
        self.frame = ttk.Frame(parent)
        self.frame.pack(side='top', fill='x', padx=5, pady=2)
    
    def show_notification(self, message: str, notification_type: str = 'info', duration: int = 5000):
        """Show notification"""
        # Color mapping
        colors = {
            'info': '#3b82f6',
            'success': '#16a34a', 
            'warning': '#d97706',
            'error': '#dc2626'
        }
        
        # Create notification frame
        notif_frame = ttk.Frame(self.frame)
        notif_frame.pack(fill='x', pady=1)
        
        # Notification content
        label = ttk.Label(notif_frame, text=message, 
                         foreground=colors.get(notification_type, '#3b82f6'))
        label.pack(side='left')
        
        # Close button
        close_btn = ttk.Button(notif_frame, text="×", width=3,
                             command=lambda: notif_frame.destroy())
        close_btn.pack(side='right')
        
        # Auto-hide after duration
        if duration > 0:
            self.parent.after(duration, lambda: notif_frame.destroy())


class AdvancedDashboard:
    """Advanced dashboard with real-time monitoring"""
    
    def __init__(self, parent, lightning_client, theme_manager):
        self.parent = parent
        self.client = lightning_client
        self.theme_manager = theme_manager
        self.update_queue = queue.Queue()
        
        self.frame = ttk.Frame(parent)
        self.frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.create_widgets()
        self.start_update_loop()
    
    def create_widgets(self):
        """Create dashboard widgets"""
        # Header
        header_frame = ttk.Frame(self.frame)
        header_frame.pack(fill='x', pady=(0, 20))
        
        title = ttk.Label(header_frame, text="Lightning Network Dashboard", style='Title.TLabel')
        title.pack(side='left')
        
        # Theme selector
        theme_var = tk.StringVar(value=self.theme_manager.current_theme)
        theme_combo = ttk.Combobox(header_frame, textvariable=theme_var,
                                  values=list(self.theme_manager.themes.keys()),
                                  state='readonly', width=10)
        theme_combo.pack(side='right', padx=(10, 0))
        theme_combo.bind('<<ComboboxSelected>>', 
                        lambda e: self.theme_manager.set_theme(theme_var.get()))
        
        # Stats row
        stats_frame = ttk.Frame(self.frame)
        stats_frame.pack(fill='x', pady=(0, 20))
        
        self.create_stat_cards(stats_frame)
        
        # Charts row
        charts_frame = ttk.Frame(self.frame)
        charts_frame.pack(fill='both', expand=True)
        
        self.create_charts(charts_frame)
        
        # Activity panel
        self.create_activity_panel()
    
    def create_stat_cards(self, parent):
        """Create statistics cards"""
        # Balance card
        balance_card = ttk.Frame(parent, style='Card.TFrame')
        balance_card.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        ttk.Label(balance_card, text="Wallet Balance", style='Subtitle.TLabel').pack(pady=10)
        self.balance_var = tk.StringVar(value="0.00000000 BTC")
        balance_label = ttk.Label(balance_card, textvariable=self.balance_var, 
                                 font=('Segoe UI', 14, 'bold'))
        balance_label.pack()
        
        # Channels card
        channels_card = ttk.Frame(parent, style='Card.TFrame')
        channels_card.pack(side='left', fill='both', expand=True, padx=5)
        
        ttk.Label(channels_card, text="Active Channels", style='Subtitle.TLabel').pack(pady=10)
        self.channels_var = tk.StringVar(value="0")
        channels_label = ttk.Label(channels_card, textvariable=self.channels_var,
                                  font=('Segoe UI', 14, 'bold'))
        channels_label.pack()
        
        # Capacity card
        capacity_card = ttk.Frame(parent, style='Card.TFrame')
        capacity_card.pack(side='left', fill='both', expand=True, padx=(10, 0))
        
        ttk.Label(capacity_card, text="Total Capacity", style='Subtitle.TLabel').pack(pady=10)
        self.capacity_var = tk.StringVar(value="0 sats")
        capacity_label = ttk.Label(capacity_card, textvariable=self.capacity_var,
                                  font=('Segoe UI', 14, 'bold'))
        capacity_label.pack()
    
    def create_charts(self, parent):
        """Create real-time charts"""
        # Balance chart
        balance_frame = ttk.Frame(parent)
        balance_frame.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        self.balance_chart = RealTimeChart(balance_frame, "Balance History")
        self.balance_chart.frame.pack(fill='both', expand=True)
        
        # Channel count chart
        channels_frame = ttk.Frame(parent)
        channels_frame.pack(side='right', fill='both', expand=True, padx=(10, 0))
        
        self.channels_chart = RealTimeChart(channels_frame, "Channel Count")
        self.channels_chart.frame.pack(fill='both', expand=True)
    
    def create_activity_panel(self):
        """Create activity monitoring panel"""
        activity_frame = ttk.LabelFrame(self.frame, text="Recent Activity")
        activity_frame.pack(fill='x', pady=(20, 0))
        
        # Activity list
        self.activity_tree = ttk.Treeview(activity_frame,
            columns=('timestamp', 'type', 'amount', 'status'), 
            show='headings', height=6)
        
        # Configure columns
        self.activity_tree.heading('timestamp', text='Time')
        self.activity_tree.heading('type', text='Type')
        self.activity_tree.heading('amount', text='Amount')
        self.activity_tree.heading('status', text='Status')
        
        self.activity_tree.column('timestamp', width=150)
        self.activity_tree.column('type', width=100)
        self.activity_tree.column('amount', width=120)
        self.activity_tree.column('status', width=100)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(activity_frame, orient='vertical', 
                                command=self.activity_tree.yview)
        self.activity_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack
        self.activity_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
    
    def start_update_loop(self):
        """Start data update loop"""
        def update_worker():
            while True:
                try:
                    self.update_data()
                    time.sleep(5)  # Update every 5 seconds
                except Exception as e:
                    print(f"Update error: {e}")
                    time.sleep(10)
        
        update_thread = threading.Thread(target=update_worker)
        update_thread.daemon = True
        update_thread.start()
    
    def update_data(self):
        """Update dashboard data"""
        if not self.client or not self.client.connected:
            return
        
        try:
            # Get balance
            balance_data = self.client.get_balance()
            balance_sats = int(balance_data.get('confirmed_balance', 0))
            balance_btc = balance_sats / 100_000_000
            
            # Get channels
            channels_data = self.client.list_channels()
            channels = channels_data.get('channels', [])
            channels_count = len(channels)
            
            # Calculate total capacity
            total_capacity = sum(int(ch.get('capacity', 0)) for ch in channels)
            
            # Update UI in main thread
            self.parent.after(0, lambda: self._update_ui(balance_btc, channels_count, total_capacity))
            
        except Exception as e:
            print(f"Failed to update data: {e}")
    
    def _update_ui(self, balance_btc: float, channels_count: int, total_capacity: int):
        """Update UI elements"""
        # Update text
        self.balance_var.set(f"{balance_btc:.8f} BTC")
        self.channels_var.set(str(channels_count))
        self.capacity_var.set(f"{total_capacity:,} sats")
        
        # Update charts
        self.balance_chart.add_data_point(balance_btc * 100_000_000)  # Convert to sats for chart
        self.channels_chart.add_data_point(channels_count)


class EnhancedMainWindow:
    """Enhanced main application window"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("BLNCS - Enhanced Bitcoin Lightning Control")
        self.root.geometry("1200x800")
        
        # State management
        self.state = UIState()
        self.config = get_config_manager()
        self.theme_manager = EnhancedThemeManager()
        
        # Lightning client
        self.lightning_client = None
        
        # Setup UI
        self.setup_ui()
        
        # Auto-connect if enabled
        if self.config.get('lightning.auto_connect', True):
            self.connect_to_node()
    
    def setup_ui(self):
        """Setup enhanced UI"""
        # Configure theme
        style = ttk.Style()
        self.theme_manager.configure_style(style)
        
        # Notification center
        self.notifications = NotificationCenter(self.root)
        
        # Menu bar
        self.setup_menu()
        
        # Toolbar
        self.setup_toolbar()
        
        # Main content
        self.setup_content()
        
        # Status bar
        self.setup_status_bar()
    
    def setup_menu(self):
        """Setup enhanced menu"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Wallet...", command=self.new_wallet)
        file_menu.add_command(label="Open Wallet...", command=self.open_wallet)
        file_menu.add_separator()
        file_menu.add_command(label="Settings", command=self.show_settings)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close)
        
        # Lightning menu
        lightning_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Lightning", menu=lightning_menu)
        lightning_menu.add_command(label="Connect to Node", command=self.connect_to_node)
        lightning_menu.add_command(label="Disconnect", command=self.disconnect_from_node)
        lightning_menu.add_separator()
        lightning_menu.add_command(label="Send Payment", command=lambda: self.show_payment_dialog('send'))
        lightning_menu.add_command(label="Receive Payment", command=lambda: self.show_payment_dialog('receive'))
        lightning_menu.add_command(label="Open Channel", command=self.show_channel_dialog)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Network Graph", command=self.show_network_graph)
        tools_menu.add_command(label="Channel Backup", command=self.backup_channels)
        tools_menu.add_command(label="System Info", command=self.show_system_info)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        theme_menu = tk.Menu(view_menu, tearoff=0)
        view_menu.add_cascade(label="Theme", menu=theme_menu)
        for theme in self.theme_manager.themes.keys():
            theme_menu.add_command(label=theme.title(), 
                                 command=lambda t=theme: self.set_theme(t))
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation", command=self.show_help)
        help_menu.add_command(label="About", command=self.show_about)
    
    def setup_toolbar(self):
        """Setup enhanced toolbar"""
        toolbar = ttk.Frame(self.root)
        toolbar.pack(side='top', fill='x', padx=5, pady=5)
        
        # Connection status and button
        self.connection_frame = ttk.Frame(toolbar)
        self.connection_frame.pack(side='left')
        
        self.connect_btn = ttk.Button(self.connection_frame, text="Connect", 
                                    command=self.connect_to_node, style='Primary.TButton')
        self.connect_btn.pack(side='left')
        
        self.status_indicator = tk.Label(toolbar, text="●", fg="red", font=('Segoe UI', 12))
        self.status_indicator.pack(side='left', padx=(5, 15))
        
        # Payment buttons
        payment_frame = ttk.Frame(toolbar)
        payment_frame.pack(side='left', padx=(20, 0))
        
        ttk.Button(payment_frame, text="💸 Send", 
                  command=lambda: self.show_payment_dialog('send')).pack(side='left', padx=(0, 5))
        ttk.Button(payment_frame, text="💰 Receive",
                  command=lambda: self.show_payment_dialog('receive')).pack(side='left')
        
        # Tools
        tools_frame = ttk.Frame(toolbar)
        tools_frame.pack(side='right')
        
        ttk.Button(tools_frame, text="🔄 Refresh", command=self.refresh_all).pack(side='left', padx=(0, 5))
        ttk.Button(tools_frame, text="⚙️ Settings", command=self.show_settings).pack(side='left')
    
    def setup_content(self):
        """Setup main content area"""
        # Create notebook with tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Dashboard tab
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="📊 Dashboard")
        self.dashboard = AdvancedDashboard(dashboard_frame, self.lightning_client, self.theme_manager)
        
        # Channels tab
        channels_frame = ttk.Frame(self.notebook)
        self.notebook.add(channels_frame, text="🔗 Channels")
        self.setup_channels_tab(channels_frame)
        
        # Transactions tab
        transactions_frame = ttk.Frame(self.notebook)
        self.notebook.add(transactions_frame, text="💳 Transactions")
        self.setup_transactions_tab(transactions_frame)
        
        # Analytics tab
        analytics_frame = ttk.Frame(self.notebook)
        self.notebook.add(analytics_frame, text="📈 Analytics")
        self.setup_analytics_tab(analytics_frame)
    
    def setup_status_bar(self):
        """Setup enhanced status bar"""
        status_frame = ttk.Frame(self.root)
        status_frame.pack(side='bottom', fill='x', padx=5, pady=2)
        
        # Connection info
        self.connection_status = ttk.Label(status_frame, text="Disconnected")
        self.connection_status.pack(side='left')
        
        # Node info
        self.node_info = ttk.Label(status_frame, text="")
        self.node_info.pack(side='left', padx=(20, 0))
        
        # Performance info
        self.perf_info = ttk.Label(status_frame, text="")
        self.perf_info.pack(side='right')
        
        # Start status updates
        self.update_status_bar()
    
    def setup_channels_tab(self, parent):
        """Setup channels management tab"""
        # Channels list
        channels_tree = ttk.Treeview(parent,
            columns=('peer', 'capacity', 'local', 'remote', 'status'),
            show='headings')
        
        # Configure columns
        for col, text in [('peer', 'Peer'), ('capacity', 'Capacity'), 
                         ('local', 'Local Balance'), ('remote', 'Remote Balance'),
                         ('status', 'Status')]:
            channels_tree.heading(col, text=text)
            channels_tree.column(col, width=150)
        
        channels_tree.pack(fill='both', expand=True, padx=10, pady=10)
    
    def setup_transactions_tab(self, parent):
        """Setup transactions history tab"""
        # Transactions list
        tx_tree = ttk.Treeview(parent,
            columns=('timestamp', 'type', 'amount', 'fee', 'status'),
            show='headings')
        
        # Configure columns
        for col, text in [('timestamp', 'Time'), ('type', 'Type'),
                         ('amount', 'Amount'), ('fee', 'Fee'), ('status', 'Status')]:
            tx_tree.heading(col, text=text)
            tx_tree.column(col, width=120)
        
        tx_tree.pack(fill='both', expand=True, padx=10, pady=10)
    
    def setup_analytics_tab(self, parent):
        """Setup analytics and reporting tab"""
        analytics_label = ttk.Label(parent, text="Analytics Dashboard", style='Title.TLabel')
        analytics_label.pack(pady=20)
        
        # Placeholder for future analytics
        placeholder = ttk.Label(parent, text="Coming Soon: Advanced Analytics and Reporting",
                              style='Subtitle.TLabel')
        placeholder.pack()
    
    def connect_to_node(self):
        """Connect to Lightning node"""
        def connect_worker():
            try:
                self.update_connection_status("Connecting...")
                
                host = self.config.get('lightning.host', 'localhost')
                port = self.config.get('lightning.port', 8080)
                
                self.lightning_client = create_client(host=host, port=port, enhanced=True)
                
                if self.lightning_client.connect():
                    node_info = self.lightning_client.get_info()
                    node_alias = node_info.get('alias', 'Unknown')
                    
                    self.state.connected = True
                    self.state.node_info = node_info
                    
                    self.root.after(0, lambda: self.update_connection_status(f"Connected to {node_alias}"))
                    self.root.after(0, lambda: self.notifications.show_notification(
                        f"Connected to Lightning node: {node_alias}", "success"))
                    
                    # Update dashboard client
                    self.dashboard.client = self.lightning_client
                    
                else:
                    raise Exception("Connection failed")
                    
            except Exception as e:
                self.root.after(0, lambda: self.update_connection_status("Connection failed"))
                self.root.after(0, lambda: self.notifications.show_notification(
                    f"Connection failed: {e}", "error"))
        
        threading.Thread(target=connect_worker, daemon=True).start()
    
    def disconnect_from_node(self):
        """Disconnect from Lightning node"""
        if self.lightning_client:
            self.lightning_client.disconnect()
            self.lightning_client = None
            self.dashboard.client = None
        
        self.state.connected = False
        self.state.node_info = None
        self.update_connection_status("Disconnected")
        self.notifications.show_notification("Disconnected from Lightning node", "info")
    
    def update_connection_status(self, status: str):
        """Update connection status display"""
        self.connection_status.config(text=status)
        
        if "Connected" in status:
            self.status_indicator.config(fg="green")
            self.connect_btn.config(text="Connected", state="disabled")
        else:
            self.status_indicator.config(fg="red")
            self.connect_btn.config(text="Connect", state="normal")
    
    def update_status_bar(self):
        """Update status bar information"""
        try:
            # Get system monitor
            try:
                from ..core.observability import get_system_monitor
                monitor = get_system_monitor()
                cpu_percent = monitor.cpu_percent()
                memory_info = monitor.virtual_memory()
            except:
                from ..utils.lightweight_fallbacks import get_system_monitor
                monitor = get_system_monitor()
                info = monitor.get_system_info()
                cpu_percent = info.cpu_percent
                memory_info = type('Memory', (), {'percent': info.memory_percent})()
            
            perf_text = f"CPU: {cpu_percent:.1f}% | RAM: {memory_info.percent:.1f}%"
            self.perf_info.config(text=perf_text)
            
        except Exception as e:
            self.perf_info.config(text="Performance info unavailable")
        
        # Schedule next update
        self.root.after(5000, self.update_status_bar)
    
    def set_theme(self, theme_name: str):
        """Set application theme"""
        if self.theme_manager.set_theme(theme_name):
            self.config.set('ui.theme', theme_name, persist=True)
            self.notifications.show_notification(f"Theme changed to {theme_name.title()}", "info")
    
    def show_payment_dialog(self, mode: str):
        """Show payment dialog"""
        if not self.state.connected:
            self.notifications.show_notification("Please connect to a Lightning node first", "warning")
            return
        messagebox.showinfo("Payment", f"Payment dialog ({mode}) not implemented yet")
    
    def show_channel_dialog(self):
        """Show channel management dialog"""
        if not self.state.connected:
            self.notifications.show_notification("Please connect to a Lightning node first", "warning")
            return
        messagebox.showinfo("Channels", "Channel management not implemented yet")
    
    def show_network_graph(self):
        """Show network graph visualization"""
        messagebox.showinfo("Network Graph", "Network graph visualization not implemented yet")
    
    def backup_channels(self):
        """Backup channel state"""
        if not self.state.connected:
            self.notifications.show_notification("Please connect to a Lightning node first", "warning")
            return
        messagebox.showinfo("Backup", "Channel backup not implemented yet")
    
    def show_system_info(self):
        """Show system information dialog"""
        info_window = tk.Toplevel(self.root)
        info_window.title("System Information")
        info_window.geometry("600x400")
        
        text_widget = scrolledtext.ScrolledText(info_window)
        text_widget.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Get system info
        info_text = f"""
BLNCS System Information
========================

Application: {self.config.get('app.name', 'BLNCS')}
Version: {self.config.get('app.version', '1.0.0')}

Lightning Node: {'Connected' if self.state.connected else 'Disconnected'}
{f"Node Alias: {self.state.node_info.get('alias', 'Unknown')}" if self.state.node_info else ''}

Configuration Sources: {len(self.config.sources)}
Database Path: {self.config.get('database.path', 'blncs.db')}
Theme: {self.theme_manager.current_theme}

Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        
        text_widget.insert(1.0, info_text)
        text_widget.config(state='disabled')
    
    def show_settings(self):
        """Show settings dialog"""
        messagebox.showinfo("Settings", "Settings dialog not implemented yet")
    
    def show_help(self):
        """Show help documentation"""
        messagebox.showinfo("Help", "Documentation not implemented yet")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
BLNCS - Enhanced Bitcoin Lightning Network Control System
Version 2.0.0

Advanced Lightning Network management with real-time monitoring,
modern UI themes, and comprehensive analytics.

Features:
• Real-time dashboard with charts
• Multi-theme support
• Advanced channel management  
• Transaction history and analytics
• System performance monitoring
• Notification center

© 2024 BLNCS Development Team
        """
        messagebox.showinfo("About BLNCS", about_text)
    
    def refresh_all(self):
        """Refresh all data"""
        if hasattr(self.dashboard, 'update_data'):
            threading.Thread(target=self.dashboard.update_data, daemon=True).start()
        self.notifications.show_notification("Refreshing data...", "info")
    
    def new_wallet(self):
        """Create new wallet"""
        messagebox.showinfo("New Wallet", "Wallet creation not implemented yet")
    
    def open_wallet(self):
        """Open existing wallet"""
        messagebox.showinfo("Open Wallet", "Wallet opening not implemented yet")
    
    def on_close(self):
        """Handle application close"""
        if self.lightning_client:
            self.lightning_client.disconnect()
        
        # Save window state
        self.config.set('ui.window_geometry', self.root.geometry(), persist=True)
        
        self.root.quit()
        self.root.destroy()
    
    def run(self):
        """Start the enhanced GUI application"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()


def main():
    """Enhanced GUI main entry point"""
    app = EnhancedMainWindow()
    app.run()


if __name__ == "__main__":
    main()