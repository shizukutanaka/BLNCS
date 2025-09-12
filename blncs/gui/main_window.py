"""
BLNCS Main Window
Modern Lightning Network management interface with intuitive UI/UX.
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
from datetime import datetime
from typing import Dict, Any, Optional
import json

# Import BLNCS modules
from ..lightning.client_simple import get_lightning_client
from ..core.config_manager import get_config_manager
from ..cli.commands.health_simple import check_system_health
from .system_tray import create_tray_integration

class ModernStyle:
    """Modern UI color scheme and styling"""
    
    # Colors
    PRIMARY = "#2563eb"      # Blue
    PRIMARY_DARK = "#1d4ed8"
    SUCCESS = "#16a34a"      # Green
    WARNING = "#d97706"      # Orange
    ERROR = "#dc2626"        # Red
    
    BG_PRIMARY = "#f8fafc"   # Light gray
    BG_SECONDARY = "#f1f5f9"
    BG_DARK = "#334155"
    
    TEXT_PRIMARY = "#0f172a"
    TEXT_SECONDARY = "#64748b"
    TEXT_LIGHT = "#ffffff"
    
    BORDER = "#e2e8f0"
    
    # Fonts
    FONT_LARGE = ("Segoe UI", 16, "bold")
    FONT_MEDIUM = ("Segoe UI", 12)
    FONT_SMALL = ("Segoe UI", 10)

class StatusBar(ttk.Frame):
    """Status bar with connection and sync status"""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.create_widgets()
        
    def create_widgets(self):
        # Status indicators
        self.connection_label = ttk.Label(self, text="⚡ Disconnected", foreground="red")
        self.connection_label.pack(side=tk.LEFT, padx=5)
        
        self.sync_label = ttk.Label(self, text="🔄 Not Synced", foreground="orange")
        self.sync_label.pack(side=tk.LEFT, padx=5)
        
        # Separator
        ttk.Separator(self, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5)
        
        # Time
        self.time_label = ttk.Label(self, text="")
        self.time_label.pack(side=tk.RIGHT, padx=5)
        
        # Update time initially
        self.update_time()
        
    def update_status(self, connected: bool = False, synced: bool = False):
        """Update connection and sync status"""
        if connected:
            self.connection_label.config(text="⚡ Connected", foreground="green")
        else:
            self.connection_label.config(text="⚡ Disconnected", foreground="red")
            
        if synced:
            self.sync_label.config(text="✅ Synced", foreground="green")
        else:
            self.sync_label.config(text="🔄 Syncing", foreground="orange")
    
    def update_time(self):
        """Update current time"""
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=current_time)
        # Schedule next update
        self.after(1000, self.update_time)

class DashboardTab(ttk.Frame):
    """Main dashboard with overview information"""
    
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.create_widgets()
        self.start_auto_refresh()
        
    def create_widgets(self):
        # Title
        title_frame = ttk.Frame(self)
        title_frame.pack(fill=tk.X, padx=10, pady=5)
        
        title_label = ttk.Label(title_frame, text="⚡ Lightning Dashboard", font=ModernStyle.FONT_LARGE)
        title_label.pack(side=tk.LEFT)
        
        self.refresh_button = ttk.Button(title_frame, text="🔄 Refresh", command=self.refresh_data)
        self.refresh_button.pack(side=tk.RIGHT)
        
        # Main container with scrolling
        self.canvas = tk.Canvas(self, bg=ModernStyle.BG_PRIMARY)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True, padx=10, pady=5)
        self.scrollbar.pack(side="right", fill="y")
        
        # Content sections
        self.create_node_section()
        self.create_balance_section()
        self.create_channels_section()
        self.create_activity_section()
        self.create_health_section()
        
    def create_section_frame(self, title: str) -> ttk.LabelFrame:
        """Create a styled section frame"""
        frame = ttk.LabelFrame(self.scrollable_frame, text=title, padding=10)
        frame.pack(fill=tk.X, padx=5, pady=5)
        return frame
        
    def create_node_section(self):
        """Node information section"""
        self.node_frame = self.create_section_frame("📡 Node Information")
        
        # Create grid layout
        self.node_alias_var = tk.StringVar(value="Loading...")
        self.node_version_var = tk.StringVar(value="Loading...")
        self.node_network_var = tk.StringVar(value="Loading...")
        self.node_peers_var = tk.StringVar(value="Loading...")
        
        ttk.Label(self.node_frame, text="Alias:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(self.node_frame, textvariable=self.node_alias_var).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(self.node_frame, text="Version:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(self.node_frame, textvariable=self.node_version_var).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(self.node_frame, text="Network:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(self.node_frame, textvariable=self.node_network_var).grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(self.node_frame, text="Peers:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(self.node_frame, textvariable=self.node_peers_var).grid(row=3, column=1, sticky=tk.W, padx=5, pady=2)
        
    def create_balance_section(self):
        """Balance information section"""
        self.balance_frame = self.create_section_frame("💰 Balances")
        
        self.wallet_balance_var = tk.StringVar(value="Loading...")
        self.channel_balance_var = tk.StringVar(value="Loading...")
        self.total_balance_var = tk.StringVar(value="Loading...")
        
        ttk.Label(self.balance_frame, text="Wallet:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(self.balance_frame, textvariable=self.wallet_balance_var).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(self.balance_frame, text="Channels:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(self.balance_frame, textvariable=self.channel_balance_var).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(self.balance_frame, text="Total:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(self.balance_frame, textvariable=self.total_balance_var, font=("Segoe UI", 12, "bold")).grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        
    def create_channels_section(self):
        """Channels information section"""
        self.channels_frame = self.create_section_frame("📡 Channels")
        
        self.active_channels_var = tk.StringVar(value="Loading...")
        self.pending_channels_var = tk.StringVar(value="Loading...")
        
        ttk.Label(self.channels_frame, text="Active:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(self.channels_frame, textvariable=self.active_channels_var).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(self.channels_frame, text="Pending:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(self.channels_frame, textvariable=self.pending_channels_var).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
    def create_activity_section(self):
        """Recent activity section"""
        self.activity_frame = self.create_section_frame("⚡ Recent Activity")
        
        # Activity log
        self.activity_text = scrolledtext.ScrolledText(self.activity_frame, height=6, width=50)
        self.activity_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add sample activity
        self.add_activity("System started", "info")
        
    def create_health_section(self):
        """System health section"""
        self.health_frame = self.create_section_frame("🏥 System Health")
        
        self.cpu_var = tk.StringVar(value="Loading...")
        self.memory_var = tk.StringVar(value="Loading...")
        self.disk_var = tk.StringVar(value="Loading...")
        
        ttk.Label(self.health_frame, text="CPU:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(self.health_frame, textvariable=self.cpu_var).grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(self.health_frame, text="Memory:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(self.health_frame, textvariable=self.memory_var).grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(self.health_frame, text="Disk:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Label(self.health_frame, textvariable=self.disk_var).grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        
    def format_sats(self, amount: int) -> str:
        """Format satoshi amounts"""
        if amount < 1000:
            return f"{amount} sats"
        elif amount < 1000000:
            return f"{amount/1000:.1f}K sats"
        else:
            return f"{amount/1000000:.2f}M sats"
    
    def add_activity(self, message: str, level: str = "info"):
        """Add activity log entry"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        icons = {"info": "ℹ️", "success": "✅", "warning": "⚠️", "error": "❌"}
        icon = icons.get(level, "ℹ️")
        
        self.activity_text.insert(tk.END, f"{timestamp} {icon} {message}\n")
        self.activity_text.see(tk.END)
        
    def refresh_data(self):
        """Refresh all dashboard data"""
        def update_data():
            try:
                # Get Lightning client
                client = get_lightning_client()
                client.connect()
                
                # Update node info
                info = client.get_info()
                self.node_alias_var.set(info.get('alias', 'Unknown'))
                self.node_version_var.set(info.get('version', 'Unknown'))
                self.node_network_var.set(info.get('chains', [{}])[0].get('network', 'Unknown'))
                self.node_peers_var.set(str(info.get('num_peers', 0)))
                
                # Update balances
                balance = client.get_balance()
                self.wallet_balance_var.set(self.format_sats(balance.get('wallet', 0)))
                self.channel_balance_var.set(self.format_sats(balance.get('channels', 0)))
                self.total_balance_var.set(self.format_sats(balance.get('total', 0)))
                
                # Update channels
                channels = client.list_channels()
                active_count = len([c for c in channels if c.get('active', False)])
                self.active_channels_var.set(str(active_count))
                self.pending_channels_var.set("0")  # Mock data
                
                # Update health
                health = check_system_health()
                health_checks = health.get('checks', {})
                
                cpu_status = health_checks.get('cpu', {})
                self.cpu_var.set(cpu_status.get('message', 'Unknown'))
                
                memory_status = health_checks.get('memory', {})
                self.memory_var.set(memory_status.get('message', 'Unknown'))
                
                disk_status = health_checks.get('disk', {})
                self.disk_var.set(disk_status.get('message', 'Unknown'))
                
                # Update status bar
                connected = info.get('identity_pubkey') is not None
                synced = info.get('synced_to_chain', False)
                self.app.status_bar.update_status(connected, synced)
                
                self.add_activity("Dashboard refreshed", "success")
                
            except Exception as e:
                self.add_activity(f"Refresh failed: {e}", "error")
                
        # Run in background thread
        threading.Thread(target=update_data, daemon=True).start()
        
    def start_auto_refresh(self):
        """Start automatic refresh timer"""
        self.refresh_data()  # Initial refresh
        self.after(30000, self.start_auto_refresh)  # Refresh every 30 seconds

class PaymentsTab(ttk.Frame):
    """Payments interface with QR code display"""
    
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.create_widgets()
        
    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Send payment section
        send_frame = ttk.LabelFrame(main_frame, text="📤 Send Payment", padding=10)
        send_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(send_frame, text="Lightning Invoice:").pack(anchor=tk.W)
        self.invoice_entry = ttk.Entry(send_frame, width=80)
        self.invoice_entry.pack(fill=tk.X, pady=5)
        
        send_button = ttk.Button(send_frame, text="💸 Send Payment", command=self.send_payment)
        send_button.pack(anchor=tk.W)
        
        # Receive payment section
        receive_frame = ttk.LabelFrame(main_frame, text="📥 Receive Payment", padding=10)
        receive_frame.pack(fill=tk.X, pady=5)
        
        amount_frame = ttk.Frame(receive_frame)
        amount_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(amount_frame, text="Amount (sats):").pack(side=tk.LEFT)
        self.amount_entry = ttk.Entry(amount_frame, width=20)
        self.amount_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(amount_frame, text="Memo:").pack(side=tk.LEFT, padx=(20, 0))
        self.memo_entry = ttk.Entry(amount_frame, width=30)
        self.memo_entry.pack(side=tk.LEFT, padx=5)
        
        create_button = ttk.Button(receive_frame, text="📋 Create Invoice", command=self.create_invoice)
        create_button.pack(anchor=tk.W, pady=5)
        
        # Generated invoice display
        self.invoice_display = scrolledtext.ScrolledText(receive_frame, height=4, width=80)
        self.invoice_display.pack(fill=tk.X, pady=5)
        
        # QR Code display
        qr_frame = ttk.LabelFrame(main_frame, text="📱 QR Code", padding=10)
        qr_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.qr_text = scrolledtext.ScrolledText(qr_frame, height=15, width=50, font=("Courier", 8))
        self.qr_text.pack(fill=tk.BOTH, expand=True)
        
        # Payment history
        history_frame = ttk.LabelFrame(main_frame, text="📋 Recent Payments", padding=10)
        history_frame.pack(fill=tk.X, pady=5)
        
        self.history_tree = ttk.Treeview(history_frame, columns=("Time", "Type", "Amount", "Status"), show="headings", height=6)
        self.history_tree.heading("Time", text="Time")
        self.history_tree.heading("Type", text="Type")
        self.history_tree.heading("Amount", text="Amount")
        self.history_tree.heading("Status", text="Status")
        
        self.history_tree.column("Time", width=120)
        self.history_tree.column("Type", width=80)
        self.history_tree.column("Amount", width=100)
        self.history_tree.column("Status", width=80)
        
        self.history_tree.pack(fill=tk.X)
        
        # Load initial data
        self.load_payment_history()
        
    def send_payment(self):
        """Send a Lightning payment"""
        invoice = self.invoice_entry.get().strip()
        if not invoice:
            messagebox.showerror("Error", "Please enter a Lightning invoice")
            return
            
        def send_async():
            try:
                client = get_lightning_client()
                client.connect()
                
                result = client.pay_invoice(invoice)
                
                # Update UI in main thread
                self.after(0, lambda: self.on_payment_sent(result))
                
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Payment Failed", str(e)))
                
        threading.Thread(target=send_async, daemon=True).start()
        
    def on_payment_sent(self, result):
        """Handle successful payment"""
        messagebox.showinfo("Payment Sent", f"Payment successful!\nHash: {result.get('payment_hash', 'N/A')[:20]}...")
        self.invoice_entry.delete(0, tk.END)
        self.load_payment_history()
        
    def create_invoice(self):
        """Create a Lightning invoice"""
        try:
            amount = int(self.amount_entry.get() or "0")
            memo = self.memo_entry.get().strip()
            
            if amount <= 0:
                messagebox.showerror("Error", "Please enter a valid amount")
                return
                
            client = get_lightning_client()
            client.connect()
            
            result = client.create_invoice(amount, memo)
            invoice = result.get('payment_request', '')
            
            # Display invoice
            self.invoice_display.delete(1.0, tk.END)
            self.invoice_display.insert(1.0, invoice)
            
            # Generate and display QR code
            self.show_qr_code(invoice)
            
            messagebox.showinfo("Invoice Created", "Invoice created successfully!")
            
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid amount")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create invoice: {e}")
            
    def show_qr_code(self, text):
        """Display ASCII QR code"""
        try:
            from ..cli.commands.qr_simple import generate_ascii_qr
            qr_code = generate_ascii_qr(text, 21)
            
            self.qr_text.delete(1.0, tk.END)
            self.qr_text.insert(1.0, qr_code)
            
        except Exception as e:
            self.qr_text.delete(1.0, tk.END)
            self.qr_text.insert(1.0, f"QR Code generation failed: {e}")
            
    def load_payment_history(self):
        """Load payment history into tree view"""
        # Clear existing items
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
            
        # Mock payment data
        payments = [
            ("10:30:25", "Sent", "10,000 sats", "✅ Success"),
            ("09:15:42", "Received", "25,000 sats", "✅ Success"),
            ("08:45:17", "Sent", "5,000 sats", "❌ Failed"),
        ]
        
        for payment in payments:
            self.history_tree.insert("", "end", values=payment)

class ChannelsTab(ttk.Frame):
    """Channels management interface"""
    
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.create_widgets()
        
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Toolbar
        toolbar = ttk.Frame(main_frame)
        toolbar.pack(fill=tk.X, pady=5)
        
        ttk.Label(toolbar, text="📡 Lightning Channels", font=ModernStyle.FONT_LARGE).pack(side=tk.LEFT)
        
        refresh_button = ttk.Button(toolbar, text="🔄 Refresh", command=self.refresh_channels)
        refresh_button.pack(side=tk.RIGHT)
        
        # Channels tree
        self.channels_tree = ttk.Treeview(main_frame, columns=("Remote", "Capacity", "Local", "Remote_Bal", "Status"), show="headings", height=15)
        
        # Configure columns
        self.channels_tree.heading("Remote", text="Remote Node")
        self.channels_tree.heading("Capacity", text="Capacity")
        self.channels_tree.heading("Local", text="Local Balance")
        self.channels_tree.heading("Remote_Bal", text="Remote Balance")
        self.channels_tree.heading("Status", text="Status")
        
        self.channels_tree.column("Remote", width=200)
        self.channels_tree.column("Capacity", width=120)
        self.channels_tree.column("Local", width=120)
        self.channels_tree.column("Remote_Bal", width=120)
        self.channels_tree.column("Status", width=100)
        
        # Scrollbar for tree
        tree_scroll = ttk.Scrollbar(main_frame, orient="vertical", command=self.channels_tree.yview)
        self.channels_tree.configure(yscrollcommand=tree_scroll.set)
        
        # Pack tree and scrollbar
        self.channels_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Load initial data
        self.refresh_channels()
        
    def format_sats(self, amount: int) -> str:
        """Format satoshi amounts"""
        if amount < 1000:
            return f"{amount} sats"
        elif amount < 1000000:
            return f"{amount/1000:.1f}K sats"
        else:
            return f"{amount/1000000:.2f}M sats"
            
    def refresh_channels(self):
        """Refresh channels data"""
        def load_data():
            try:
                client = get_lightning_client()
                client.connect()
                
                channels = client.list_channels()
                
                # Update UI in main thread
                self.after(0, lambda: self.update_channels_display(channels))
                
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Error", f"Failed to load channels: {e}"))
                
        threading.Thread(target=load_data, daemon=True).start()
        
    def update_channels_display(self, channels):
        """Update channels tree view"""
        # Clear existing items
        for item in self.channels_tree.get_children():
            self.channels_tree.delete(item)
            
        # Add channels
        for channel in channels:
            remote = channel.get('remote_pubkey', 'Unknown')[:20] + "..."
            capacity = self.format_sats(channel.get('capacity', 0))
            local_balance = self.format_sats(channel.get('local_balance', 0))
            remote_balance = self.format_sats(channel.get('remote_balance', 0))
            status = "✅ Active" if channel.get('active') else "❌ Inactive"
            
            self.channels_tree.insert("", "end", values=(remote, capacity, local_balance, remote_balance, status))

class SettingsTab(ttk.Frame):
    """Settings and configuration interface"""
    
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.create_widgets()
        
    def create_widgets(self):
        # Main frame with scrolling
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = ttk.Label(main_frame, text="⚙️ Settings", font=ModernStyle.FONT_LARGE)
        title_label.pack(anchor=tk.W, pady=5)
        
        # Lightning settings
        lightning_frame = ttk.LabelFrame(main_frame, text="⚡ Lightning Node", padding=10)
        lightning_frame.pack(fill=tk.X, pady=5)
        
        # Host
        host_frame = ttk.Frame(lightning_frame)
        host_frame.pack(fill=tk.X, pady=2)
        ttk.Label(host_frame, text="Host:", width=15).pack(side=tk.LEFT)
        self.host_var = tk.StringVar(value="localhost")
        ttk.Entry(host_frame, textvariable=self.host_var, width=30).pack(side=tk.LEFT, padx=5)
        
        # Port
        port_frame = ttk.Frame(lightning_frame)
        port_frame.pack(fill=tk.X, pady=2)
        ttk.Label(port_frame, text="Port:", width=15).pack(side=tk.LEFT)
        self.port_var = tk.StringVar(value="8080")
        ttk.Entry(port_frame, textvariable=self.port_var, width=10).pack(side=tk.LEFT, padx=5)
        
        # Network
        network_frame = ttk.Frame(lightning_frame)
        network_frame.pack(fill=tk.X, pady=2)
        ttk.Label(network_frame, text="Network:", width=15).pack(side=tk.LEFT)
        self.network_var = tk.StringVar(value="testnet")
        network_combo = ttk.Combobox(network_frame, textvariable=self.network_var, values=["mainnet", "testnet", "regtest"], width=15)
        network_combo.pack(side=tk.LEFT, padx=5)
        
        # Mock mode
        self.mock_mode_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(lightning_frame, text="Mock Mode (for testing)", variable=self.mock_mode_var).pack(anchor=tk.W, pady=5)
        
        # UI Settings
        ui_frame = ttk.LabelFrame(main_frame, text="🎨 Interface", padding=10)
        ui_frame.pack(fill=tk.X, pady=5)
        
        # Auto-refresh
        self.auto_refresh_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(ui_frame, text="Auto-refresh dashboard", variable=self.auto_refresh_var).pack(anchor=tk.W)
        
        # System tray
        self.system_tray_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(ui_frame, text="Minimize to system tray", variable=self.system_tray_var).pack(anchor=tk.W)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="💾 Save Settings", command=self.save_settings).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🔄 Load Settings", command=self.load_settings).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🏭 Reset to Defaults", command=self.reset_settings).pack(side=tk.LEFT, padx=5)
        
        # Load current settings
        self.load_settings()
        
    def save_settings(self):
        """Save settings to configuration"""
        try:
            config = get_config_manager()
            
            # Save Lightning settings
            config.set('lightning.host', self.host_var.get())
            config.set('lightning.port', int(self.port_var.get()))
            config.set('lightning.network', self.network_var.get())
            config.set('lightning.mock_mode', self.mock_mode_var.get())
            
            messagebox.showinfo("Settings", "Settings saved successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {e}")
            
    def load_settings(self):
        """Load settings from configuration"""
        try:
            config = get_config_manager()
            
            lightning_config = config.get('lightning', {})
            self.host_var.set(lightning_config.get('host', 'localhost'))
            self.port_var.set(str(lightning_config.get('port', 8080)))
            self.network_var.set(lightning_config.get('network', 'testnet'))
            self.mock_mode_var.set(lightning_config.get('mock_mode', True))
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load settings: {e}")
            
    def reset_settings(self):
        """Reset settings to defaults"""
        if messagebox.askyesno("Confirm", "Reset all settings to defaults?"):
            self.host_var.set("localhost")
            self.port_var.set("8080")
            self.network_var.set("testnet")
            self.mock_mode_var.set(True)
            self.auto_refresh_var.set(True)
            self.system_tray_var.set(False)

class BLNCSMainWindow:
    """Main BLNCS GUI application window"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.lightning_client = get_lightning_client()
        self.config = get_config_manager()
        self.tray_integration = None
        
        self.setup_window()
        self.create_widgets()
        self.setup_system_tray()
        
    def setup_window(self):
        """Setup main window properties"""
        self.root.title("BLNCS - Lightning Network Control System")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        
        # Set icon (if available)
        try:
            # You could add an icon file here
            pass
        except:
            pass
            
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')  # Modern theme
        
    def create_widgets(self):
        """Create main window widgets"""
        # Menu bar
        self.create_menu()
        
        # Main container
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create tabs
        self.dashboard_tab = DashboardTab(self.notebook, self)
        self.payments_tab = PaymentsTab(self.notebook, self)
        self.channels_tab = ChannelsTab(self.notebook, self)
        self.settings_tab = SettingsTab(self.notebook, self)
        
        # Add tabs to notebook
        self.notebook.add(self.dashboard_tab, text="📊 Dashboard")
        self.notebook.add(self.payments_tab, text="💰 Payments")
        self.notebook.add(self.channels_tab, text="📡 Channels")
        self.notebook.add(self.settings_tab, text="⚙️ Settings")
        
        # Status bar
        self.status_bar = StatusBar(main_container)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        
    def create_menu(self):
        """Create application menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Exit", command=self.quit_app)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Refresh Dashboard", command=self.dashboard_tab.refresh_data)
        view_menu.add_separator()
        view_menu.add_command(label="Full Screen", command=self.toggle_fullscreen)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Health Check", command=self.show_health_check)
        tools_menu.add_command(label="Network Test", command=self.show_network_test)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        
    def toggle_fullscreen(self):
        """Toggle fullscreen mode"""
        current_state = self.root.attributes('-fullscreen')
        self.root.attributes('-fullscreen', not current_state)
        
    def show_health_check(self):
        """Show health check dialog"""
        def run_health_check():
            try:
                health = check_system_health()
                
                # Create results window
                health_window = tk.Toplevel(self.root)
                health_window.title("System Health Check")
                health_window.geometry("500x400")
                
                # Results text
                text_widget = scrolledtext.ScrolledText(health_window, wrap=tk.WORD)
                text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
                
                # Format health data
                text_widget.insert(tk.END, "🏥 SYSTEM HEALTH CHECK\n")
                text_widget.insert(tk.END, "=" * 50 + "\n\n")
                
                status = health.get('status', 'unknown')
                text_widget.insert(tk.END, f"Overall Status: {status.upper()}\n")
                text_widget.insert(tk.END, f"Timestamp: {health.get('timestamp', 'Unknown')}\n\n")
                
                checks = health.get('checks', {})
                for check_name, check_data in checks.items():
                    status_icon = {"ok": "✅", "warning": "⚠️", "critical": "❌", "error": "❌"}.get(check_data.get('status'), "❓")
                    text_widget.insert(tk.END, f"{status_icon} {check_name.upper()}: {check_data.get('message', 'No message')}\n")
                
            except Exception as e:
                messagebox.showerror("Error", f"Health check failed: {e}")
                
        threading.Thread(target=run_health_check, daemon=True).start()
        
    def show_network_test(self):
        """Show network test dialog"""
        messagebox.showinfo("Network Test", "Network testing functionality would be implemented here.")
        
    def show_about(self):
        """Show about dialog"""
        about_text = """BLNCS - Lightning Network Control System
Version 1.0.0 GUI Edition

A modern, intuitive interface for managing Lightning Network nodes.

Features:
• Real-time dashboard
• Payment management
• Channel monitoring
• System health checks
• Configuration management

Built with Python and Tkinter for maximum compatibility."""
        
        messagebox.showinfo("About BLNCS", about_text)
        
    def setup_system_tray(self):
        """Setup system tray integration"""
        try:
            self.tray_integration = create_tray_integration(self, self.lightning_client)
            if self.tray_integration:
                print("✅ System tray integration enabled")
            else:
                print("⚠️  System tray integration not available")
        except Exception as e:
            print(f"Error setting up system tray: {e}")
    
    def quit_app(self):
        """Quit the application"""
        if messagebox.askyesno("Quit", "Are you sure you want to quit BLNCS?"):
            self.root.quit()
            
    def run(self):
        """Start the GUI application"""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self.quit_app()

def main():
    """Launch the BLNCS GUI application"""
    app = BLNCSMainWindow()
    app.run()

if __name__ == "__main__":
    main()