#!/usr/bin/env python3
"""
BLNCS Mobile UI - スマートフォン向け直感的インターフェース
Intuitive mobile interface for Lightning Network management on smartphones.
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
from datetime import datetime
from typing import Dict, Any, Optional, Callable
import json
import math

# Import BLNCS modules
try:
    from ..lightning.client_simple import get_lightning_client
    from ..core.config_manager import get_config_manager
    from ..cli.commands.qr_simple import generate_ascii_qr
except ImportError:
    # Fallback for testing
    import sys
    from pathlib import Path
    sys.path.append(str(Path(__file__).parent.parent))
    from lightning.client_simple import get_lightning_client
    from core.config_manager import get_config_manager
    from cli.commands.qr_simple import generate_ascii_qr


class MobileStyle:
    """Mobile-optimized styling for touch interfaces"""
    
    # Mobile color scheme - high contrast for outdoor viewing
    PRIMARY = "#1a73e8"          # Google blue
    PRIMARY_DARK = "#1557b0"
    PRIMARY_LIGHT = "#4285f4"
    
    SUCCESS = "#34a853"          # Green
    WARNING = "#fbbc05"          # Yellow
    ERROR = "#ea4335"            # Red
    
    # Background colors
    BG_PRIMARY = "#ffffff"       # Pure white for brightness
    BG_SECONDARY = "#f8f9fa"     # Light gray
    BG_CARD = "#ffffff"          # White cards
    BG_ACCENT = "#e8f0fe"        # Light blue accent
    
    # Text colors - high contrast
    TEXT_PRIMARY = "#202124"     # Dark gray
    TEXT_SECONDARY = "#5f6368"   # Medium gray
    TEXT_LIGHT = "#ffffff"       # White
    TEXT_SUCCESS = "#137333"     # Dark green
    TEXT_ERROR = "#d93025"       # Dark red
    
    # Mobile-specific colors
    TOUCH_FEEDBACK = "#e3f2fd"   # Light blue for touch feedback
    LIGHTNING_GOLD = "#ff6f00"   # Bitcoin orange
    
    # Mobile-optimized fonts (larger for touch)
    FONT_LARGE = ("Segoe UI", 18, "bold")    # Headers
    FONT_MEDIUM = ("Segoe UI", 16)           # Body text
    FONT_SMALL = ("Segoe UI", 14)            # Secondary text
    FONT_BUTTON = ("Segoe UI", 16, "bold")   # Buttons
    FONT_MONO = ("Consolas", 14)             # Monospace
    
    # Mobile dimensions
    BUTTON_HEIGHT = 50           # Minimum 44pt for touch
    CARD_PADDING = 16           # Standard mobile padding
    MARGIN_SMALL = 8
    MARGIN_MEDIUM = 16
    MARGIN_LARGE = 24
    
    # Touch target sizes (minimum 44pt = 44px)
    TOUCH_MIN = 44
    BUTTON_MIN_WIDTH = 120
    
    @classmethod
    def configure_mobile_style(cls, root):
        """Configure mobile-optimized ttk styling"""
        style = ttk.Style(root)
        
        # Configure buttons for touch
        style.configure('Mobile.TButton',
                       font=cls.FONT_BUTTON,
                       padding=[20, 15],  # Larger padding for touch
                       background=cls.PRIMARY,
                       foreground=cls.TEXT_LIGHT)
        style.map('Mobile.TButton',
                 background=[('active', cls.PRIMARY_LIGHT),
                           ('pressed', cls.PRIMARY_DARK)])
        
        # Large success button
        style.configure('MobileSuccess.TButton',
                       font=cls.FONT_BUTTON,
                       padding=[20, 15],
                       background=cls.SUCCESS,
                       foreground=cls.TEXT_LIGHT)
        
        # Large error button
        style.configure('MobileError.TButton',
                       font=cls.FONT_BUTTON,
                       padding=[20, 15],
                       background=cls.ERROR,
                       foreground=cls.TEXT_LIGHT)
        
        # Mobile cards
        style.configure('MobileCard.TFrame',
                       background=cls.BG_CARD,
                       relief='raised',
                       borderwidth=1)
        
        # Mobile labels
        style.configure('MobileHeader.TLabel',
                       font=cls.FONT_LARGE,
                       background=cls.BG_PRIMARY,
                       foreground=cls.TEXT_PRIMARY)
        
        style.configure('MobileBody.TLabel',
                       font=cls.FONT_MEDIUM,
                       background=cls.BG_PRIMARY,
                       foreground=cls.TEXT_PRIMARY)
        
        style.configure('MobileSecondary.TLabel',
                       font=cls.FONT_SMALL,
                       background=cls.BG_PRIMARY,
                       foreground=cls.TEXT_SECONDARY)
        
        # Mobile entries (larger for touch keyboards)
        style.configure('Mobile.TEntry',
                       font=cls.FONT_MEDIUM,
                       fieldbackground=cls.BG_SECONDARY,
                       padding=[12, 15])  # Larger padding
        
        # Mobile notebook tabs
        style.configure('Mobile.TNotebook',
                       background=cls.BG_PRIMARY)
        style.configure('Mobile.TNotebook.Tab',
                       font=cls.FONT_MEDIUM,
                       padding=[20, 15],  # Larger tabs for touch
                       background=cls.BG_SECONDARY,
                       foreground=cls.TEXT_PRIMARY)
        style.map('Mobile.TNotebook.Tab',
                 background=[('selected', cls.PRIMARY),
                           ('active', cls.BG_ACCENT)],
                 foreground=[('selected', cls.TEXT_LIGHT)])


class TouchableButton(ttk.Button):
    """Touch-optimized button with visual feedback"""
    
    def __init__(self, parent, text="", command=None, style="Mobile.TButton", **kwargs):
        super().__init__(parent, text=text, command=command, style=style, **kwargs)
        
        # Touch feedback
        self.bind("<Button-1>", self.on_touch_down)
        self.bind("<ButtonRelease-1>", self.on_touch_up)
        
        # Configure minimum size for touch
        self.config(width=max(len(text), 12))  # Minimum width
    
    def on_touch_down(self, event):
        """Visual feedback on touch down"""
        self.config(relief='sunken')
    
    def on_touch_up(self, event):
        """Reset visual state on touch up"""
        self.config(relief='raised')


class SwipeableFrame(ttk.Frame):
    """Frame with swipe gesture support for mobile navigation"""
    
    def __init__(self, parent, on_swipe_left=None, on_swipe_right=None, **kwargs):
        super().__init__(parent, **kwargs)
        
        self.on_swipe_left = on_swipe_left
        self.on_swipe_right = on_swipe_right
        
        # Touch tracking
        self.touch_start_x = 0
        self.touch_start_y = 0
        self.is_swiping = False
        
        # Bind touch events
        self.bind("<Button-1>", self.on_touch_start)
        self.bind("<B1-Motion>", self.on_touch_move)
        self.bind("<ButtonRelease-1>", self.on_touch_end)
        
        # Make focusable for touch events
        self.focus_set()
    
    def on_touch_start(self, event):
        """Handle touch start"""
        self.touch_start_x = event.x
        self.touch_start_y = event.y
        self.is_swiping = False
    
    def on_touch_move(self, event):
        """Handle touch move"""
        if abs(event.x - self.touch_start_x) > 10:  # Minimum swipe distance
            self.is_swiping = True
    
    def on_touch_end(self, event):
        """Handle touch end and detect swipe"""
        if self.is_swiping:
            dx = event.x - self.touch_start_x
            dy = event.y - self.touch_start_y
            
            # Check for horizontal swipe (must be predominantly horizontal)
            if abs(dx) > abs(dy) and abs(dx) > 50:  # Minimum swipe distance
                if dx > 0 and self.on_swipe_right:
                    self.on_swipe_right()
                elif dx < 0 and self.on_swipe_left:
                    self.on_swipe_left()
        
        self.is_swiping = False


class MobileStatusBar(ttk.Frame):
    """Mobile-optimized status bar with larger touch targets"""
    
    def __init__(self, parent):
        super().__init__(parent, style='MobileCard.TFrame')
        self.create_widgets()
        
    def create_widgets(self):
        """Create mobile status bar widgets"""
        # Status container
        status_frame = ttk.Frame(self, style='MobileCard.TFrame')
        status_frame.pack(fill='x', padx=MobileStyle.MARGIN_MEDIUM, 
                         pady=MobileStyle.MARGIN_SMALL)
        
        # Connection status with larger indicator
        self.conn_frame = ttk.Frame(status_frame, style='MobileCard.TFrame')
        self.conn_frame.pack(side='left', fill='x', expand=True)
        
        self.conn_indicator = ttk.Label(self.conn_frame, text="●", 
                                       font=("Segoe UI", 20),
                                       foreground=MobileStyle.ERROR)
        self.conn_indicator.pack(side='left')
        
        self.conn_label = ttk.Label(self.conn_frame, text="接続待機中", 
                                   style='MobileBody.TLabel')
        self.conn_label.pack(side='left', padx=(8, 0))
        
        # Last update time
        self.update_label = ttk.Label(status_frame, text="", 
                                     style='MobileSecondary.TLabel')
        self.update_label.pack(side='right')
    
    def update_status(self, connected=False, block_height=None):
        """Update mobile status display"""
        if connected:
            self.conn_indicator.config(foreground=MobileStyle.SUCCESS)
            self.conn_label.config(text="接続済み")
        else:
            self.conn_indicator.config(foreground=MobileStyle.ERROR)
            self.conn_label.config(text="未接続")
        
        # Update time
        now = datetime.now().strftime("%H:%M")
        self.update_label.config(text=f"更新: {now}")


class MobileDashboard(SwipeableFrame):
    """Mobile-optimized dashboard with card layout"""
    
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.create_mobile_dashboard()
        self.start_updates()
        
    def create_mobile_dashboard(self):
        """Create mobile dashboard with card layout"""
        # Scrollable main frame
        self.canvas = tk.Canvas(self, bg=MobileStyle.BG_PRIMARY)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas, style='TFrame')
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        # Pack canvas and scrollbar
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        # Dashboard content
        self.create_balance_card()
        self.create_node_status_card()
        self.create_channels_card()
        self.create_quick_actions()
        
        # Enable mouse wheel scrolling
        self.bind_mousewheel()
    
    def bind_mousewheel(self):
        """Bind mouse wheel for scrolling"""
        def _on_mousewheel(event):
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        
        self.canvas.bind("<MouseWheel>", _on_mousewheel)  # Windows
        self.canvas.bind("<Button-4>", lambda e: self.canvas.yview_scroll(-1, "units"))  # Linux
        self.canvas.bind("<Button-5>", lambda e: self.canvas.yview_scroll(1, "units"))   # Linux
    
    def create_balance_card(self):
        """Create balance display card"""
        card_frame = ttk.Frame(self.scrollable_frame, style='MobileCard.TFrame')
        card_frame.pack(fill='x', padx=MobileStyle.MARGIN_MEDIUM, 
                       pady=MobileStyle.MARGIN_MEDIUM)
        
        # Card padding
        content_frame = ttk.Frame(card_frame, style='MobileCard.TFrame')
        content_frame.pack(fill='x', padx=MobileStyle.CARD_PADDING, 
                          pady=MobileStyle.CARD_PADDING)
        
        # Header
        ttk.Label(content_frame, text="💰 残高", 
                 style='MobileHeader.TLabel').pack(anchor='w', pady=(0, 12))
        
        # Lightning balance (prominent)
        lightning_frame = ttk.Frame(content_frame, style='MobileCard.TFrame')
        lightning_frame.pack(fill='x', pady=(0, 12))
        
        ttk.Label(lightning_frame, text="⚡ Lightning", 
                 style='MobileBody.TLabel').pack(anchor='w')
        
        self.lightning_balance = ttk.Label(lightning_frame, text="0 sats", 
                                          font=("Segoe UI", 24, "bold"),
                                          foreground=MobileStyle.LIGHTNING_GOLD)
        self.lightning_balance.pack(anchor='w', pady=(4, 0))
        
        self.lightning_btc = ttk.Label(lightning_frame, text="≈ 0.00000000 BTC", 
                                      style='MobileSecondary.TLabel')
        self.lightning_btc.pack(anchor='w')
        
        # On-chain balance
        onchain_frame = ttk.Frame(content_frame, style='MobileCard.TFrame')
        onchain_frame.pack(fill='x')
        
        ttk.Label(onchain_frame, text="🔗 オンチェーン", 
                 style='MobileBody.TLabel').pack(anchor='w')
        
        self.onchain_balance = ttk.Label(onchain_frame, text="0 sats", 
                                        font=("Segoe UI", 20, "bold"),
                                        foreground=MobileStyle.SUCCESS)
        self.onchain_balance.pack(anchor='w', pady=(4, 0))
        
        self.onchain_btc = ttk.Label(onchain_frame, text="≈ 0.00000000 BTC", 
                                    style='MobileSecondary.TLabel')
        self.onchain_btc.pack(anchor='w')
    
    def create_node_status_card(self):
        """Create node status card"""
        card_frame = ttk.Frame(self.scrollable_frame, style='MobileCard.TFrame')
        card_frame.pack(fill='x', padx=MobileStyle.MARGIN_MEDIUM, 
                       pady=(0, MobileStyle.MARGIN_MEDIUM))
        
        content_frame = ttk.Frame(card_frame, style='MobileCard.TFrame')
        content_frame.pack(fill='x', padx=MobileStyle.CARD_PADDING, 
                          pady=MobileStyle.CARD_PADDING)
        
        # Header
        ttk.Label(content_frame, text="📊 ノード状態", 
                 style='MobileHeader.TLabel').pack(anchor='w', pady=(0, 12))
        
        # Status items
        status_items = [
            ("エイリアス", "alias_label"),
            ("同期状態", "sync_label"),
            ("ブロック高", "block_label"),
            ("ピア数", "peers_label")
        ]
        
        for label_text, attr_name in status_items:
            item_frame = ttk.Frame(content_frame, style='MobileCard.TFrame')
            item_frame.pack(fill='x', pady=(0, 8))
            
            ttk.Label(item_frame, text=label_text, 
                     style='MobileSecondary.TLabel').pack(anchor='w')
            
            label_widget = ttk.Label(item_frame, text="読み込み中...", 
                                   style='MobileBody.TLabel')
            label_widget.pack(anchor='w')
            setattr(self, attr_name, label_widget)
    
    def create_channels_card(self):
        """Create channels overview card"""
        card_frame = ttk.Frame(self.scrollable_frame, style='MobileCard.TFrame')
        card_frame.pack(fill='x', padx=MobileStyle.MARGIN_MEDIUM, 
                       pady=(0, MobileStyle.MARGIN_MEDIUM))
        
        content_frame = ttk.Frame(card_frame, style='MobileCard.TFrame')
        content_frame.pack(fill='x', padx=MobileStyle.CARD_PADDING, 
                          pady=MobileStyle.CARD_PADDING)
        
        # Header with tap action
        header_frame = ttk.Frame(content_frame, style='MobileCard.TFrame')
        header_frame.pack(fill='x', pady=(0, 12))
        
        ttk.Label(header_frame, text="⚡ チャンネル", 
                 style='MobileHeader.TLabel').pack(side='left')
        
        ttk.Label(header_frame, text="詳細 →", 
                 style='MobileSecondary.TLabel').pack(side='right')
        
        # Channel stats in grid
        stats_frame = ttk.Frame(content_frame, style='MobileCard.TFrame')
        stats_frame.pack(fill='x')
        
        # Create 2x2 grid for channel stats
        stats_data = [
            ("合計", "total_channels", 0, 0),
            ("アクティブ", "active_channels", 0, 1),
            ("非アクティブ", "pending_channels", 1, 0),
            ("容量", "total_capacity", 1, 1)
        ]
        
        for label_text, attr_name, row, col in stats_data:
            stat_frame = ttk.Frame(stats_frame, style='MobileCard.TFrame')
            stat_frame.grid(row=row, column=col, sticky='ew', padx=8, pady=4)
            
            ttk.Label(stat_frame, text=label_text, 
                     style='MobileSecondary.TLabel').pack()
            
            label_widget = ttk.Label(stat_frame, text="0", 
                                   style='MobileBody.TLabel',
                                   font=("Segoe UI", 16, "bold"))
            label_widget.pack()
            setattr(self, attr_name, label_widget)
        
        # Configure grid weights
        stats_frame.columnconfigure(0, weight=1)
        stats_frame.columnconfigure(1, weight=1)
    
    def create_quick_actions(self):
        """Create quick action buttons"""
        card_frame = ttk.Frame(self.scrollable_frame, style='MobileCard.TFrame')
        card_frame.pack(fill='x', padx=MobileStyle.MARGIN_MEDIUM, 
                       pady=(0, MobileStyle.MARGIN_LARGE))
        
        content_frame = ttk.Frame(card_frame, style='MobileCard.TFrame')
        content_frame.pack(fill='x', padx=MobileStyle.CARD_PADDING, 
                          pady=MobileStyle.CARD_PADDING)
        
        # Header
        ttk.Label(content_frame, text="🚀 クイックアクション", 
                 style='MobileHeader.TLabel').pack(anchor='w', pady=(0, 12))
        
        # Action buttons in grid
        actions_frame = ttk.Frame(content_frame, style='MobileCard.TFrame')
        actions_frame.pack(fill='x')
        
        # Create action buttons
        TouchableButton(actions_frame, text="💸 支払い", 
                       command=lambda: self.app.switch_tab(1),
                       style='Mobile.TButton').grid(row=0, column=0, 
                                                  sticky='ew', padx=4, pady=4)
        
        TouchableButton(actions_frame, text="📄 請求", 
                       command=lambda: self.app.switch_tab(1),
                       style='MobileSuccess.TButton').grid(row=0, column=1, 
                                                          sticky='ew', padx=4, pady=4)
        
        TouchableButton(actions_frame, text="⚡ チャンネル", 
                       command=lambda: self.app.switch_tab(2),
                       style='Mobile.TButton').grid(row=1, column=0, 
                                                  sticky='ew', padx=4, pady=4)
        
        TouchableButton(actions_frame, text="🔄 更新", 
                       command=self.refresh_data,
                       style='Mobile.TButton').grid(row=1, column=1, 
                                                  sticky='ew', padx=4, pady=4)
        
        # Configure grid weights
        actions_frame.columnconfigure(0, weight=1)
        actions_frame.columnconfigure(1, weight=1)
    
    def refresh_data(self):
        """Refresh dashboard data"""
        try:
            client = self.app.lightning_client
            
            # Get node info
            info = client.get_info()
            if info:
                self.alias_label.config(text=info.get('alias', 'Unknown'))
                self.sync_label.config(text="同期済み" if info.get('synced_to_chain') else "同期中")
                self.block_label.config(text=f"{info.get('block_height', 0):,}")
                self.peers_label.config(text=str(info.get('num_peers', 0)))
            
            # Get balance
            balance = client.get_balance()
            if balance:
                # Lightning balance
                lightning = balance.get('total', 0)
                self.lightning_balance.config(text=f"{lightning:,} sats")
                self.lightning_btc.config(text=f"≈ {lightning / 100000000:.8f} BTC")
                
                # On-chain balance
                onchain = balance.get('confirmed', 0)
                self.onchain_balance.config(text=f"{onchain:,} sats")
                self.onchain_btc.config(text=f"≈ {onchain / 100000000:.8f} BTC")
            
            # Get channels
            channels = client.list_channels()
            if channels:
                active = sum(1 for c in channels if c.get('active', False))
                pending = len(channels) - active
                total_capacity = sum(c.get('capacity', 0) for c in channels)
                
                self.total_channels.config(text=str(len(channels)))
                self.active_channels.config(text=str(active))
                self.pending_channels.config(text=str(pending))
                self.total_capacity.config(text=f"{total_capacity//1000}K")
                
        except Exception as e:
            print(f"Error refreshing mobile dashboard: {e}")
    
    def start_updates(self):
        """Start automatic updates"""
        def update_loop():
            while True:
                try:
                    self.refresh_data()
                    time.sleep(30)  # Update every 30 seconds
                except:
                    break
        
        thread = threading.Thread(target=update_loop, daemon=True)
        thread.start()
        
        # Initial refresh
        self.refresh_data()


class MobilePayments(SwipeableFrame):
    """Mobile-optimized payments interface"""
    
    def __init__(self, parent, app):
        super().__init__(parent, 
                        on_swipe_left=lambda: app.switch_tab(2),
                        on_swipe_right=lambda: app.switch_tab(0))
        self.app = app
        self.create_mobile_payments()
    
    def create_mobile_payments(self):
        """Create mobile payments interface"""
        # Scrollable container
        self.canvas = tk.Canvas(self, bg=MobileStyle.BG_PRIMARY)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas, style='TFrame')
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        # Payment interface
        self.create_quick_pay_card()
        self.create_receive_card()
        self.create_qr_card()
        self.create_history_card()
        
        # Enable scrolling
        self.bind_mousewheel()
    
    def bind_mousewheel(self):
        """Bind mouse wheel for scrolling"""
        def _on_mousewheel(event):
            self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        
        self.canvas.bind("<MouseWheel>", _on_mousewheel)
        self.canvas.bind("<Button-4>", lambda e: self.canvas.yview_scroll(-1, "units"))
        self.canvas.bind("<Button-5>", lambda e: self.canvas.yview_scroll(1, "units"))
    
    def create_quick_pay_card(self):
        """Create quick payment card"""
        card_frame = ttk.Frame(self.scrollable_frame, style='MobileCard.TFrame')
        card_frame.pack(fill='x', padx=MobileStyle.MARGIN_MEDIUM, 
                       pady=MobileStyle.MARGIN_MEDIUM)
        
        content_frame = ttk.Frame(card_frame, style='MobileCard.TFrame')
        content_frame.pack(fill='x', padx=MobileStyle.CARD_PADDING, 
                          pady=MobileStyle.CARD_PADDING)
        
        # Header
        ttk.Label(content_frame, text="💸 支払い", 
                 style='MobileHeader.TLabel').pack(anchor='w', pady=(0, 12))
        
        # Invoice input
        ttk.Label(content_frame, text="Lightning請求書", 
                 style='MobileBody.TLabel').pack(anchor='w', pady=(0, 4))
        
        self.invoice_entry = ttk.Entry(content_frame, style='Mobile.TEntry')
        self.invoice_entry.pack(fill='x', pady=(0, 12))
        
        # Payment buttons
        button_frame = ttk.Frame(content_frame, style='MobileCard.TFrame')
        button_frame.pack(fill='x')
        
        TouchableButton(button_frame, text="📷 QRスキャン", 
                       command=self.scan_qr,
                       style='Mobile.TButton').pack(side='left', fill='x', expand=True, padx=(0, 4))
        
        TouchableButton(button_frame, text="💸 支払い実行", 
                       command=self.pay_invoice,
                       style='MobileSuccess.TButton').pack(side='right', fill='x', expand=True, padx=(4, 0))
    
    def create_receive_card(self):
        """Create payment receive card"""
        card_frame = ttk.Frame(self.scrollable_frame, style='MobileCard.TFrame')
        card_frame.pack(fill='x', padx=MobileStyle.MARGIN_MEDIUM, 
                       pady=(0, MobileStyle.MARGIN_MEDIUM))
        
        content_frame = ttk.Frame(card_frame, style='MobileCard.TFrame')
        content_frame.pack(fill='x', padx=MobileStyle.CARD_PADDING, 
                          pady=MobileStyle.CARD_PADDING)
        
        # Header
        ttk.Label(content_frame, text="📄 請求書作成", 
                 style='MobileHeader.TLabel').pack(anchor='w', pady=(0, 12))
        
        # Amount input
        ttk.Label(content_frame, text="金額 (sats)", 
                 style='MobileBody.TLabel').pack(anchor='w', pady=(0, 4))
        
        self.amount_entry = ttk.Entry(content_frame, style='Mobile.TEntry')
        self.amount_entry.pack(fill='x', pady=(0, 8))
        
        # Memo input
        ttk.Label(content_frame, text="メモ (任意)", 
                 style='MobileBody.TLabel').pack(anchor='w', pady=(0, 4))
        
        self.memo_entry = ttk.Entry(content_frame, style='Mobile.TEntry')
        self.memo_entry.pack(fill='x', pady=(0, 12))
        
        # Create invoice button
        TouchableButton(content_frame, text="📄 請求書作成", 
                       command=self.create_invoice,
                       style='MobileSuccess.TButton').pack(fill='x')
    
    def create_qr_card(self):
        """Create QR code display card"""
        self.qr_card = ttk.Frame(self.scrollable_frame, style='MobileCard.TFrame')
        self.qr_card.pack(fill='x', padx=MobileStyle.MARGIN_MEDIUM, 
                         pady=(0, MobileStyle.MARGIN_MEDIUM))
        
        content_frame = ttk.Frame(self.qr_card, style='MobileCard.TFrame')
        content_frame.pack(fill='x', padx=MobileStyle.CARD_PADDING, 
                          pady=MobileStyle.CARD_PADDING)
        
        # Header
        ttk.Label(content_frame, text="📱 QRコード", 
                 style='MobileHeader.TLabel').pack(anchor='w', pady=(0, 12))
        
        # QR display area
        self.qr_text = tk.Text(content_frame, height=12, font=("Courier", 8),
                              bg=MobileStyle.BG_SECONDARY,
                              fg=MobileStyle.TEXT_PRIMARY,
                              wrap='none', state='disabled')
        self.qr_text.pack(fill='x', pady=(0, 12))
        
        # Initially hidden
        self.qr_card.pack_forget()
    
    def create_history_card(self):
        """Create payment history card"""
        card_frame = ttk.Frame(self.scrollable_frame, style='MobileCard.TFrame')
        card_frame.pack(fill='x', padx=MobileStyle.MARGIN_MEDIUM, 
                       pady=(0, MobileStyle.MARGIN_LARGE))
        
        content_frame = ttk.Frame(card_frame, style='MobileCard.TFrame')
        content_frame.pack(fill='x', padx=MobileStyle.CARD_PADDING, 
                          pady=MobileStyle.CARD_PADDING)
        
        # Header
        header_frame = ttk.Frame(content_frame, style='MobileCard.TFrame')
        header_frame.pack(fill='x', pady=(0, 12))
        
        ttk.Label(header_frame, text="📊 履歴", 
                 style='MobileHeader.TLabel').pack(side='left')
        
        TouchableButton(header_frame, text="更新", 
                       command=self.load_payment_history,
                       style='Mobile.TButton').pack(side='right')
        
        # History list
        self.history_frame = ttk.Frame(content_frame, style='MobileCard.TFrame')
        self.history_frame.pack(fill='x')
        
        self.load_payment_history()
    
    def scan_qr(self):
        """Simulate QR code scanning"""
        messagebox.showinfo("QRスキャン", "QRコードスキャン機能は開発中です")
    
    def pay_invoice(self):
        """Pay Lightning invoice"""
        invoice = self.invoice_entry.get().strip()
        if not invoice:
            messagebox.showwarning("警告", "請求書を入力してください")
            return
        
        try:
            result = self.app.lightning_client.pay_invoice(invoice)
            if result and result.get('payment_preimage'):
                messagebox.showinfo("成功", "支払いが完了しました！")
                self.invoice_entry.delete(0, tk.END)
                self.load_payment_history()
            else:
                messagebox.showerror("エラー", "支払いに失敗しました")
        except Exception as e:
            messagebox.showerror("エラー", f"支払いエラー: {e}")
    
    def create_invoice(self):
        """Create Lightning invoice"""
        try:
            amount = int(self.amount_entry.get().strip() or "0")
            if amount <= 0:
                messagebox.showwarning("警告", "有効な金額を入力してください")
                return
            
            memo = self.memo_entry.get().strip()
            
            invoice_data = self.app.lightning_client.create_invoice(amount, memo)
            if invoice_data and 'payment_request' in invoice_data:
                invoice = invoice_data['payment_request']
                
                # Generate QR code
                qr_code = generate_ascii_qr(invoice, 21)
                if qr_code:
                    self.qr_text.config(state='normal')
                    self.qr_text.delete('1.0', tk.END)
                    self.qr_text.insert(tk.END, qr_code)
                    self.qr_text.insert(tk.END, f"\n\n請求書: {invoice}")
                    self.qr_text.config(state='disabled')
                    
                    # Show QR card
                    self.qr_card.pack(fill='x', padx=MobileStyle.MARGIN_MEDIUM, 
                                     pady=(0, MobileStyle.MARGIN_MEDIUM),
                                     before=self.history_frame.master.master)
                
                messagebox.showinfo("成功", f"{amount:,} satsの請求書を作成しました")
                
                # Clear inputs
                self.amount_entry.delete(0, tk.END)
                self.memo_entry.delete(0, tk.END)
            else:
                messagebox.showerror("エラー", "請求書の作成に失敗しました")
        
        except ValueError:
            messagebox.showwarning("警告", "有効な金額を入力してください")
        except Exception as e:
            messagebox.showerror("エラー", f"請求書作成エラー: {e}")
    
    def load_payment_history(self):
        """Load payment history"""
        try:
            # Clear existing items
            for widget in self.history_frame.winfo_children():
                widget.destroy()
            
            # Get payment history
            payments = self.app.lightning_client.list_payments(max_payments=10)
            
            if not payments:
                ttk.Label(self.history_frame, text="履歴がありません", 
                         style='MobileSecondary.TLabel').pack(pady=20)
                return
            
            for payment in payments:
                self.create_history_item(payment)
                
        except Exception as e:
            print(f"Error loading payment history: {e}")
    
    def create_history_item(self, payment):
        """Create a payment history item"""
        item_frame = ttk.Frame(self.history_frame, style='MobileCard.TFrame')
        item_frame.pack(fill='x', pady=4)
        
        # Payment type and amount
        main_frame = ttk.Frame(item_frame, style='MobileCard.TFrame')
        main_frame.pack(fill='x', padx=8, pady=8)
        
        amount = payment.get('value', 0)
        is_send = amount < 0
        
        # Icon and type
        icon = "💸" if is_send else "📥"
        type_text = "送金" if is_send else "受取"
        
        type_frame = ttk.Frame(main_frame, style='MobileCard.TFrame')
        type_frame.pack(fill='x')
        
        ttk.Label(type_frame, text=f"{icon} {type_text}", 
                 style='MobileBody.TLabel').pack(side='left')
        
        # Amount
        amount_text = f"{abs(amount):,} sats"
        color = MobileStyle.TEXT_ERROR if is_send else MobileStyle.TEXT_SUCCESS
        
        amount_label = ttk.Label(type_frame, text=amount_text, 
                                style='MobileBody.TLabel',
                                font=("Segoe UI", 14, "bold"))
        amount_label.pack(side='right')
        amount_label.config(foreground=color)
        
        # Status and time
        status_frame = ttk.Frame(main_frame, style='MobileCard.TFrame')
        status_frame.pack(fill='x', pady=(4, 0))
        
        status = "✅ 完了" if payment.get('settled') else "⏳ 処理中"
        ttk.Label(status_frame, text=status, 
                 style='MobileSecondary.TLabel').pack(side='left')
        
        timestamp = datetime.fromtimestamp(
            payment.get('creation_date', 0)
        ).strftime("%m/%d %H:%M")
        ttk.Label(status_frame, text=timestamp, 
                 style='MobileSecondary.TLabel').pack(side='right')
        
        # Add separator
        ttk.Separator(item_frame, orient='horizontal').pack(fill='x', pady=2)


class BLNCSMobileApp:
    """Main mobile application class"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.lightning_client = get_lightning_client()
        self.config = get_config_manager()
        
        self.setup_mobile_window()
        self.create_mobile_interface()
        
        # Configure mobile styling
        MobileStyle.configure_mobile_style(self.root)
        
    def setup_mobile_window(self):
        """Configure window for mobile-like experience"""
        self.root.title("⚡ BLNCS Mobile")
        
        # Mobile-like dimensions (portrait orientation)
        width, height = 375, 667  # iPhone-like dimensions
        self.root.geometry(f"{width}x{height}")
        self.root.minsize(320, 568)  # Minimum mobile size
        self.root.configure(bg=MobileStyle.BG_PRIMARY)
        
        # Center window on screen
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        self.root.geometry(f"{width}x{height}+{x}+{y}")
    
    def create_mobile_interface(self):
        """Create mobile interface"""
        # Status bar at top
        self.status_bar = MobileStatusBar(self.root)
        self.status_bar.pack(fill='x')
        
        # Tab navigation
        self.notebook = ttk.Notebook(self.root, style='Mobile.TNotebook')
        self.notebook.pack(fill='both', expand=True)
        
        # Create mobile tabs
        self.dashboard_tab = MobileDashboard(self.notebook, self)
        self.payments_tab = MobilePayments(self.notebook, self)
        
        # Add tabs with mobile-friendly labels
        self.notebook.add(self.dashboard_tab, text="📊 ホーム")
        self.notebook.add(self.payments_tab, text="💰 ペイメント")
        
        # Start status updates
        self.start_status_updates()
        
        # Enable swipe navigation between tabs
        self.setup_swipe_navigation()
    
    def setup_swipe_navigation(self):
        """Setup swipe navigation between tabs"""
        def switch_to_next_tab():
            current = self.notebook.index(self.notebook.select())
            next_tab = (current + 1) % self.notebook.index('end')
            self.notebook.select(next_tab)
        
        def switch_to_prev_tab():
            current = self.notebook.index(self.notebook.select())
            prev_tab = (current - 1) % self.notebook.index('end')
            self.notebook.select(prev_tab)
        
        # Bind swipe gestures to notebook
        self.notebook.bind('<Button-1>', self.on_tab_touch)
    
    def on_tab_touch(self, event):
        """Handle tab touch events"""
        # Simple touch feedback
        pass
    
    def switch_tab(self, tab_index):
        """Switch to specific tab"""
        if 0 <= tab_index < self.notebook.index('end'):
            self.notebook.select(tab_index)
    
    def start_status_updates(self):
        """Start periodic status updates"""
        def update_status():
            try:
                # Try to get connection status
                info = self.lightning_client.get_info()
                connected = info is not None
                block_height = info.get('block_height') if info else None
                
                self.status_bar.update_status(connected, block_height)
            except:
                self.status_bar.update_status(False, None)
            
            # Schedule next update
            self.root.after(30000, update_status)  # Every 30 seconds
        
        # Initial update
        update_status()
    
    def run(self):
        """Start the mobile application"""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            pass


def main():
    """Main entry point for mobile application"""
    try:
        print("📱 Starting BLNCS Mobile Interface...")
        app = BLNCSMobileApp()
        app.run()
    except Exception as e:
        print(f"❌ Mobile app error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()