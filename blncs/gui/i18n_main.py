#!/usr/bin/env python3
"""
BLNCS Internationalized Main GUI
Enhanced main application with multi-language support.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import logging
from pathlib import Path
from typing import Optional

try:
    from ..i18n import get_translator, get_language_manager
    from ..i18n.gui_integration import I18nWindow, I18nFrame, LanguageSelector, I18nMessageBox, LocalizedStatusBar
    from ..i18n.locale_utils import format_currency, format_datetime
    from ..core.config_manager import get_config
    from ..lightning.client import get_client
except ImportError:
    # For standalone testing
    import sys
    sys.path.append(str(Path(__file__).parent.parent))
    from i18n import get_translator, get_language_manager
    from i18n.gui_integration import I18nWindow, I18nFrame, LanguageSelector, I18nMessageBox, LocalizedStatusBar
    from i18n.locale_utils import format_currency, format_datetime

logger = logging.getLogger(__name__)


class I18nMainApplication(I18nWindow):
    """Main BLNCS application with internationalization support"""
    
    def __init__(self):
        super().__init__()
        
        self.title("BLNCS - Bitcoin Lightning Network Control System")
        self.geometry("1000x700")
        self.minsize(800, 600)
        
        # Initialize components
        self.translator = get_translator()
        self.language_manager = get_language_manager()
        
        # Application state
        self.lightning_client = None
        self.connection_status = "disconnected"
        
        self.setup_ui()
        self.setup_menu()
        self.apply_current_language()
        
        # Start with connection status check
        self.after(1000, self.update_status)
    
    def setup_ui(self):
        """Setup main user interface"""
        # Main container
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Top section - Connection and status
        self.setup_connection_section(main_frame)
        
        # Middle section - Tabs
        self.setup_tabs_section(main_frame)
        
        # Bottom section - Status bar
        self.setup_status_bar()
    
    def setup_connection_section(self, parent):
        """Setup connection control section"""
        # Connection frame
        conn_frame = ttk.LabelFrame(parent, padding="10")
        conn_frame.pack(fill=tk.X, pady=(0, 10))
        self.add_translatable_widget(conn_frame, 'lightning.status', 'text')
        
        # Connection controls
        controls_frame = ttk.Frame(conn_frame)
        controls_frame.pack(fill=tk.X)
        
        # Connect button
        self.connect_button = ttk.Button(
            controls_frame,
            command=self.toggle_connection,
            width=15
        )
        self.connect_button.pack(side=tk.LEFT, padx=(0, 10))
        self.add_translatable_widget(self.connect_button, 'action.connect')
        
        # Status indicator
        self.status_label = ttk.Label(controls_frame, text="", font=("Arial", 10))
        self.status_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Connection info
        info_frame = ttk.Frame(conn_frame)
        info_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.node_id_label = ttk.Label(info_frame, text="", font=("Arial", 9))
        self.node_id_label.pack(side=tk.LEFT)
        
        self.balance_label = ttk.Label(info_frame, text="", font=("Arial", 9))
        self.balance_label.pack(side=tk.RIGHT)
    
    def setup_tabs_section(self, parent):
        """Setup tabbed interface"""
        # Notebook for tabs
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Dashboard tab
        dashboard_frame = I18nFrame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")
        self.setup_dashboard_tab(dashboard_frame)
        
        # Wallet tab
        wallet_frame = I18nFrame(self.notebook)
        self.notebook.add(wallet_frame, text="Wallet")
        self.setup_wallet_tab(wallet_frame)
        
        # Channels tab
        channels_frame = I18nFrame(self.notebook)
        self.notebook.add(channels_frame, text="Channels")
        self.setup_channels_tab(channels_frame)
        
        # Settings tab
        settings_frame = I18nFrame(self.notebook)
        self.notebook.add(settings_frame, text="Settings")
        self.setup_settings_tab(settings_frame)
        
        # Update tab labels with translations
        self.update_tab_labels()
    
    def setup_dashboard_tab(self, parent):
        """Setup dashboard tab content"""
        # Dashboard content
        dashboard_content = ttk.Frame(parent, padding="20")
        dashboard_content.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(
            dashboard_content,
            text="",
            font=("Arial", 16, "bold")
        )
        title_label.pack(pady=(0, 20))
        self.add_translatable_widget(title_label, 'nav.dashboard')
        
        # Stats grid
        stats_frame = ttk.Frame(dashboard_content)
        stats_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Configure grid
        for i in range(3):
            stats_frame.columnconfigure(i, weight=1)
        
        # Balance card
        self.balance_card = self.create_stat_card(
            stats_frame, 
            "Balance", 
            "0 sats", 
            0, 0
        )
        
        # Channels card  
        self.channels_card = self.create_stat_card(
            stats_frame,
            "Channels",
            "0 / 0",
            0, 1
        )
        
        # Status card
        self.status_card = self.create_stat_card(
            stats_frame,
            "Status", 
            "Offline",
            0, 2
        )
        
        # Recent activity
        activity_frame = ttk.LabelFrame(dashboard_content, padding="10")
        activity_frame.pack(fill=tk.BOTH, expand=True)
        self.add_translatable_widget(activity_frame, 'wallet.history', 'text')
        
        self.activity_text = tk.Text(
            activity_frame,
            height=10,
            wrap=tk.WORD,
            state=tk.DISABLED,
            font=("Consolas", 9)
        )
        activity_scrollbar = ttk.Scrollbar(activity_frame, orient="vertical", command=self.activity_text.yview)
        self.activity_text.configure(yscrollcommand=activity_scrollbar.set)
        
        self.activity_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        activity_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_stat_card(self, parent, title_key: str, value: str, row: int, col: int):
        """Create a statistics card widget"""
        card_frame = ttk.LabelFrame(parent, padding="15")
        card_frame.grid(row=row, column=col, padx=5, pady=5, sticky="ew")
        
        # Title
        title_label = ttk.Label(card_frame, text="", font=("Arial", 12, "bold"))
        title_label.pack()
        self.add_translatable_widget(title_label, title_key)
        
        # Value
        value_label = ttk.Label(card_frame, text=value, font=("Arial", 14))
        value_label.pack(pady=(5, 0))
        
        return {
            'frame': card_frame,
            'title': title_label,
            'value': value_label
        }
    
    def setup_wallet_tab(self, parent):
        """Setup wallet tab content"""
        wallet_content = ttk.Frame(parent, padding="20")
        wallet_content.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(wallet_content, text="", font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))
        self.add_translatable_widget(title_label, 'nav.wallet')
        
        # Wallet operations
        ops_frame = ttk.Frame(wallet_content)
        ops_frame.pack(fill=tk.X, pady=(0, 20))
        
        send_button = ttk.Button(ops_frame, text="", width=15)
        send_button.pack(side=tk.LEFT, padx=(0, 10))
        self.add_translatable_widget(send_button, 'wallet.send')
        
        receive_button = ttk.Button(ops_frame, text="", width=15)
        receive_button.pack(side=tk.LEFT)
        self.add_translatable_widget(receive_button, 'wallet.receive')
        
        # Transaction history placeholder
        history_label = ttk.Label(wallet_content, text="", font=("Arial", 12))
        history_label.pack(pady=(20, 10))
        self.add_translatable_widget(history_label, 'wallet.history')
    
    def setup_channels_tab(self, parent):
        """Setup channels tab content"""
        channels_content = ttk.Frame(parent, padding="20")
        channels_content.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(channels_content, text="", font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))
        self.add_translatable_widget(title_label, 'nav.channels')
        
        # Channels info placeholder
        info_label = ttk.Label(channels_content, text="", font=("Arial", 12))
        info_label.pack(pady=20)
        self.add_translatable_widget(info_label, 'lightning.channels')
    
    def setup_settings_tab(self, parent):
        """Setup settings tab content"""
        settings_content = ttk.Frame(parent, padding="20")
        settings_content.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(settings_content, text="", font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))
        self.add_translatable_widget(title_label, 'nav.settings')
        
        # Language selector
        self.language_selector = LanguageSelector(
            settings_content, 
            self.on_language_changed
        )
        
        # Other settings placeholder
        other_settings_frame = ttk.LabelFrame(settings_content, padding="10")
        other_settings_frame.pack(fill=tk.X, pady=(20, 0))
        self.add_translatable_widget(other_settings_frame, 'settings.advanced', 'text')
        
        placeholder_label = ttk.Label(other_settings_frame, text="Additional settings will be available here")
        placeholder_label.pack(pady=10)
    
    def setup_status_bar(self):
        """Setup status bar"""
        self.status_bar = LocalizedStatusBar(self)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_bar.set_status('app.loading')
    
    def setup_menu(self):
        """Setup application menu"""
        menubar = tk.Menu(self)
        self.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Exit", command=self.quit)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Refresh", command=self.refresh_data)
        
        # Language menu
        language_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Language", menu=language_menu)
        
        # Add language options
        available_languages = self.language_manager.get_available_languages()
        current_language = self.language_manager.get_current_language()
        
        for code, name in available_languages.items():
            def set_lang(lang_code=code):
                self.set_language(lang_code)
            
            menu_label = f"{name} ({code})"
            if code == current_language:
                menu_label += " ✓"
            
            language_menu.add_command(label=menu_label, command=set_lang)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
    
    def apply_current_language(self):
        """Apply current language to all UI elements"""
        # Update window title
        self.title(self.translator.translate('app.title'))
        
        # Update tab labels
        self.update_tab_labels()
        
        # Update status
        self.update_connection_status()
    
    def update_tab_labels(self):
        """Update notebook tab labels"""
        tab_keys = ['nav.dashboard', 'nav.wallet', 'nav.channels', 'nav.settings']
        for i, key in enumerate(tab_keys):
            try:
                label = self.translator.translate(key)
                self.notebook.tab(i, text=label)
            except tk.TclError:
                pass  # Tab might not exist yet
    
    def set_language(self, language_code: str):
        """Set application language"""
        success = self.language_manager.set_language(language_code)
        if success:
            self.apply_current_language()
            self.language_selector.update_language_list()
            self.status_bar.update_language_indicator()
            
            # Show success message
            I18nMessageBox.show_info(
                'app.success',
                'success.updated'
            )
    
    def on_language_changed(self, language_code: str):
        """Handle language change from language selector"""
        self.apply_current_language()
        self.status_bar.update_language_indicator()
    
    def toggle_connection(self):
        """Toggle Lightning Network connection"""
        if self.connection_status == "disconnected":
            self.connect_to_lightning()
        else:
            self.disconnect_from_lightning()
    
    def connect_to_lightning(self):
        """Connect to Lightning Network"""
        try:
            # Simulate connection (replace with actual client code)
            self.connection_status = "connecting"
            self.update_connection_status()
            self.status_bar.set_status('lightning.connecting')
            
            # Simulate connection delay
            self.after(2000, self.on_connection_established)
            
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            self.connection_status = "disconnected"
            self.update_connection_status()
            
            I18nMessageBox.show_error(
                'app.error',
                'error.connection_failed'
            )
    
    def on_connection_established(self):
        """Handle successful connection"""
        self.connection_status = "connected"
        self.update_connection_status()
        self.status_bar.set_status('success.connected')
        
        # Update dashboard data
        self.update_dashboard_data()
        
        I18nMessageBox.show_info(
            'app.success', 
            'success.connected'
        )
    
    def disconnect_from_lightning(self):
        """Disconnect from Lightning Network"""
        self.connection_status = "disconnected"
        self.update_connection_status()
        self.status_bar.set_status('lightning.offline')
    
    def update_connection_status(self):
        """Update connection status display"""
        if self.connection_status == "connected":
            self.connect_button.config(text=self.translator.translate('action.disconnect'))
            self.status_label.config(text=self.translator.translate('lightning.online'), foreground="green")
        elif self.connection_status == "connecting":
            self.connect_button.config(text=self.translator.translate('lightning.connecting'))
            self.status_label.config(text=self.translator.translate('lightning.connecting'), foreground="orange")
        else:
            self.connect_button.config(text=self.translator.translate('action.connect'))
            self.status_label.config(text=self.translator.translate('lightning.offline'), foreground="red")
    
    def update_dashboard_data(self):
        """Update dashboard with mock data"""
        # Update balance card
        mock_balance = 1234567  # sats
        formatted_balance = format_currency(mock_balance, 'sats')
        self.balance_card['value'].config(text=formatted_balance)
        
        # Update channels card
        self.channels_card['value'].config(text="3 / 3")
        
        # Update status card
        self.status_card['value'].config(text=self.translator.translate('lightning.online'))
        
        # Update node info
        self.node_id_label.config(text="Node ID: 03a1b2c3d4e5f6...")
        self.balance_label.config(text=f"{self.translator.translate('lightning.balance')}: {formatted_balance}")
    
    def update_status(self):
        """Periodic status update"""
        try:
            # Update status based on current state
            if self.connection_status == "connected":
                self.status_bar.set_status('lightning.online')
            else:
                self.status_bar.set_status('lightning.offline')
        except Exception as e:
            logger.error(f"Status update failed: {e}")
        
        # Schedule next update
        self.after(5000, self.update_status)
    
    def refresh_data(self):
        """Refresh application data"""
        self.status_bar.set_status('app.loading')
        
        # Simulate data refresh
        self.after(1000, lambda: self.status_bar.set_status('success.updated'))
    
    def show_about(self):
        """Show about dialog"""
        I18nMessageBox.show_info(
            'nav.help',
            'app.title'
        )


def main():
    """Main entry point"""
    logging.basicConfig(level=logging.INFO)
    
    try:
        app = I18nMainApplication()
        app.mainloop()
    except Exception as e:
        logger.error(f"Application error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())