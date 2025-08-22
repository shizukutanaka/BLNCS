# BLRCS Enhanced Desktop GUI
# Integrated desktop application with all optimized features
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import asyncio
import json
from datetime import datetime, timedelta
from pathlib import Path
import sys
import os
from concurrent.futures import ThreadPoolExecutor

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from blrcs.config import get_config
from blrcs.database import Database
from blrcs.cache import Cache
from blrcs.logger import setup_logging, get_logger
from blrcs.i18n import Translator
from blrcs.compression import Compressor, CompressionType
from blrcs.backup import BackupManager, AutoBackupScheduler
from blrcs.monitoring import PerformanceMonitor, RequestTracker
from blrcs.tray import MinimalTray
from blrcs.lightning import LightningClient, LNDProcessManager
from blrcs.tk_after import TkAfterGuardMixin

class BLRCSDesktopApp(TkAfterGuardMixin):
    """Desktop GUI application for BLRCS"""
    
    def __init__(self):
        self.config = get_config()
        self.db = None
        self.cache = Cache()
        self.translator = Translator(self.config.default_lang)
        self.logger = get_logger(__name__)
        self.compressor = Compressor(CompressionType.AUTO)
        self.backup_manager = BackupManager(Path("backups"))
        self.monitor = PerformanceMonitor()
        self.auto_backup = None
        self.lightning_client = LightningClient()
        self.lnd_manager = LNDProcessManager()
        # LND status poller state (watchdog + backoff)
        # Read defaults from config (env or config.json)
        self._lnd_poll_base_interval_ms = int(self.config.lnd_poll_base_ms)
        self._lnd_poll_interval_ms = self._lnd_poll_base_interval_ms
        self._lnd_poll_max_interval_ms = int(self.config.lnd_poll_max_ms)
        self._lnd_poll_backoff_factor = float(self.config.lnd_poll_backoff_factor)
        self._lnd_poll_consecutive_failures = 0
        # Keep watchdog slightly below interval to allow graceful cancellation
        self._lnd_poll_watchdog_margin_ms = int(self.config.lnd_poll_watchdog_margin_ms)
        self._lnd_last_update_at = None
        self._lnd_poll_in_flight = False
        self._lnd_next_poll_due_at = None
        # Poller timers and future tracking for clean shutdown
        self._lnd_after_next_tick_id = None
        self._lnd_after_watchdog_id = None
        self._lnd_after_update_ago_id = None
        self._lnd_poll_future = None
        self._is_shutting_down = False
        # General periodic timers
        self._general_after_refresh_id = None
        # Central tracking of all tkinter after() ids for bulk cancel
        self._tracked_after_ids = set()
        # Initialize mixin guard
        self._init_after_guard()
        # Path validation state
        self._last_valid_tls_path = str(self.config.lnd_tls_cert or "")
        self._last_valid_mac_path = str(self.config.lnd_admin_macaroon or "")
        self._suppress_tls_trace = False
        self._suppress_mac_trace = False
        # Poller settings change debounce and trace suppression
        self._lnd_poller_apply_after_id = None
        self._suppress_poller_trace = False
        
        # Setup GUI
        self.root = tk.Tk()
        self.root.title(self.translator.get("app.name"))
        self.root.geometry("900x700")
        
        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Setup system tray (wire quit to full app shutdown)
        self.tray = MinimalTray(self.root, self.translator.get("app.name"), on_quit=self.quit)
        
        # Setup UI
        self.setup_ui()
        
        # Initialize async components
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run_async_loop, daemon=True)
        self.thread.start()
        # Dedicated single-threaded executor for LND poller tasks
        self._poll_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="lnd-poller")
        
        # Initialize components
        self.async_init()
    
    def setup_ui(self):
        """Setup the enhanced user interface"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Main tab
        self.main_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.main_tab, text=self.translator.get("app.tab.main"))
        self.setup_main_tab()
        
        # Performance tab
        self.perf_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.perf_tab, text=self.translator.get("app.tab.monitor"))
        self.setup_performance_tab()
        
        # Backup tab
        self.backup_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.backup_tab, text=self.translator.get("app.tab.backup"))
        self.setup_backup_tab()
        
        # Lightning tab
        self.lightning_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.lightning_tab, text=self.translator.get("lightning.tab"))
        self.setup_lightning_tab()
        
        # Settings tab
        self.settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_tab, text=self.translator.get("app.tab.settings"))
        self.setup_settings_tab()
        
        # Status bar
        self.status_var = tk.StringVar(value=self.translator.get("app.common.ready"))
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=2)
    
    def setup_main_tab(self):
        """Setup main processing tab"""
        # Control panel
        self.main_control_frame = ttk.LabelFrame(self.main_tab, text=self.translator.get("app.main.controls.title"), padding="10")
        self.main_control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Input field
        self.lbl_input = ttk.Label(self.main_control_frame, text=self.translator.get("app.main.input.title"))
        self.lbl_input.grid(row=0, column=0, sticky=tk.W, padx=5)
        self.input_var = tk.StringVar()
        input_entry = ttk.Entry(self.main_control_frame, textvariable=self.input_var, width=50)
        input_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # Compression option
        self.compress_var = tk.BooleanVar(value=True)
        self.compress_check = ttk.Checkbutton(self.main_control_frame, text=self.translator.get("app.main.compress"), variable=self.compress_var)
        self.compress_check.grid(row=0, column=2, padx=5)
        
        # Process button
        self.process_btn = ttk.Button(self.main_control_frame, text=self.translator.get("app.actions.process"), command=self.process_input)
        self.process_btn.grid(row=0, column=3, padx=5)
        
        # Output area
        self.output_frame = ttk.LabelFrame(self.main_tab, text=self.translator.get("app.main.output.title"), padding="10")
        self.output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Text widget with scrollbar
        self.output_text = tk.Text(self.output_frame, wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(self.output_frame, orient=tk.VERTICAL, command=self.output_text.yview)
        self.output_text.config(yscrollcommand=scrollbar.set)
        
        self.output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Action buttons
        self.button_frame = ttk.Frame(self.main_tab)
        self.button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.btn_clear = ttk.Button(self.button_frame, text=self.translator.get("app.actions.clear"), command=self.clear_output)
        self.btn_clear.pack(side=tk.LEFT, padx=5)
        self.btn_import = ttk.Button(self.button_frame, text=self.translator.get("app.actions.import"), command=self.import_data)
        self.btn_import.pack(side=tk.LEFT, padx=5)
        self.btn_export = ttk.Button(self.button_frame, text=self.translator.get("app.actions.export"), command=self.export_data)
        self.btn_export.pack(side=tk.LEFT, padx=5)
    
    def setup_performance_tab(self):
        """Setup performance monitoring tab"""
        # Controls
        self.perf_control_frame = ttk.Frame(self.perf_tab)
        self.perf_control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.monitor_var = tk.BooleanVar(value=False)
        self.monitor_check = ttk.Checkbutton(self.perf_control_frame, text=self.translator.get("app.monitor.enable"), 
                                       variable=self.monitor_var, 
                                       command=self.toggle_monitoring)
        self.monitor_check.pack(side=tk.LEFT, padx=5)
        
        self.btn_perf_refresh = ttk.Button(self.perf_control_frame, text=self.translator.get("app.common.refresh"), command=self.refresh_performance)
        self.btn_perf_refresh.pack(side=tk.LEFT, padx=5)
        self.btn_alerts_clear = ttk.Button(self.perf_control_frame, text=self.translator.get("app.alerts.clear"), command=self.clear_alerts)
        self.btn_alerts_clear.pack(side=tk.LEFT, padx=5)
        
        # Metrics display
        self.metrics_frame = ttk.LabelFrame(self.perf_tab, text=self.translator.get("app.monitor.metrics.title"), padding="10")
        self.metrics_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create treeview for metrics
        columns = ('metric', 'value', 'status')
        self.metrics_tree = ttk.Treeview(self.metrics_frame, columns=columns, show='headings', height=15)
        # Localized headings
        self.metrics_tree.heading('metric', text=self.translator.get("app.monitor.columns.metric"))
        self.metrics_tree.heading('value', text=self.translator.get("app.monitor.columns.value"))
        self.metrics_tree.heading('status', text=self.translator.get("app.monitor.columns.status"))
        # Column widths
        self.metrics_tree.column('metric', width=150)
        self.metrics_tree.column('value', width=150)
        self.metrics_tree.column('status', width=150)
        
        self.metrics_tree.pack(fill=tk.BOTH, expand=True)
        
        # Alerts display
        self.alerts_frame = ttk.LabelFrame(self.perf_tab, text=self.translator.get("app.alerts.title"), padding="10")
        self.alerts_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.alerts_text = tk.Text(self.alerts_frame, height=5, wrap=tk.WORD)
        self.alerts_text.pack(fill=tk.X)
    
    def setup_backup_tab(self):
        """Setup backup management tab"""
        # Controls
        self.backup_control_frame = ttk.LabelFrame(self.backup_tab, text=self.translator.get("app.backup.controls.title"), padding="10")
        self.backup_control_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Backup type selection
        self.lbl_backup_type = ttk.Label(self.backup_control_frame, text=self.translator.get("app.backup.label.type"))
        self.lbl_backup_type.grid(row=0, column=0, padx=5, pady=5)
        # Value/label mappings for backup type
        self.backup_type_value_to_label = {
            "full": self.translator.get("app.backup.type.full"),
            "incremental": self.translator.get("app.backup.type.incremental"),
        }
        self.backup_type_label_to_value = {v: k for k, v in self.backup_type_value_to_label.items()}
        type_labels = list(self.backup_type_value_to_label.values())
        self.backup_type_var = tk.StringVar(value=self.backup_type_value_to_label["full"])
        self.backup_type_combo = ttk.Combobox(self.backup_control_frame, textvariable=self.backup_type_var, 
                                   values=type_labels, width=15)
        self.backup_type_combo.grid(row=0, column=1, padx=5, pady=5)
        
        # Backup buttons
        self.btn_backup_create = ttk.Button(self.backup_control_frame, text=self.translator.get("app.backup.button.create"), 
                  command=self.create_backup)
        self.btn_backup_create.grid(row=0, column=2, padx=5, pady=5)
        self.btn_backup_restore = ttk.Button(self.backup_control_frame, text=self.translator.get("app.backup.button.restore"), 
                  command=self.restore_backup)
        self.btn_backup_restore.grid(row=0, column=3, padx=5, pady=5)
        
        # Auto backup
        self.auto_backup_var = tk.BooleanVar(value=False)
        self.auto_backup_check = ttk.Checkbutton(self.backup_control_frame, text=self.translator.get("app.backup.auto.toggle"), 
                                    variable=self.auto_backup_var,
                                    command=self.toggle_auto_backup)
        self.auto_backup_check.grid(row=1, column=0, columnspan=2, padx=5, pady=5)
        
        # Backup list
        self.backup_list_frame = ttk.LabelFrame(self.backup_tab, text=self.translator.get("app.backup.list.title"), padding="10")
        self.backup_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create treeview for backups
        columns = ('name', 'type', 'date', 'size', 'status')
        self.backup_tree = ttk.Treeview(self.backup_list_frame, columns=columns, show='headings')
        # Localized headings
        self.backup_tree.heading('name', text=self.translator.get("app.backup.columns.name"))
        self.backup_tree.heading('type', text=self.translator.get("app.backup.columns.type"))
        self.backup_tree.heading('date', text=self.translator.get("app.backup.columns.date"))
        self.backup_tree.heading('size', text=self.translator.get("app.backup.columns.size"))
        self.backup_tree.heading('status', text=self.translator.get("app.backup.columns.status"))
        # Column widths
        self.backup_tree.column('name', width=120)
        self.backup_tree.column('type', width=120)
        self.backup_tree.column('date', width=120)
        self.backup_tree.column('size', width=120)
        self.backup_tree.column('status', width=120)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(self.backup_list_frame, orient=tk.VERTICAL, command=self.backup_tree.yview)
        self.backup_tree.config(yscrollcommand=scrollbar.set)
        
        self.backup_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Refresh backup list
        self.refresh_backups()
    
    def setup_lightning_tab(self):
        """Setup Lightning connectivity tab"""
        # Process settings
        self.ln_proc_frame = ttk.LabelFrame(self.lightning_tab, text=self.translator.get("lightning.group.process"), padding="10")
        self.ln_proc_frame.pack(fill=tk.X, padx=10, pady=10)

        self.lbl_lnd_exe = ttk.Label(self.ln_proc_frame, text=self.translator.get("lightning.label.lnd_exe"))
        self.lbl_lnd_exe.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.lnd_exe_var = tk.StringVar(value=str(self.config.lnd_exe or ""))
        ttk.Entry(self.ln_proc_frame, textvariable=self.lnd_exe_var, width=48).grid(row=0, column=1, columnspan=3, padx=5, pady=5, sticky=tk.W)
        self.ln_browse_lnd_exe_btn = ttk.Button(self.ln_proc_frame, text=self.translator.get("common.browse"), command=self._browse_lnd_exe)
        self.ln_browse_lnd_exe_btn.grid(row=0, column=4, padx=5, pady=5)

        self.lbl_lnd_dir = ttk.Label(self.ln_proc_frame, text=self.translator.get("lightning.label.lnd_dir"))
        self.lbl_lnd_dir.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.lnd_dir_var = tk.StringVar(value=str(self.config.lnd_dir or ""))
        ttk.Entry(self.ln_proc_frame, textvariable=self.lnd_dir_var, width=48).grid(row=1, column=1, columnspan=3, padx=5, pady=5, sticky=tk.W)
        self.ln_browse_lnd_dir_btn = ttk.Button(self.ln_proc_frame, text=self.translator.get("common.browse"), command=self._browse_lnd_dir)
        self.ln_browse_lnd_dir_btn.grid(row=1, column=4, padx=5, pady=5)

        self.lbl_network = ttk.Label(self.ln_proc_frame, text=self.translator.get("lightning.label.network"))
        self.lbl_network.grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.lnd_net_var = tk.StringVar(value=self.config.lnd_network)
        net_combo = ttk.Combobox(self.ln_proc_frame, textvariable=self.lnd_net_var, values=["mainnet", "testnet", "signet", "regtest"], state="readonly", width=12)
        net_combo.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)

        self.lbl_backend = ttk.Label(self.ln_proc_frame, text=self.translator.get("lightning.label.backend"))
        self.lbl_backend.grid(row=2, column=2, padx=5, pady=5, sticky=tk.W)
        self.lnd_backend_var = tk.StringVar(value=self.config.lnd_backend)
        backend_combo = ttk.Combobox(self.ln_proc_frame, textvariable=self.lnd_backend_var, values=["neutrino", "bitcoind"], state="readonly", width=12)
        backend_combo.grid(row=2, column=3, padx=5, pady=5, sticky=tk.W)

        self.lbl_extra_args = ttk.Label(self.ln_proc_frame, text=self.translator.get("lightning.label.extra_args"))
        self.lbl_extra_args.grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.lnd_extra_var = tk.StringVar(value=str(self.config.lnd_extra_args or ""))
        ttk.Entry(self.ln_proc_frame, textvariable=self.lnd_extra_var, width=48).grid(row=3, column=1, columnspan=3, padx=5, pady=5, sticky=tk.W)

        proc_actions = ttk.Frame(self.lightning_tab)
        proc_actions.pack(fill=tk.X, padx=10, pady=5)
        self.ln_start_btn = ttk.Button(proc_actions, text=self.translator.get("lightning.button.start"), command=self.start_lnd)
        self.ln_start_btn.pack(side=tk.LEFT, padx=5)
        self.ln_stop_btn = ttk.Button(proc_actions, text=self.translator.get("lightning.button.stop"), command=self.stop_lnd)
        self.ln_stop_btn.pack(side=tk.LEFT, padx=5)
        self.lnd_status_var = tk.StringVar(value=self.translator.get("lightning.status.proc_stopped"))
        ttk.Label(proc_actions, textvariable=self.lnd_status_var).pack(side=tk.LEFT, padx=10)

        # Poller status labels
        self.lnd_poll_interval_var = tk.StringVar(value=self.translator.get("lightning.poll.interval_ms", ms=self._lnd_poll_interval_ms))
        self.lnd_poll_last_update_var = tk.StringVar(value=self.translator.get("lightning.poll.last_update_never"))
        self.lnd_poll_last_update_ago_var = tk.StringVar(value="")
        self.lnd_poll_failures_var = tk.StringVar(value=self.translator.get("lightning.poll.failures", n=0))
        self.lnd_poll_next_in_var = tk.StringVar(value="")
        self.lnd_poll_backoff_state_var = tk.StringVar(value=self.translator.get("lightning.poll.backoff_inactive"))
        self.lnd_poll_last_error_var = tk.StringVar(value=self.translator.get("lightning.poll.last_error_none"))
        # Poller control/state
        self._lnd_poll_paused = False
        self.lnd_poll_inflight_var = tk.StringVar(value="")
        poller_frame = ttk.Frame(self.lightning_tab)
        poller_frame.pack(fill=tk.X, padx=10, pady=0)
        ttk.Label(poller_frame, textvariable=self.lnd_poll_interval_var).pack(side=tk.LEFT, padx=10)
        ttk.Label(poller_frame, textvariable=self.lnd_poll_last_update_var).pack(side=tk.LEFT, padx=10)
        ttk.Label(poller_frame, textvariable=self.lnd_poll_last_update_ago_var).pack(side=tk.LEFT, padx=10)
        ttk.Label(poller_frame, textvariable=self.lnd_poll_next_in_var).pack(side=tk.LEFT, padx=10)
        ttk.Label(poller_frame, textvariable=self.lnd_poll_inflight_var).pack(side=tk.LEFT, padx=10)
        ttk.Label(poller_frame, textvariable=self.lnd_poll_failures_var).pack(side=tk.LEFT, padx=10)
        ttk.Label(poller_frame, textvariable=self.lnd_poll_backoff_state_var).pack(side=tk.LEFT, padx=10)
        ttk.Label(poller_frame, textvariable=self.lnd_poll_last_error_var).pack(side=tk.LEFT, padx=10)
        # Controls: Pause/Resume and Refresh
        self.lnd_poll_pause_btn = ttk.Button(poller_frame, text=self.translator.get("lightning.button.pause"), command=self._toggle_lnd_poll_pause)
        self.lnd_poll_pause_btn.pack(side=tk.RIGHT, padx=10)
        self.lnd_refresh_btn = ttk.Button(poller_frame, text=self.translator.get("lightning.button.refresh_now"), command=self._refresh_lnd_status_now)
        self.lnd_refresh_btn.pack(side=tk.RIGHT, padx=10)
        
        # Poller settings (live editable)
        poller_settings = ttk.LabelFrame(self.lightning_tab, text=self.translator.get("lightning.group.poller"), padding="10")
        poller_settings.pack(fill=tk.X, padx=10, pady=10)
        
        # Variables
        self.lnd_poll_base_var = tk.IntVar(value=int(self._lnd_poll_base_interval_ms))
        self.lnd_poll_max_var = tk.IntVar(value=int(self._lnd_poll_max_interval_ms))
        self.lnd_poll_backoff_var = tk.DoubleVar(value=float(self._lnd_poll_backoff_factor))
        self.lnd_poll_watchdog_var = tk.IntVar(value=int(self._lnd_poll_watchdog_margin_ms))
        # Error vars per field
        self.lnd_poll_base_err_var = tk.StringVar(value="")
        self.lnd_poll_max_err_var = tk.StringVar(value="")
        self.lnd_poll_backoff_err_var = tk.StringVar(value="")
        self.lnd_poll_watchdog_err_var = tk.StringVar(value="")
        # Status
        self.lnd_poller_status_var = tk.StringVar(value="")
        
        # Base interval
        ttk.Label(poller_settings, text=self.translator.get("lightning.poller.label.base_ms")).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        ttk.Spinbox(poller_settings, from_=100, to=3_600_000, increment=100, textvariable=self.lnd_poll_base_var, width=12).grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Label(poller_settings, textvariable=self.lnd_poll_base_err_var, foreground="#b00020").grid(row=0, column=2, columnspan=3, padx=5, pady=5, sticky=tk.W)
        # Max interval
        ttk.Label(poller_settings, text=self.translator.get("lightning.poller.label.max_ms")).grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        ttk.Spinbox(poller_settings, from_=100, to=7_200_000, increment=100, textvariable=self.lnd_poll_max_var, width=12).grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Label(poller_settings, textvariable=self.lnd_poll_max_err_var, foreground="#b00020").grid(row=1, column=2, columnspan=3, padx=5, pady=5, sticky=tk.W)
        # Backoff factor
        ttk.Label(poller_settings, text=self.translator.get("lightning.poller.label.backoff")).grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        ttk.Spinbox(poller_settings, from_=1.0, to=10.0, increment=0.1, format="%.1f", textvariable=self.lnd_poll_backoff_var, width=12).grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Label(poller_settings, textvariable=self.lnd_poll_backoff_err_var, foreground="#b00020").grid(row=2, column=2, columnspan=3, padx=5, pady=5, sticky=tk.W)
        # Watchdog margin
        ttk.Label(poller_settings, text=self.translator.get("lightning.poller.label.watchdog_ms")).grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        ttk.Spinbox(poller_settings, from_=0, to=60_000, increment=100, textvariable=self.lnd_poll_watchdog_var, width=12).grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Label(poller_settings, textvariable=self.lnd_poll_watchdog_err_var, foreground="#b00020").grid(row=3, column=2, columnspan=3, padx=5, pady=5, sticky=tk.W)
        # Status line
        ttk.Label(poller_settings, textvariable=self.lnd_poller_status_var).grid(row=4, column=0, columnspan=5, padx=5, pady=(5,0), sticky=tk.W)

        # Trace changes (debounced)
        try:
            self.lnd_poll_base_var.trace_add('write', lambda *args: self._on_poller_setting_var_change())
            self.lnd_poll_max_var.trace_add('write', lambda *args: self._on_poller_setting_var_change())
            self.lnd_poll_backoff_var.trace_add('write', lambda *args: self._on_poller_setting_var_change())
            self.lnd_poll_watchdog_var.trace_add('write', lambda *args: self._on_poller_setting_var_change())
        except Exception:
            pass

        # Start periodic update for "last update ago"
        self._lnd_after_update_ago_id = self._safe_after(1000, self._update_last_update_ago_label)

        # Connection settings
        self.ln_conn_frame = ttk.LabelFrame(self.lightning_tab, text=self.translator.get("lightning.group.connection"), padding="10")
        self.ln_conn_frame.pack(fill=tk.X, padx=10, pady=10)

        self.lbl_host = ttk.Label(self.ln_conn_frame, text=self.translator.get("lightning.label.host"))
        self.lbl_host.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.lnd_host_var = tk.StringVar(value=self.config.lnd_rest_host)
        ttk.Entry(self.ln_conn_frame, textvariable=self.lnd_host_var, width=24).grid(row=0, column=1, padx=5, pady=5)

        self.lbl_port = ttk.Label(self.ln_conn_frame, text=self.translator.get("lightning.label.port"))
        self.lbl_port.grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.lnd_port_var = tk.IntVar(value=self.config.lnd_rest_port)
        ttk.Spinbox(self.ln_conn_frame, from_=1, to=65535, textvariable=self.lnd_port_var, width=10).grid(row=0, column=3, padx=5, pady=5)

        self.lbl_tls = ttk.Label(self.ln_conn_frame, text=self.translator.get("lightning.label.tls"))
        self.lbl_tls.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.lnd_tls_var = tk.StringVar(value=str(self.config.lnd_tls_cert or ""))
        ttk.Entry(self.ln_conn_frame, textvariable=self.lnd_tls_var, width=48).grid(row=1, column=1, columnspan=3, padx=5, pady=5, sticky=tk.W)
        self.ln_browse_tls_btn = ttk.Button(self.ln_conn_frame, text=self.translator.get("common.browse"), command=self._browse_tls)
        self.ln_browse_tls_btn.grid(row=1, column=4, padx=5, pady=5)
        self.ln_tls_clear_btn = ttk.Button(self.ln_conn_frame, text=self.translator.get("app.actions.clear"), command=lambda: self.lnd_tls_var.set(""))
        self.ln_tls_clear_btn.grid(row=1, column=5, padx=5, pady=5)

        self.lbl_macaroon = ttk.Label(self.ln_conn_frame, text=self.translator.get("lightning.label.macaroon"))
        self.lbl_macaroon.grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.lnd_macaroon_var = tk.StringVar(value=str(self.config.lnd_admin_macaroon or ""))
        ttk.Entry(self.ln_conn_frame, textvariable=self.lnd_macaroon_var, width=48).grid(row=2, column=1, columnspan=3, padx=5, pady=5, sticky=tk.W)
        self.ln_browse_mac_btn = ttk.Button(self.ln_conn_frame, text=self.translator.get("common.browse"), command=self._browse_macaroon)
        self.ln_browse_mac_btn.grid(row=2, column=4, padx=5, pady=5)
        self.ln_mac_clear_btn = ttk.Button(self.ln_conn_frame, text=self.translator.get("app.actions.clear"), command=lambda: self.lnd_macaroon_var.set(""))
        self.ln_mac_clear_btn.grid(row=2, column=5, padx=5, pady=5)

        # Hints for accepted file types and browse behavior
        self.tls_hint_label = ttk.Label(self.ln_conn_frame, text=self.translator.get("lightning.hint.tls_path"), wraplength=640)
        self.tls_hint_label.grid(row=3, column=1, columnspan=5, padx=5, pady=(0,5), sticky=tk.W)
        self.mac_hint_label = ttk.Label(self.ln_conn_frame, text=self.translator.get("lightning.hint.macaroon_path"), wraplength=640)
        self.mac_hint_label.grid(row=4, column=1, columnspan=5, padx=5, pady=(0,5), sticky=tk.W)

        # Validate on manual edits
        try:
            self.lnd_tls_var.trace_add('write', lambda *args: self._on_tls_change())
            self.lnd_macaroon_var.trace_add('write', lambda *args: self._on_macaroon_change())
        except Exception:
            pass

        # Auto-detect TLS and macaroon from LND dir/network
        self.ln_auto_detect_btn = ttk.Button(self.ln_conn_frame, text=self.translator.get("lightning.button.auto_detect"), command=self.auto_detect_lnd_paths)
        self.ln_auto_detect_btn.grid(row=5, column=0, padx=5, pady=5, sticky=tk.W)

        # React to context changes: if TLS/macaroon empty, try auto-detect
        try:
            self.lnd_dir_var.trace_add('write', lambda *args: self._on_lnd_context_change())
            self.lnd_net_var.trace_add('write', lambda *args: self._on_lnd_context_change())
        except Exception:
            pass

        actions = ttk.Frame(self.lightning_tab)
        actions.pack(fill=tk.X, padx=10, pady=5)
        self.ln_check_btn = ttk.Button(actions, text=self.translator.get("lightning.button.check"), command=self.check_lightning_connectivity)
        self.ln_check_btn.pack(side=tk.LEFT, padx=5)

        # Attempt auto-detect on startup if values are empty
        if (not self.lnd_tls_var.get().strip()) or (not self.lnd_macaroon_var.get().strip()):
            self._auto_detect_and_fill(silent=True)

        # Begin periodic process status polling
        self._schedule_lnd_status_poll()

        # Wallet lifecycle
        wallet_frame = ttk.LabelFrame(self.lightning_tab, text=self.translator.get("lightning.group.wallet"), padding="10")
        wallet_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(wallet_frame, text=self.translator.get("lightning.wallet.label.password")).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.wallet_pass_var = tk.StringVar()
        ttk.Entry(wallet_frame, textvariable=self.wallet_pass_var, width=30, show="*").grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(wallet_frame, text=self.translator.get("lightning.wallet.label.recovery_window")).grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.recovery_window_var = tk.IntVar(value=0)
        ttk.Spinbox(wallet_frame, from_=0, to=100000, textvariable=self.recovery_window_var, width=10).grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)

        ttk.Label(wallet_frame, text=self.translator.get("lightning.wallet.label.seed_hint")).grid(row=1, column=0, columnspan=4, padx=5, pady=(10, 5), sticky=tk.W)
        self.seed_text = tk.Text(wallet_frame, height=4, width=80, wrap=tk.WORD)
        self.seed_text.grid(row=2, column=0, columnspan=4, padx=5, pady=5, sticky=tk.W)

        ttk.Label(wallet_frame, text=self.translator.get("lightning.wallet.label.seed_passphrase")).grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.seed_passphrase_var = tk.StringVar()
        ttk.Entry(wallet_frame, textvariable=self.seed_passphrase_var, width=30, show="*").grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)

        wl_actions = ttk.Frame(wallet_frame)
        wl_actions.grid(row=4, column=0, columnspan=4, sticky=tk.W, padx=5, pady=10)
        ttk.Button(wl_actions, text=self.translator.get("lightning.wallet.button.generate_seed"), command=self.generate_seed).pack(side=tk.LEFT, padx=5)
        ttk.Button(wl_actions, text=self.translator.get("lightning.wallet.button.init_wallet"), command=self.init_wallet).pack(side=tk.LEFT, padx=5)
        ttk.Button(wl_actions, text=self.translator.get("lightning.wallet.button.unlock_wallet"), command=self.unlock_wallet).pack(side=tk.LEFT, padx=5)

        # Invoices
        invoices_frame = ttk.LabelFrame(self.lightning_tab, text=self.translator.get("lightning.group.invoices"), padding="10")
        invoices_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(invoices_frame, text=self.translator.get("lightning.invoice.label.amount_sats")).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.invoice_amount_var = tk.IntVar(value=0)
        ttk.Spinbox(invoices_frame, from_=0, to=21_000_000_000_000, textvariable=self.invoice_amount_var, width=16).grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

        ttk.Label(invoices_frame, text=self.translator.get("lightning.invoice.label.memo")).grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.invoice_memo_var = tk.StringVar()
        ttk.Entry(invoices_frame, textvariable=self.invoice_memo_var, width=30).grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)

        ttk.Label(invoices_frame, text=self.translator.get("lightning.invoice.label.expiry_s")).grid(row=0, column=4, padx=5, pady=5, sticky=tk.W)
        self.invoice_expiry_var = tk.IntVar(value=3600)
        ttk.Spinbox(invoices_frame, from_=60, to=604800, textvariable=self.invoice_expiry_var, width=10).grid(row=0, column=5, padx=5, pady=5, sticky=tk.W)

        inv_actions_top = ttk.Frame(invoices_frame)
        inv_actions_top.grid(row=1, column=0, columnspan=6, sticky=tk.W, padx=5, pady=5)
        ttk.Button(inv_actions_top, text=self.translator.get("lightning.invoice.button.create"), command=self.create_invoice).pack(side=tk.LEFT, padx=5)

        ttk.Label(invoices_frame, text=self.translator.get("lightning.invoice.label.payreq")).grid(row=2, column=0, columnspan=6, padx=5, pady=(10, 5), sticky=tk.W)
        self.payreq_entry = ttk.Entry(invoices_frame, width=96)
        self.payreq_entry.grid(row=3, column=0, columnspan=6, padx=5, pady=5, sticky=tk.W)

        inv_actions_bottom = ttk.Frame(invoices_frame)
        inv_actions_bottom.grid(row=4, column=0, columnspan=6, sticky=tk.W, padx=5, pady=5)
        ttk.Button(inv_actions_bottom, text=self.translator.get("lightning.invoice.button.decode"), command=self.decode_invoice).pack(side=tk.LEFT, padx=5)
        ttk.Button(inv_actions_bottom, text=self.translator.get("lightning.invoice.button.pay"), command=self.pay_invoice).pack(side=tk.LEFT, padx=5)

        ttk.Label(invoices_frame, text=self.translator.get("lightning.invoice.label.list")).grid(row=5, column=0, padx=5, pady=(10,5), sticky=tk.W)
        self.pending_only_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(invoices_frame, text=self.translator.get("lightning.invoice.checkbox.pending_only"), variable=self.pending_only_var).grid(row=5, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Label(invoices_frame, text=self.translator.get("lightning.invoice.label.max")).grid(row=5, column=2, padx=5, pady=5, sticky=tk.W)
        self.max_invoices_var = tk.IntVar(value=50)
        ttk.Spinbox(invoices_frame, from_=1, to=2000, textvariable=self.max_invoices_var, width=10).grid(row=5, column=3, padx=5, pady=5, sticky=tk.W)
        ttk.Button(invoices_frame, text=self.translator.get("lightning.invoice.button.list"), command=self.list_invoices).grid(row=5, column=4, padx=5, pady=5, sticky=tk.W)

        # Channels
        channels_frame = ttk.LabelFrame(self.lightning_tab, text=self.translator.get("lightning.group.channels"), padding="10")
        channels_frame.pack(fill=tk.X, padx=10, pady=10)

        # Connect Peer
        ttk.Label(channels_frame, text=self.translator.get("lightning.channels.label.peer_pubkey")).grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.peer_pubkey_var = tk.StringVar()
        ttk.Entry(channels_frame, textvariable=self.peer_pubkey_var, width=42).grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Label(channels_frame, text=self.translator.get("lightning.channels.label.hostport")).grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)
        self.peer_hostport_var = tk.StringVar()
        ttk.Entry(channels_frame, textvariable=self.peer_hostport_var, width=22).grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)
        self.peer_perm_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(channels_frame, text=self.translator.get("lightning.channels.checkbox.permanent"), variable=self.peer_perm_var).grid(row=0, column=4, padx=5, pady=5, sticky=tk.W)
        ttk.Button(channels_frame, text=self.translator.get("lightning.channels.button.connect_peer"), command=self.connect_peer).grid(row=0, column=5, padx=5, pady=5)

        # Open Channel (basic)
        ttk.Label(channels_frame, text=self.translator.get("lightning.channels.label.node_pubkey")).grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.chan_pubkey_var = tk.StringVar()
        ttk.Entry(channels_frame, textvariable=self.chan_pubkey_var, width=42).grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Label(channels_frame, text=self.translator.get("lightning.channels.label.amount_sats")).grid(row=1, column=2, padx=5, pady=5, sticky=tk.W)
        self.chan_amount_var = tk.IntVar(value=0)
        ttk.Spinbox(channels_frame, from_=1, to=21_000_000_000_000, textvariable=self.chan_amount_var, width=16).grid(row=1, column=3, padx=5, pady=5, sticky=tk.W)
        self.chan_private_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(channels_frame, text=self.translator.get("lightning.channels.checkbox.private"), variable=self.chan_private_var).grid(row=1, column=4, padx=5, pady=5, sticky=tk.W)
        self.chan_spend_unconf_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(channels_frame, text=self.translator.get("lightning.channels.checkbox.spend_unconfirmed"), variable=self.chan_spend_unconf_var).grid(row=1, column=5, padx=5, pady=5, sticky=tk.W)

        # Open Channel (fee/confirm options)
        ttk.Label(channels_frame, text=self.translator.get("lightning.channels.label.target_conf")).grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.chan_target_conf_var = tk.IntVar(value=0)
        ttk.Spinbox(channels_frame, from_=0, to=200, textvariable=self.chan_target_conf_var, width=10).grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Label(channels_frame, text=self.translator.get("lightning.channels.label.sat_vbyte")).grid(row=2, column=2, padx=5, pady=5, sticky=tk.W)
        self.chan_sat_vb_var = tk.IntVar(value=0)
        ttk.Spinbox(channels_frame, from_=0, to=10_000, textvariable=self.chan_sat_vb_var, width=10).grid(row=2, column=3, padx=5, pady=5, sticky=tk.W)
        ttk.Button(channels_frame, text=self.translator.get("lightning.channels.button.open"), command=self.open_channel).grid(row=2, column=5, padx=5, pady=5)

        # Close Channel
        ttk.Label(channels_frame, text=self.translator.get("lightning.channels.label.funding_txid")).grid(row=3, column=0, padx=5, pady=5, sticky=tk.W)
        self.close_txid_var = tk.StringVar()
        ttk.Entry(channels_frame, textvariable=self.close_txid_var, width=42).grid(row=3, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Label(channels_frame, text=self.translator.get("lightning.channels.label.index")).grid(row=3, column=2, padx=5, pady=5, sticky=tk.W)
        self.close_index_var = tk.IntVar(value=0)
        ttk.Spinbox(channels_frame, from_=0, to=1000, textvariable=self.close_index_var, width=10).grid(row=3, column=3, padx=5, pady=5, sticky=tk.W)
        self.close_force_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(channels_frame, text=self.translator.get("lightning.channels.checkbox.force"), variable=self.close_force_var).grid(row=3, column=4, padx=5, pady=5, sticky=tk.W)
        ttk.Button(channels_frame, text=self.translator.get("lightning.channels.button.close"), command=self.close_channel).grid(row=3, column=5, padx=5, pady=5)

        # List Channels
        ttk.Label(channels_frame, text=self.translator.get("lightning.channels.label.filters")).grid(row=4, column=0, padx=5, pady=5, sticky=tk.W)
        self.list_active_only_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(channels_frame, text=self.translator.get("lightning.channels.checkbox.active"), variable=self.list_active_only_var).grid(row=4, column=1, padx=5, pady=5, sticky=tk.W)
        self.list_inactive_only_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(channels_frame, text=self.translator.get("lightning.channels.checkbox.inactive"), variable=self.list_inactive_only_var).grid(row=4, column=2, padx=5, pady=5, sticky=tk.W)
        self.list_public_only_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(channels_frame, text=self.translator.get("lightning.channels.checkbox.public"), variable=self.list_public_only_var).grid(row=4, column=3, padx=5, pady=5, sticky=tk.W)
        self.list_private_only_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(channels_frame, text=self.translator.get("lightning.channels.checkbox.private_only"), variable=self.list_private_only_var).grid(row=4, column=4, padx=5, pady=5, sticky=tk.W)
        ttk.Label(channels_frame, text=self.translator.get("lightning.channels.label.peer_filter_pubkey")).grid(row=5, column=0, padx=5, pady=5, sticky=tk.W)
        self.list_peer_filter_var = tk.StringVar()
        ttk.Entry(channels_frame, textvariable=self.list_peer_filter_var, width=42).grid(row=5, column=1, columnspan=3, padx=5, pady=5, sticky=tk.W)
        ttk.Button(channels_frame, text=self.translator.get("lightning.channels.button.list"), command=self.list_channels).grid(row=5, column=4, padx=5, pady=5)
        ttk.Button(channels_frame, text=self.translator.get("lightning.channels.button.pending"), command=self.list_pending_channels).grid(row=5, column=5, padx=5, pady=5)

        # Result display
        result_frame = ttk.LabelFrame(self.lightning_tab, text=self.translator.get("lightning.group.result"), padding="10")
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.lnd_result_text = tk.Text(result_frame, height=12, wrap=tk.NONE)
        self.lnd_result_text.pack(fill=tk.BOTH, expand=True)

    def _browse_tls(self):
        # Choose a sensible starting directory
        init_dir = None
        try:
            lnd_dir_txt = (self.lnd_dir_var.get() or '').strip()
            lnd_dir = Path(lnd_dir_txt) if lnd_dir_txt else None
            if lnd_dir and lnd_dir.exists() and lnd_dir.is_dir():
                init_dir = str(lnd_dir)
            else:
                cur_tls = (self.lnd_tls_var.get() or '').strip()
                if cur_tls:
                    p = Path(cur_tls)
                    if p.exists() and p.parent.exists():
                        init_dir = str(p.parent)
        except Exception:
            init_dir = None

        filename = filedialog.askopenfilename(
            title=self.translator.get("lightning.file_dialog.tls_title"),
            initialdir=init_dir,
            filetypes=[
                (self.translator.get("common.filetype.pem_or_cert_files"), ("*.pem", "*.cert", "*.PEM", "*.CERT")),
                (self.translator.get("common.filetype.pem_files"), ("*.pem", "*.PEM")),
                (self.translator.get("common.filetype.cert_files"), ("*.cert", "*.CERT")),
                (self.translator.get("common.filetype.all_files"), "*.*"),
            ],
        )
        if filename:
            # Validate selected TLS before setting
            if self._validate_tls_path(filename, show_dialog=True):
                self.lnd_tls_var.set(filename)
                self._last_valid_tls_path = filename

    def _browse_macaroon(self):
        # Choose a sensible starting directory
        init_dir = None
        try:
            lnd_dir_txt = (self.lnd_dir_var.get() or '').strip()
            lnd_dir = Path(lnd_dir_txt) if lnd_dir_txt else None
            if lnd_dir and lnd_dir.exists() and lnd_dir.is_dir():
                init_dir = str(lnd_dir)
            else:
                cur_mac = (self.lnd_macaroon_var.get() or '').strip()
                if cur_mac:
                    p = Path(cur_mac)
                    if p.exists() and p.parent.exists():
                        init_dir = str(p.parent)
        except Exception:
            init_dir = None

        filename = filedialog.askopenfilename(
            title=self.translator.get("lightning.file_dialog.macaroon_title"),
            initialdir=init_dir,
            filetypes=[
                (self.translator.get("common.filetype.macaroon"), ("*.macaroon", "*.MACAROON")),
                (self.translator.get("common.filetype.all_files"), "*.*"),
            ],
        )
        if filename:
            # Validate selected macaroon before setting
            if self._validate_macaroon_path(filename, show_dialog=True):
                self.lnd_macaroon_var.set(filename)
                self._last_valid_mac_path = filename

    def auto_detect_lnd_paths(self):
        """Public handler: attempt to detect TLS/macaroon and update fields."""
        self._auto_detect_and_fill(silent=False)

    def _candidate_default_lnd_dirs(self):
        """Yield common default LND data directories based on OS."""
        home = Path.home()
        candidates = []
        # Windows
        local = os.getenv('LOCALAPPDATA')
        if local:
            candidates.append(Path(local) / 'Lnd')
            candidates.append(Path(local) / 'lnd')
        # macOS
        candidates.append(home / 'Library' / 'Application Support' / 'Lnd')
        # Linux/Unix
        candidates.append(home / '.lnd')
        return [p for p in candidates if p.exists()]

    def _auto_detect_and_fill(self, silent: bool = True):
        """Try to detect TLS certificate and admin macaroon from LND dir and network.
        - Only fills fields that are empty.
        - Does nothing if paths cannot be determined.
        """
        # Determine base lnd_dir
        lnd_dir_txt = (self.lnd_dir_var.get() or '').strip()
        lnd_dir = Path(lnd_dir_txt) if lnd_dir_txt else None
        if not lnd_dir or not lnd_dir.exists():
            # Try known defaults
            for cand in self._candidate_default_lnd_dirs():
                if cand.exists():
                    lnd_dir = cand
                    break

        if not lnd_dir or not lnd_dir.exists():
            if not silent:
                messagebox.showwarning(self.translator.get("lightning.auto_detect.title"), self.translator.get("lightning.auto_detect.dir_missing"))
            return

        # Compute expected paths
        tls_path = lnd_dir / 'tls.cert'
        network = (self.lnd_net_var.get() or 'mainnet').strip().lower()
        mac_path = lnd_dir / 'data' / 'chain' / 'bitcoin' / network / 'admin.macaroon'

        updated = False
        tls_empty = not (self.lnd_tls_var.get() or '').strip()
        mac_empty = not (self.lnd_macaroon_var.get() or '').strip()
        if tls_empty and tls_path.exists():
            if self._validate_tls_path(str(tls_path), show_dialog=not silent):
                self.lnd_tls_var.set(str(tls_path))
                self._last_valid_tls_path = str(tls_path)
                updated = True
        if mac_empty and mac_path.exists():
            if self._validate_macaroon_path(str(mac_path), show_dialog=not silent):
                self.lnd_macaroon_var.set(str(mac_path))
                self._last_valid_mac_path = str(mac_path)
                updated = True

        if updated:
            self.status_var.set(self.translator.get("lightning.auto_detect.detected"))
            if not silent:
                messagebox.showinfo(self.translator.get("lightning.auto_detect.title"), self.translator.get("lightning.auto_detect.detected.info"))
        else:
            if not silent:
                messagebox.showwarning(self.translator.get("lightning.auto_detect.title"), self.translator.get("lightning.auto_detect.not_found"))

    def _on_tls_change(self):
        """Validate TLS path when edited manually; revert on failure."""
        if getattr(self, "_is_shutting_down", False):
            return
        if self._suppress_tls_trace:
            return
        val = (self.lnd_tls_var.get() or '').strip()
        if not val:
            return  # allow clearing
        if not self._validate_tls_path(val, show_dialog=True):
            try:
                self._suppress_tls_trace = True
                # Revert to last valid or clear
                self.lnd_tls_var.set(self._last_valid_tls_path or "")
            finally:
                self._suppress_tls_trace = False
        else:
            self._last_valid_tls_path = val

    def _on_macaroon_change(self):
        """Validate macaroon path when edited manually; revert on failure."""
        if getattr(self, "_is_shutting_down", False):
            return
        if self._suppress_mac_trace:
            return
        val = (self.lnd_macaroon_var.get() or '').strip()
        if not val:
            return  # allow clearing
        if not self._validate_macaroon_path(val, show_dialog=True):
            try:
                self._suppress_mac_trace = True
                # Revert to last valid or clear
                self.lnd_macaroon_var.set(self._last_valid_mac_path or "")
            finally:
                self._suppress_mac_trace = False
        else:
            self._last_valid_mac_path = val

    def _validate_tls_path(self, path: str, show_dialog: bool = True) -> bool:
        """Validate TLS certificate file: existence, extension, minimal PEM header check."""
        try:
            p = Path(path)
            if not p.exists() or not p.is_file():
                if show_dialog and not getattr(self, "_is_shutting_down", False):
                    messagebox.showwarning(
                        self.translator.get("lightning.validation.title"),
                        self.translator.get("lightning.validation.tls.missing", path=str(path)),
                    )
                return False
            ext = p.suffix.lower()
            if ext not in (".pem", ".cert"):
                if show_dialog and not getattr(self, "_is_shutting_down", False):
                    messagebox.showwarning(
                        self.translator.get("lightning.validation.title"),
                        self.translator.get("lightning.validation.tls.ext"),
                    )
                return False
            # Minimal content check: PEM header
            try:
                with p.open("r", encoding="utf-8", errors="ignore") as fh:
                    head = fh.read(2048)
                if "BEGIN CERTIFICATE" not in head:
                    if show_dialog and not getattr(self, "_is_shutting_down", False):
                        messagebox.showwarning(
                            self.translator.get("lightning.validation.title"),
                            self.translator.get("lightning.validation.tls.content"),
                        )
                    return False
            except Exception:
                # If content can't be read as text, consider invalid
                if show_dialog and not getattr(self, "_is_shutting_down", False):
                    messagebox.showwarning(
                        self.translator.get("lightning.validation.title"),
                        self.translator.get("lightning.validation.tls.content"),
                    )
                return False
            return True
        except Exception:
            return False

    def _validate_macaroon_path(self, path: str, show_dialog: bool = True) -> bool:
        """Validate admin macaroon file: existence, extension, minimal non-empty check."""
        try:
            p = Path(path)
            if not p.exists() or not p.is_file():
                if show_dialog and not getattr(self, "_is_shutting_down", False):
                    messagebox.showwarning(
                        self.translator.get("lightning.validation.title"),
                        self.translator.get("lightning.validation.macaroon.missing", path=str(path)),
                    )
                return False
            if p.suffix.lower() != ".macaroon":
                if show_dialog and not getattr(self, "_is_shutting_down", False):
                    messagebox.showwarning(
                        self.translator.get("lightning.validation.title"),
                        self.translator.get("lightning.validation.macaroon.ext"),
                    )
                return False
            try:
                if p.stat().st_size <= 0:
                    if show_dialog and not getattr(self, "_is_shutting_down", False):
                        messagebox.showwarning(
                            self.translator.get("lightning.validation.title"),
                            self.translator.get("lightning.validation.macaroon.content"),
                        )
                    return False
            except Exception:
                if show_dialog and not getattr(self, "_is_shutting_down", False):
                    messagebox.showwarning(
                        self.translator.get("lightning.validation.title"),
                        self.translator.get("lightning.validation.macaroon.content"),
                    )
                return False
            return True
        except Exception:
            return False

    def _on_lnd_context_change(self):
        """Callback when LND dir or network changes. Attempt auto-detect if fields are empty."""
        tls_empty = not (self.lnd_tls_var.get() or '').strip()
        mac_empty = not (self.lnd_macaroon_var.get() or '').strip()
        if tls_empty or mac_empty:
            if getattr(self, "_is_shutting_down", False):
                return
            # Use a short delay to debounce rapid changes
            self._safe_after(100, lambda: self._auto_detect_and_fill(silent=True))

    # ---- LND poller settings: validation, apply, reschedule ----
    def _on_poller_setting_var_change(self):
        if getattr(self, "_suppress_poller_trace", False):
            return
        self._schedule_debounced_apply_poller_settings(300)

    def _schedule_debounced_apply_poller_settings(self, delay_ms: int = 300):
        try:
            if self._lnd_poller_apply_after_id:
                self._cancel_after(self._lnd_poller_apply_after_id)
        except Exception:
            pass
        self._lnd_poller_apply_after_id = self._safe_after(delay_ms, self._apply_ui_poller_settings)

    def _apply_ui_poller_settings(self):
        valid, vals, errors = self._validate_and_collect_poller_settings()
        # Show errors
        try:
            self.lnd_poll_base_err_var.set(errors.get("base", ""))
            self.lnd_poll_max_err_var.set(errors.get("max", ""))
            self.lnd_poll_backoff_err_var.set(errors.get("backoff", ""))
            self.lnd_poll_watchdog_err_var.set(errors.get("watchdog", ""))
        except Exception:
            pass
        if not valid:
            return
        base_ms = vals["base"]
        max_ms = vals["max"]
        backoff = vals["backoff"]
        watchdog_ms = vals["watchdog"]
        self._apply_lnd_poller_settings(base_ms, max_ms, backoff, watchdog_ms)

    def _validate_and_collect_poller_settings(self):
        errors = {}
        # Read raw values
        try:
            base_ms = int(self.lnd_poll_base_var.get())
        except Exception:
            base_ms = 0
        try:
            max_ms = int(self.lnd_poll_max_var.get())
        except Exception:
            max_ms = 0
        try:
            backoff = float(self.lnd_poll_backoff_var.get())
        except Exception:
            backoff = 0.0
        try:
            watchdog_ms = int(self.lnd_poll_watchdog_var.get())
        except Exception:
            watchdog_ms = -1

        # Validate constraints
        if base_ms <= 0:
            errors["base"] = self.translator.get("lightning.poller.validation.base_positive")
        # If base is invalid, also flag max to prompt user to correct both
        if max_ms <= 0 or base_ms <= 0 or max_ms < base_ms:
            errors["max"] = self.translator.get("lightning.poller.validation.max_ge_base")
        if backoff < 1.0:
            errors["backoff"] = self.translator.get("lightning.poller.validation.backoff_ge_one")
        if watchdog_ms < 0 or watchdog_ms >= base_ms:
            errors["watchdog"] = self.translator.get("lightning.poller.validation.watchdog_range")

        valid = len(errors) == 0
        return valid, {"base": base_ms, "max": max_ms, "backoff": backoff, "watchdog": watchdog_ms}, errors

    def _apply_lnd_poller_settings(self, base_ms: int, max_ms: int, backoff: float, watchdog_ms: int):
        # Update internal state (clamp current interval within new bounds)
        self._lnd_poll_base_interval_ms = int(base_ms)
        self._lnd_poll_max_interval_ms = int(max_ms)
        self._lnd_poll_backoff_factor = float(backoff)
        self._lnd_poll_watchdog_margin_ms = int(watchdog_ms)
        # Clamp current interval
        try:
            cur = int(self._lnd_poll_interval_ms)
        except Exception:
            cur = base_ms
        self._lnd_poll_interval_ms = int(min(max(base_ms, cur), max_ms))

        # Update UI labels
        try:
            self.lnd_poll_interval_var.set(self.translator.get("lightning.poll.interval_ms", ms=int(self._lnd_poll_interval_ms)))
        except Exception:
            pass

        # Persist to config
        try:
            self.config.lnd_poll_base_ms = int(base_ms)
            self.config.lnd_poll_max_ms = int(max_ms)
            self.config.lnd_poll_backoff_factor = float(backoff)
            self.config.lnd_poll_watchdog_margin_ms = int(watchdog_ms)
            try:
                self.config._validate()  # ensure overall config still valid
            except Exception:
                pass
            self.config.save()
            try:
                self.lnd_poller_status_var.set(self.translator.get("lightning.poller.status.saved"))
            except Exception:
                pass
        except Exception:
            try:
                self.lnd_poller_status_var.set(self.translator.get("lightning.poller.status.applied"))
            except Exception:
                pass

        # Reschedule next tick according to new interval
        self._reschedule_lnd_poller()

    def _reschedule_lnd_poller(self):
        if getattr(self, "_is_shutting_down", False) or getattr(self, "_lnd_poll_paused", False):
            return
        # Cancel any scheduled next tick
        try:
            if getattr(self, "_lnd_after_next_tick_id", None):
                self._cancel_after(self._lnd_after_next_tick_id)
                self._lnd_after_next_tick_id = None
        except Exception:
            pass
        # If a poll is currently in flight, let completion schedule the next using updated values
        if getattr(self, "_lnd_poll_in_flight", False):
            return
        # Schedule next tick based on current interval
        next_interval = int(self._lnd_poll_interval_ms or self._lnd_poll_base_interval_ms or 5000)
        try:
            self._lnd_next_poll_due_at = datetime.now() + timedelta(milliseconds=next_interval)
        except Exception:
            self._lnd_next_poll_due_at = None
        self._lnd_after_next_tick_id = self._safe_after(next_interval, lambda: self._lnd_status_poll_tick(next_interval))

    # ---- Periodic LND status poller ----
    def _schedule_lnd_status_poll(self, interval_ms: int = 5000):
        """Schedule periodic polling of LND process and REST getinfo.

        Kicks a tick immediately, then each completion schedules the next tick
        based on backoff-adjusted interval. Guards against shutdown/pause.
        """
        # Run one tick now, then reschedule
        self._lnd_status_poll_tick(interval_ms)

    def _lnd_status_poll_tick(self, interval_ms: int = 5000):
        """Execute one poll iteration.

        Avoids overlapping polls; computes watchdog and HTTP timeout; dispatches
        REST getinfo in the dedicated executor; updates UI to show in-flight;
        schedules watchdog checks until completion or timeout.
        """
        try:
            # If app is shutting down, do nothing
            if getattr(self, "_is_shutting_down", False):
                return
            # If paused, drop this tick
            if getattr(self, "_lnd_poll_paused", False):
                return
            # Avoid overlapping polls
            if getattr(self, "_lnd_poll_in_flight", False):
                # Drop this scheduled tick; a new next tick will be scheduled on completion
                return
            # Use current backoff-adjusted interval
            current_interval = int(self._lnd_poll_interval_ms or interval_ms or 5000)
            try:
                self.logger.debug("LND poll: tick start (interval_ms=%d)", current_interval)
            except Exception:
                pass
            # Start timing and compute watchdog and HTTP timeout before dispatch
            started_at = datetime.now()
            watchdog_ms = max(
                2000,
                min(int(0.9 * current_interval), current_interval - self._lnd_poll_watchdog_margin_ms),
            )
            # Ensure HTTP timeout is shorter than watchdog to avoid lingering threads
            http_timeout_s = max(1.0, min((watchdog_ms / 1000.0) - 0.2, 4.0))
            future = asyncio.run_coroutine_threadsafe(
                self._poll_lnd_status_async(http_timeout_s), self.loop
            )
            self._lnd_poll_future = future
            self._lnd_poll_in_flight = True
            try:
                self.lnd_refresh_btn.state(["disabled"])
            except Exception:
                pass
            # Show in-flight indicator
            try:
                self.lnd_poll_inflight_var.set(self.translator.get("lightning.poll.inflight"))
            except Exception:
                pass
            try:
                self.logger.debug("LND poll: watchdog scheduled at ~%d ms from start", watchdog_ms)
            except Exception:
                pass
            self._lnd_after_watchdog_id = self._safe_after(100, lambda: self._handle_lnd_status_result(future, current_interval, started_at, watchdog_ms))
        except Exception:
            # Ensure we continue scheduling even on unexpected errors
            next_interval = int(self._lnd_poll_interval_ms or interval_ms or 5000)
            try:
                self.logger.exception("LND poll: unexpected error while scheduling, scheduling next tick in %d ms", next_interval)
            except Exception:
                pass
            if not getattr(self, "_is_shutting_down", False) and not getattr(self, "_lnd_poll_paused", False):
                self._lnd_after_next_tick_id = self._safe_after(next_interval, lambda: self._lnd_status_poll_tick(next_interval))

    async def _poll_lnd_status_async(self, timeout_s: float):
        """Run LightningClient.get_info_rest in poller executor with timeout.

        Returns a dict: { ok: bool, status: int|None, data: dict|None, error: str|None }.
        """
        host = (self.lnd_host_var.get() or "127.0.0.1").strip()
        try:
            port = int(self.lnd_port_var.get())
        except Exception:
            port = 8080
        tls = Path(self.lnd_tls_var.get().strip()) if (self.lnd_tls_var.get() or '').strip() else None
        mac = Path(self.lnd_macaroon_var.get().strip()) if (self.lnd_macaroon_var.get() or '').strip() else None

        loop = asyncio.get_running_loop()
        def _work():
            return self.lightning_client.get_info_rest(
                host, port, tls_cert=tls, macaroon_path=mac, timeout=float(timeout_s)
            )
        return await loop.run_in_executor(self._poll_executor, _work)

    def _handle_lnd_status_result(self, future, interval_ms: int, started_at: datetime, watchdog_ms: int):
        """Handle poll completion or watchdog timeout.

        - Cancels and backs off on timeout/exception
        - Resets backoff on success
        - Updates localized UI labels and schedules next tick (unless paused)
        - Fully guarded during shutdown to avoid UI updates/rescheduling
        """
        # Parse result and update UI, then schedule next tick after completion
        if getattr(self, "_is_shutting_down", False):
            try:
                if future and not future.done():
                    future.cancel()
            except Exception:
                pass
            try:
                self._lnd_poll_future = None
            except Exception:
                pass
            # Ensure in-flight flag is cleared during shutdown to avoid lingering state
            try:
                self._lnd_poll_in_flight = False
            except Exception:
                pass
            return
        if not future.done():
            # If not done yet, enforce watchdog
            try:
                elapsed_ms = int((datetime.now() - started_at).total_seconds() * 1000)
            except Exception:
                elapsed_ms = 0
            if elapsed_ms >= watchdog_ms:
                try:
                    future.cancel()
                except Exception:
                    pass
                # Log and treat as timeout failure
                try:
                    self.logger.warning("LND poll watchdog timeout after %d ms; cancelling and backing off", elapsed_ms)
                except Exception:
                    pass
                res = {"ok": False, "status": None, "data": None, "error": "timeout"}
            else:
                # Not timed out yet; check again shortly
                if not getattr(self, "_is_shutting_down", False) and not getattr(self, "_lnd_poll_paused", False):
                    self._lnd_after_watchdog_id = self._safe_after(100, lambda: self._handle_lnd_status_result(future, interval_ms, started_at, watchdog_ms))
                return
        else:
            try:
                res = future.result()
            except Exception as e:
                res = {"ok": False, "status": None, "data": None, "error": str(e)}
        # Clear watchdog id; no more watchdog checks for this future
        try:
            self._lnd_after_watchdog_id = None
        except Exception:
            pass

        # Process manager state
        proc_running = self.lnd_manager.is_running()

        # REST getinfo state
        ok = bool(res.get("ok"))
        data = res.get("data") or {}
        alias = data.get("alias") or ""
        synced = data.get("synced_to_chain")
        block_height = data.get("block_height")
        chan_cnt = data.get("num_active_channels")

        # Emit timing and outcome log
        try:
            elapsed_ms2 = int((datetime.now() - started_at).total_seconds() * 1000)
        except Exception:
            elapsed_ms2 = 0
        try:
            if ok:
                self.logger.debug("LND poll: success in %d ms (synced=%s, height=%s, active_ch=%s)", elapsed_ms2, str(bool(synced)), str(block_height), str(chan_cnt))
            else:
                self.logger.info("LND poll: failure in %d ms (error=%s, status=%s)", elapsed_ms2, str(res.get("error")), str(res.get("status")))
        except Exception:
            pass

        # Build concise localized status
        proc_part = self.translator.get("lightning.status.proc_running") if proc_running else self.translator.get("lightning.status.proc_stopped")
        if ok:
            sync_part = self.translator.get("lightning.status.synced") if synced else self.translator.get("lightning.status.syncing")
            rest_part = self.translator.get("lightning.status.rest_ok")
            extra = []
            if isinstance(block_height, int):
                extra.append(f"h={block_height}")
            if isinstance(chan_cnt, int):
                extra.append(f"ch={chan_cnt}")
            extra_s = (" "+" ".join(extra)) if extra else ""
            alias_part = f" [{alias}]" if alias else ""
            status_text = self.translator.get("lightning.status.base", proc=proc_part, rest=rest_part, sync=sync_part, extra=extra_s, alias=alias_part)
        else:
            err = res.get("error") or (f"HTTP {res.get('status')}" if res.get("status") else self.translator.get("lightning.status.unreachable"))
            rest_part = self.translator.get("lightning.status.rest_error", err=err)
            status_text = self.translator.get("lightning.status.base", proc=proc_part, rest=rest_part, sync="", extra="", alias="")

        # Update labels
        try:
            self.lnd_status_var.set(status_text)
        except Exception:
            pass
        # Update poller meta labels
        try:
            self._lnd_last_update_at = datetime.now()
            self.lnd_poll_last_update_var.set(self.translator.get("lightning.poll.last_update_at", time=self._lnd_last_update_at.strftime("%H:%M:%S")))
        except Exception:
            pass

        # Backoff management: on success reset; on failure increase interval
        if ok:
            if self._lnd_poll_consecutive_failures:
                try:
                    self.logger.info("LND poll recovered after %d failures; resetting interval to %d ms", self._lnd_poll_consecutive_failures, self._lnd_poll_base_interval_ms)
                except Exception:
                    pass
            self._lnd_poll_consecutive_failures = 0
            self._lnd_poll_interval_ms = self._lnd_poll_base_interval_ms
            try:
                self.lnd_poll_backoff_state_var.set(self.translator.get("lightning.poll.backoff_inactive"))
                self.lnd_poll_last_error_var.set(self.translator.get("lightning.poll.last_error_none"))
            except Exception:
                pass
        else:
            self._lnd_poll_consecutive_failures += 1
            next_interval = int(min(max(self._lnd_poll_base_interval_ms, int(self._lnd_poll_interval_ms * self._lnd_poll_backoff_factor)), self._lnd_poll_max_interval_ms))
            try:
                self.logger.warning("LND poll failure (%d in a row): %s; backing off to %d ms", self._lnd_poll_consecutive_failures, (res.get("error") or res.get("status") or "unknown"), next_interval)
            except Exception:
                pass
            self._lnd_poll_interval_ms = next_interval
            # Update backoff indicator and last error
            try:
                self.lnd_poll_backoff_state_var.set(self.translator.get("lightning.poll.backoff_active"))
                err_txt = str(res.get("error") or res.get("status") or "unknown")
                if len(err_txt) > 120:
                    err_txt = err_txt[:117] + "..."
                self.lnd_poll_last_error_var.set(self.translator.get("lightning.poll.last_error", err=err_txt))
            except Exception:
                pass

        # Schedule next poll after completion using current backoff interval
        # Update poller interval/failure labels
        try:
            self.lnd_poll_interval_var.set(self.translator.get("lightning.poll.interval_ms", ms=int(self._lnd_poll_interval_ms)))
            self.lnd_poll_failures_var.set(self.translator.get("lightning.poll.failures", n=int(self._lnd_poll_consecutive_failures)))
        except Exception:
            pass
        # Mark poll finished
        self._lnd_poll_in_flight = False
        try:
            self._lnd_poll_future = None
        except Exception:
            pass
        try:
            if not getattr(self, "_lnd_poll_paused", False):
                self.lnd_refresh_btn.state(["!disabled"])
            else:
                self.lnd_refresh_btn.state(["disabled"])
        except Exception:
            pass
        # Hide in-flight indicator
        try:
            self.lnd_poll_inflight_var.set("")
        except Exception:
            pass
        # Schedule next tick only if not paused
        if not getattr(self, "_lnd_poll_paused", False):
            next_interval = int(self._lnd_poll_interval_ms or interval_ms or 5000)
            try:
                self._lnd_next_poll_due_at = datetime.now() + timedelta(milliseconds=next_interval)
            except Exception:
                self._lnd_next_poll_due_at = None
            try:
                self.logger.debug("LND poll: scheduling next tick in %d ms (due_at=%s)", next_interval, str(getattr(self, "_lnd_next_poll_due_at", None)))
            except Exception:
                pass
            self._lnd_after_next_tick_id = self._safe_after(next_interval, lambda: self._lnd_status_poll_tick(next_interval))
        else:
            try:
                self._lnd_next_poll_due_at = None
            except Exception:
                pass
            try:
                self.logger.info("LND poll: paused; next tick not scheduled")
            except Exception:
                pass

    def _update_last_update_ago_label(self):
        """Update 'last update ago' and 'next in' labels every second.

        Shows 'paused' state when paused; suppresses updates during shutdown.
        """
        try:
            if self._lnd_last_update_at is None:
                self.lnd_poll_last_update_ago_var.set("")
            else:
                sec = max(0, int((datetime.now() - self._lnd_last_update_at).total_seconds()))
                self.lnd_poll_last_update_ago_var.set(self.translator.get("lightning.poll.last_update_ago", sec=sec))
            if getattr(self, "_lnd_poll_paused", False):
                self.lnd_poll_next_in_var.set(self.translator.get("lightning.poll.paused"))
            elif self._lnd_next_poll_due_at is None:
                self.lnd_poll_next_in_var.set("")
            else:
                sec_next = max(0, int((self._lnd_next_poll_due_at - datetime.now()).total_seconds()))
                self.lnd_poll_next_in_var.set(self.translator.get("lightning.poll.next_in", sec=sec_next))
        except Exception:
            pass
        finally:
            try:
                if not getattr(self, "_is_shutting_down", False):
                    self._lnd_after_update_ago_id = self._safe_after(1000, self._update_last_update_ago_label)
            except Exception:
                pass

    def _toggle_lnd_poll_pause(self):
        """Toggle poller paused state and update UI controls/labels.

        On resume, immediately triggers one poll tick using current interval.
        """
        try:
            self._lnd_poll_paused = not getattr(self, "_lnd_poll_paused", False)
            try:
                self.logger.info("LND poll: %s", "paused" if self._lnd_poll_paused else "resumed")
            except Exception:
                pass
            if self._lnd_poll_paused:
                # Update button to Resume and clear next countdown
                try:
                    self.lnd_poll_pause_btn.config(text=self.translator.get("lightning.button.resume"))
                except Exception:
                    pass
                try:
                    self._lnd_next_poll_due_at = None
                except Exception:
                    pass
                # Disable manual refresh while paused
                try:
                    self.lnd_refresh_btn.state(["disabled"])
                except Exception:
                    pass
            else:
                # Update button to Pause and immediately schedule a tick
                try:
                    self.lnd_poll_pause_btn.config(text=self.translator.get("lightning.button.pause"))
                except Exception:
                    pass
                # Re-enable manual refresh if not in-flight
                try:
                    if not getattr(self, "_lnd_poll_in_flight", False):
                        self.lnd_refresh_btn.state(["!disabled"])
                except Exception:
                    pass
                # Kick off polling now using current interval
                try:
                    self.logger.debug("LND poll: resume kick-off immediate tick")
                except Exception:
                    pass
                try:
                    self._lnd_status_poll_tick(int(self._lnd_poll_interval_ms or 5000))
                except Exception:
                    pass
        except Exception:
            pass

    def _refresh_lnd_status_now(self):
        """Manual trigger to poll immediately if not in-flight.

        Disabled by in-flight or paused state via button state management.
        """
        try:
            try:
                self.logger.info("LND poll: manual refresh triggered")
            except Exception:
                pass
            self._lnd_status_poll_tick(int(self._lnd_poll_interval_ms or 5000))
        except Exception:
            pass
    
    def _safe_after(self, delay_ms, callback):
        return super()._safe_after(delay_ms, callback)

    def _cancel_after(self, after_id):
        try:
            if after_id:
                try:
                    self.logger.debug("Shutdown: cancelled after() id=%s", str(after_id))
                except Exception:
                    pass
                return super()._cancel_after(after_id)
        except Exception:
            pass

    def _cancel_all_afters(self):
        return super()._cancel_all_afters()

    def _shutdown_lnd_poller(self):
        """Cancel all scheduled Lightning poller callbacks and in-flight futures."""
        try:
            self._is_shutting_down = True
            try:
                self.logger.info("Shutdown: stopping LND poller")
            except Exception:
                pass
        except Exception:
            pass
        # Pause poller and clear due time
        try:
            self._lnd_poll_paused = True
            self._lnd_next_poll_due_at = None
        except Exception:
            pass
        # Cancel scheduled tkinter after() callbacks
        try:
            self._cancel_after(getattr(self, "_lnd_after_watchdog_id", None))
            self._lnd_after_watchdog_id = None
        except Exception:
            pass
        try:
            self._cancel_after(getattr(self, "_lnd_after_next_tick_id", None))
            self._lnd_after_next_tick_id = None
        except Exception:
            pass
        try:
            self._cancel_after(getattr(self, "_lnd_after_update_ago_id", None))
            self._lnd_after_update_ago_id = None
        except Exception:
            pass
        # Cancel in-flight asyncio future if any
        try:
            fut = getattr(self, "_lnd_poll_future", None)
            if fut and not fut.done():
                fut.cancel()
                try:
                    self.logger.debug("Shutdown: cancelled in-flight LND poll future")
                except Exception:
                    pass
        except Exception:
            pass
        # Clear in-flight flag regardless of future state
        try:
            self._lnd_poll_in_flight = False
        except Exception:
            pass
        # Shutdown poller executor to abort queued tasks
        try:
            if getattr(self, "_poll_executor", None) is not None:
                self._poll_executor.shutdown(wait=False, cancel_futures=True)
                self._poll_executor = None
                try:
                    self.logger.info("Shutdown: LND poller executor shut down")
                except Exception:
                    pass
        except Exception:
            pass
        # Reset in-flight/UI indicators
        try:
            self._lnd_poll_in_flight = False
            self.lnd_poll_inflight_var.set("")
            try:
                self.logger.info("Shutdown: LND poller stopped")
            except Exception:
                pass
        except Exception:
            pass

    def _shutdown_general_timers(self):
        """Cancel general periodic UI timers (non-Lightning)."""
        try:
            self._cancel_after(getattr(self, "_general_after_refresh_id", None))
            self._general_after_refresh_id = None
            try:
                self.logger.info("Shutdown: general UI timers cancelled")
            except Exception:
                pass
        except Exception:
            pass

    def check_lightning_connectivity(self):
        """Run connectivity checks without blocking UI"""
        self.status_var.set(self.translator.get("lightning.ui.checking"))
        future = asyncio.run_coroutine_threadsafe(self._check_lightning_async(), self.loop)
        self._safe_after(100, lambda: self._handle_lightning_result(future))

    async def _check_lightning_async(self):
        host = self.lnd_host_var.get().strip() or "127.0.0.1"
        port = int(self.lnd_port_var.get())
        tls = Path(self.lnd_tls_var.get().strip()) if self.lnd_tls_var.get().strip() else None
        mac = Path(self.lnd_macaroon_var.get().strip()) if self.lnd_macaroon_var.get().strip() else None

        loop = asyncio.get_running_loop()
        def _work():
            return self.lightning_client.check_connectivity(host, port, tls_cert=tls, macaroon_path=mac)
        return await loop.run_in_executor(None, _work)
    def _handle_lightning_result(self, future):
        if getattr(self, "_is_shutting_down", False):
            return
        if future.done():
            try:
                result = future.result()
                pretty = json.dumps(result, indent=2)
                self.lnd_result_text.delete(1.0, tk.END)
                self.lnd_result_text.insert(1.0, pretty)
                self.status_var.set(self.translator.get("lightning.ui.check_done"))
                ok = bool(result.get("getinfo", {}).get("ok"))
                if not ok:
                    # show concise message
                    gi = result.get("getinfo", {})
                    err = gi.get("error") or self.translator.get("lightning.ui.http_status", status=gi.get('status'))
                    messagebox.showwarning(self.translator.get("lightning.ui.title"), self.translator.get("lightning.ui.connectivity_issue", err=err))
            except Exception as e:
                self.status_var.set(self.translator.get("lightning.ui.error_with_message", error=str(e)))
                messagebox.showerror(self.translator.get("lightning.error.title"), str(e))
        else:
            if not getattr(self, "_is_shutting_down", False):
                self._safe_after(100, lambda: self._handle_lightning_result(future))

    def generate_seed(self):
        self.status_var.set(self.translator.get("lightning.wallet.status.generating_seed"))
        future = asyncio.run_coroutine_threadsafe(self._generate_seed_async(), self.loop)
        self._safe_after(100, lambda: self._handle_wallet_result(future, self.translator.get("lightning.wallet.success.seed_generated")))

    async def _generate_seed_async(self):
        host = self.lnd_host_var.get().strip() or "127.0.0.1"
        port = int(self.lnd_port_var.get())
        tls_cert = Path(self.lnd_tls_var.get().strip()) if self.lnd_tls_var.get().strip() else None
        aezeed_passphrase = self.seed_passphrase_var.get().strip() or None

        loop = asyncio.get_running_loop()
        def _work():
            return self.lightning_client.genseed_rest(host, port, tls_cert=tls_cert, aezeed_passphrase=aezeed_passphrase)
        return await loop.run_in_executor(None, _work)

    def init_wallet(self):
        self.status_var.set(self.translator.get("lightning.wallet.status.init_wallet"))
        future = asyncio.run_coroutine_threadsafe(self._init_wallet_async(), self.loop)
        self._safe_after(100, lambda: self._handle_wallet_result(future, self.translator.get("lightning.wallet.success.init_ok")))

    async def _init_wallet_async(self):
        host = self.lnd_host_var.get().strip() or "127.0.0.1"
        port = int(self.lnd_port_var.get())
        tls_cert = Path(self.lnd_tls_var.get().strip()) if self.lnd_tls_var.get().strip() else None
        wallet_password = self.wallet_pass_var.get()
        if not wallet_password:
            raise ValueError(self.translator.get("lightning.wallet.error.password_required"))
        # parse seed words
        raw = self.seed_text.get(1.0, tk.END).strip()
        words = [w for w in raw.replace("\n", " ").split(" ") if w]
        if not words:
            raise ValueError(self.translator.get("lightning.wallet.error.seed_required"))
        recovery_window = int(self.recovery_window_var.get() or 0)

        loop = asyncio.get_running_loop()
        def _work():
            return self.lightning_client.initwallet_rest(
                host,
                port,
                wallet_password=wallet_password,
                cipher_seed_mnemonic=words,
                tls_cert=tls_cert,
                aezeed_passphrase=(self.seed_passphrase_var.get().strip() or None),
                recovery_window=recovery_window,
            )
        return await loop.run_in_executor(None, _work)

    def unlock_wallet(self):
        self.status_var.set(self.translator.get("lightning.wallet.status.unlocking"))
        future = asyncio.run_coroutine_threadsafe(self._unlock_wallet_async(), self.loop)
        self._safe_after(100, lambda: self._handle_wallet_result(future, self.translator.get("lightning.wallet.success.unlock_attempted")))

    async def _unlock_wallet_async(self):
        host = self.lnd_host_var.get().strip() or "127.0.0.1"
        port = int(self.lnd_port_var.get())
        tls_cert = Path(self.lnd_tls_var.get().strip()) if self.lnd_tls_var.get().strip() else None
        wallet_password = self.wallet_pass_var.get()
        if not wallet_password:
            raise ValueError(self.translator.get("lightning.wallet.error.password_required"))

        loop = asyncio.get_running_loop()
        def _work():
            return self.lightning_client.unlockwallet_rest(host, port, wallet_password=wallet_password, tls_cert=tls_cert)
        return await loop.run_in_executor(None, _work)

    def _handle_wallet_result(self, future, success_msg: str):
        if getattr(self, "_is_shutting_down", False):
            return
        if future.done():
            try:
                result = future.result()
                pretty = json.dumps(result, indent=2)
                self.lnd_result_text.delete(1.0, tk.END)
                self.lnd_result_text.insert(1.0, pretty)
                self.status_var.set(success_msg if result.get("ok") else self.translator.get("lightning.common.operation_status", status=result.get('status')))
                if not result.get("ok"):
                    messagebox.showwarning(self.translator.get("lightning.ui.title"), self.translator.get("lightning.common.operation_maybe_failed", status=result.get('status')))
            except Exception as e:
                self.status_var.set(self.translator.get("lightning.wallet.error.with_message", error=str(e)))
                messagebox.showerror(self.translator.get("lightning.wallet.error.title"), str(e))
        else:
            if not getattr(self, "_is_shutting_down", False):
                self._safe_after(100, lambda: self._handle_wallet_result(future, success_msg))

    # Invoice operations
    def create_invoice(self):
        self.status_var.set(self.translator.get("lightning.invoice.status.creating"))
        future = asyncio.run_coroutine_threadsafe(self._create_invoice_async(), self.loop)
        self._safe_after(100, lambda: self._handle_invoice_result(future, self.translator.get("lightning.invoice.success.created")))

    async def _create_invoice_async(self):
        host = self.lnd_host_var.get().strip() or "127.0.0.1"
        port = int(self.lnd_port_var.get())
        tls_cert = Path(self.lnd_tls_var.get().strip()) if self.lnd_tls_var.get().strip() else None
        mac = Path(self.lnd_macaroon_var.get().strip()) if self.lnd_macaroon_var.get().strip() else None
        value = int(self.invoice_amount_var.get() or 0)
        if value <= 0:
            raise ValueError(self.translator.get("lightning.invoice.error.amount_required"))
        memo = self.invoice_memo_var.get().strip() or None
        expiry = int(self.invoice_expiry_var.get() or 0) or None

        loop = asyncio.get_running_loop()
        def _work():
            return self.lightning_client.add_invoice_rest(host, port, value_sat=value, memo=memo, expiry=expiry, tls_cert=tls_cert, macaroon_path=mac)
        return await loop.run_in_executor(None, _work)

    def decode_invoice(self):
        self.status_var.set(self.translator.get("lightning.invoice.status.decoding"))
        future = asyncio.run_coroutine_threadsafe(self._decode_invoice_async(), self.loop)
        self._safe_after(100, lambda: self._handle_invoice_result(future, self.translator.get("lightning.invoice.success.decoded")))

    async def _decode_invoice_async(self):
        host = self.lnd_host_var.get().strip() or "127.0.0.1"
        port = int(self.lnd_port_var.get())
        tls_cert = Path(self.lnd_tls_var.get().strip()) if self.lnd_tls_var.get().strip() else None
        payreq = self.payreq_entry.get().strip()
        if not payreq:
            raise ValueError(self.translator.get("lightning.invoice.error.payreq_required"))
        loop = asyncio.get_running_loop()
        def _work():
            return self.lightning_client.decode_payreq_rest(host, port, pay_req=payreq, tls_cert=tls_cert)
        return await loop.run_in_executor(None, _work)

    def pay_invoice(self):
        self.status_var.set(self.translator.get("lightning.invoice.status.paying"))
        future = asyncio.run_coroutine_threadsafe(self._pay_invoice_async(), self.loop)
        self._safe_after(100, lambda: self._handle_invoice_result(future, self.translator.get("lightning.invoice.success.payment_attempted")))

    async def _pay_invoice_async(self):
        host = self.lnd_host_var.get().strip() or "127.0.0.1"
        port = int(self.lnd_port_var.get())
        tls_cert = Path(self.lnd_tls_var.get().strip()) if self.lnd_tls_var.get().strip() else None
        mac = Path(self.lnd_macaroon_var.get().strip()) if self.lnd_macaroon_var.get().strip() else None
        payreq = self.payreq_entry.get().strip()
        if not payreq:
            raise ValueError(self.translator.get("lightning.invoice.error.payreq_required"))
        loop = asyncio.get_running_loop()
        def _work():
            return self.lightning_client.send_payment_sync_rest(
                host, port, payment_request=payreq, tls_cert=tls_cert, macaroon_path=mac
            )
        return await loop.run_in_executor(None, _work)

    def list_invoices(self):
        self.status_var.set(self.translator.get("lightning.invoice.status.listing"))
        future = asyncio.run_coroutine_threadsafe(self._list_invoices_async(), self.loop)
        self._safe_after(100, lambda: self._handle_invoice_result(future, self.translator.get("lightning.invoice.success.listed")))

    async def _list_invoices_async(self):
        host = self.lnd_host_var.get().strip() or "127.0.0.1"
        port = int(self.lnd_port_var.get())
        tls_cert = Path(self.lnd_tls_var.get().strip()) if self.lnd_tls_var.get().strip() else None
        mac = Path(self.lnd_macaroon_var.get().strip()) if self.lnd_macaroon_var.get().strip() else None
        pending_only = bool(self.pending_only_var.get())
        num_max = int(self.max_invoices_var.get() or 50)
        loop = asyncio.get_running_loop()
        def _work():
            return self.lightning_client.list_invoices_rest(host, port, pending_only=pending_only, num_max_invoices=num_max, tls_cert=tls_cert, macaroon_path=mac)
        return await loop.run_in_executor(None, _work)

    def _handle_invoice_result(self, future, success_msg: str):
        if getattr(self, "_is_shutting_down", False):
            return
        if future.done():
            try:
                result = future.result()
                pretty = json.dumps(result, indent=2)
                self.lnd_result_text.delete(1.0, tk.END)
                self.lnd_result_text.insert(1.0, pretty)
                self.status_var.set(success_msg if result.get("ok") else self.translator.get("lightning.common.operation_status", status=result.get('status')))
                if not result.get("ok"):
                    messagebox.showwarning(self.translator.get("lightning.ui.title"), self.translator.get("lightning.common.operation_maybe_failed", status=result.get('status')))
            except Exception as e:
                self.status_var.set(self.translator.get("lightning.invoice.error.with_message", error=str(e)))
                messagebox.showerror(self.translator.get("lightning.error.title"), str(e))
        else:
            if not getattr(self, "_is_shutting_down", False):
                self._safe_after(100, lambda: self._handle_invoice_result(future, success_msg))

    # Channel operations
    def connect_peer(self):
        self.status_var.set(self.translator.get("lightning.channels.status.connecting_peer"))
        future = asyncio.run_coroutine_threadsafe(self._connect_peer_async(), self.loop)
        self._safe_after(100, lambda: self._handle_invoice_result(future, self.translator.get("lightning.channels.success.connect_attempted")))

    async def _connect_peer_async(self):
        host = self.lnd_host_var.get().strip() or "127.0.0.1"
        port = int(self.lnd_port_var.get())
        tls_cert = Path(self.lnd_tls_var.get().strip()) if self.lnd_tls_var.get().strip() else None
        mac = Path(self.lnd_macaroon_var.get().strip()) if self.lnd_macaroon_var.get().strip() else None
        pubkey = self.peer_pubkey_var.get().strip()
        hostport = self.peer_hostport_var.get().strip()
        if not pubkey or not hostport:
            raise ValueError(self.translator.get("lightning.channels.error.peer_required"))
        perm = bool(self.peer_perm_var.get())
        loop = asyncio.get_running_loop()
        def _work():
            return self.lightning_client.connect_peer_rest(host, port, pubkey=pubkey, hostport=hostport, perm=perm, tls_cert=tls_cert, macaroon_path=mac)
        return await loop.run_in_executor(None, _work)

    def open_channel(self):
        self.status_var.set(self.translator.get("lightning.channels.status.opening"))
        future = asyncio.run_coroutine_threadsafe(self._open_channel_async(), self.loop)
        self._safe_after(100, lambda: self._handle_invoice_result(future, self.translator.get("lightning.channels.success.open_requested")))

    async def _open_channel_async(self):
        host = self.lnd_host_var.get().strip() or "127.0.0.1"
        port = int(self.lnd_port_var.get())
        tls_cert = Path(self.lnd_tls_var.get().strip()) if self.lnd_tls_var.get().strip() else None
        mac = Path(self.lnd_macaroon_var.get().strip()) if self.lnd_macaroon_var.get().strip() else None
        node_pubkey = self.chan_pubkey_var.get().strip()
        amount = int(self.chan_amount_var.get() or 0)
        if not node_pubkey or amount <= 0:
            raise ValueError(self.translator.get("lightning.channels.error.node_and_amount_required"))
        private = bool(self.chan_private_var.get())
        spend_unconf = bool(self.chan_spend_unconf_var.get())
        target_conf = int(self.chan_target_conf_var.get() or 0) or None
        sat_per_vb = int(self.chan_sat_vb_var.get() or 0) or None
        loop = asyncio.get_running_loop()
        def _work():
            return self.lightning_client.open_channel_rest(
                host,
                port,
                node_pubkey=node_pubkey,
                local_funding_amount=amount,
                private=private,
                spend_unconfirmed=spend_unconf,
                target_conf=target_conf,
                sat_per_vbyte=sat_per_vb,
                tls_cert=tls_cert,
                macaroon_path=mac,
            )
        return await loop.run_in_executor(None, _work)

    def close_channel(self):
        self.status_var.set(self.translator.get("lightning.channels.status.closing"))
        future = asyncio.run_coroutine_threadsafe(self._close_channel_async(), self.loop)
        self._safe_after(100, lambda: self._handle_invoice_result(future, self.translator.get("lightning.channels.success.close_requested")))

    async def _close_channel_async(self):
        host = self.lnd_host_var.get().strip() or "127.0.0.1"
        port = int(self.lnd_port_var.get())
        tls_cert = Path(self.lnd_tls_var.get().strip()) if self.lnd_tls_var.get().strip() else None
        mac = Path(self.lnd_macaroon_var.get().strip()) if self.lnd_macaroon_var.get().strip() else None
        txid = self.close_txid_var.get().strip()
        index = int(self.close_index_var.get() or 0)
        if not txid:
            raise ValueError(self.translator.get("lightning.channels.error.funding_txid_required"))
        force = bool(self.close_force_var.get())
        loop = asyncio.get_running_loop()
        def _work():
            return self.lightning_client.close_channel_rest(
                host,
                port,
                funding_txid_str=txid,
                output_index=index,
                force=force,
                tls_cert=tls_cert,
                macaroon_path=mac,
            )
        return await loop.run_in_executor(None, _work)

    def list_channels(self):
        self.status_var.set(self.translator.get("lightning.channels.status.listing"))
        future = asyncio.run_coroutine_threadsafe(self._list_channels_async(), self.loop)
        self._safe_after(100, lambda: self._handle_invoice_result(future, self.translator.get("lightning.channels.success.listed")))

    async def _list_channels_async(self):
        host = self.lnd_host_var.get().strip() or "127.0.0.1"
        port = int(self.lnd_port_var.get())
        tls_cert = Path(self.lnd_tls_var.get().strip()) if self.lnd_tls_var.get().strip() else None
        mac = Path(self.lnd_macaroon_var.get().strip()) if self.lnd_macaroon_var.get().strip() else None
        active_only = bool(self.list_active_only_var.get())
        inactive_only = bool(self.list_inactive_only_var.get())
        public_only = bool(self.list_public_only_var.get())
        private_only = bool(self.list_private_only_var.get())
        peer_filter = self.list_peer_filter_var.get().strip() or None
        loop = asyncio.get_running_loop()
        def _work():
            return self.lightning_client.list_channels_rest(
                host,
                port,
                active_only=active_only,
                inactive_only=inactive_only,
                public_only=public_only,
                private_only=private_only,
                peer=peer_filter,
                tls_cert=tls_cert,
                macaroon_path=mac,
            )
        return await loop.run_in_executor(None, _work)

    def list_pending_channels(self):
        self.status_var.set(self.translator.get("lightning.channels.status.listing_pending"))
        future = asyncio.run_coroutine_threadsafe(self._pending_channels_async(), self.loop)
        self._safe_after(100, lambda: self._handle_invoice_result(future, self.translator.get("lightning.channels.success.pending_listed")))

    async def _pending_channels_async(self):
        host = self.lnd_host_var.get().strip() or "127.0.0.1"
        port = int(self.lnd_port_var.get())
        tls_cert = Path(self.lnd_tls_var.get().strip()) if self.lnd_tls_var.get().strip() else None
        mac = Path(self.lnd_macaroon_var.get().strip()) if self.lnd_macaroon_var.get().strip() else None
        loop = asyncio.get_running_loop()
        def _work():
            return self.lightning_client.pending_channels_rest(host, port, tls_cert=tls_cert, macaroon_path=mac)
        return await loop.run_in_executor(None, _work)

    def _browse_lnd_exe(self):
        filename = filedialog.askopenfilename(
            title=self.translator.get("lightning.file_dialog.lnd_exe_title"),
            filetypes=[
                (self.translator.get("common.filetype.executable"), "*"),
                (self.translator.get("common.filetype.all_files"), "*.*"),
            ],
        )
        if filename:
            self.lnd_exe_var.set(filename)

    def _browse_lnd_dir(self):
        dirname = filedialog.askdirectory(title=self.translator.get("lightning.file_dialog.lnd_dir_title"))
        if dirname:
            self.lnd_dir_var.set(dirname)

    def start_lnd(self):
        self.status_var.set(self.translator.get("lightning.process.status.starting"))
        future = asyncio.run_coroutine_threadsafe(self._start_lnd_async(), self.loop)
        self._safe_after(100, lambda: self._handle_lnd_started(future))

    async def _start_lnd_async(self):
        exe = Path(self.lnd_exe_var.get().strip()) if self.lnd_exe_var.get().strip() else None
        if not exe:
            raise ValueError(self.translator.get("lightning.process.error.exe_required"))
        lnddir = Path(self.lnd_dir_var.get().strip()) if self.lnd_dir_var.get().strip() else None
        host = self.lnd_host_var.get().strip() or "127.0.0.1"
        port = int(self.lnd_port_var.get())
        network = self.lnd_net_var.get().strip() or "mainnet"
        backend = self.lnd_backend_var.get().strip() or "neutrino"
        extra = self.lnd_extra_var.get().strip() or None

        loop = asyncio.get_running_loop()
        def _work():
            return self.lnd_manager.start(exe, lnddir, host, port, network=network, backend=backend, extra_args=extra)
        return await loop.run_in_executor(None, _work)

    def _handle_lnd_started(self, future):
        if future.done():
            try:
                pid = future.result()
                self.status_var.set(self.translator.get("lightning.process.success.started", pid=pid))
                self.lnd_status_var.set(self.translator.get("lightning.status.proc_running"))
            except Exception as e:
                self.status_var.set(self.translator.get("lightning.process.error.start_failed_status", error=str(e)))
                messagebox.showerror(self.translator.get("lightning.process.error.start_failed_title"), str(e))
            finally:
                self._schedule_lnd_status_poll()
        else:
            if not getattr(self, "_is_shutting_down", False):
                self._safe_after(100, lambda: self._handle_lnd_started(future))

    def stop_lnd(self):
        self.status_var.set(self.translator.get("lightning.process.status.stopping"))
        future = asyncio.run_coroutine_threadsafe(self._stop_lnd_async(), self.loop)
        self._safe_after(100, lambda: self._handle_lnd_stopped(future))

    async def _stop_lnd_async(self):
        loop = asyncio.get_running_loop()
        def _work():
            return self.lnd_manager.stop()
        return await loop.run_in_executor(None, _work)

    def _handle_lnd_stopped(self, future):
        if future.done():
            ok = bool(future.result())
            self.status_var.set(self.translator.get("lightning.process.success.stopped") if ok else self.translator.get("lightning.process.error.stop_failed"))
            self.lnd_status_var.set(self.translator.get("lightning.status.proc_stopped") if ok else self.translator.get("lightning.status.proc_unknown"))
        else:
            if not getattr(self, "_is_shutting_down", False):
                self._safe_after(100, lambda: self._handle_lnd_stopped(future))

    
    
    def setup_settings_tab(self):
        """Setup settings tab"""
        # General settings
        self.settings_general_frame = ttk.LabelFrame(self.settings_tab, text=self.translator.get("app.settings.general.title"), padding="10")
        self.settings_general_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Language
        self.lbl_language = ttk.Label(self.settings_general_frame, text=self.translator.get("app.settings.language"))
        self.lbl_language.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.lang_var = tk.StringVar(value=self.config.default_lang)
        lang_combo = ttk.Combobox(self.settings_general_frame, textvariable=self.lang_var, 
                                 values=self.config.supported_langs, width=20)
        lang_combo.grid(row=0, column=1, padx=5, pady=5)
        
        # Cache settings
        self.settings_cache_frame = ttk.LabelFrame(self.settings_tab, text=self.translator.get("app.settings.cache.title"), padding="10")
        self.settings_cache_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.lbl_cache_size = ttk.Label(self.settings_cache_frame, text=self.translator.get("app.settings.cache_size"))
        self.lbl_cache_size.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.cache_size_var = tk.IntVar(value=self.config.cache_size)
        cache_spin = ttk.Spinbox(self.settings_cache_frame, from_=100, to=10000, textvariable=self.cache_size_var, width=20)
        cache_spin.grid(row=0, column=1, padx=5, pady=5)
        
        self.lbl_cache_ttl = ttk.Label(self.settings_cache_frame, text=self.translator.get("app.settings.cache_ttl"))
        self.lbl_cache_ttl.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.cache_ttl_var = tk.IntVar(value=self.config.cache_ttl)
        ttl_spin = ttk.Spinbox(self.settings_cache_frame, from_=60, to=3600, textvariable=self.cache_ttl_var, width=20)
        ttl_spin.grid(row=1, column=1, padx=5, pady=5)
        
        # Performance settings
        self.settings_perf_frame = ttk.LabelFrame(self.settings_tab, text=self.translator.get("app.settings.performance.title"), padding="10")
        self.settings_perf_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.lbl_cpu_alert = ttk.Label(self.settings_perf_frame, text=self.translator.get("app.settings.cpu_alert"))
        self.lbl_cpu_alert.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.cpu_threshold_var = tk.IntVar(value=80)
        cpu_spin = ttk.Spinbox(self.settings_perf_frame, from_=50, to=100, textvariable=self.cpu_threshold_var, width=20)
        cpu_spin.grid(row=0, column=1, padx=5, pady=5)
        
        self.lbl_mem_alert = ttk.Label(self.settings_perf_frame, text=self.translator.get("app.settings.memory_alert"))
        self.lbl_mem_alert.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.mem_threshold_var = tk.IntVar(value=85)
        mem_spin = ttk.Spinbox(self.settings_perf_frame, from_=50, to=100, textvariable=self.mem_threshold_var, width=20)
        mem_spin.grid(row=1, column=1, padx=5, pady=5)
        
        # Save button
        self.btn_save_settings = ttk.Button(self.settings_tab, text=self.translator.get("app.settings.save_button"), 
                  command=self.save_settings)
        self.btn_save_settings.pack(pady=20)
        
        # Info display
        self.settings_info_frame = ttk.LabelFrame(self.settings_tab, text=self.translator.get("app.system_info.title"), padding="10")
        self.settings_info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.info_text = tk.Text(self.settings_info_frame, height=8, wrap=tk.WORD)
        self.info_text.pack(fill=tk.BOTH, expand=True)
        self.display_system_info()
    
    def _run_async_loop(self):
        """Run async event loop in separate thread"""
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_forever()
        finally:
            # Ensure loop resources are cleaned up in the loop's own thread
            try:
                self.logger.info("Shutdown(loop-thread): beginning loop cleanup")
            except Exception:
                pass
            try:
                # Best-effort cancellation of any remaining tasks
                self.loop.run_until_complete(self._graceful_asyncio_shutdown())
                try:
                    self.logger.info("Shutdown(loop-thread): graceful task cancellation completed")
                except Exception:
                    pass
            except Exception:
                pass
            try:
                if hasattr(self.loop, "shutdown_asyncgens"):
                    self.loop.run_until_complete(self.loop.shutdown_asyncgens())
                try:
                    self.logger.info("Shutdown(loop-thread): async generators shutdown completed")
                except Exception:
                    pass
            except Exception:
                pass
            try:
                if hasattr(self.loop, "shutdown_default_executor"):
                    self.loop.run_until_complete(self.loop.shutdown_default_executor())
                try:
                    self.logger.info("Shutdown(loop-thread): default executor shutdown completed")
                except Exception:
                    pass
            except Exception:
                pass
            try:
                self.loop.close()
                try:
                    self.logger.info("Shutdown(loop-thread): loop closed")
                except Exception:
                    pass
            except Exception:
                pass
    
    async def _graceful_asyncio_shutdown(self):
        """Cancel all pending asyncio tasks running on our loop."""
        try:
            tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
            for t in tasks:
                t.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
        except Exception:
            pass
    
    def async_init(self):
        """Initialize async components"""
        future = asyncio.run_coroutine_threadsafe(self._async_init(), self.loop)
        self._safe_after(100, lambda: self._check_future(future))
    
    async def _async_init(self):
        """Async initialization"""
        self.db = Database(self.config.db_path)
        await self.db.connect()
        await self.cache.initialize()
        await self.monitor.start_monitoring()
        return True
    
    def _check_future(self, future):
        """Check if async operation completed"""
        if future.done():
            try:
                result = future.result()
                self.status_var.set(self.translator.get("app.init.success"))
                self.refresh_performance()
            except Exception as e:
                self.status_var.set(self.translator.get("app.common.error_with_message", error=str(e)))
                messagebox.showerror(self.translator.get("app.init.error.title"), str(e))
        else:
            if not getattr(self, "_is_shutting_down", False):
                self._safe_after(100, lambda: self._check_future(future))
    
    def process_input(self):
        """Process input with compression"""
        input_text = self.input_var.get()
        if not input_text:
            messagebox.showwarning(
                self.translator.get("app.common.warning.title"),
                self.translator.get("app.input.warning.enter_data"),
            )
            return
        
        self.status_var.set(self.translator.get("app.processing.status.processing"))
        
        # Process asynchronously
        future = asyncio.run_coroutine_threadsafe(
            self._process_async(input_text, self.compress_var.get()), 
            self.loop
        )
        self._safe_after(100, lambda: self._handle_process_result(future))
    
    async def _process_async(self, input_text, compress):
        """Async processing with compression"""
        # Track performance
        tracker = RequestTracker(self.monitor)
        request_id = f"req_{datetime.now().timestamp()}"
        await tracker.track_request(request_id)
        
        try:
            # Check cache
            cache_key = f"process_{input_text}"
            cached = await self.cache.get(cache_key)
            if cached:
                await tracker.complete_request(request_id, True)
                return {"cached": True, "result": cached}
            
            # Process data
            result = {
                "input": input_text,
                "processed_at": datetime.now().isoformat(),
                "length": len(input_text),
                "words": len(input_text.split())
            }
            
            # Compress if requested
            if compress:
                compressed = self.compressor.compress_json(result)
                result["compressed"] = compressed
                result["compression_ratio"] = f"{self.compressor.stats['compression_ratio']:.1%}"
            
            # Store in cache and database
            await self.cache.set(cache_key, result)
            await self.db.set(f"result_{datetime.now().timestamp()}", result)
            
            await tracker.complete_request(request_id, True)
            return {"cached": False, "result": result}
            
        except Exception as e:
            await tracker.complete_request(request_id, False)
            raise e
    
    def _handle_process_result(self, future):
        """Handle processing result"""
        if getattr(self, "_is_shutting_down", False):
            return
        if future.done():
            try:
                result = future.result()
                output = json.dumps(result, indent=2)
                self.output_text.insert(tk.END, output + "\n\n")
                self.output_text.see(tk.END)
                
                status = (
                    self.translator.get("app.processing.status.cache_hit")
                    if result.get("cached")
                    else self.translator.get("app.processing.status.success")
                )
                self.status_var.set(status)
            except Exception as e:
                self.status_var.set(self.translator.get("app.common.error_with_message", error=str(e)))
                messagebox.showerror(self.translator.get("app.processing.error.title"), str(e))
        else:
            if not getattr(self, "_is_shutting_down", False):
                self._safe_after(100, lambda: self._handle_process_result(future))
    
    def toggle_monitoring(self):
        """Toggle performance monitoring"""
        if self.monitor_var.get():
            asyncio.run_coroutine_threadsafe(
                self.monitor.start_monitoring(), self.loop
            )
            self.status_var.set(self.translator.get("app.monitoring.enabled"))
        else:
            asyncio.run_coroutine_threadsafe(
                self.monitor.stop_monitoring(), self.loop
            )
            self.status_var.set(self.translator.get("app.monitoring.disabled"))
    
    def refresh_performance(self):
        """Refresh performance metrics display"""
        # Clear existing items
        for item in self.metrics_tree.get_children():
            self.metrics_tree.delete(item)
        
        # Get current metrics
        metrics = self.monitor.get_current_metrics()
        
        # Display metrics
        for key, value in metrics.items():
            if isinstance(value, float):
                value_str = f"{value:.2f}"
            else:
                value_str = str(value)
            
            # Determine status
            status = self.translator.get("common.level.ok")
            if "percent" in key:
                if value > 80:
                    status = self.translator.get("common.level.warning")
                if value > 90:
                    status = self.translator.get("common.level.critical")
            
            self.metrics_tree.insert('', tk.END, values=(key, value_str, status))
        
        # Display alerts
        alerts = self.monitor.get_alerts()
        self.alerts_text.delete(1.0, tk.END)
        for alert in alerts[-5:]:  # Show last 5 alerts
            self.alerts_text.insert(tk.END, f"[{alert['level']}] {alert['message']}\n")
    
    def clear_alerts(self):
        """Clear performance alerts"""
        self.monitor.clear_alerts()
        self.alerts_text.delete(1.0, tk.END)
        self.status_var.set(self.translator.get("app.alerts.cleared"))
    
    def create_backup(self):
        """Create a backup"""
        selected_label = self.backup_type_var.get()
        internal_type = getattr(self, 'backup_type_label_to_value', {}).get(selected_label, selected_label)
        # Show localized type in status
        self.status_var.set(self.translator.get("app.backup.status.creating", type=selected_label))
        
        future = asyncio.run_coroutine_threadsafe(
            self.backup_manager.backup(self.config.db_path.parent, internal_type),
            self.loop
        )
        self._safe_after(100, lambda: self._handle_backup_result(future))
    
    def _handle_backup_result(self, future):
        """Handle backup result"""
        if getattr(self, "_is_shutting_down", False):
            return
        if future.done():
            try:
                result = future.result()
                self.status_var.set(self.translator.get("app.backup.status.created", name=result['name']))
                self.refresh_backups()
                messagebox.showinfo(
                    self.translator.get("app.backup.success.title"),
                    self.translator.get("app.backup.success.created", name=result['name']),
                )
            except Exception as e:
                self.status_var.set(self.translator.get("app.backup.status.failed", error=str(e)))
                messagebox.showerror(self.translator.get("app.backup.error.title"), str(e))
        else:
            if not getattr(self, "_is_shutting_down", False):
                self._safe_after(100, lambda: self._handle_backup_result(future))
    
    def restore_backup(self):
        """Restore from backup"""
        selected = self.backup_tree.selection()
        if not selected:
            messagebox.showwarning(
                self.translator.get("app.common.warning.title"),
                self.translator.get("app.backup.warning.select_restore"),
            )
            return
        
        item = self.backup_tree.item(selected[0])
        backup_name = item['values'][0]
        
        if not messagebox.askyesno(
            self.translator.get("app.common.confirm.title"),
            self.translator.get("app.backup.confirm.restore", name=backup_name),
        ):
            return
        
        restore_path = filedialog.askdirectory(title=self.translator.get("app.backup.select_restore_dir.title"))
        if not restore_path:
            return
        
        self.status_var.set(self.translator.get("app.backup.status.restoring", name=backup_name))
        
        future = asyncio.run_coroutine_threadsafe(
            self.backup_manager.restore(backup_name, Path(restore_path)),
            self.loop
        )
        self._safe_after(100, lambda: self._handle_restore_result(future))
    
    def _handle_restore_result(self, future):
        """Handle restore result"""
        if getattr(self, "_is_shutting_down", False):
            return
        if future.done():
            try:
                result = future.result()
                if result:
                    self.status_var.set(self.translator.get("app.backup.status.completed"))
                    messagebox.showinfo(
                        self.translator.get("app.backup.success.title"),
                        self.translator.get("app.backup.success.restored"),
                    )
                else:
                    self.status_var.set(self.translator.get("app.backup.status.failed_simple"))
                    messagebox.showerror(
                        self.translator.get("app.backup.error.restore_failed_title"),
                        self.translator.get("app.backup.error.restore_failed"),
                    )
            except Exception as e:
                self.status_var.set(self.translator.get("app.backup.status.error", error=str(e)))
                messagebox.showerror(self.translator.get("app.backup.error.restore_title"), str(e))
        else:
            if not getattr(self, "_is_shutting_down", False):
                self._safe_after(100, lambda: self._handle_restore_result(future))
    
    def toggle_auto_backup(self):
        """Toggle automatic backup"""
        if self.auto_backup_var.get():
            self.auto_backup = AutoBackupScheduler(self.backup_manager)
            asyncio.run_coroutine_threadsafe(
                self.auto_backup.start(
                    self.config.db_path.parent,
                    full_interval=timedelta(days=7),
                    incremental_interval=timedelta(days=1)
                ),
                self.loop
            )
            self.status_var.set(self.translator.get("app.backup.auto.enabled"))
        else:
            if self.auto_backup:
                asyncio.run_coroutine_threadsafe(
                    self.auto_backup.stop(),
                    self.loop
                )
            self.status_var.set(self.translator.get("app.backup.auto.disabled"))
    
    def refresh_backups(self):
        """Refresh backup list"""
        # Clear existing items
        for item in self.backup_tree.get_children():
            self.backup_tree.delete(item)
        
        # Get backup list
        backups = self.backup_manager.list_backups()
        
        # Display backups
        for backup in backups:
            size_mb = backup['size'] / (1024 * 1024)
            date = datetime.strptime(backup['timestamp'], "%Y%m%d_%H%M%S").strftime("%Y-%m-%d %H:%M")
            status = self.translator.get("app.backup.list.status.verified") if backup.get('checksum') else self.translator.get("app.backup.list.status.unknown")
            # Localize type for display
            display_type = getattr(self, 'backup_type_value_to_label', {}).get(backup['type'], backup['type'])
            
            self.backup_tree.insert('', tk.END, values=(
                backup['name'],
                display_type,
                date,
                f"{size_mb:.2f} {self.translator.get('common.unit.mb')}",
                status
            ))
    
    def save_settings(self):
        """Save application settings"""
        # Update configuration
        self.config.default_lang = self.lang_var.get()
        self.config.cache_size = self.cache_size_var.get()
        self.config.cache_ttl = self.cache_ttl_var.get()

        # Update thresholds
        self.monitor.set_threshold("cpu_percent", self.cpu_threshold_var.get())
        self.monitor.set_threshold("memory_percent", self.mem_threshold_var.get())

        # Persist Lightning settings from UI
        self.config.lnd_rest_host = (self.lnd_host_var.get() or '127.0.0.1').strip()
        try:
            self.config.lnd_rest_port = int(self.lnd_port_var.get())
        except Exception:
            self.config.lnd_rest_port = 8080
        tls_txt = (self.lnd_tls_var.get() or '').strip()
        self.config.lnd_tls_cert = Path(tls_txt) if tls_txt else None
        mac_txt = (self.lnd_macaroon_var.get() or '').strip()
        self.config.lnd_admin_macaroon = Path(mac_txt) if mac_txt else None
        exe_txt = (self.lnd_exe_var.get() or '').strip()
        self.config.lnd_exe = Path(exe_txt) if exe_txt else None
        dir_txt = (self.lnd_dir_var.get() or '').strip()
        self.config.lnd_dir = Path(dir_txt) if dir_txt else None
        self.config.lnd_network = (self.lnd_net_var.get() or 'mainnet').strip()
        self.config.lnd_backend = (self.lnd_backend_var.get() or 'neutrino').strip()
        extra = (self.lnd_extra_var.get() or '').strip()
        self.config.lnd_extra_args = extra or None

        # Apply language change
        self.translator.set_language(self.lang_var.get())
        # Live-refresh UI texts without restart
        try:
            self._refresh_ui_texts()
        except Exception:
            pass

        # Save config to file
        self.config.save()
        
        self.status_var.set(self.translator.get("app.settings.status.saved"))
        messagebox.showinfo(
            self.translator.get("app.settings.success.title"),
            self.translator.get("app.settings.success.saved"),
        )

    def _refresh_ui_texts(self):
        """Refresh translatable UI texts for live language switching.
        Currently updates window title, notebook tab titles, and key tab widgets.
        """
        # Window title
        try:
            self.root.title(self.translator.get("app.name"))
        except Exception:
            pass

        # Notebook tab titles
        try:
            self.notebook.tab(self.main_tab, text=self.translator.get("app.tab.main"))
            self.notebook.tab(self.perf_tab, text=self.translator.get("app.tab.monitor"))
            self.notebook.tab(self.backup_tab, text=self.translator.get("app.tab.backup"))
            self.notebook.tab(self.lightning_tab, text=self.translator.get("lightning.tab"))
            self.notebook.tab(self.settings_tab, text=self.translator.get("app.tab.settings"))
        except Exception:
            pass

        # Main tab
        try:
            self.main_control_frame.config(text=self.translator.get("app.main.controls.title"))
            self.lbl_input.config(text=self.translator.get("app.main.input.title"))
            self.compress_check.config(text=self.translator.get("app.main.compress"))
            self.process_btn.config(text=self.translator.get("app.actions.process"))
            self.output_frame.config(text=self.translator.get("app.main.output.title"))
            self.btn_clear.config(text=self.translator.get("app.actions.clear"))
            self.btn_import.config(text=self.translator.get("app.actions.import"))
            self.btn_export.config(text=self.translator.get("app.actions.export"))
        except Exception:
            pass

        # Performance (Monitor) tab
        try:
            self.monitor_check.config(text=self.translator.get("app.monitor.enable"))
            self.btn_perf_refresh.config(text=self.translator.get("app.common.refresh"))
            self.btn_alerts_clear.config(text=self.translator.get("app.alerts.clear"))
            self.metrics_frame.config(text=self.translator.get("app.monitor.metrics.title"))
            self.alerts_frame.config(text=self.translator.get("app.alerts.title"))
            # Tree headings
            self.metrics_tree.heading('metric', text=self.translator.get("app.monitor.columns.metric"))
            self.metrics_tree.heading('value', text=self.translator.get("app.monitor.columns.value"))
            self.metrics_tree.heading('status', text=self.translator.get("app.monitor.columns.status"))
        except Exception:
            pass

        # Backup tab
        try:
            self.backup_control_frame.config(text=self.translator.get("app.backup.controls.title"))
            self.lbl_backup_type.config(text=self.translator.get("app.backup.label.type"))
            # Rebuild type mappings and update combobox options and selection
            cur_label = self.backup_type_var.get()
            cur_value = None
            try:
                cur_value = self.backup_type_label_to_value.get(cur_label, None)
            except Exception:
                cur_value = None
            self.backup_type_value_to_label = {
                "full": self.translator.get("app.backup.type.full"),
                "incremental": self.translator.get("app.backup.type.incremental"),
            }
            self.backup_type_label_to_value = {v: k for k, v in self.backup_type_value_to_label.items()}
            type_labels = list(self.backup_type_value_to_label.values())
            try:
                self.backup_type_combo.config(values=type_labels)
            except Exception:
                pass
            # Restore selection based on previous value (default to full)
            if not cur_value:
                cur_value = "full"
            self.backup_type_var.set(self.backup_type_value_to_label.get(cur_value, type_labels[0] if type_labels else ""))

            self.btn_backup_create.config(text=self.translator.get("app.backup.button.create"))
            self.btn_backup_restore.config(text=self.translator.get("app.backup.button.restore"))
            self.auto_backup_check.config(text=self.translator.get("app.backup.auto.toggle"))
            self.backup_list_frame.config(text=self.translator.get("app.backup.list.title"))
            # Tree headings
            self.backup_tree.heading('name', text=self.translator.get("app.backup.columns.name"))
            self.backup_tree.heading('type', text=self.translator.get("app.backup.columns.type"))
            self.backup_tree.heading('date', text=self.translator.get("app.backup.columns.date"))
            self.backup_tree.heading('size', text=self.translator.get("app.backup.columns.size"))
            self.backup_tree.heading('status', text=self.translator.get("app.backup.columns.status"))
        except Exception:
            pass

        # Lightning: group frames
        try:
            self.ln_proc_frame.config(text=self.translator.get("lightning.group.process"))
            self.ln_conn_frame.config(text=self.translator.get("lightning.group.connection"))
        except Exception:
            pass

        # Lightning: labels
        try:
            self.lbl_lnd_exe.config(text=self.translator.get("lightning.label.lnd_exe"))
            self.lbl_lnd_dir.config(text=self.translator.get("lightning.label.lnd_dir"))
            self.lbl_network.config(text=self.translator.get("lightning.label.network"))
            self.lbl_backend.config(text=self.translator.get("lightning.label.backend"))
            self.lbl_extra_args.config(text=self.translator.get("lightning.label.extra_args"))
            self.lbl_host.config(text=self.translator.get("lightning.label.host"))
            self.lbl_port.config(text=self.translator.get("lightning.label.port"))
            self.lbl_tls.config(text=self.translator.get("lightning.label.tls"))
            self.lbl_macaroon.config(text=self.translator.get("lightning.label.macaroon"))
        except Exception:
            pass

        # Lightning: buttons
        try:
            self.ln_browse_lnd_exe_btn.config(text=self.translator.get("common.browse"))
            self.ln_browse_lnd_dir_btn.config(text=self.translator.get("common.browse"))
            self.ln_start_btn.config(text=self.translator.get("lightning.button.start"))
            self.ln_stop_btn.config(text=self.translator.get("lightning.button.stop"))
            self.lnd_refresh_btn.config(text=self.translator.get("lightning.button.refresh_now"))
            # Pause/Resume depends on current paused state
            if getattr(self, "_lnd_poll_paused", False):
                self.lnd_poll_pause_btn.config(text=self.translator.get("lightning.button.resume"))
            else:
                self.lnd_poll_pause_btn.config(text=self.translator.get("lightning.button.pause"))
            self.ln_browse_tls_btn.config(text=self.translator.get("common.browse"))
            self.ln_tls_clear_btn.config(text=self.translator.get("app.actions.clear"))
            self.ln_browse_mac_btn.config(text=self.translator.get("common.browse"))
            self.ln_mac_clear_btn.config(text=self.translator.get("app.actions.clear"))
            self.ln_auto_detect_btn.config(text=self.translator.get("lightning.button.auto_detect"))
            self.ln_check_btn.config(text=self.translator.get("lightning.button.check"))
        except Exception:
            pass

        # Lightning: hints
        try:
            self.tls_hint_label.config(text=self.translator.get("lightning.hint.tls_path"))
            self.mac_hint_label.config(text=self.translator.get("lightning.hint.macaroon_path"))
        except Exception:
            pass

        # Lightning poller: some stringvars with static prefixes
        try:
            self.lnd_poll_interval_var.set(self.translator.get("lightning.poll.interval_ms", ms=self._lnd_poll_interval_ms))
            self.lnd_poll_failures_var.set(self.translator.get("lightning.poll.failures", n=self._lnd_poll_consecutive_failures))
            # Do not override dynamic ones like next_in/last_error here
        except Exception:
            pass

        # Settings tab
        try:
            self.settings_general_frame.config(text=self.translator.get("app.settings.general.title"))
            self.lbl_language.config(text=self.translator.get("app.settings.language"))
            self.settings_cache_frame.config(text=self.translator.get("app.settings.cache.title"))
            self.lbl_cache_size.config(text=self.translator.get("app.settings.cache_size"))
            self.lbl_cache_ttl.config(text=self.translator.get("app.settings.cache_ttl"))
            self.settings_perf_frame.config(text=self.translator.get("app.settings.performance.title"))
            self.lbl_cpu_alert.config(text=self.translator.get("app.settings.cpu_alert"))
            self.lbl_mem_alert.config(text=self.translator.get("app.settings.memory_alert"))
            self.btn_save_settings.config(text=self.translator.get("app.settings.save_button"))
            self.settings_info_frame.config(text=self.translator.get("app.system_info.title"))
        except Exception:
            pass
    
    def display_system_info(self):
        """Display system information"""
        import platform
        import psutil
        
        info = f"""System Information:
OS: {platform.system()} {platform.release()}
Python: {platform.python_version()}
CPU: {psutil.cpu_count()} cores
Memory: {psutil.virtual_memory().total / (1024**3):.1f} GB
Disk: {psutil.disk_usage('/').total / (1024**3):.1f} GB

Application:
Version: 1.0.0
Mode: {self.config.mode}
Database: {self.config.db_path}
"""
        self.info_text.delete(1.0, tk.END)
        self.info_text.insert(1.0, info)
    
    def clear_output(self):
        """Clear output text"""
        self.output_text.delete(1.0, tk.END)
        self.input_var.set("")
        self.status_var.set(self.translator.get("app.output.cleared"))
    
    def import_data(self):
        """Import data from file"""
        filename = filedialog.askopenfilename(
            title=self.translator.get("app.files.import.title"),
            filetypes=[
                (self.translator.get("common.filetype.json_files"), "*.json"),
                (self.translator.get("common.filetype.all_files"), "*.*"),
            ],
        )
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self.output_text.insert(tk.END, json.dumps(data, indent=2) + "\n\n")
                self.status_var.set(self.translator.get("app.files.import.status.imported", name=Path(filename).name))
            except Exception as e:
                messagebox.showerror(self.translator.get("app.files.import.error.title"), str(e))
    
    def export_data(self):
        """Export data to file"""
        content = self.output_text.get(1.0, tk.END).strip()
        if not content:
            messagebox.showwarning(
                self.translator.get("app.common.warning.title"),
                self.translator.get("app.export.warning.no_data"),
            )
            return
        
        filename = filedialog.asksaveasfilename(
            title=self.translator.get("app.export.title"),
            defaultextension=".json",
            filetypes=[
                (self.translator.get("common.filetype.json_files"), "*.json"),
                (self.translator.get("common.filetype.text_files"), "*.txt"),
                (self.translator.get("common.filetype.all_files"), "*.*"),
            ],
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.status_var.set(self.translator.get("app.export.status.exported", name=Path(filename).name))
                messagebox.showinfo(
                    self.translator.get("app.export.success.title"),
                    self.translator.get("app.export.success.message", filename=filename),
                )
            except Exception as e:
                messagebox.showerror(self.translator.get("app.export.error.title"), str(e))
    
    def quit(self):
        """Quit application"""
        if messagebox.askokcancel(
            self.translator.get("app.quit.confirm.title"),
            self.translator.get("app.quit.confirm.message"),
        ):
            # Mark shutdown and cancel timers first
            try:
                self._is_shutting_down = True
                try:
                    self._shutting_down_started_at = datetime.now()
                    self.logger.info("Shutdown: begin quit sequence")
                except Exception:
                    pass
            except Exception:
                pass
            # Bulk cancel any remaining scheduled tkinter callbacks
            try:
                self._cancel_all_afters()
            except Exception:
                pass
            try:
                self._shutdown_lnd_poller()
            except Exception:
                pass
            try:
                self._shutdown_general_timers()
            except Exception:
                pass

            # Stop system tray if available (duck-typed: supports SystemTray.stop())
            try:
                if getattr(self, "tray", None) and hasattr(self.tray, "stop"):
                    self.tray.stop()
                try:
                    self.logger.info("Shutdown: tray stop invoked")
                except Exception:
                    pass
            except Exception:
                pass

            # Stop async services and wait briefly for completion
            futs = []
            try:
                futs.append(asyncio.run_coroutine_threadsafe(self.monitor.stop_monitoring(), self.loop))
            except Exception:
                pass
            try:
                if self.auto_backup:
                    futs.append(asyncio.run_coroutine_threadsafe(self.auto_backup.stop(), self.loop))
            except Exception:
                pass
            try:
                if getattr(self, "cache", None):
                    futs.append(asyncio.run_coroutine_threadsafe(self.cache.stop(), self.loop))
            except Exception:
                pass
            try:
                if self.db:
                    futs.append(asyncio.run_coroutine_threadsafe(self.db.disconnect(), self.loop))
            except Exception:
                pass
            for f in futs:
                try:
                    f.result(timeout=2.0)
                except Exception:
                    pass
            try:
                self.logger.info("Shutdown: async services stopped")
            except Exception:
                pass

            # Cancel remaining asyncio tasks gracefully
            try:
                asyncio.run_coroutine_threadsafe(self._graceful_asyncio_shutdown(), self.loop).result(timeout=3.0)
                try:
                    self.logger.info("Shutdown: graceful asyncio cancellation requested from main thread")
                except Exception:
                    pass
            except Exception:
                pass

            # Explicitly shutdown the loop's default ThreadPoolExecutor
            try:
                if hasattr(self.loop, "shutdown_default_executor"):
                    asyncio.run_coroutine_threadsafe(self.loop.shutdown_default_executor(), self.loop).result(timeout=3.0)
                try:
                    self.logger.info("Shutdown: default executor shutdown requested from main thread")
                except Exception:
                    pass
            except Exception:
                pass

            # Stop loop and join thread
            try:
                self.loop.call_soon_threadsafe(self.loop.stop)
                try:
                    self.logger.info("Shutdown: loop.stop() signalled")
                except Exception:
                    pass
            except Exception:
                pass
            try:
                if getattr(self, "thread", None):
                    self.thread.join(timeout=5.0)
                    try:
                        self.logger.info("Shutdown: loop thread join attempted (<=5s)")
                    except Exception:
                        pass
            except Exception:
                pass

            # Destroy UI last
            try:
                self.root.destroy()
                try:
                    dur = None
                    try:
                        if getattr(self, "_shutting_down_started_at", None):
                            dur = (datetime.now() - self._shutting_down_started_at).total_seconds()
                    except Exception:
                        dur = None
                    if dur is not None:
                        self.logger.info("Shutdown: UI destroyed; total quit duration %.3fs", dur)
                    else:
                        self.logger.info("Shutdown: UI destroyed")
                except Exception:
                    pass
            except Exception:
                pass
    
    def run(self):
        """Run the application"""
        self.root.protocol("WM_DELETE_WINDOW", self.quit)
        
        # Start performance refresh timer
        self.refresh_timer()
        
        self.root.mainloop()
    
    def refresh_timer(self):
        """Timer to refresh performance metrics"""
        if getattr(self, "_is_shutting_down", False):
            return
        if self.monitor_var.get():
            self.refresh_performance()
        
        # Schedule next refresh and keep ID for cancellation
        try:
            self._general_after_refresh_id = self._safe_after(2000, self.refresh_timer)  # Every 2 seconds
        except Exception:
            pass

def main():
    """Main entry point for desktop app"""
    setup_logging("INFO")
    app = BLRCSDesktopApp()
    app.run()

if __name__ == "__main__":
    main()
