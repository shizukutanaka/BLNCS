# BLRCS Unified Application
# Single entry point for all modes
import sys
import asyncio
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
import json
import time
import threading
from typing import Optional, Dict, Any
from datetime import datetime

# Performance optimization on import
import gc
gc.set_threshold(700, 10, 10)
sys.setrecursionlimit(3000)

from blrcs.config import get_config
from blrcs.database import Database
from blrcs.cache import Cache
from blrcs.logger import setup_logging, get_logger
from blrcs.compression import Compressor, CompressionType
from blrcs.backup import BackupManager
from blrcs.monitoring import PerformanceMonitor
from blrcs.i18n import Translator
from blrcs.security import SecurityManager, SecurityLevel
from blrcs.ux_stability_enhancements import ux_optimizer, track_response_time

class BLRCS:
    """Unified BLRCS Application"""
    
    def __init__(self, mode: str = "auto"):
        """
        Initialize BLRCS
        Args:
            mode: "gui", "cli", "server", or "auto" (detect best mode)
        """
        self.mode = mode
        self.config = get_config()
        self.logger = get_logger(__name__)
        self.db = None
        self.cache = Cache()
        self.compressor = Compressor(CompressionType.AUTO)
        self.backup_manager = BackupManager(Path("backups"))
        self.monitor = PerformanceMonitor()
        self.translator = Translator(self.config.default_lang)
        self.security = SecurityManager(SecurityLevel.HIGH)
        self.ux_optimizer = ux_optimizer
        
        # GUI components
        self.root = None
        self.widgets = {}
        
        # Async components
        self.loop = None
        self.thread = None
        self._is_shutting_down = False
        # Track tkinter after() callbacks for cancellation on shutdown
        self._after_ids = set()
        
        # Initialize based on mode
        if mode == "auto":
            self.mode = self._detect_mode()
        
        setup_logging(self.config.log_level, self.config.log_file)
    
    def _detect_mode(self) -> str:
        """Detect best mode based on environment"""
        if sys.stdin.isatty() and sys.stdout.isatty():
            try:
                # Try to create a test window
                test = tk.Tk()
                test.withdraw()
                test.destroy()
                return "gui"
            except:
                return "cli"
        return "server"
    
    def run(self):
        """Run application in detected/specified mode"""
        if self.mode == "gui":
            self._run_gui()
        elif self.mode == "cli":
            self._run_cli()
        elif self.mode == "server":
            self._run_server()
        else:
            self.logger.error(f"Unknown mode: {self.mode}")
    
    def _run_gui(self):
        """Run GUI mode"""
        self.root = tk.Tk()
        self.root.title(self.translator.get("app.name"))
        self.root.geometry("800x600")
        
        # Setup async event loop in thread
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run_async_loop, daemon=True)
        self.thread.start()
        
        # Initialize components
        asyncio.run_coroutine_threadsafe(self._init_async(), self.loop)
        
        # Build GUI
        self._build_gui()
        
        # Run main loop
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _safe_after(self, ms: int, func):
        """Schedule a tkinter after() callback only if not shutting down.
        Tracks the callback id for later cancellation and removes it when executed.
        """
        if getattr(self, "_is_shutting_down", False) or not self.root:
            return None

        af_id = None

        def wrapped():
            # Remove id from tracking when it fires
            if af_id is not None:
                self._after_ids.discard(af_id)
            # Do not execute during shutdown
            if getattr(self, "_is_shutting_down", False):
                return
            try:
                func()
            except Exception:
                # GUI callbacks should never raise
                try:
                    self.logger.exception("GUI after() callback raised")
                except Exception:
                    pass

        try:
            af_id = self.root.after(ms, wrapped)
            self._after_ids.add(af_id)
            return af_id
        except Exception:
            return None

    def _cancel_all_afters(self):
        """Cancel all pending tkinter after() callbacks safely."""
        if not self.root:
            self._after_ids.clear()
            return
        for af_id in list(self._after_ids):
            try:
                self.root.after_cancel(af_id)
            except Exception:
                pass
            finally:
                self._after_ids.discard(af_id)
    
    def _run_cli(self):
        """Run CLI mode"""
        print(self.translator.get("app.cli.title"))
        print("-" * 40)
        
        # Run async initialization
        asyncio.run(self._init_async())
        
        while True:
            try:
                cmd = input(self.translator.get("app.cli.prompt")).strip().lower()
                if cmd == "exit":
                    break
                elif cmd == "help":
                    self._print_help()
                elif cmd == "status":
                    self._print_status()
                elif cmd == "process":
                    data = input(self.translator.get("app.cli.process.data_prompt"))
                    result = asyncio.run(self._process_data(data))
                    print(self.translator.get("app.cli.process.result", result=result))
                elif cmd == "backup":
                    asyncio.run(self._create_backup())
                    print(self.translator.get("app.cli.backup.created"))
                else:
                    print(self.translator.get("app.cli.unknown_command", cmd=cmd))
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(self.translator.get("app.cli.error", error=str(e)))
        
        # Cleanup
        asyncio.run(self._cleanup())
    
    def _run_server(self):
        """Run server mode"""
        import uvicorn
        from fastapi import FastAPI, Request, HTTPException, Depends
        from fastapi.responses import JSONResponse
        from fastapi.middleware.cors import CORSMiddleware
        from starlette.middleware.base import BaseHTTPMiddleware
        
        app = FastAPI(title="BLRCS", docs_url=None, redoc_url=None)
        
        # Security middleware
        security_mgr = self.security
        
        class SecurityMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request, call_next):
                # Check IP blocking
                client_ip = request.client.host
                if security_mgr.is_ip_blocked(client_ip):
                    return JSONResponse(status_code=403, content={"error": "Forbidden"})
                
                # Process request
                response = await call_next(request)
                
                # Add enhanced security headers
                security_headers = {
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "X-XSS-Protection": "1; mode=block",
                    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
                    "Referrer-Policy": "strict-origin-when-cross-origin",
                    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
                    "X-Permitted-Cross-Domain-Policies": "none",
                    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"
                }
                
                for header, value in security_headers.items():
                    response.headers[header] = value
                    
                # Add custom security headers from manager
                for header, value in security_mgr.get_security_headers().items():
                    response.headers[header] = value
                
                return response
        
        app.add_middleware(SecurityMiddleware)
        
        # Dynamic CORS middleware - configurable origins
        # 動的CORS設定 - 環境別対応
        default_origins = f"http://localhost:{os.getenv('BLRCS_PORT', 3000)},http://127.0.0.1:{os.getenv('BLRCS_PORT', 3000)}"
        cors_origins = os.getenv("BLRCS_CORS_ORIGINS", default_origins)
        allowed_origins = [origin.strip() for origin in cors_origins.split(",") if origin.strip()]
        
        app.add_middleware(
            CORSMiddleware,
            allow_origins=allowed_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
            max_age=600,
        )
        
        @app.on_event("startup")
        async def startup():
            await self._init_async()
            await self.monitor.start_monitoring()
            # Start security cleanup task
            asyncio.create_task(self.security.periodic_cleanup())
        
        @app.on_event("shutdown")
        async def shutdown():
            await self._cleanup()
        
        @app.get("/")
        async def root():
            return {"name": "BLRCS", "version": "1.0.0", "status": "running"}
        
        @app.get("/health")
        async def health():
            return {
                "status": "healthy",
                "database": await self.db.health_check() if self.db else False,
                "cache": self.cache.health_check()
            }
        
        @app.post("/process")
        async def process(request: Request):
            # Rate limiting
            client_ip = request.client.host
            if not self.security.check_rate_limit(client_ip):
                raise HTTPException(status_code=429, detail="Rate limit exceeded")
            
            try:
                data = await request.json()
                
                # Validate input
                if isinstance(data, str):
                    data = self.security.sanitize_input(data)
                
                result = await self._process_data(data)
                
                # Compress response if large
                response_data = {"success": True, "result": result}
                if len(str(response_data)) > 1024:  # Compress responses > 1KB
                    compressed_result = self.compressor.compress_json(result)
                    response_data = {
                        "success": True, 
                        "result": compressed_result,
                        "compressed": True
                    }
                
                return JSONResponse(response_data)
            except Exception as e:
                self.logger.error(f"Process error: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        # Run server
        uvicorn.run(app, host=self.config.host, port=self.config.port)
    
    def _build_gui(self):
        """Build GUI interface"""
        # Notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Main tab
        main_frame = ttk.Frame(notebook)
        notebook.add(main_frame, text=self.translator.get("app.tab.main"))
        self._build_main_tab(main_frame)
        
        # Monitor tab
        monitor_frame = ttk.Frame(notebook)
        notebook.add(monitor_frame, text=self.translator.get("app.tab.monitor"))
        self._build_monitor_tab(monitor_frame)
        
        # Settings tab
        settings_frame = ttk.Frame(notebook)
        notebook.add(settings_frame, text=self.translator.get("app.tab.settings"))
        self._build_settings_tab(settings_frame)
        
        # Status bar
        self.widgets['status'] = tk.StringVar(value=self.translator.get("app.common.ready"))
        status_bar = ttk.Label(self.root, textvariable=self.widgets['status'], relief=tk.SUNKEN)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def _build_main_tab(self, parent):
        """Build main processing tab"""
        # Input
        input_frame = ttk.LabelFrame(parent, text=self.translator.get("app.main.input.title"), padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.widgets['input'] = tk.StringVar()
        entry = ttk.Entry(input_frame, textvariable=self.widgets['input'], width=50)
        entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(input_frame, text=self.translator.get("app.actions.process"), command=self._gui_process).pack(side=tk.LEFT, padx=5)
        ttk.Button(input_frame, text=self.translator.get("app.actions.clear"), command=self._gui_clear).pack(side=tk.LEFT, padx=5)
        
        # Output
        output_frame = ttk.LabelFrame(parent, text=self.translator.get("app.main.output.title"), padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.widgets['output'] = tk.Text(output_frame, wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(output_frame, command=self.widgets['output'].yview)
        self.widgets['output'].config(yscrollcommand=scrollbar.set)
        
        self.widgets['output'].pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Actions
        action_frame = ttk.Frame(parent)
        action_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(action_frame, text=self.translator.get("app.actions.import"), command=self._gui_import).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text=self.translator.get("app.actions.export"), command=self._gui_export).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text=self.translator.get("app.actions.backup"), command=self._gui_backup).pack(side=tk.LEFT, padx=5)
    
    def _build_monitor_tab(self, parent):
        """Build performance monitor tab"""
        # Controls
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.widgets['monitor_enabled'] = tk.BooleanVar(value=False)
        ttk.Checkbutton(control_frame, text=self.translator.get("app.monitor.enable"), 
                       variable=self.widgets['monitor_enabled'],
                       command=self._toggle_monitoring).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(control_frame, text=self.translator.get("app.common.refresh"), command=self._refresh_monitor).pack(side=tk.LEFT, padx=5)
        
        # Metrics
        metrics_frame = ttk.LabelFrame(parent, text=self.translator.get("app.monitor.metrics.title"), padding=10)
        metrics_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        columns = ('Metric', 'Value', 'Status')
        self.widgets['metrics_tree'] = ttk.Treeview(metrics_frame, columns=columns, show='headings')
        
        for col in columns:
            heading_text = {
                'Metric': self.translator.get('app.monitor.columns.metric'),
                'Value': self.translator.get('app.monitor.columns.value'),
                'Status': self.translator.get('app.monitor.columns.status')
            }[col]
            self.widgets['metrics_tree'].heading(col, text=heading_text)
            self.widgets['metrics_tree'].column(col, width=150)
        
        self.widgets['metrics_tree'].pack(fill=tk.BOTH, expand=True)
    
    def _build_settings_tab(self, parent):
        """Build settings tab"""
        settings_frame = ttk.LabelFrame(parent, text=self.translator.get("app.settings.config.title"), padding=10)
        settings_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Cache settings
        ttk.Label(settings_frame, text=self.translator.get("app.settings.cache_size")).grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.widgets['cache_size'] = tk.IntVar(value=self.config.cache_size)
        ttk.Spinbox(settings_frame, from_=100, to=10000, 
                   textvariable=self.widgets['cache_size'], width=20).grid(row=0, column=1, padx=5, pady=5)
        
        # Log level
        ttk.Label(settings_frame, text=self.translator.get("app.settings.log_level")).grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.widgets['log_level'] = tk.StringVar(value=self.config.log_level)
        ttk.Combobox(settings_frame, textvariable=self.widgets['log_level'],
                    values=["DEBUG", "INFO", "WARNING", "ERROR"], width=18).grid(row=1, column=1, padx=5, pady=5)
        
        # Save button
        ttk.Button(settings_frame, text=self.translator.get("app.settings.save_button"), 
                  command=self._save_settings).grid(row=2, column=0, columnspan=2, pady=10)
        
        # Info
        info_frame = ttk.LabelFrame(parent, text=self.translator.get("app.system_info.title"), padding=10)
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.widgets['info'] = tk.Text(info_frame, height=10, wrap=tk.WORD)
        self.widgets['info'].pack(fill=tk.BOTH, expand=True)
        self._update_info()
    
    async def _init_async(self):
        """Initialize async components"""
        self.db = Database(self.config.db_path)
        await self.db.connect()
        await self.cache.initialize()
        await self.monitor.start_monitoring()
    
    async def _cleanup(self):
        """Cleanup async components"""
        if self.monitor:
            await self.monitor.stop_monitoring()
        # Stop cache background cleanup task
        if self.cache:
            try:
                await self.cache.stop()
            except Exception:
                pass
        if self.db:
            await self.db.disconnect()
    
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
    
    async def _process_data(self, data: Any) -> Dict[str, Any]:
        """Process data with caching and compression"""
        # Check cache
        cache_key = str(data)
        cached = await self.cache.get(cache_key)
        if cached:
            return {"cached": True, "result": cached}
        
        # Process
        result = {
            "input": data,
            "processed_at": datetime.now().isoformat(),
            "compressed": None
        }
        
        # Compress if beneficial
        if isinstance(data, (str, dict, list)):
            compressed = self.compressor.compress_json(data)
            if len(compressed) < len(str(data)):
                result["compressed"] = compressed
        
        # Store in cache and database
        await self.cache.set(cache_key, result)
        await self.db.set(f"result_{time.time()}", result)
        
        return {"cached": False, "result": result}
    
    async def _create_backup(self):
        """Create backup"""
        return await self.backup_manager.backup(self.config.db_path.parent, "full")
    
    def _run_async_loop(self):
        """Run async event loop in thread"""
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_forever()
        finally:
            # Ensure loop resources are cleaned up in the loop's own thread
            try:
                self.loop.run_until_complete(self._graceful_asyncio_shutdown())
            except Exception:
                pass
            try:
                if hasattr(self.loop, "shutdown_asyncgens"):
                    self.loop.run_until_complete(self.loop.shutdown_asyncgens())
            except Exception:
                pass
            try:
                if hasattr(self.loop, "shutdown_default_executor"):
                    self.loop.run_until_complete(self.loop.shutdown_default_executor())
            except Exception:
                pass
            try:
                self.loop.close()
            except Exception:
                pass
    
    def _gui_process(self):
        """Process input (GUI)"""
        data = self.widgets['input'].get()
        if not data:
            messagebox.showwarning(self.translator.get("app.common.warning.title"), self.translator.get("app.input.warning.enter_data"))
            return
        
        self.widgets['status'].set(self.translator.get("app.processing.status.processing"))
        
        future = asyncio.run_coroutine_threadsafe(
            self._process_data(data), self.loop
        )
        
        def callback():
            try:
                result = future.result(timeout=0.1)
                output = json.dumps(result, indent=2)
                self.widgets['output'].insert(tk.END, output + "\n\n")
                self.widgets['output'].see(tk.END)
                self.widgets['status'].set(self.translator.get("app.common.ready"))
            except:
                if not getattr(self, "_is_shutting_down", False):
                    self._safe_after(100, callback)
        
        self._safe_after(100, callback)
    
    def _gui_clear(self):
        """Clear GUI fields"""
        self.widgets['input'].set("")
        self.widgets['output'].delete(1.0, tk.END)
        self.widgets['status'].set(self.translator.get("app.output.cleared"))
    
    def _gui_import(self):
        """Import data from file"""
        filename = filedialog.askopenfilename(
            title=self.translator.get("app.files.import.title"),
            filetypes=[
                (self.translator.get("common.filetype.json_files"), "*.json"),
                (self.translator.get("common.filetype.all_files"), "*.*")
            ]
        )
        if filename:
            try:
                with open(filename, 'r') as f:
                    data = json.load(f)
                self.widgets['output'].insert(tk.END, json.dumps(data, indent=2) + "\n\n")
                self.widgets['status'].set(self.translator.get("app.files.import.status.imported", name=Path(filename).name))
            except Exception as e:
                messagebox.showerror(self.translator.get("app.files.import.error.title"), self.translator.get("app.common.error_with_message", error=str(e)))
    
    def _gui_export(self):
        """Export data to file"""
        content = self.widgets['output'].get(1.0, tk.END).strip()
        if not content:
            messagebox.showwarning(self.translator.get("app.common.warning.title"), self.translator.get("app.export.warning.no_data"))
            return
        
        filename = filedialog.asksaveasfilename(
            title=self.translator.get("app.export.select_file.title"),
            defaultextension=".json",
            filetypes=[
                (self.translator.get("common.filetype.json_files"), "*.json"),
                (self.translator.get("common.filetype.text_files"), "*.txt")
            ]
        )
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(content)
                self.widgets['status'].set(self.translator.get("app.export.status.exported", name=Path(filename).name))
            except Exception as e:
                messagebox.showerror(self.translator.get("app.export.error.title"), self.translator.get("app.common.error_with_message", error=str(e)))
    
    def _gui_backup(self):
        """Create backup (GUI)"""
        self.widgets['status'].set(self.translator.get("app.backup.status.creating", type=self.translator.get("app.backup.type.full")))
        
        future = asyncio.run_coroutine_threadsafe(
            self._create_backup(), self.loop
        )
        
        def callback():
            try:
                result = future.result(timeout=0.1)
                self.widgets['status'].set(self.translator.get("app.backup.status.created", name=result['name']))
                messagebox.showinfo(self.translator.get("app.backup.success.title"), self.translator.get("app.backup.success.created", name=result['name']))
            except:
                if not getattr(self, "_is_shutting_down", False):
                    self._safe_after(100, callback)
        
        self._safe_after(100, callback)
    
    def _toggle_monitoring(self):
        """Toggle performance monitoring"""
        if self.widgets['monitor_enabled'].get():
            asyncio.run_coroutine_threadsafe(
                self.monitor.start_monitoring(), self.loop
            )
        else:
            asyncio.run_coroutine_threadsafe(
                self.monitor.stop_monitoring(), self.loop
            )
    
    def _refresh_monitor(self):
        """Refresh monitor display"""
        tree = self.widgets['metrics_tree']
        
        # Clear existing
        for item in tree.get_children():
            tree.delete(item)
        
        # Get metrics
        metrics = self.monitor.get_current_metrics()
        
        # Display
        for key, value in metrics.items():
            if isinstance(value, float):
                value_str = f"{value:.2f}"
            else:
                value_str = str(value)
            
            status_key = 'common.level.ok'
            if "percent" in key and isinstance(value, (int, float)):
                if value > 90:
                    status_key = 'common.level.critical'
                elif value > 80:
                    status_key = 'common.level.warning'
            
            status_text = self.translator.get(status_key)
            tree.insert('', tk.END, values=(key, value_str, status_text))
    
    def _save_settings(self):
        """Save settings"""
        self.config.cache_size = self.widgets['cache_size'].get()
        self.config.log_level = self.widgets['log_level'].get()
        self.config.save()
        
        self.widgets['status'].set(self.translator.get("app.settings.status.saved"))
        messagebox.showinfo(self.translator.get("app.settings.success.title"), self.translator.get("app.settings.success.saved"))
    
    def _update_info(self):
        """Update system info display"""
        import platform
        import psutil
        
        mem_gb = psutil.virtual_memory().total / (1024**3)
        disk_gb = psutil.disk_usage('/').total / (1024**3)

        lines = [
            f"{self.translator.get('app.system_info.title')}:",
            self.translator.get("app.system_info.os", system=platform.system(), release=platform.release()),
            self.translator.get("app.system_info.python", version=platform.python_version()),
            self.translator.get("app.system_info.cpu_cores", cores=psutil.cpu_count()),
            self.translator.get("app.system_info.memory_total_gb", gb=f"{mem_gb:.1f}"),
            self.translator.get("app.system_info.disk_total_gb", gb=f"{disk_gb:.1f}"),
            "",
            self.translator.get("app.system_info.application.title"),
            self.translator.get("app.system_info.mode", mode=self.mode),
            self.translator.get("app.system_info.database", path=str(self.config.db_path)),
            self.translator.get("app.system_info.cache_size", size=str(self.config.cache_size)),
        ]
        info = "\n".join(lines)
        if self.widgets.get('info'):
            self.widgets['info'].delete(1.0, tk.END)
            self.widgets['info'].insert(1.0, info)
    
    def _print_help(self):
        """Print CLI help"""
        lines = [
            self.translator.get("app.cli.help.title"),
            f"  help    - {self.translator.get('app.cli.help.help')}",
            f"  status  - {self.translator.get('app.cli.help.status')}",
            f"  process - {self.translator.get('app.cli.help.process')}",
            f"  backup  - {self.translator.get('app.cli.help.backup')}",
            f"  exit    - {self.translator.get('app.cli.help.exit')}",
        ]
        print("\n".join(lines))
    
    def _print_status(self):
        """Print status"""
        db_status = self.translator.get("common.status.connected") if self.db else self.translator.get("common.status.disconnected")
        print(self.translator.get("app.cli.status.database", status=db_status))
        print(self.translator.get("app.cli.status.cache", stats=str(self.cache.get_stats())))
        print(self.translator.get("app.cli.status.monitor", metrics=str(self.monitor.get_current_metrics())))
    
    def _on_close(self):
        """Handle window close"""
        if messagebox.askokcancel(self.translator.get("app.quit.confirm.title"), self.translator.get("app.quit.confirm.message", app=self.translator.get("app.name"))):
            self._is_shutting_down = True
            # Cancel any scheduled tkinter callbacks to avoid UI work during shutdown
            try:
                self._cancel_all_afters()
            except Exception:
                pass
            # Request async cleanup and wait briefly
            try:
                asyncio.run_coroutine_threadsafe(self._cleanup(), self.loop).result(timeout=3.0)
            except Exception:
                pass
            # Ask loop to cancel any remaining tasks gracefully
            try:
                asyncio.run_coroutine_threadsafe(self._graceful_asyncio_shutdown(), self.loop).result(timeout=3.0)
            except Exception:
                pass
            # Shutdown the default executor if available
            try:
                if hasattr(self.loop, "shutdown_default_executor"):
                    asyncio.run_coroutine_threadsafe(self.loop.shutdown_default_executor(), self.loop).result(timeout=3.0)
            except Exception:
                pass
            # Stop loop and join thread
            try:
                self.loop.call_soon_threadsafe(self.loop.stop)
            except Exception:
                pass
            try:
                if self.thread:
                    self.thread.join(timeout=5.0)
            except Exception:
                pass
            # Destroy UI last
            try:
                self.root.destroy()
            except Exception:
                pass

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="BLRCS Application")
    parser.add_argument("--mode", choices=["gui", "cli", "server", "auto"], 
                       default="auto", help="Application mode")
    args = parser.parse_args()
    
    app = BLRCS(mode=args.mode)
    app.run()

if __name__ == "__main__":
    main()
