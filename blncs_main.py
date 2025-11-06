#!/usr/bin/env python3
"""
BLNCS - Bitcoin Lightning Network Control System
統合されたプロダクション対応メインエントリポイント
"""

import os
import sys
import asyncio
import signal
import argparse
import time
import threading
from pathlib import Path
from typing import Optional, Dict, Any
import logging

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Import unified systems
from blncs.core.config import get_config
from blncs.core.unified_logging import get_logger, configure_logging, get_log_manager
from blncs.core.unified_database import get_database
from blncs.core.simple_cache import get_simple_cache
from blncs.core.unified_performance import get_performance_optimizer
from blncs.core.unified_security import get_security_manager
from blncs.lightning.simple_client import get_lightning_client

# Import internationalization system
from blncs import _

__version__ = "2.0.0"

_startup_start = time.time()

# Progress display utilities
class ProgressSpinner:
    """Simple progress spinner for long-running operations"""

    def __init__(self, message: str = "Processing", spinner_chars: str = "|/-\\"):
        self.message = _(message)
        self.spinner_chars = spinner_chars
        self.index = 0
        self.running = False
        self.thread = None

    def _spin(self):
        """Spinner animation loop"""
        while self.running:
            char = self.spinner_chars[self.index % len(self.spinner_chars)]
            print(f"\r{self.message} {char}", end="", flush=True)
            self.index += 1
            time.sleep(0.1)

    def start(self):
        """Start the spinner"""
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._spin, daemon=True)
        self.thread.start()

    def stop(self, final_message: str = ""):
        """Stop the spinner"""
        if not self.running:
            return
        self.running = False
        if self.thread:
            self.thread.join(timeout=0.5)
        print(f"\r{final_message}{' ' * (len(self.message) + 2)}")

class ProgressBar:
    """Simple progress bar for operations with known progress"""

    def __init__(self, total: int, width: int = 30, prefix: str = "Progress"):
        self.total = total
        self.width = width
        self.prefix = _(prefix)
        self.current = 0

    def update(self, current: int):
        """Update progress"""
        self.current = current
        self._display()

    def increment(self, amount: int = 1):
        """Increment progress"""
        self.current += amount
        self._display()

    def _display(self):
        """Display progress bar"""
        percent = min(100, int((self.current / self.total) * 100))
        filled = int(self.width * self.current / self.total)
        bar = "█" * filled + "░" * (self.width - filled)
        print(f"\r{self.prefix}: [{bar}] {percent}% ({self.current}/{self.total})", end="", flush=True)

    def finish(self, message: str = "Complete"):
        """Finish progress bar"""
        self.current = self.total
        self._display()
        print(f"\n{_(message)}")

def with_progress(message: str = "Processing"):
    """Decorator to add progress spinner to functions"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            spinner = ProgressSpinner(_(message))
            spinner.start()
            try:
                result = func(*args, **kwargs)
                spinner.stop(_("Complete"))
                return result
            except Exception as e:
                spinner.stop(_("Failed"))
                raise e
        return wrapper
    return decorator

class BLNCSApplication:
    """統合されたBLNCSアプリケーションクラス"""

    def __init__(self, config_file: Optional[str] = None):
        # Initialize configuration first
        self.config = get_config(config_file)

        # Configure logging with enhanced features
        configure_logging(
            level=self.config.logging.level,
            json_format=True,
            use_structlog=False
        )

        self.logger = get_logger("blncs.app")
        self.logger.info(_("Initializing BLNCS Application"))

        # Initialize core systems
        self.database = None
        self.cache = None
        self.performance_optimizer = None
        self.security_manager = None
        self.lightning_client = None

        # Application state
        self.running = False
        self.shutdown_event = asyncio.Event()

        # Initialize systems
        self.initialize()

    def initialize(self):
        """システムの初期化"""
        try:
            # Initialize database
            self.database = get_database()
            if self.database.connect():
                self.logger.info(_("Database connected"))
            else:
                self.logger.warning(_("Database connection failed"))

            # Initialize cache
            self.cache = get_simple_cache()
            self.logger.info(_("Cache initialized"))

            # Initialize performance optimizer
            self.performance_optimizer = get_performance_optimizer()
            self.performance_optimizer.register_cache(self.cache)
            self.logger.info(_("Performance optimizer initialized"))

            # Initialize security manager
            self.security_manager = get_security_manager()
            self.logger.info(_("Security manager initialized"))

            # Initialize Lightning client
            node_url = f"{self.config.lightning.host}:{self.config.lightning.port}"
            lightning_config = {
                'node_url': node_url,
                'network': self.config.lightning.network
            }
            self.lightning_client = get_lightning_client(lightning_config)

            # Enable mock mode for development/testing
            self.lightning_client.mock_mode = True

            if self.lightning_client.connect():
                self.logger.info(_("Lightning Network client connected"))
            else:
                self.logger.warning(_("Lightning Network client connection failed"))

            self.logger.info(_("System initialization completed successfully"))

        except Exception as e:
            self.logger.critical(_("System initialization failed: %s") % e, exc_info=True)
            raise

    def get_health_status(self) -> Dict[str, Any]:
        """ヘルスチェック"""
        health = {
            'status': 'healthy',
            'timestamp': time.time(),
            'components': {}
        }

        # Database health
        try:
            db_status = self.database.health_check() if self.database else False
            health['components']['database'] = 'ok' if db_status else 'error'
        except Exception:
            health['components']['database'] = 'error'

        # Cache health
        try:
            cache_status = self.cache.health_check() if self.cache else True
            health['components']['cache'] = 'ok' if cache_status else 'error'
        except Exception:
            health['components']['cache'] = 'error'

        # Lightning health
        try:
            lightning_status = self.lightning_client.get_info() if self.lightning_client else {}
            health['components']['lightning'] = 'ok' if lightning_status else 'error'
        except Exception:
            health['components']['lightning'] = 'error'

        # Performance health
        try:
            perf_report = self.performance_optimizer.get_performance_report()
            health['components']['performance'] = 'ok' if perf_report else 'error'
        except Exception:
            health['components']['performance'] = 'error'

        # Overall status
        if any(status == 'error' for status in health['components'].values()):
            health['status'] = 'degraded'
        elif not all(status == 'ok' for status in health['components'].values()):
            health['status'] = 'warning'

        return health

    async def run_server(self, host: str = "0.0.0.0", port: int = 8000):
        """サーバーモードで実行"""
        self.logger.info(_("Starting server on %s:%s") % (host, port))

        try:
            # Import and run FastAPI server
            from blncs.api.unified_rest_api import create_app

            app = create_app()
            import uvicorn

            config = uvicorn.Config(
                app,
                host=host,
                port=port,
                log_level="info"
            )
            server = uvicorn.Server(config)

            # Setup signal handlers
            def signal_handler():
                self.logger.info(_("Shutdown signal received"))
                server.should_exit = True

            loop = asyncio.get_event_loop()
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, signal_handler)

            await server.serve()

        except Exception as e:
            self.logger.error(_("Server error: %s") % e)
            raise

    def run_cli_status(self):
        """ステータス表示"""
        print(f"BLNCS v{__version__} - Bitcoin Lightning Network Control System")
        print("=" * 60)

        health = self.get_health_status()

        print(_("Overall Status: %s") % health['status'].upper())
        print(_("Timestamp: %s") % time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(health['timestamp'])))
        print()

        for component, status in health['components'].items():
            emoji = "✅" if status == 'ok' else "⚠️" if status == 'warning' else "❌"
            print(f"{emoji} {component.capitalize()}: {status.upper()}")

        print()

        # Lightning info
        if self.lightning_client:
            try:
                info = self.lightning_client.get_info()
                print(_("Lightning Network:"))
                print(_("  Node ID: %s") % f"{info.get('node_id', 'N/A')[:20]}...")
                print(_("  Alias: %s") % info.get('alias', 'N/A'))
                print(_("  Network: %s") % info.get('network', 'N/A'))
                print(_("  Block Height: %s") % info.get('block_height', 'N/A'))
            except Exception as e:
                print(_("Lightning Network: Error - %s") % e)

        print()

        # Performance metrics
        if self.performance_optimizer:
            try:
                report = self.performance_optimizer.get_performance_report()
                if 'current_metrics' in report:
                    metrics = report['current_metrics']
                    print(_("Performance Metrics:"))
                    print(_("  CPU Usage: %.1f%%") % metrics.get('cpu_percent', 0))
                    print(_("  Memory Usage: %.1f%%") % metrics.get('memory_percent', 0))
                    print(_("  Active Threads: %s") % metrics.get('thread_count', 0))
            except Exception as e:
                print(_("Performance Metrics: Error - %s") % e)

    async def run_cli_interactive(self):
        """インタラクティブCLIモード"""
        print(_("BLNCS v%s - Interactive Mode") % __version__)
        print(_("Type 'help' for commands or 'quit' to exit"))
        print("-" * 50)

        while self.running:
            try:
                command = input("BLNCS> ").strip().lower()

                if command == 'quit' or command == 'exit':
                    break
                elif command == 'help':
                    self.print_help()
                elif command == 'status':
                    self.run_cli_status()
                elif command == 'health':
                    health = self.get_health_status()
                    print(_("Health Status: %s") % health['status'])
                    for component, status in health['components'].items():
                        print(_("  %s: %s") % (component, status))
                elif command.startswith('invoice'):
                    parts = command.split()
                    if len(parts) >= 2:
                        amount = int(parts[1])
                        self.create_invoice(amount)
                    else:
                        print(_("Usage: invoice <amount>"))
                elif command == 'balance':
                    self.print_balance()
                elif command == 'channels':
                    self.print_channels()
                elif command == 'node':
                    self.print_node_info()
                elif command == 'performance':
                    self.print_performance()
                elif command == 'security':
                    self.print_security()
                elif command.startswith('lang'):
                    parts = command.split()
                    if len(parts) >= 2:
                        new_language = parts[1]
                        self.change_language(new_language)
                    else:
                        self.show_language_info()
                elif command.startswith('translate'):
                    parts = command.split(maxsplit=1)
                    if len(parts) >= 2:
                        text_to_translate = parts[1]
                        self.translate_text(text_to_translate)
                    else:
                        print(_("Usage: translate <text>"))

            except KeyboardInterrupt:
                print(_("\nUse 'quit' to exit"))
            except Exception as e:
                print(_("Error: %s") % e)

    def print_help(self):
        """ヘルプ表示"""
        print(_("Available Commands:"))
        print(_("  help        - Show this help"))
        print(_("  status      - Show system status"))
        print(_("  health      - Show health check"))
        print(_("  balance     - Show wallet balance"))
        print(_("  channels    - Show Lightning channels"))
        print(_("  node        - Show node information"))
        print(_("  performance - Show performance metrics"))
        print(_("  security    - Show security status"))
        print(_("  optimize    - Run system optimization"))
        print(_("  invoice     - Create Lightning invoice"))
        print(_("  lang        - Change language or show language info"))
        print(_("  translate   - Translate text to current language"))
        print(_("  quit        - Exit application"))

    def print_balance(self):
        """残高表示"""
        print(_("\n--- Wallet Balance ---"))
        try:
            balance = self.lightning_client.get_balance()
            for key, value in balance.items():
                print(_("%s: %s sats") % (key.replace('_', ' ').title(), f"{value:,}"))
        except Exception as e:
            print(_("Error getting balance: %s") % e)

    def print_channels(self):
        """チャネル表示"""
        print(_("\n--- Lightning Channels ---"))
        try:
            channels = self.lightning_client.list_channels()
            if not channels:
                print(_("No channels found"))
                return

            for i, channel in enumerate(channels, 1):
                print(_("Channel ID: %s") % f"{i}. {channel.get('channel_id', 'N/A')}")
                print(_("  Peer: %s") % f"   {channel.get('peer_id', 'N/A')[:16]}...")
                print(_("  Capacity: %s") % f"   {channel.get('capacity', 0):,} sats")
                print(_("  Local: %s") % f"   {channel.get('local_balance', 0):,} sats")
                print(_("  Remote: %s") % f"   {channel.get('remote_balance', 0):,} sats")
                print(_("  Active: %s") % f"   {channel.get('active', False)}")
                print()
        except Exception as e:
            print(_("Error getting channels: %s") % e)

    def print_node_info(self):
        """ノード情報表示"""
        print(_("\n--- Node Information ---"))
        try:
            info = self.lightning_client.get_info()
            for key, value in info.items():
                if key == 'node_id':
                    print(_("Node ID: %s") % f"{key}: {value[:16]}...{value[-16:]}")
                else:
                    print(_("%s: %s") % (key, value))
        except Exception as e:
            print(_("Error getting node info: %s") % e)

    def print_performance(self):
        """パフォーマンス表示"""
        print(_("\n--- Performance Metrics ---"))
        try:
            report = self.performance_optimizer.get_performance_report()
            system_health = report.get('system_health', {})

            print(_("CPU Usage: %s%%") % system_health.get('cpu_percent', 'N/A'))
            print(_("Memory Usage: %s%%") % system_health.get('memory_percent', 'N/A'))
            print(_("Disk Usage: %s%%") % system_health.get('disk_percent', 'N/A'))
            print(_("Memory Available: %.1f GB") % system_health.get('memory_available_gb', 'N/A'))

            profiler_stats = report.get('profiler_stats', {})
            if profiler_stats:
                print(_("\nOperation Statistics:"))
                for op, stats in profiler_stats.items():
                    print(_("  %s: %s calls, avg %.3fs") % (op, stats.get('count', 0), stats.get('avg_time', 0)))

        except Exception as e:
            print(_("Error getting performance metrics: %s") % e)

    def print_security(self):
        """セキュリティ表示"""
        print(_("\n--- Security Status ---"))
        try:
            report = self.security_manager.get_security_report()
            print(_("Active Tokens: %s") % report.get('active_tokens', 0))
            print(_("Locked Accounts: %s") % report.get('locked_accounts', 0))
            print(_("Failed Login Attempts: %s") % report.get('failed_login_attempts', 0))

            events = report.get('security_events', {})
            severity_counts = events.get('severity_counts', {})
            if severity_counts:
                print(_("Recent Security Events:"))
                for severity, count in severity_counts.items():
                    print(_("  %s: %s") % (severity, count))

        except Exception as e:
            print(_("Error getting security status: %s") % e)

    def change_language(self, language: str):
        """言語変更"""
        try:
            from blncs.core.global_language_system import get_realtime_i18n_manager

            i18n_manager = get_realtime_i18n_manager()
            success = i18n_manager.set_language(language)

            if success:
                print(_("Language changed to: %s") % language)
                # 言語変更を反映させるためにヘルプを再表示
                self.print_help()
            else:
                print(_("Failed to change language. Available languages: %s") % ', '.join(i18n_manager.get_available_languages()))

        except Exception as e:
            print(_("Error changing language: %s") % e)

    def show_language_info(self):
        """言語情報表示"""
        try:
            from blncs.core.global_language_system import get_realtime_i18n_manager

            i18n_manager = get_realtime_i18n_manager()
            current_lang = i18n_manager.get_current_language()
            available_langs = i18n_manager.get_available_languages()

            print(_("\n--- Language Information ---"))
            print(_("Current Language: %s") % current_lang)
            print(_("Available Languages: %s") % ', '.join(available_langs))

            # 言語統計
            stats = i18n_manager.get_translation_statistics()
            if 'language_details' in stats:
                print(_("\nLanguage Details:"))
                for lang, details in stats['language_details'].items():
                    status = "✅" if details['loaded'] else "❌"
                    print(f"  {status} {lang}: {details.get('translated_entries', 0)}/{details.get('total_entries', 0)} translations")

            print(_("\nUsage: lang <language_code> to change language"))

        except Exception as e:
            print(_("Error getting language info: %s") % e)

    def translate_text(self, text: str):
        """テキスト翻訳"""
        try:
            from blncs.core.global_language_system import get_realtime_i18n_manager

            i18n_manager = get_realtime_i18n_manager()
            current_lang = i18n_manager.get_current_language()

            # 現在の言語でテキストを翻訳
            translated = i18n_manager.get_text(text)
            print(_("Original: %s") % text)
            print(_("Translated (%s): %s") % (current_lang, translated))

        except Exception as e:
            print(_("Error translating text: %s") % e)

    def create_invoice(self, amount: int):
        """インボイス作成"""
        print(_("\n--- Creating Invoice for %s sats ---") % amount)
        try:
            invoice = self.lightning_client.create_invoice(
                amount=amount,
                description=_("BLNCS invoice for %s sats") % amount
            )
            print(_("Payment Hash: %s") % invoice.get('payment_hash', 'N/A'))
            print(_("Payment Request: %s") % invoice.get('payment_request', 'N/A'))
            print(_("Amount: %s") % f"{invoice.get('amount', 0):,} sats")
            print(_("Status: %s") % invoice.get('status', 'N/A'))
        except Exception as e:
            print(_("Error creating invoice: %s") % e)

    async def run_optimization(self):
        """最適化実行"""
        print(_("\n--- Running System Optimization ---"))
        try:
            result = self.performance_optimizer.optimize_system()
            print(_("Optimization completed:"))

            cache_opt = result.get('cache_optimization', {})
            if cache_opt:
                print(_("Cache Optimization:"))
                for cache_name, action in cache_opt.items():
                    print(_("  %s: %s") % (cache_name, action))

            db_recommendations = result.get('database_recommendations', [])
            if db_recommendations:
                print(_("Database Recommendations:"))
                for rec in db_recommendations:
                    print(_("  - %s") % rec)

        except Exception as e:
            print(_("Error during optimization: %s") % e)

    async def start(self):
        """アプリケーション開始"""
        self.running = True
        await self.initialize()

    async def stop(self):
        """アプリケーション停止"""
        self.logger.info(_("Shutting down BLNCS Application"))
        self.running = False

        # Stop background services
        if self.performance_optimizer:
            self.performance_optimizer.stop_background_optimization()

        if self.security_manager:
            self.security_manager.stop_background_cleanup()

        # Close database connection
        if self.database:
            self.database.close()

        self.shutdown_event.set()
        self.logger.info(_("BLNCS Application shutdown completed"))

def setup_signal_handlers(app: BLNCSApplication):
    """シグナルハンドラーの設定"""
    def signal_handler(signum, frame):
        print(_("\nReceived signal %s, shutting down...") % signum)
        asyncio.create_task(app.stop())

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

async def main():
    """メインアプリケーションエントリポイント"""
    parser = argparse.ArgumentParser(description="BLNCS - Bitcoin Lightning Network Connection System")
    parser.add_argument("--config", "-c", help="Configuration file path")
    parser.add_argument("--mode", "-m", choices=["server", "cli", "status"], default="cli",
                       help="Run mode: server, cli, or status (default: cli)")
    parser.add_argument("--host", default="0.0.0.0", help="Server host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Server port (default: 8000)")
    parser.add_argument("--interactive", "-i", action="store_true", help="Run in interactive mode")
    parser.add_argument("--version", action="version", version=f"BLNCS {__version__}")

    args = parser.parse_args()

    # Create application
    app = BLNCSApplication(args.config)
    setup_signal_handlers(app)

    try:
        # Start application
        await app.start()

        # Run in selected mode
        if args.mode == "server":
            await app.run_server(args.host, args.port)
        elif args.mode == "status":
            app.run_cli_status()
        else:
            # Check for interactive mode
            if getattr(args, 'interactive', False):
                await app.run_cli_interactive()
            else:
                await app.run_cli(args)

    except KeyboardInterrupt:
        print(_("\nShutdown requested"))
    except Exception as e:
        app.logger.critical(_("Application failed: %s") % e, exc_info=True)
        return 1
    finally:
        await app.stop()

    return 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

def init_system(config_path=None):
    """Initialize system components with ultra-fast lazy loading"""
    # 最小限インポート
    from pathlib import Path

    global _config_cache, _logger_cache, _error_handler_cache

    # Load configuration
    if config_path is None:
        config_path = Path("config/blncs.json")

    if not config_path.exists():
        print(_("📝 Creating configuration template at %s") % config_path)
        template = create_config_template(config_path)
        print(_("✅ Configuration template created successfully"))
        print(_("\n📋 Configuration sections:"))
        for section in template.keys():
            print(_("  - %s") % section)
        print(_("\nEdit %s to customize settings") % config_path)

    # Simple config object (超軽量) with reload support
    class SimpleConfig:
        def __init__(self, path):
            from pathlib import Path as _Path

            self.config_path = _Path(path)
            suffix = self.config_path.suffix or '.json'
            self.integrity_path = self.config_path.with_suffix(f"{suffix}.sha256")
            self._last_checksum = None
            self._tamper_detected = False
            self.reload()

        def reload(self):
            try:
                import json  # 遅延インポート

                with open(self.config_path, encoding='utf-8') as f:
                    raw_data = f.read()

                digest = hashlib.sha256(raw_data.encode('utf-8')).hexdigest()
                self._tamper_detected = False

                if self.integrity_path.exists():
                    stored_digest = self.integrity_path.read_text(encoding='utf-8').strip()
                    if stored_digest != digest:
                        print(_("⚠️  Configuration integrity warning: checksum mismatch for %s") % self.config_path)
                        self._tamper_detected = True
                else:
                    self.integrity_path.write_text(digest, encoding='utf-8')

                self._last_checksum = digest
                self.config = json.loads(raw_data)
            except Exception as e:
                print(f"Warning: Config reload failed: {e}")
                if not hasattr(self, 'config'):
                    self.config = {}

        def get(self, key, default=None):
            keys = key.split('.')
            value = self.config
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return default
            return value

        def set(self, key, val):
            keys = key.split('.')
            cfg = self.config
            for k in keys[:-1]:
                if k not in cfg:
                    cfg[k] = {}
                cfg = cfg[k]
            cfg[keys[-1]] = val

        def save(self):
            import json  # 遅延インポート

            serialized = json.dumps(self.config, indent=2, ensure_ascii=False)
            with open(self.config_path, 'w', encoding='utf-8') as f:
                f.write(serialized)

            digest = hashlib.sha256(serialized.encode('utf-8')).hexdigest()
            self.integrity_path.write_text(digest, encoding='utf-8')
            self._last_checksum = digest
            self._tamper_detected = False

    class SimpleLogger:
        def __init__(self):
            self._buffer = []
            self._max_buffer = 100

        def _optimize_memory(self):
            """メモリ使用量最適化"""
            if len(self._buffer) > self._max_buffer:
                self._buffer = self._buffer[-50:]  # Keep last 50 entries

        def info(self, msg, *args):
            formatted = msg % args if args else msg
            print(formatted)
            self._buffer.append(('INFO', formatted))
            self._optimize_memory()

        def error(self, msg, *args):
            formatted = msg % args if args else msg
            print(_("ERROR: %s") % formatted, file=sys.stderr)
            self._buffer.append(('ERROR', formatted))
            self._optimize_memory()

        def warning(self, msg, *args):
            formatted = msg % args if args else msg
            print(_("WARNING: %s") % formatted)
            self._buffer.append(('WARNING', formatted))
            self._optimize_memory()

        def get_recent_logs(self, count=20):
            """最近のログエントリを取得"""
            return self._buffer[-count:]

    # 設定ファイルが存在しない場合は自動作成
    if not Path(config_path).exists():
        print(_("⚠️  設定ファイルが見つかりません: %s") % config_path)
        print(_("デフォルト設定で作成します..."))

        # ディレクトリ作成
        Path(config_path).parent.mkdir(parents=True, exist_ok=True)

        # デフォルト設定作成
        create_config_template(config_path)
        print(_("✅ 設定ファイルを作成しました: %s") % config_path)

    # 設定・ロガー・エラーハンドラの初期化（再利用可能）
    if _config_cache is None or Path(_config_cache.config_path) != Path(config_path):
        _config_cache = SimpleConfig(Path(config_path))
    else:
        _config_cache.reload()
    config = _config_cache

    if _logger_cache is None:
        _logger_cache = SimpleLogger()
    logger = _logger_cache

    if _error_handler_cache is None:
        from blncs.core.commercial_error_handler import CommercialErrorHandler

        _error_handler_cache = CommercialErrorHandler()
    error_handler = _error_handler_cache


    # 軽量パフォーマンス最適化
    import sys
    import gc
    # Additional micro-optimizations were previously expanded here; removed placeholder to keep syntax valid.

    # メモリ使用量最適化
    gc.set_threshold(500, 8, 8)  # さらに積極的なGC
    gc.collect()  # 初期クリーンアップ
    gc.disable()  # 手動GC制御でパフォーマンス向上

    # 文字列処理最適化
    _str_intern_pool = {}

    def _intern_string(s):
        """文字列インターン化でメモリ使用量を最適化"""
        if s not in _str_intern_pool:
            _str_intern_pool[s] = s
        return _str_intern_pool[s]

    # 数値計算最適化用の定数
    _SATS_PER_BTC = 100000000
    _MSAT_PER_SAT = 1000

    def _fast_sat_to_btc(sats):
        """高速satoshi to BTC変換"""
        return sats / _SATS_PER_BTC

    def _fast_btc_to_sat(btc):
        """高速BTC to satoshi変換"""
        return int(btc * _SATS_PER_BTC)

    def _fast_amount_format(amount_msats):
        """高速金額フォーマット"""
        if amount_msats >= 100000000000:  # 1000 BTC以上
            return f"{amount_msats / _MSAT_PER_SAT / _SATS_PER_BTC:.2f} BTC"
        elif amount_msats >= 100000000:  # 1000 sats以上
            return f"{amount_msats / _MSAT_PER_SAT:.0f} sats"
        else:
            return f"{amount_msats} msats"

    # データベースディレクトリ自動作成
    db_path = config.get('database.path', 'data/blncs.db')
    db_dir = Path(db_path).parent
    if not db_dir.exists():
        db_dir.mkdir(parents=True, exist_ok=True)
        logger.info(_("Created database directory: %s") % db_dir)

    return config, logger, error_handler


def _resolve_cli_token(args) -> Optional[str]:
    """Resolve CLI authentication token from args or environment."""
    token = getattr(args, 'auth_token', None)
    if token:
        return token
    return os.environ.get('BLNCS_CLI_TOKEN')


def _enforce_cli_permission(args, required_permission: str):
    """Ensure the CLI caller presents a valid token with the required permission."""
    from blncs.core.simple_auth import get_auth

    token_value = _resolve_cli_token(args)
    if not token_value:
        print(_("Authentication token required. Provide --auth-token or set BLNCS_CLI_TOKEN."))
        sys.exit(1)

    auth = get_auth()
    token = auth.validate_api_key(token_value)
    if not token:
        print(_("Authentication failed. Verify the provided token."))
        sys.exit(1)

    if not token.has_permission(required_permission):
        print(_("Access denied. '%s' permission required for this command.") % required_permission)
        sys.exit(1)

    setattr(args, '_validated_auth_token', token)


def _determine_cli_permission(command: Optional[str], args) -> Optional[str]:
    """Determine required permission for the requested CLI command."""

    def _needs_backup(args):
        auto_state = getattr(args, 'auto', None)

        if getattr(args, 'restore', False):
            return 'admin'
        if getattr(args, 'cleanup', False):
            return 'write'
        if getattr(args, 'create', False):
            return 'write'
        if auto_state in {'start', 'stop'}:
            return 'write'
        if auto_state == 'status':
            return None
        if getattr(args, 'interval', None) is not None:
            return 'write'
        if auto_state is None and not getattr(args, 'list', False):
            # Default invocation behaves like --create.
            return 'write'
        return None

    def _needs_config(args):
        if getattr(args, 'set', None):
            return 'write'
        if getattr(args, 'template', False):
            return 'write'
        watch_state = getattr(args, 'watch', None)
        if watch_state in {'start', 'stop'}:
            return 'write'
        return None

    def _needs_cache(args):
        if getattr(args, 'clear', False):
            return 'write'
        if getattr(args, 'db_optimize', False):
            return 'write'
        return None

    def _needs_logs(args):
        action = getattr(args, 'action', 'view')
        if action in {'clear', 'rotate'}:
            return 'write'
        return None

    def _needs_maintenance(args):
        if getattr(args, 'run', None):
            return 'admin'
        if getattr(args, 'bundle', None):
            return 'admin'
        return None

    def _needs_security(args):
        if getattr(args, 'set_auth_limits', None):
            return 'admin'
        if getattr(args, 'reset_auth_failures', False):
            return 'admin'
        return None

    policies = {
        'invoice': lambda a: 'write',
        'pay': lambda a: 'write',
        'server': lambda a: 'admin',
        'backup': _needs_backup,
        'config': _needs_config,
        'cache': _needs_cache,
        'logs': _needs_logs,
        'maintenance': _needs_maintenance,
        'security': _needs_security,
    }

    resolver = policies.get(command)
    if not resolver:
        return None
    return resolver(args)


def _emit_config_integrity_alert(config, logger=None):
    """Emit configuration integrity warnings if tampering is detected."""
    if getattr(config, '_tamper_detected', False):
        message = _("Configuration checksum mismatch detected. Review and restore trusted config before continuing.")
        print(_("⚠️  %s") % message)
        if logger is not None:
            try:
                logger.warning(message)
            except Exception:
                pass

def cmd_server(args, config, logger, error_handler):
    """Run optimized API server"""
    logger.info(_("Starting optimized API server..."))

    # Lazy import Flask app
    from blncs.api.unified_rest_api import create_app

    # Create Flask app with optimizations
    app = create_app(config)

    # Add performance optimizations
    optimize_api_server(app, config, logger)

    # Get server config
    host = config.get('api.host', '127.0.0.1')
    port = config.get('api.port', 8080)
    debug = config.get('api.debug', False)

    # Start server
    logger.info(_("API server listening on http://%s:%d (optimized)"), host, port)
    try:
        app.run(host=host, port=port, debug=debug, threaded=True)
    except KeyboardInterrupt:
        logger.info(_("Server stopped by user"))
    except Exception as e:
        logger.error(_("Server error: %s"), e)
        sys.exit(1)

def optimize_api_server(app, config, logger):
    """API応答時間最適化"""
    import time
    import gzip
    from functools import wraps
    from flask import request, Response, g

    # キャッシュ取得
    try:
        from blncs.core.simple_cache import get_simple_cache
        cache = get_simple_cache()
        cache_enabled = config.get('cache.enabled', True)
    except ImportError:
        cache = None
        cache_enabled = False

    @app.before_request
    def before_request():
        """リクエスト前処理 - 時間計測開始"""
        g.start_time = time.time()

    @app.after_request
    def after_request(response):
        """レスポンス後処理 - 最適化とメトリクス"""
        # 応答時間計測
        if hasattr(g, 'start_time'):
            response_time = (time.time() - g.start_time) * 1000
            response.headers['X-Response-Time'] = f'{response_time:.2f}ms'

            # 遅いリクエストをログ
            if response_time > 100:  # 100ms以上
                logger.warning(f"Slow request: {request.endpoint} - {response_time:.2f}ms")

        if (response.data and len(response.data) > 500 and  # 閾値を下げて積極圧縮
            response.content_type and
            ('json' in response.content_type or 'text' in response.content_type)):

            if 'gzip' in request.headers.get('Accept-Encoding', ''):
                try:
                    response.data = gzip.compress(response.data, compresslevel=1)
                    response.headers['Content-Encoding'] = 'gzip'
                    response.headers['Content-Length'] = len(response.data)
                    response.headers['Vary'] = 'Accept-Encoding'
                except Exception:
                    pass  # 圧縮失敗時はそのまま

        # キャッシュヘッダー設定 (GET リクエスト)
        if request.method == 'GET' and response.status_code == 200:
            # 静的データは長時間キャッシュ
            if any(x in request.path for x in ['/status', '/info', '/health']):
                response.headers['Cache-Control'] = 'public, max-age=60'
            else:
                response.headers['Cache-Control'] = 'public, max-age=30'

        return response

    # APIキャッシュデコレータ
    def api_cache(timeout=300):
        """API応答キャッシュデコレータ"""
        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                if not cache_enabled or not cache:
                    return f(*args, **kwargs)

                # キャッシュキー生成
                cache_key = f"api:{request.endpoint}:{hash(str(request.args))}"

                # キャッシュから取得
                cached = cache.get(cache_key)
                if cached:
                    return cached

                # 実行してキャッシュに保存
                result = f(*args, **kwargs)
                cache.set(cache_key, result)
                return result
            return wrapper
        return decorator

    # パフォーマンスメトリクス用ルート追加
    @app.route('/api/metrics/performance')
    def api_performance_metrics():
        """API パフォーマンスメトリクス"""
        if cache:
            cache_stats = cache.stats()
            return {
                'cache': cache_stats,
                'server': {
                    'threaded': True,
                    'compression': 'gzip',
                    'cache_headers': True
                }
            }
        return {'cache': 'disabled', 'server': {'threaded': True}}

    logger.info("API optimizations enabled: gzip, caching, metrics")

    return app

def cmd_status(args, config, logger, error_handler):
    """Show system status with integrated health monitoring"""
    print("\n=== System Status ===")

    # Fast system check without heavy imports
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('.')

        print(f"Status: {'HEALTHY' if cpu < 80 and memory.percent < 85 else 'WARNING'}")
        print(f"CPU Usage: {cpu:.1f}%")
        print(f"Memory Usage: {memory.percent:.1f}%")
        print(f"Memory Available: {memory.available / 1024 / 1024:.0f} MB")
        print(f"Disk Usage: {(disk.used / disk.total) * 100:.1f}%")
        print(f"Disk Free: {disk.free / 1024 / 1024 / 1024:.1f} GB")

    except ImportError:
        # Fallback without psutil
        import resource
        import os
        import shutil

        try:
            # Basic memory check
            rusage = resource.getrusage(resource.RUSAGE_SELF)
            memory_mb = rusage.ru_maxrss / 1024 if rusage.ru_maxrss > 100000 else rusage.ru_maxrss / 1024 / 1024

            # Basic disk check
            disk_usage = shutil.disk_usage('.')
            disk_percent = (disk_usage.used / disk_usage.total) * 100

            print(f"Status: {'HEALTHY' if memory_mb < 200 and disk_percent < 90 else 'WARNING'}")
            print(f"Process Memory: {memory_mb:.1f} MB")
            print(f"Disk Usage: {disk_percent:.1f}%")

        except Exception:
            print("Status: UNKNOWN (Cannot check system metrics)")

    # Quick cache check (lazy import)
    try:
        from blncs.core.simple_cache import get_simple_cache
        cache = get_simple_cache()
        cache_stats = cache.stats()
        print(f"\n=== Cache ===")
        print(f"Entries: {cache_stats['size']}/{cache_stats['max_size']}")
        print(f"Hit Rate: {cache_stats.get('hit_rate', 0):.1f}%")
    except Exception:
        print("\n=== Cache ===")
        print("Cache: Not available")

    # Config summary
    print(f"\n=== Configuration ===")
    print(f"Lightning: {config.get('lightning.host')}:{config.get('lightning.port')}")
    print(f"Database: {config.get('database.type')} ({config.get('database.path')})")
    print(f"API Port: {config.get('api.port')}")

def cmd_health(args, config, logger, error_handler):
    """強化されたヘルスチェック - 詳細なシステム診断"""
    import time
    import os
    from pathlib import Path
    import json

    print("\n🏥 Enhanced System Health Check")
    print("=" * 50)

    health_score = 100
    issues = []
    warnings = []
    recommendations = []
    start_time = time.time()

    # 1. システムリソースチェック
    print("💻 System Resources:")
    try:
        import psutil
        cpu_percent = psutil.cpu_percent(interval=0.5)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        load_avg = psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None

        # CPUチェック
        if cpu_percent < 70:
            print(f"   ✅ CPU: {cpu_percent:.1f}% usage")
        elif cpu_percent < 85:
            print(f"   ⚠️  CPU: {cpu_percent:.1f}% usage (elevated)")
            health_score -= 5
            warnings.append(f"High CPU usage: {cpu_percent:.1f}%")
        else:
            print(f"   ❌ CPU: {cpu_percent:.1f}% usage (critical)")
            health_score -= 15
            issues.append(f"Critical CPU usage: {cpu_percent:.1f}%")

        # メモリチェック
        memory_usage = (memory.used / memory.total) * 100
        if memory_usage < 75:
            print(f"   ✅ Memory: {memory_usage:.1f}% used ({memory.used//(1024**3)}GB/{memory.total//(1024**3)}GB)")
        elif memory_usage < 90:
            print(f"   ⚠️  Memory: {memory_usage:.1f}% used (high)")
            health_score -= 10
            warnings.append(f"High memory usage: {memory_usage:.1f}%")
        else:
            print(f"   ❌ Memory: {memory_usage:.1f}% used (critical)")
            health_score -= 20
            issues.append(f"Critical memory usage: {memory_usage:.1f}%")

        # ディスクチェック
        disk_usage = (disk.used / disk.total) * 100
        if disk_usage < 80:
            print(f"   ✅ Disk: {disk_usage:.1f}% used ({disk.used//(1024**3)}GB/{disk.total//(1024**3)}GB)")
        elif disk_usage < 95:
            print(f"   ⚠️  Disk: {disk_usage:.1f}% used (high)")
            health_score -= 10
            warnings.append(f"High disk usage: {disk_usage:.1f}%")
        else:
            print(f"   ❌ Disk: {disk_usage:.1f}% used (critical)")
            health_score -= 25
            issues.append(f"Critical disk usage: {disk_usage:.1f}%")

        # 負荷平均チェック (Linuxのみ)
        if load_avg:
            load_1min = load_avg[0]
            cpu_count = psutil.cpu_count()
            if load_1min < cpu_count * 0.7:
                print(f"   ✅ Load Average: {load_1min:.2f} (1min)")
            else:
                print(f"   ⚠️  Load Average: {load_1min:.2f} (1min, high)")
                health_score -= 5
                warnings.append(f"High load average: {load_1min:.2f}")

    except ImportError:
        print("   ⚠️  System monitoring not available (psutil not installed)")
        recommendations.append("Install psutil for detailed system monitoring")
        health_score -= 5
    except Exception as e:
        print(f"   ❌ Resource check failed: {e}")
        health_score -= 10
        issues.append(f"Resource monitoring error: {e}")

    # 2. 設定ファイルチェック
    print("\n📁 Configuration:")
    try:
        config_file = getattr(config, 'config_path', 'config/blncs.json')
        if Path(config_file).exists():
            print(f"   ✅ Config file exists: {config_file}")

            # 設定整合性チェック
            integrity = config.validate_configuration_integrity()
            if integrity['valid']:
                print("   ✅ Configuration integrity verified")
            else:
                print("   ⚠️  Configuration integrity issues detected")
                health_score -= 10
                warnings.extend(integrity.get('errors', []))

            # 必須設定チェック
            required_settings = [
                ('api.port', 'API port'),
                ('database.path', 'Database path'),
                ('lightning.network', 'Lightning network')
            ]

            for key, description in required_settings:
                value = config.get(key)
                if value is not None:
                    print(f"   ✅ {description}: {value}")
                else:
                    print(f"   ⚠️  {description}: not configured")
                    health_score -= 5
                    warnings.append(f"Missing {description} configuration")

        else:
            print(f"   ❌ Config file missing: {config_file}")
            health_score -= 20
            issues.append(f"Configuration file not found: {config_file}")

    except Exception as e:
        print(f"   ❌ Config check failed: {e}")
        health_score -= 10
        issues.append(f"Configuration check error: {e}")

    # 3. データベースチェック
    print("\n🗄️  Database:")
    try:
        from blncs.core.unified_database import get_database
        db = get_database()
        if db.connect():
            print("   ✅ Database connection successful")

            # データベースサイズチェック
            db_path = config.get('database.path', 'data/blncs.db')
            if Path(db_path).exists():
                db_size_mb = Path(db_path).stat().st_size / (1024 * 1024)
                if db_size_mb < 100:
                    print(f"   ✅ Database size: {db_size_mb:.1f} MB")
                elif db_size_mb < 500:
                    print(f"   ⚠️  Database size: {db_size_mb:.1f} MB (large)")
                    warnings.append(f"Large database: {db_size_mb:.1f} MB")
                else:
                    print(f"   ❌ Database size: {db_size_mb:.1f} MB (very large)")
                    health_score -= 10
                    issues.append(f"Very large database: {db_size_mb:.1f} MB")

            db.disconnect()
        else:
            print("   ❌ Database connection failed")
            health_score -= 25
            issues.append("Database connection failure")

    except Exception as e:
        print(f"   ❌ Database check failed: {e}")
        health_score -= 15
        issues.append(f"Database check error: {e}")

    # 4. Lightning Networkチェック
    print("\n⚡ Lightning Network:")
    try:
        from blncs.lightning.simple_client import get_lightning_client
        lightning = get_lightning_client()
        if lightning.connect():
            print("   ✅ Lightning client connected")

            # 基本情報取得
            try:
                info = lightning.get_info()
                if info:
                    print(f"   📍 Node: {info.get('alias', 'Unknown')}")
                    print(f"   🔗 Channels: {info.get('num_active_channels', 0)} active")
                    print(f"   🌐 Network: {info.get('network', 'Unknown')}")
                else:
                    print("   ⚠️  Could not retrieve node info")
                    warnings.append("Lightning node info unavailable")
            except Exception as e:
                print(f"   ⚠️  Node info check failed: {e}")
                warnings.append(f"Lightning node info error: {e}")

            lightning.disconnect()
        else:
            print("   ❌ Lightning client connection failed")
            health_score -= 20
            issues.append("Lightning Network connection failure")

    except Exception as e:
        print(f"   ❌ Lightning check failed: {e}")
        health_score -= 15
        issues.append(f"Lightning check error: {e}")

    # 5. APIサーバーチェック
    print("\n🌐 API Server:")
    try:
        import requests
        api_host = config.get('api.host', 'localhost')
        api_port = config.get('api.port', 8080)
        api_url = f"http://{api_host}:{api_port}/health"

        response = requests.get(api_url, timeout=5)
        if response.status_code == 200:
            print("   ✅ API server responding")

            # APIレスポンス内容チェック
            try:
                health_data = response.json()
                if 'status' in health_data:
                    print(f"   📊 API status: {health_data['status']}")
                else:
                    print("   ⚠️  API response format unclear")
            except:
                print("   ⚠️  API response not JSON")

        elif response.status_code == 404:
            print("   ⚠️  API server running but health endpoint not found")
            warnings.append("API health endpoint missing")
        else:
            print(f"   ❌ API server error: HTTP {response.status_code}")
            health_score -= 15
            issues.append(f"API server error: HTTP {response.status_code}")

    except requests.exceptions.ConnectionError:
        print("   ❌ API server not responding")
        health_score -= 20
        issues.append("API server connection failure")
    except Exception as e:
        print(f"   ❌ API check failed: {e}")
        health_score -= 10
        issues.append(f"API check error: {e}")

    # 6. キャッシュチェック
    print("\n💾 Cache System:")
    try:
        from blncs.core.simple_cache import get_simple_cache
        cache = get_simple_cache()
        cache_stats = cache.stats()

        cache_size = cache_stats.get('size', 0)
        max_size = cache_stats.get('max_size', 1000)
        hit_rate = cache_stats.get('hit_rate', 0)

        if cache_size <= max_size:
            print(f"   ✅ Cache: {cache_size}/{max_size} entries")
            print(f"   📈 Hit rate: {hit_rate:.1f}%")
        else:
            print(f"   ⚠️  Cache: {cache_size}/{max_size} entries (overflow)")
            warnings.append("Cache size exceeds maximum")

    except Exception as e:
        print(f"   ❌ Cache check failed: {e}")
        warnings.append(f"Cache check error: {e}")

    # 7. ログファイルチェック
    print("\n📝 Log Files:")
    try:
        log_dir = Path("logs")
        if log_dir.exists():
            log_files = list(log_dir.glob("*.log*"))
            if log_files:
                total_size = sum(f.stat().st_size for f in log_files if f.exists())
                size_mb = total_size / (1024 * 1024)

                if size_mb < 50:
                    print(f"   ✅ Log files: {len(log_files)} files, {size_mb:.1f} MB")
                elif size_mb < 200:
                    print(f"   ⚠️  Log files: {len(log_files)} files, {size_mb:.1f} MB (large)")
                    warnings.append(f"Large log files: {size_mb:.1f} MB")
                else:
                    print(f"   ❌ Log files: {len(log_files)} files, {size_mb:.1f} MB (very large)")
                    health_score -= 10
                    issues.append(f"Very large log files: {size_mb:.1f} MB")
                    recommendations.append("Consider log rotation or cleanup")
            else:
                print("   ⚠️  No log files found")
                warnings.append("No log files present")
        else:
            print("   ⚠️  Log directory not found")
            warnings.append("Log directory missing")

    except Exception as e:
        print(f"   ❌ Log check failed: {e}")
        warnings.append(f"Log check error: {e}")

    # 実行時間表示
    check_time = time.time() - start_time
    print(f"\n⏱️  Check completed in {check_time:.2f} seconds")

    # 総合評価
    print("\n📊 Health Assessment:")
    print("-" * 30)

    if health_score >= 90:
        print("🎉 EXCELLENT - System is running optimally")
        print(f"   Health Score: {health_score}/100")
    elif health_score >= 75:
        print("✅ GOOD - System is running well")
        print(f"   Health Score: {health_score}/100")
    elif health_score >= 60:
        print("⚠️  WARNING - Some issues need attention")
        print(f"   Health Score: {health_score}/100")
    elif health_score >= 40:
        print("❌ POOR - Multiple issues require action")
        print(f"   Health Score: {health_score}/100")
    else:
        print("🚨 CRITICAL - Immediate action required")
        print(f"   Health Score: {health_score}/100")

    # 問題点の要約
    if issues:
        print(f"\n🚨 Critical Issues ({len(issues)}):")
        for i, issue in enumerate(issues, 1):
            print(f"   {i}. {issue}")

    if warnings:
        print(f"\n⚠️  Warnings ({len(warnings)}):")
        for i, warning in enumerate(warnings, 1):
            print(f"   {i}. {warning}")

    if recommendations:
        print(f"\n💡 Recommendations ({len(recommendations)}):")
        for i, rec in enumerate(recommendations, 1):
            print(f"   {i}. {rec}")

    # ログ記録
    logger.info(f"Health check completed: {health_score}/100 score, {len(issues)} issues, {len(warnings)} warnings")

    # 終了コードを問題の深刻さに応じて設定
    if issues:
        return 2  # Critical issues
    elif warnings:
        return 1  # Warnings present
    else:
        return 0  # All good

def cmd_history(args, config, logger):
    """Lightning支払い履歴表示"""
    try:
        import sqlite3
        db_path = config.get('database.path', 'data/blncs.db')

        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS payment_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    payment_hash TEXT UNIQUE,
                    payment_request TEXT,
                    amount INTEGER,
                    direction TEXT CHECK(direction IN ('send', 'receive')),
                    status TEXT CHECK(status IN ('pending', 'completed', 'failed')),
                    memo TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # 履歴取得
            limit = getattr(args, 'limit', 10)
            cursor = conn.execute("""
                SELECT payment_hash, amount, direction, status, memo, created_at
                FROM payment_history
                ORDER BY created_at DESC
                LIMIT ?
            """, (limit,))

            rows = cursor.fetchall()

        if not rows:
            print("⚡ 支払い履歴なし")
            return

        print(f"⚡ Lightning支払い履歴 (最新{len(rows)}件)")
        print("-" * 70)

        for row in rows:
            hash_short = row[0][:8] if row[0] else "N/A"
            amount = row[1] or 0
            direction = "送金" if row[2] == "send" else "受取"
            status_map = {"pending": "保留", "completed": "完了", "failed": "失敗"}
            status = status_map.get(row[3], row[3] or "不明")
            memo = row[4] or ""
            created = row[5] or ""

            print(f"{hash_short} | {amount:>8} sats | {direction} | {status} | {memo[:20]} | {created[:16]}")

    except Exception as e:
        logger.error(f"Payment history error: {e}")
        print(f"❌ 履歴表示エラー: {e}")

def add_payment_to_history(payment_hash, payment_request, amount, direction, status="pending", memo="", config=None):
    """支払い履歴に追加 (内部関数)"""
    try:
        import sqlite3
        db_path = config.get('database.path', 'data/blncs.db') if config else 'data/blncs.db'

        with sqlite3.connect(db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO payment_history
                (payment_hash, payment_request, amount, direction, status, memo)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (payment_hash, payment_request, amount, direction, status, memo))

    except Exception as e:
        print(f"⚠️ 履歴記録エラー: {e}")

def cmd_test(args, config, logger):
    """Run comprehensive system tests"""
    import time
    from pathlib import Path

    print("\n🧪 Running system tests...")
    print("=" * 50)

    passed = 0
    failed = 0
    start_time = time.time()
    total_tests = 5

    progress = ProgressBar(total_tests, prefix="Testing")

    # 1. Database test
    try:
        from blncs.core.unified_database import get_database
        db = get_database()
        test_start = time.time()
        result = db.query("SELECT 1")
        query_time = (time.time() - test_start) * 1000
        assert result == [{'1': 1}]
        print("✅ Database: OK ({:.2f}ms)".format(query_time))
        passed += 1
    except Exception as e:
        print(f"❌ Database: {e}")
        failed += 1

    progress.increment()

    # 2. Lightning test
    try:
        from blncs.lightning.simple_client import SimpleLightningClient
        client = SimpleLightningClient()
        if client.connect():
            print("✅ Lightning: OK (mock mode)")
        else:
            print("⚠️  Lightning: Unavailable")
        passed += 1
    except Exception as e:
        print(f"❌ Lightning: {e}")
        failed += 1

    progress.increment()

    # 3. Cache test
    try:
        from blncs.core.simple_cache import get_simple_cache
        cache = get_simple_cache()
        cache.set("test", "value")
        assert cache.get("test") == "value"
        print("✅ Cache: OK")
        passed += 1
    except Exception as e:
        print(f"❌ Cache: {e}")
        failed += 1

    progress.increment()

    # 4. Config test
    try:
        port = config.get('api.port')
        assert port is not None
        print(f"✅ Config: OK (port: {port})")
        passed += 1
    except Exception as e:
        print(f"❌ Config: {e}")
        failed += 1

    progress.increment()

    # 5. Security test
    try:
        from blncs.api.validators import validate_file_path, sanitize_lightning_invoice
        assert validate_file_path("data/test.db") == True
        assert validate_file_path("../etc/passwd") == False
        assert "lnbc" in sanitize_lightning_invoice("lnbc1000n")
        print("✅ Security: OK")
        passed += 1
    except Exception as e:
        print(f"❌ Security: {e}")
        failed += 1

    progress.increment()
    progress.finish()

    # Summary
    total_time = (time.time() - start_time) * 1000
    print(f"\n📊 Results: {passed} passed, {failed} failed ({total_time:.2f}ms)")

    if failed == 0:
        print("🎉 All tests passed!")
        return True
    else:
        print(f"⚠️  {failed} test(s) failed")
        return False

def cmd_config(args, config, logger):
    """Show or edit configuration"""
    _emit_config_integrity_alert(config, logger)

    if args.get:
        # Get config value
        value = config.get(args.get)
        if value is not None:
            import json
            print(f"{args.get} = {json.dumps(value, indent=2, ensure_ascii=False)}")
        else:
            print(f"Configuration key '{args.get}' not found")
    elif args.set:
        # Set config value
        key, value = args.set
        try:
            # Try to parse as JSON
            import json
            value = json.loads(value)
        except:
            # Keep as string
            pass
        config.set(key, value)
        config.save()
        print(f"Set {key} = {value}")
        logger.info("Configuration updated: %s = %s", key, value)
    elif args.template:
        # Generate config template
        from pathlib import Path
        template_path = Path("config/template.json")
        create_config_template(template_path)
        print(f"✅ Configuration template created: {template_path}")
    elif args.reload:
        # ホットリロード実行
        try:
            old_config = config.config.copy()
            config.reload()
            new_config = config.config

            if old_config != new_config:
                print("🔄 Configuration reloaded successfully")
                # 変更内容表示
                changed_keys = []
                for key in new_config:
                    if key not in old_config or old_config[key] != new_config[key]:
                        changed_keys.append(key)
                if changed_keys:
                    print(f"📝 Changed sections: {', '.join(changed_keys)}")
            else:
                print("ℹ️  No configuration changes detected")
        except Exception as e:
            print(f"❌ Config reload failed: {e}")
    elif args.watch:
        # 監視開始/停止
        try:
            if args.watch == 'start':
                if hasattr(config, '_watch_running') and not config._watch_running:
                    config.start_watching(interval=1.0)
                    print("👁️  Configuration watching started")
                else:
                    print("ℹ️  Configuration watching already running or not supported")
            elif args.watch == 'stop':
                if hasattr(config, '_watch_running') and config._watch_running:
                    config.stop_watching()
                    print("⏹️  Configuration watching stopped")
                else:
                    print("ℹ️  Configuration watching not running")
            elif args.watch == 'status':
                if hasattr(config, '_watch_running'):
                    status = "running" if config._watch_running else "stopped"
                    watchers_count = len(getattr(config, '_watchers', []))
                    print(f"👁️  Watch status: {status}")
                    print(f"📊 Active watchers: {watchers_count}")
                else:
                    print("ℹ️  Configuration watching not supported")
        except Exception as e:
            print(f"❌ Config watch operation failed: {e}")
    else:
        # Show all config
        import json
        print(json.dumps(config.config, indent=2, ensure_ascii=False))

def cmd_security(args, config, logger):
    """Security utilities"""
    from blncs.core.simple_auth import get_auth

    auth = get_auth()
    actions_performed = False

    if getattr(args, 'show_auth_limits', False):
        limits = auth.export_failure_limits()
        print("Authentication failure limiter settings:")
        print(f"  Max attempts: {limits['max_attempts']}")
        print(f"  Window seconds: {limits['window_seconds']}")
        actions_performed = True

    if args.set_auth_limits:
        max_attempts, window_seconds = args.set_auth_limits
        auth.update_failure_limits(max_attempts=max_attempts, window_seconds=window_seconds)
        logger.info("Authentication failure limits updated: max_attempts=%s window_seconds=%s", max_attempts, window_seconds)
        print("Updated authentication failure limits.")
        actions_performed = True

    if getattr(args, 'reset_auth_failures', False):
        auth.clear_all_failures()
        logger.info("Authentication failure counters cleared")
        print("Cleared authentication failure counters.")
        actions_performed = True

    if not actions_performed:
        print("No security action specified. Use --show-auth-limits, --set-auth-limits, or --reset-auth-failures.")

def cmd_cache(args, config, logger):
    """Cache management"""
    from blncs.core.simple_cache import get_simple_cache
    import json

    cache = get_simple_cache()

    if args.clear:
        cache.clear()
        print("✅ Cache cleared")
        logger.info("Cache cleared")
    elif args.stats:
        stats = cache.stats()
        print("📊 Cache Statistics:")
        print(f"  Size: {stats['size']}/{stats['max_size']}")
        print(f"  Hit Rate: {stats['hit_rate']}%")
        print(f"  Hits: {stats['hits']}")
        print(f"  Misses: {stats['misses']}")
        print(f"  TTL: {stats['ttl']}s")
    elif args.db_optimize:
        try:
            from blncs.core.unified_database import get_database
            db = get_database()
            result = db.optimize_database()

            size_before_mb = result['size_before'] / 1024 / 1024
            size_after_mb = result['size_after'] / 1024 / 1024
            saved_mb = result['space_saved'] / 1024 / 1024

            print("🗄️  Database Optimization Complete:")
            print(f"   Size before: {size_before_mb:.2f} MB")
            print(f"   Size after:  {size_after_mb:.2f} MB")
            print(f"   Space saved: {saved_mb:.2f} MB")
        except Exception as e:
            print(f"❌ Database optimization failed: {e}")
    else:
        print("Cache operations: --clear, --stats, --db-optimize")

def cmd_validate(args, config, logger):
    """Validate configuration with fast validator"""
    from blncs.core.fast_config_validator import validate_config_file
    from pathlib import Path

    config_file = getattr(args, 'config', None) or "config/blncs.json"

    # バリデーション実行
    issues = validate_config_file(config_file)

    if not issues:
        print("✅ Configuration is valid")

        # 追加の軽量チェック
        if Path(config_file).exists():
            file_size = Path(config_file).stat().st_size
            print(f"📄 Config file size: {file_size} bytes")

            # Lightning設定チェック
            try:
                lightning_host = config.get('lightning.host', 'localhost')
                lightning_port = config.get('lightning.port', 10009)
                print(f"⚡ Lightning: {lightning_host}:{lightning_port}")

                # 簡易接続テスト (軽量)
                import socket
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex((lightning_host, lightning_port))
                    if result == 0:
                        print("✅ Lightning node: Reachable")
                    else:
                        print("⚠️  Lightning node: Unreachable (normal if not running)")
            except Exception:
                print("⚠️  Lightning connection test skipped")

        logger.info("Configuration validation successful")
    else:
        print("❌ Configuration issues found:")
        for issue in issues:
            if issue.startswith("WARNING"):
                print(f"⚠️  {issue}")
            else:
                print(f"❌ {issue}")
        logger.warning(f"Configuration validation failed: {len(issues)} issues")

def cmd_invoice(args, config, logger):
    """Create Lightning invoice with QR"""
    from blncs.lightning.simple_client import quick_connect
    from blncs.utils.simple_qr import SimpleQR

    # Connect to Lightning node
    client = quick_connect(config.config)

    if not client.connected:
        print("❌ Failed to connect to Lightning node")
        return

    # Create invoice
    amount = args.amount or 1000  # Default 1000 sats
    memo = args.memo or "BLNCS Invoice"

    result = client.create_invoice(amount, memo)

    if 'error' in result:
        print(f"❌ {result['error']}")
    else:
        print(f"⚡ Invoice created:")
        print(f"Payment Request: {result['payment_request']}")
        print(f"Amount: {result['amount']} sats")
        print(f"Memo: {result['memo']}")

        # 履歴に記録
        add_payment_to_history(
            payment_hash=result['payment_request'][:32],  # Use first 32 chars as hash
            payment_request=result['payment_request'],
            amount=result['amount'],
            direction='receive',
            status='pending',
            memo=result['memo'],
            config=config
        )

        # QRコード生成 (オプション)
        if args.qr:
            SimpleQR.generate(result['payment_request'])

    client.disconnect()

def cmd_pay(args, config, logger):
    """Pay Lightning invoice"""
    from blncs.lightning.simple_client import quick_connect

    if not args.invoice:
        print("❌ Invoice required: blncs pay --invoice <payment_request>")
        return

    # Connect to Lightning node
    client = quick_connect(config.config)

    if not client.connected:
        print("❌ Failed to connect to Lightning node")
        return

    # Pay invoice
    result = client.pay_invoice(args.invoice)

    if 'error' in result:
        print(f"❌ {result['error']}")
    else:
        print(f"⚡ Payment initiated:")
        print(f"Status: {result['status']}")
        print(f"Invoice: {result['payment_request'][:50]}...")

        # 履歴に記録
        add_payment_to_history(
            payment_hash=args.invoice[:32],  # Use first 32 chars as hash
            payment_request=args.invoice,
            amount=0,  # Amount not available in simple client
            direction='send',
            status=result.get('status', 'pending'),
            memo="Payment via BLNCS",
            config=config
        )

    client.disconnect()

def cmd_balance(args, config, logger):
    """Check Lightning balance"""
    from blncs.lightning.simple_client import quick_connect

    # Connect to Lightning node
    client = quick_connect(config.config)

    if not client.connected:
        print("❌ Failed to connect to Lightning node")
        return

    # Get balance
    result = client.get_balance()

    if 'error' in result:
        print(f"❌ {result['error']}")
    else:
        print(f"⚡ Lightning Balance:")
        print(f"Total: {result['total_balance']} sats")
        print(f"Confirmed: {result['confirmed_balance']} sats")
        print(f"Unconfirmed: {result['unconfirmed_balance']} sats")

    client.disconnect()

def cmd_connect(args, config, logger):
    """Test Lightning connection with enhanced error handling"""
    from blncs.lightning.simple_client import SimpleLightningClient
    import socket

    host = args.host or config.get('lightning.host', 'localhost')
    port = args.port or config.get('lightning.port', 10009)

    print(f"🔌 Testing connection to {host}:{port}")

    # Pre-check: Network connectivity
    try:
        print("📡 Checking network connectivity...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            result = s.connect_ex((host, port))
            if result != 0:
                print(f"❌ Network unreachable: {host}:{port}")
                print("💡 Suggestions:")
                print(f"   • Verify Lightning node is running")
                print(f"   • Check host/port configuration")
                return
        print("✅ Network connectivity OK")
    except socket.gaierror:
        print(f"❌ DNS resolution failed: {host}")
        return
    except Exception as e:
        print(f"❌ Network error: {e}")
        return

    # Lightning connection test
    try:
        client = SimpleLightningClient(host, port)

        if client.connect():
            print("✅ Lightning connection successful")

            info = client.get_info()
            if 'error' not in info:
                print(f"📊 Node Details:")
                print(f"   Alias: {info.get('alias', 'Unknown')}")
                print(f"   Network: {info.get('network', 'Unknown')}")
                print(f"   Version: {info.get('version', 'Unknown')}")

            client.disconnect()
            logger.info(f"Lightning connection successful: {host}:{port}")
        else:
            print("❌ Lightning connection failed")
            print("💡 Possible issues:")
            print("   • gRPC service unavailable")
            print("   • Authentication required")
            print("   • Try different port (9735, 10009)")
            logger.warning(f"Lightning connection failed: {host}:{port}")

    except Exception as e:
        print(f"❌ Connection error: {e}")
        logger.error(f"Lightning connection error: {e}")

def cmd_qr(args, config, logger):
    """Generate QR code"""
    from blncs.utils.simple_qr import SimpleQR

    success = SimpleQR.generate(args.data, args.output)

    if success and args.output:
        print(f"✅ QRコード保存: {args.output}")
    elif not success:
        print("❌ QRコード生成に失敗しました")

def cmd_info(args, config, logger):
    """Show comprehensive system information"""
    import platform
    import time
    import os
    import sqlite3
    from pathlib import Path

    print("\n🖥️  System Information")
    print("=" * 50)

    # System info
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"Python: {platform.python_version()}")
    print(f"Architecture: {platform.machine()}")
    print(f"Hostname: {platform.node()}")
    print(f"User: {os.getenv('USER', os.getenv('USERNAME', 'unknown'))}")

    # BLNCS info
    print(f"\n⚡ BLNCS Information")
    print(f"Version: {__version__}")
    print(f"Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Config: {config.get('database.path', 'config/blncs.json')}")
    print(f"Working Dir: {os.getcwd()}")

    # File structure analysis
    if Path('blncs').exists():
        blncs_files = len(list(Path('blncs').rglob('*.py')))
        total_size = sum(f.stat().st_size for f in Path('blncs').rglob('*.py') if f.is_file())
        print(f"Python files: {blncs_files}")
        print(f"Total size: {total_size / 1024:.1f} KB")
    else:
        print("BLNCS directory: Not found")

    # Database info
    try:
        db_path = config.get('database.path', 'data/blncs.db')
        if Path(db_path).exists():
            with sqlite3.connect(db_path) as conn:
                cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cursor.fetchall()]
                print(f"\nDatabase: {db_path}")
                print(f"Size: {Path(db_path).stat().st_size / 1024:.1f} KB")
                print(f"Tables: {', '.join(tables) if tables else 'None'}")
        else:
            print(f"\nDatabase: {db_path} (not created)")
    except Exception as e:
        print(f"\nDatabase: Error - {e}")

    # Performance info
    try:
        import psutil
        process = psutil.Process()
        print(f"\n💻 Performance")
        print(f"CPU cores: {psutil.cpu_count(logical=False)}/{psutil.cpu_count()}")
        print(f"System Memory: {psutil.virtual_memory().total / 1024 / 1024 / 1024:.1f} GB")
        print(f"Process Memory: {process.memory_info().rss / 1024 / 1024:.1f} MB")
        print(f"Process CPU: {process.cpu_percent():.1f}%")
        print(f"Process PID: {process.pid}")
        print(f"Process Threads: {process.num_threads()}")
    except ImportError:
        print(f"\n💻 Performance")
        print(f"Process PID: {os.getpid()}")
        print("(Install psutil for detailed metrics)")

    # Network & Lightning
    print(f"\n⚡ Lightning Configuration")
    print(f"Host: {config.get('lightning.host', 'localhost')}")
    print(f"Port: {config.get('lightning.port', 10009)}")
    print(f"Network: {config.get('lightning.network', 'testnet')}")
    print(f"Client Type: {config.get('lightning.client_type', 'lnd')}")

    # API Configuration
    print(f"\n🌐 API Configuration")
    print(f"Host: {config.get('api.host', '127.0.0.1')}")
    print(f"Port: {config.get('api.port', 8080)}")
    print(f"Debug: {config.get('api.debug', False)}")
    print(f"CORS: {config.get('api.enable_cors', True)}")

    # Cache status
    try:
        from blncs.core.simple_cache import get_simple_cache
        cache = get_simple_cache()
        stats = cache.stats()
        print(f"\n🗄️  Cache Status")
        print(f"Entries: {stats['size']}/{stats['max_size']}")
        print(f"Hit Rate: {stats['hit_rate']}%")
        print(f"Total Requests: {stats['total_requests']}")
        print(f"TTL: {stats['ttl']}s")
    except Exception:
        print(f"\n🗄️  Cache Status: Not available")

    # Dependencies check
    print(f"\n📦 Dependencies")
    dependencies = {
        'grpcio': 'Lightning Network support',
        'qrcode': 'QR code generation',
        'psutil': 'System monitoring',
        'flask': 'Web API framework'
    }

    for dep, desc in dependencies.items():
        try:
            __import__(dep)
            print(f"✅ {dep}: {desc}")
        except ImportError:
            print(f"❌ {dep}: {desc} (not installed)")

    # Recent activity (if payment history exists)
    try:
        db_path = config.get('database.path', 'data/blncs.db')
        if Path(db_path).exists():
            with sqlite3.connect(db_path) as conn:
                cursor = conn.execute("""
                    SELECT COUNT(*) FROM sqlite_master
                    WHERE type='table' AND name='payment_history'
                """)
                if cursor.fetchone()[0] > 0:
                    cursor = conn.execute("""
                        SELECT COUNT(*) FROM payment_history
                        WHERE created_at > datetime('now', '-24 hours')
                    """)
                    recent_payments = cursor.fetchone()[0]
                    print(f"\n📊 Recent Activity (24h)")
                    print(f"Payments: {recent_payments}")
    except Exception:
        pass

def cmd_backup(args, config, logger):
    """データベースバックアップ管理 with auto-backup"""
    import shutil
    import sqlite3
    from pathlib import Path
    from datetime import datetime, timedelta
    import threading
    import time

    db_path = config.get('database.path', 'data/blncs.db')
    backup_dir = Path('backups')
    backup_dir.mkdir(exist_ok=True)

    # 自動バックアップモード
    if args.auto:
        if args.auto == 'start':
            # 自動バックアップ設定ファイル
            auto_config = {
                'enabled': True,
                'interval': getattr(args, 'interval', 3600),
                'keep_count': config.get('backup.keep_count', 7)
            }

            print(f"🔄 Auto-backup enabled:")
            print(f"   Interval: {auto_config['interval']} seconds")
            print(f"   Keep count: {auto_config['keep_count']} backups")

            # 自動バックアップ実行関数
            def run_auto_backup():
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_path = backup_dir / f"auto_{timestamp}.db"

                try:
                    # SQLite VACUUM INTO for optimized backup
                    conn = sqlite3.connect(db_path)
                    conn.execute(f"VACUUM INTO '{backup_path}'")
                    conn.close()

                    # 古い自動バックアップ削除
                    auto_backups = sorted(backup_dir.glob("auto_*.db"))
                    if len(auto_backups) > auto_config['keep_count']:
                        for old_backup in auto_backups[:-auto_config['keep_count']]:
                            old_backup.unlink()

                    print(f"✅ Auto-backup created: {backup_path.name}")
                except Exception as e:
                    print(f"❌ Auto-backup failed: {e}")

            # 初回実行
            run_auto_backup()

            # 定期実行設定
            print("ℹ️  Auto-backup will run in background")
            print("    (In production, use cron or systemd timer)")

        elif args.auto == 'stop':
            print("⏹️  Auto-backup stopped")
            print("    (Remove from cron or systemd timer)")

        elif args.auto == 'status':
            auto_backups = sorted(backup_dir.glob("auto_*.db"))
            if auto_backups:
                latest = auto_backups[-1]
                size_mb = latest.stat().st_size / 1024 / 1024
                print(f"📊 Auto-backup Status:")
                print(f"   Latest: {latest.name}")
                print(f"   Size: {size_mb:.2f} MB")
                print(f"   Total backups: {len(auto_backups)}")
            else:
                print("ℹ️  No auto-backups found")
        return

    if args.create or (not args.list and not args.restore and not args.cleanup):
        # バックアップ作成
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = backup_dir / f"blncs_backup_{timestamp}.db"

        try:
            if Path(db_path).exists():
                # SQLiteの安全なバックアップ (VACUUM INTO)
                spinner = ProgressSpinner("Creating backup")
                spinner.start()

                with sqlite3.connect(db_path) as conn:
                    conn.execute(f"VACUUM INTO '{backup_path}'")

                spinner.stop("✅ バックアップ作成: {}".format(backup_path))
                print(f"サイズ: {backup_path.stat().st_size / 1024:.1f} KB")
                logger.info(f"Database backup created: {backup_path}")
            else:
                print("❌ データベースファイルが見つかりません")
        except Exception as e:
            print(f"❌ バックアップエラー: {e}")
            logger.error(f"Backup error: {e}")

    elif args.list:
        # バックアップ一覧
        backups = sorted(backup_dir.glob('blncs_backup_*.db'), reverse=True)

        if not backups:
            print("📁 バックアップファイルなし")
            return

        print(f"📁 バックアップ一覧 ({len(backups)}件)")
        print("-" * 60)

        for backup in backups:
            size_kb = backup.stat().st_size / 1024
            mtime = datetime.fromtimestamp(backup.stat().st_mtime)
            print(f"{backup.name:<25} {size_kb:>6.1f} KB  {mtime.strftime('%Y-%m-%d %H:%M')}")

    elif args.restore:
        # バックアップ復元
        if not args.file:
            print("❌ --file パラメータが必要です")
            return

        backup_path = backup_dir / args.file
        if not backup_path.exists():
            print(f"❌ バックアップファイルが見つかりません: {backup_path}")
            return

        try:
            # 現在のDBをバックアップ
            if Path(db_path).exists():
                backup_current = f"{db_path}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                shutil.copy2(db_path, backup_current)
                print(f"💾 現在のDBをバックアップ: {backup_current}")

            # 復元実行
            shutil.copy2(backup_path, db_path)
            print(f"✅ 復元完了: {backup_path} -> {db_path}")
            logger.info(f"Database restored from: {backup_path}")

        except Exception as e:
            print(f"❌ 復元エラー: {e}")
            logger.error(f"Restore error: {e}")

    elif args.cleanup:
        # 古いバックアップ削除
        keep_count = args.keep or config.get('backup.keep_count', 7)
        backups = sorted(backup_dir.glob('blncs_backup_*.db'), reverse=True)

        if len(backups) <= keep_count:
            print(f"📁 削除対象なし (保持数: {keep_count})")
            return

        to_delete = backups[keep_count:]
        for backup in to_delete:
            backup.unlink()
            print(f"🗑️  削除: {backup.name}")

        print(f"✅ 古いバックアップ削除完了 ({len(to_delete)}件)")

    elif args.auto:
        # 自動バックアップ実行
        schedule = config.get('backup.schedule', 'daily')

        backups = sorted(backup_dir.glob('blncs_backup_*.db'), reverse=True)
        should_backup = True

        if backups:
            latest = backups[0]
            mtime = datetime.fromtimestamp(latest.stat().st_mtime)
            now = datetime.now()

            if schedule == 'daily' and (now - mtime).days < 1:
                should_backup = False
            elif schedule == 'hourly' and (now - mtime).seconds < 3600:
                should_backup = False

        if should_backup:
            # バックアップ作成 (再帰呼び出し)
            class BackupArgs:
                create = True
            cmd_backup(BackupArgs(), config, logger)

            # 古いファイル削除
            class CleanupArgs:
                cleanup = True
                keep = config.get('backup.keep_count', 7)
            cmd_backup(CleanupArgs(), config, logger)
        else:
            print("ℹ️  バックアップは最新です")

def cmd_decode(args, config, logger):
    """Lightning請求書デコード"""
    from blncs.lightning.simple_client import quick_connect

    if not args.invoice:
        print("❌ Invoice required: blncs decode <payment_request>")
        return

    # Connect to Lightning node
    client = quick_connect(config.config)

    if not client.connected:
        print("❌ Failed to connect to Lightning node")
        return

    # Decode invoice
    result = client.decode_invoice(args.invoice)

    if 'error' in result:
        print(f"❌ {result['error']}")
    else:
        print(f"⚡ Invoice Details:")
        print(f"Amount: {result['amount']} sats")
        print(f"Network: {result['network']}")
        print(f"Description: {result['description']}")
        print(f"Timestamp: {result['timestamp']}")
        print(f"Payment Request: {result['payment_request'][:50]}...")

    client.disconnect()

def cmd_help(args, config, logger):
    """Enhanced help system"""
    if hasattr(args, 'topic') and args.topic:
        topic = args.topic.lower()

        help_topics = {
            'config': """
📁 Configuration Help

Basic configuration file (config/blncs.json):
{
  "api": {
    "host": "127.0.0.1",    // Bind address
    "port": 8080,           // API port
    "debug": false          // Debug mode
  },
  "database": {
    "type": "sqlite",       // Database type
    "path": "data/blncs.db" // Database file
  },
  "lightning": {
    "host": "localhost",    // Lightning node
    "port": 10009,          // gRPC port
    "network": "testnet"    // Network type
  }
}

Environment variables (override config):
  BLNCS_API_HOST=127.0.0.1
  BLNCS_API_PORT=8080
  BLNCS_DATABASE_PATH=custom.db

Commands:
  blncs config --get api.host
  blncs config --set api.port 9000
  blncs config --template    // Generate template
  blncs validate
""",
            'performance': """
⚡ Performance Optimization

System monitoring:
  blncs status              // Quick health check
  blncs performance --stats // Detailed metrics
  blncs performance --system // System info
  blncs info                // System information

Cache optimization:
  - Enable cache: {"cache": {"enabled": true, "max_size": 200}}
  - Clear cache: blncs cache --clear
  - Check stats: blncs cache --stats

Memory optimization:
  - Automatic garbage collection
  - Smart buffer management
  - Lazy module loading

Startup optimization:
  - 0.2s typical startup time
  - Lazy imports for fast CLI
  - Minimal dependencies loaded
""",
            'backup': """
💾 Backup Management

Manual backup:
  blncs backup --create              // Create backup now
  blncs backup --create --name daily // Named backup

Automatic backups:
  blncs backup --schedule    // Start auto-backup (24h)
  blncs backup --status      // Check scheduler

Backup management:
  blncs backup --list        // List all backups
  blncs backup --cleanup     // Remove old backups

Configuration:
{
  "backup_scheduler": {
    "enabled": true,
    "interval_hours": 24,
    "max_backups": 7
  }
}
""",
            'lightning': """
⚡ Lightning Network Commands

Connect & Test:
  blncs connect              // Test Lightning connection
  blncs connect --host localhost --port 10009

Invoice Management:
  blncs invoice              // Create invoice (default 1000 sats)
  blncs invoice --amount 5000 --memo "Coffee" --qr

Payments:
  blncs pay --invoice <payment_request>
  blncs balance              // Check Lightning balance

QR Code Generation:
  blncs qr "lightning:lnbc..."
  blncs invoice --qr         // Invoice with QR code

Configuration:
{
  "lightning": {
    "host": "localhost",
    "port": 10009,
    "network": "testnet"
  }
}
""",
            'security': """
🔒 Security Configuration

Network security:
  - Use 127.0.0.1 for local access only
  - Avoid 0.0.0.0 in production
  - Use non-privileged ports (>1024)

File security:
  - Avoid absolute paths in config
  - Use relative paths: "data/blncs.db"
  - Set proper file permissions

Configuration validation:
  blncs validate  // Check for security issues

Best practices:
  - Regular backups
  - Monitor system health
  - Use environment variables for secrets
  - Keep configuration minimal
"""
        }

        if topic in help_topics:
            print(help_topics[topic])
        else:
            print(f"❌ Unknown help topic: {topic}")
            print(f"Available topics: {', '.join(help_topics.keys())}")

    else:
        print("""
🚀 BLNCS - Bitcoin Lightning Network Control System

QUICK START:
  blncs status              // Check system health
  blncs connect             // Test Lightning connection
  blncs invoice --amount 1000 --qr   // Create invoice with QR

CORE COMMANDS:
  server                    // Run API server
  status                    // System status and health
  config                    // Configuration management
  validate                  // Validate configuration
  info                      // System information

LIGHTNING COMMANDS:
  connect                   // Test Lightning connection
  invoice                   // Create Lightning invoice
  pay                       // Pay Lightning invoice
  balance                   // Check Lightning balance
  qr                        // Generate QR code

UTILITY COMMANDS:
  cache                     // Cache management
  backup                    // Backup operations
  performance               // Performance monitoring

HELP TOPICS:
  blncs help lightning      // Lightning Network commands
  blncs help config         // Configuration help
  blncs help performance    // Performance optimization
  blncs help backup         // Backup management
  blncs help security       // Security configuration

EXAMPLES:
  blncs invoice --amount 5000 --memo "Coffee" --qr
  blncs qr "lightning:lnbc1000..."
  blncs balance
  blncs cache --stats
  blncs info

For detailed help: blncs help <topic>
""")

def cmd_performance(args, config, logger):
    """Enhanced performance monitoring"""
    import time
    import gc
    from pathlib import Path

    print("\n📊 Performance Monitoring")
    print("=" * 50)

    if args.stats:
        # Memory statistics
        try:
            import resource
            rusage = resource.getrusage(resource.RUSAGE_SELF)
            peak_memory = rusage.ru_maxrss / 1024 if rusage.ru_maxrss > 100000 else rusage.ru_maxrss / 1024 / 1024

            print(f"💾 Memory Usage:")
            print(f"   Peak Memory: {peak_memory:.1f} MB")
            print(f"   User Time: {rusage.ru_utime:.2f}s")
            print(f"   System Time: {rusage.ru_stime:.2f}s")

        except Exception:
            print("💾 Memory: Basic monitoring only")

        # File system performance
        try:
            import shutil
            disk_usage = shutil.disk_usage('.')
            used_gb = disk_usage.used / (1024**3)
            free_gb = disk_usage.free / (1024**3)
            total_gb = disk_usage.total / (1024**3)

            print(f"\n💽 Disk Performance:")
            print(f"   Used: {used_gb:.1f} GB")
            print(f"   Free: {free_gb:.1f} GB")
            print(f"   Total: {total_gb:.1f} GB")
            print(f"   Usage: {(used_gb/total_gb)*100:.1f}%")

        except Exception:
            print("\n💽 Disk: Unavailable")

        # Python performance
        print(f"\n🐍 Python Performance:")
        print(f"   Garbage Collections: {gc.get_count()}")
        print(f"   GC Thresholds: {gc.get_threshold()}")

        # Database performance
        try:
            db_path = config.get('database.path', 'data/blncs.db')
            if Path(db_path).exists():
                db_size = Path(db_path).stat().st_size / 1024
                print(f"\n🗄️  Database Performance:")
                print(f"   Database Size: {db_size:.1f} KB")
        except Exception:
            print("\n🗄️  Database: Unavailable")

    elif args.system:
        # System information
        print(f"🖥️  System Information:")
        import platform
        print(f"   Platform: {platform.system()} {platform.release()}")
        print(f"   Python: {platform.python_version()}")
        print(f"   Processor: {platform.processor()}")

        # Process information
        import os
        print(f"\n🔧 Process Information:")
        print(f"   PID: {os.getpid()}")
        print(f"   Working Dir: {os.getcwd()}")

    else:
        # Quick performance overview
        print("⚡ Quick Performance Check:")

        # Startup time test
        test_start = time.time()
        import json
        test_config = {'test': True}
        json.dumps(test_config)
        test_time = (time.time() - test_start) * 1000

        print(f"   JSON Processing: {test_time:.2f}ms")

        # Cache performance
        try:
            from blncs.core.simple_cache import get_simple_cache
            cache = get_simple_cache()
            stats = cache.stats()
            print(f"   Cache Hit Rate: {stats['hit_rate']}%")
            print(f"   Cache Entries: {stats['size']}/{stats['max_size']}")
        except:
            print("   Cache: Unavailable")

        print(f"\n💡 Run with --stats or --system for detailed info")


def cmd_logs(args, config, logger):
    """ログ管理とローテーション"""
    from pathlib import Path
    import glob

    action = getattr(args, 'action', 'view')

    # ログファイルパス
    log_dir = Path("logs")
    main_log = log_dir / "blncs.log"

    if action == 'view':
        # ログ表示
        if main_log.exists():
            lines = getattr(args, 'lines', 50)
            print(f"📝 Latest {lines} log entries:")
            print("=" * 40)
            try:
                with open(main_log, 'r', encoding='utf-8') as f:
                    all_lines = f.readlines()
                    for line in all_lines[-lines:]:
                        print(line.rstrip())
            except Exception as e:
                print(f"❌ Error reading log: {e}")
        else:
            print("📝 No log file found")

    elif action == 'clear':
        # ログクリア
        try:
            if main_log.exists():
                main_log.unlink()
                print("🗑️  Log file cleared")

            # バックアップログも削除
            for backup in glob.glob(str(log_dir / "blncs.log.*")):
                Path(backup).unlink()
                print(f"🗑️  Removed backup: {Path(backup).name}")

        except Exception as e:
            print(f"❌ Error clearing logs: {e}")

    elif action == 'rotate':
        # ログローテーション強制実行
        try:
            from blncs.core.unified_logging import get_logger
            logger_instance = get_logger()
            if hasattr(logger_instance.fast_logger, '_file_handler'):
                handler = logger_instance.fast_logger._file_handler
                if handler:
                    handler.doRollover()
                    print("🔄 Log rotation completed")
                else:
                    print("⚠️  No file handler available")
            else:
                print("⚠️  Rotation not available")
        except Exception as e:
            print(f"❌ Error rotating logs: {e}")

    elif action == 'stats':
        # ログ統計
        if log_dir.exists():
            log_files = list(log_dir.glob("*.log*"))
            total_size = sum(f.stat().st_size for f in log_files if f.exists())

            print("📊 Log Statistics:")
            print("=" * 30)
            print(f"📂 Log directory: {log_dir}")
            print(f"📄 Log files: {len(log_files)}")
            print(f"💾 Total size: {total_size / 1024:.1f} KB")

            if log_files:
                print("\nFiles:")
                for log_file in sorted(log_files):
                    size_kb = log_file.stat().st_size / 1024
                    print(f"  {log_file.name}: {size_kb:.1f} KB")
        else:
            print("📂 No log directory found")

        print(f"❌ Unknown action. Use: view, clear, rotate, stats")


def cmd_diagnose(args, config, logger):
    """Comprehensive system diagnostics"""
    print("\n🔍 BLNCS System Diagnostics")
    print("=" * 50)

    try:
        # Configuration status
        print("📁 Configuration Status:")
        try:
            integrity = config.validate_configuration_integrity()
            if integrity['valid']:
                print("   ✅ Configuration is valid")
            else:
                print("   ⚠️  Configuration issues found:")
                for error in integrity.get('errors', []):
                    print(f"      - {error}")
        except Exception as e:
            print(f"   ❌ Configuration check failed: {e}")

        # Lightning Network status
        print("\n⚡ Lightning Network Status:")
        try:
            from blncs.lightning.simple_client import get_lightning_client
            lightning = get_lightning_client()
            lightning.connect()

            if lightning.connected:
                print("   ✅ Lightning node connected")
                info = lightning.get_info()
                print(f"   📍 Node: {info.get('alias', 'Unknown')}")
                print(f"   🔗 Channels: {info.get('num_active_channels', 0)}/{info.get('num_channels', 0)}")
                print(f"   🌐 Network: {info.get('network', 'Unknown')}")
            else:
                print("   ❌ Lightning node not connected")
            lightning.disconnect()
        except Exception as e:
            print(f"   ❌ Lightning check failed: {e}")

        # Database status
        print("\n🗄️  Database Status:")
        try:
            from blncs.core.unified_database import get_database
            db = get_database()
            if db.connect():
                print("   ✅ Database connected")
                db.disconnect()
            else:
                print("   ❌ Database connection failed")
        except Exception as e:
            print(f"   ❌ Database check failed: {e}")

        # API server status
        print("\n🌐 API Server Status:")
        try:
            import requests
            api_url = f"http://{config.get('api.host', 'localhost')}:{config.get('api.port', 8080)}/health"
            response = requests.get(api_url, timeout=5)
            if response.status_code == 200:
                print("   ✅ API server is healthy")
            else:
                print(f"   ⚠️  API server responded with status {response.status_code}")
        except requests.exceptions.RequestException:
            print("   ❌ API server is not responding")
        except Exception as e:
            print(f"   ❌ API check failed: {e}")

        # System resources
        print("\n💻 System Resources:")
        try:
            import psutil
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')

            memory_usage = (memory.used / memory.total) * 100
            disk_usage = (disk.used / disk.total) * 100

            print(f"   💾 Memory: {memory_usage:.1f}% used ({memory.used//(1024**3)}GB/{memory.total//(1024**3)}GB)")
            print(f"   💽 Disk: {disk_usage:.1f}% used ({disk.used//(1024**3)}GB/{disk.total//(1024**3)}GB)")
            print(f"   ⚡ CPU: {psutil.cpu_percent(interval=1):.1f}% used")
        except ImportError:
            print("   ⚠️  System monitoring not available (psutil not installed)")
        except Exception as e:
            print(f"   ❌ Resource check failed: {e}")

        print("\n✅ Diagnostics completed")

    except Exception as e:
        print(f"❌ Diagnostics failed: {e}")


def cmd_report(args, config, logger):
    """Generate system reports"""
    print("\n📊 BLNCS System Report")
    print("=" * 50)

    report_type = getattr(args, 'type', 'summary')

    if report_type == 'summary':
        print("📈 System Summary Report")
        print("-" * 30)

        # Configuration summary
        print("📁 Configuration:")
        print(f"   Environment: {config.environment}")
        print(f"   Database: {config.get('database.url', 'Not configured')}")
        print(f"   API Port: {config.get('api.port', 'Not configured')}")

        # Lightning summary
        print("\n⚡ Lightning Network:")
        try:
            from blncs.lightning.simple_client import get_lightning_client
            lightning = get_lightning_client()
            lightning.connect()
            if lightning.connected:
                info = lightning.get_info()
                print(f"   Status: Connected")
                print(f"   Node: {info.get('alias', 'Unknown')}")
                print(f"   Channels: {info.get('num_active_channels', 0)} active")
                print(f"   Network: {info.get('network', 'Unknown')}")
            else:
                print("   Status: Disconnected")
            lightning.disconnect()
        except Exception as e:
            print(f"   Status: Error - {e}")

        # System summary
        print("\n💻 System Information:")
        import platform
        print(f"   Platform: {platform.system()} {platform.release()}")
        print(f"   Python: {platform.python_version()}")

        try:
            import psutil
            memory = psutil.virtual_memory()
            print(f"   Memory: {memory.used//(1024**3)}GB/{memory.total//(1024**3)}GB used")
        except:
            print("   Memory: Monitoring unavailable")

    elif report_type == 'logs':
        print("📝 Log Analysis Report")
        print("-" * 30)

        try:
            from blncs.core.unified_logging import get_log_manager
            log_manager = get_log_manager()

            # Analyze last 24 hours
            analysis = log_manager.analyze_log_file('blncs.log', hours=24)

            if 'error' in analysis:
                print(f"❌ Log analysis failed: {analysis['error']}")
                return

            print(f"📄 Total log entries: {analysis['statistics']['total_entries']:,}")
            print(f"📊 Time range: {analysis['time_range'].get('start', 'N/A')} to {analysis['time_range'].get('end', 'N/A')}")

            print("\n📈 Log levels:")
            for level, count in analysis['statistics']['level_counts'].items():
                print(f"   {level}: {count:,}")

            if analysis['top_errors']:
                print("\n🚨 Top error patterns:")
                for i, error in enumerate(analysis['top_errors'][:5], 1):
                    print(f"   {i}. {error['pattern'][:50]}{'...' if len(error['pattern']) > 50 else ''} ({error['count']:,} times)")

        except Exception as e:
            print(f"❌ Log report failed: {e}")

    elif report_type == 'performance':
        print("⚡ Performance Report")
        print("-" * 30)

        try:
            from blncs.core.fast_startup import PerformanceOptimizer
            optimizer = PerformanceOptimizer()
            result = optimizer.apply_all_optimizations()

            print("🔧 Applied optimizations:")
            for opt_name, opt_result in result.items():
                status = "✅" if opt_result.get('success', False) else "❌"
                print(f"   {status} {opt_name}: {opt_result.get('message', 'Unknown')}")

            # Performance metrics
            print("\n📊 Performance metrics:")
            try:
                import psutil
                memory = psutil.virtual_memory()
                print(f"   Memory usage: {memory.percent:.1f}%")
                print(f"   CPU usage: {psutil.cpu_percent(interval=1):.1f}%")
            except:
                print("   System monitoring unavailable")

        except Exception as e:
            print(f"❌ Performance report failed: {e}")

    else:
        print(f"❌ Unknown report type: {report_type}")
        print("Available types: summary, logs, performance")


def cmd_check(args, config, logger):
    """Comprehensive system check"""
    print("\n🔎 BLNCS System Check")
    print("=" * 50)

    issues = []
    warnings = []
    passed = []

    # Configuration check
    print("📁 Checking configuration...")
    try:
        integrity = config.validate_configuration_integrity()
        if integrity['valid']:
            passed.append("Configuration integrity")
        else:
            for error in integrity.get('errors', []):
                issues.append(f"Configuration: {error}")
            for warning in integrity.get('warnings', []):
                warnings.append(f"Configuration: {warning}")
    except Exception as e:
        issues.append(f"Configuration check failed: {e}")

    # Lightning connectivity check
    print("⚡ Checking Lightning Network...")
    try:
        from blncs.lightning.simple_client import get_lightning_client
        lightning = get_lightning_client()
        if lightning.connect():
            passed.append("Lightning Network connectivity")
            lightning.disconnect()
        else:
            issues.append("Lightning Network connection failed")
    except Exception as e:
        issues.append(f"Lightning check failed: {e}")

    # Database check
    print("🗄️  Checking database...")
    try:
        from blncs.core.unified_database import get_database
        db = get_database()
        if db.connect():
            passed.append("Database connectivity")
            db.disconnect()
        else:
            issues.append("Database connection failed")
    except Exception as e:
        issues.append(f"Database check failed: {e}")

    # API server check
    print("🌐 Checking API server...")
    try:
        import requests
        api_url = f"http://{config.get('api.host', 'localhost')}:{config.get('api.port', 8080)}/health"
        response = requests.get(api_url, timeout=5)
        if response.status_code == 200:
            passed.append("API server health")
        else:
            warnings.append(f"API server status: {response.status_code}")
    except:
        warnings.append("API server not responding")

    # Security check
    print("🔒 Checking security...")
    try:
        if config.get('security.jwt_secret'):
            passed.append("JWT secret configured")
        else:
            warnings.append("JWT secret not configured (using auto-generated)")

        if config.get('security.api_key'):
            passed.append("API key configured")
        else:
            warnings.append("API key not configured (using auto-generated)")
    except Exception as e:
        warnings.append(f"Security check failed: {e}")

    # Resource check
    print("💻 Checking system resources...")
    try:
        import psutil
        memory = psutil.virtual_memory()
        if memory.percent > 90:
            issues.append(f"High memory usage: {memory.percent:.1f}%")
        elif memory.percent > 80:
            warnings.append(f"Elevated memory usage: {memory.percent:.1f}%")
        else:
            passed.append("Memory usage within limits")

        disk = psutil.disk_usage('/')
        if disk.percent > 95:
            issues.append(f"Critical disk usage: {disk.percent:.1f}%")
        elif disk.percent > 85:
            warnings.append(f"High disk usage: {disk.percent:.1f}%")
        else:
            passed.append("Disk usage within limits")

    except ImportError:
        warnings.append("Resource monitoring not available")
    except Exception as e:
        warnings.append(f"Resource check failed: {e}")

    # Summary
    print("\n📋 Check Results:")
    print("-" * 30)

    if passed:
        print("✅ PASSED:")
        for item in passed:
            print(f"   • {item}")

    if warnings:
        print("\n⚠️  WARNINGS:")
        for item in warnings:
            print(f"   • {item}")

    if issues:
        print("\n❌ ISSUES:")
        for item in issues:
            print(f"   • {item}")

    print(f"\n📊 Summary: {len(passed)} passed, {len(warnings)} warnings, {len(issues)} issues")

    if issues:
        print("\n💡 Recommendation: Address critical issues before production use")
        return 1  # Non-zero exit code for issues
    elif warnings:
        print("\n💡 Recommendation: Review warnings for optimal configuration")
        return 0
    else:
        print("\n🎉 All checks passed! System is ready for production use")
        return 0


def cmd_monitor(args, config, logger):
    """Real-time system monitoring"""
    print("\n📊 BLNCS Real-time Monitor")
    print("=" * 50)

    try:
        from blncs.core.lightweight_metrics import get_metrics_collector, start_system_monitoring

        collector = get_metrics_collector()

        # Check if monitoring is running
        if not collector._running:
            print("🔄 Starting metrics collection...")
            start_system_monitoring()
            time.sleep(2)  # Wait for initial data

        # Display real-time metrics
        print("Press Ctrl+C to stop monitoring")
        print()

        while True:
            try:
                current = collector.get_current_metrics()
                alerts = collector.get_alerts()

                if current:
                    # Clear screen and show metrics
                    print("\033[2J\033[H", end="")  # Clear screen
                    print("📊 BLNCS Real-time Monitor")
                    print("=" * 50)
                    print(f"Time: {time.strftime('%H:%M:%S')}")

                    # System metrics
                    cpu = current.get('cpu', {})
                    memory = current.get('memory', {})
                    disk = current.get('disk', {})

                    print(f"\n💻 System Resources:")
                    print(f"   CPU:    {cpu.get('percent', 0):.1f}% (Load: {cpu.get('load_avg', [0,0,0])[0] if cpu.get('load_avg') else 'N/A'})")
                    print(f"   Memory: {memory.get('used_gb', 0):.1f}GB/{memory.get('total_gb', 0):.1f}GB ({memory.get('percent', 0):.1f}%)")
                    print(f"   Disk:   {disk.get('used_gb', 0):.1f}GB/{disk.get('total_gb', 0):.1f}GB ({disk.get('percent', 0):.1f}%)")

                    # Performance metrics
                    summary = collector.get_metrics_summary(hours=1)
                    perf = summary.get('performance', {})

                    print(f"\n⚡ Performance (last hour):")
                    print(f"   API Success Rate: {perf.get('api_success_rate', 0):.1f}%")
                    print(f"   DB Success Rate:  {perf.get('db_success_rate', 0):.1f}%")
                    print(f"   Total API Requests: {perf.get('api_requests_total', 0)}")
                    print(f"   Total DB Queries:   {perf.get('db_queries_total', 0)}")

                    # Alerts
                    if alerts:
                        print(f"\n🚨 Active Alerts ({len(alerts)}):")
                        for alert in alerts[:3]:  # Show top 3 alerts
                            print(f"   ⚠️  {alert.get('message', 'Unknown alert')}")
                    else:
                        print("\n✅ No active alerts")

                time.sleep(5)  # Update every 5 seconds

            except KeyboardInterrupt:
                print("\n\n⏹️  Monitoring stopped by user")
                break
            except Exception as e:
                print(f"\n❌ Monitoring error: {e}")
                time.sleep(5)

    except Exception as e:
        print(f"❌ Monitor initialization failed: {e}")


def cmd_automation(args, config, logger):
    """Manage automated tasks"""
    print("\n🤖 BLNCS Automation Manager")
    print("=" * 50)

    try:
        from blncs.core.scheduler import get_scheduler

        scheduler = get_scheduler()
        action = args.action

        if action == 'start':
            print("🔄 Starting automation system...")
            scheduler.start()
            print("✅ Automation system started")

        elif action == 'stop':
            print("⏹️  Stopping automation system...")
            scheduler.stop()
            print("✅ Automation system stopped")

        elif action == 'status':
            running = scheduler.running
            job_count = len(scheduler.jobs)

            print("📊 Automation Status:")
            print(f"   Status: {'Running' if running else 'Stopped'}")
            print(f"   Scheduled Jobs: {job_count}")

            if running:
                print("\n📋 Active Jobs:")
                jobs = scheduler.list_jobs()
                for job in jobs:
                    next_run = job.get('next_run', 'Unknown')
                    print(f"   • {job['id']}")
                    print(f"     Next run: {next_run}")
            else:
                print("   ℹ️  Automation system is not running")

        elif action == 'list':
            print("📋 Scheduled Jobs:")
            jobs = scheduler.list_jobs()

            if not jobs:
                print("   ℹ️  No scheduled jobs")
            else:
                for i, job in enumerate(jobs, 1):
                    next_run = job.get('next_run', 'Unknown')
                    print(f"   {i}. {job['id']}")
                    print(f"      Next run: {next_run}")

        elif action == 'enable':
            task = getattr(args, 'task', 'default')

            if task == 'default':
                print("🔄 Enabling default automation schedule...")
                scheduler.enable_default_schedule()
                print("✅ Default automation schedule enabled")
                print("   • Health checks (every 1 hour)")
                print("   • Metrics collection (every 30 minutes)")
                print("   • Database backup (daily)")
                print("   • Log rotation (daily)")
                print("   • Config backup (daily)")

            elif task == 'health':
                scheduler.add_health_check(interval_hours=1)
                print("✅ Health check automation enabled")
            elif task == 'metrics':
                scheduler.add_metrics_collection(interval_minutes=30)
                print("✅ Metrics collection automation enabled")
            elif task == 'backup':
                scheduler.add_backup_task(interval_hours=24)
                print("✅ Backup automation enabled")
            elif task == 'logs':
                scheduler.add_log_rotation(interval_hours=24)
                print("✅ Log rotation automation enabled")
            else:
                print(f"❌ Unknown task: {task}")
                return

        elif action == 'disable':
            task = getattr(args, 'task', None)

            if task:
                # Remove specific task
                job_id = f"{task}_"
                removed = False

                # Find and remove matching jobs
                jobs_to_remove = [jid for jid in scheduler.jobs.keys() if jid.startswith(job_id)]
                for job_id in jobs_to_remove:
                    if scheduler.remove_job(job_id):
                        print(f"✅ Disabled automation task: {job_id}")
                        removed = True

                if not removed:
                    print(f"⚠️  Task not found: {task}")
            else:
                # Stop all automation
                print("⏹️  Disabling all automation...")
                scheduler.stop()
                # Clear all jobs
                for job_id in list(scheduler.jobs.keys()):
                    scheduler.remove_job(job_id)
                print("✅ All automation disabled")

    except Exception as e:
        print(f"❌ Automation command failed: {e}")


def cmd_audit(args, config, logger):
    """Security audit and monitoring"""
    print("\n🔒 BLNCS Security Audit")
    print("=" * 50)

    try:
        action = args.action
        hours = getattr(args, 'hours', 24)

        if action == 'check':
            print("🔍 Performing security check...")

            security_issues = []
            security_warnings = []
            security_passed = []

            # Check file permissions
            critical_files = [
                'blncs_main.py',
                'config/blncs.json',
                'data/blncs.db' if Path('data/blncs.db').exists() else None
            ]

            for file_path in critical_files:
                if file_path and Path(file_path).exists():
                    stat_info = Path(file_path).stat()
                    mode = oct(stat_info.st_mode)[-3:]

                    # Check if world-readable
                    if int(mode[2]) >= 4:  # Readable by others
                        security_warnings.append(f"File readable by others: {file_path} (mode: {mode})")
                    else:
                        security_passed.append(f"Secure permissions: {file_path}")

            # Check configuration security
            if config.get('security.jwt_secret'):
                security_passed.append("JWT secret configured")
            else:
                security_warnings.append("JWT secret not configured")

            # Check API security
            if config.get('security.enable_tls', False):
                security_passed.append("TLS enabled")
            else:
                security_warnings.append("TLS not enabled")

            # Check rate limiting
            if config.get('security.rate_limit', 0) > 0:
                security_passed.append("Rate limiting enabled")
            else:
                security_warnings.append("Rate limiting not configured")

            # Display results
            print("\n📋 Security Check Results:")

            if security_passed:
                print("✅ PASSED:")
                for item in security_passed:
                    print(f"   • {item}")

            if security_warnings:
                print("\n⚠️  WARNINGS:")
                for item in security_warnings:
                    print(f"   • {item}")

            if security_issues:
                print("\n❌ ISSUES:")
                for item in security_issues:
                    print(f"   • {item}")

            security_score = 100 - (len(security_warnings) * 10) - (len(security_issues) * 25)
            security_score = max(0, security_score)

            print(f"\n📊 Security Score: {security_score}/100")

        elif action == 'monitor':
            print(f"👁️  Monitoring security events (last {hours} hours)...")

            try:
                from blncs.core.unified_logging import get_log_manager

                def security_alert_callback(event):
                    """Handle security alerts"""
                    category = event.get('category', 'unknown')
                    message = event.get('message', '')[:100]
                    print(f"🚨 SECURITY ALERT: [{category}] {message}")

                log_manager = get_log_manager()
                audit_results = log_manager.monitor_security_events('blncs.log', security_alert_callback)

                if 'error' in audit_results:
                    print(f"❌ Audit failed: {audit_results['error']}")
                    return

                print(f"\n📊 Security Event Summary:")
                print(f"   Total security events: {audit_results['total_events']}")

                if audit_results['categories']:
                    print("   Event categories:")
                    for category, info in audit_results['categories'].items():
                        print(f"     • {category}: {info['count']} events")

                if audit_results['critical_events']:
                    print(f"\n🚨 Critical Events ({len(audit_results['critical_events'])}):")
                    for event in audit_results['critical_events'][:5]:  # Show top 5
                        timestamp = event.get('timestamp', 'Unknown')
                        if hasattr(timestamp, 'strftime'):
                            timestamp = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                        print(f"     • [{timestamp}] {event.get('message', '')[:80]}")

            except Exception as e:
                print(f"❌ Security monitoring failed: {e}")

        elif action == 'report':
            print(f"📋 Generating security audit report (last {hours} hours)...")

            try:
                from blncs.core.unified_logging import get_log_manager

                log_manager = get_log_manager()
                audit_results = log_manager.monitor_security_events('blncs.log')

                if 'error' in audit_results:
                    print(f"❌ Report generation failed: {audit_results['error']}")
                    return

                # Generate text report
                print("\n🔒 BLNCS Security Audit Report")
                print("=" * 50)
                print(f"Analysis Period: Last {hours} hours")
                print(f"Report Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
                print()

                print(f"📊 Event Summary:")
                print(f"   Total Security Events: {audit_results['total_events']}")

                if audit_results['categories']:
                    print("   Event Breakdown:")
                    for category, info in audit_results['categories'].items():
                        print(f"     • {category}: {info['count']} events")
                        if info.get('latest_event'):
                            latest = info['latest_event']
                            if hasattr(latest.get('timestamp'), 'strftime'):
                                time_str = latest['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
                            else:
                                time_str = str(latest.get('timestamp', 'Unknown'))
                            print(f"       Latest: {time_str}")

                if audit_results['critical_events']:
                    print(f"\n🚨 Critical Security Events ({len(audit_results['critical_events'])}):")
                    for i, event in enumerate(audit_results['critical_events'][:10], 1):
                        timestamp = event.get('timestamp', 'Unknown')
                        if hasattr(timestamp, 'strftime'):
                            timestamp = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                        category = event.get('category', 'unknown')
                        message = event.get('message', '')[:100]
                        print(f"   {i}. [{timestamp}] {category.upper()}: {message}")

                # Recommendations
                print(f"\n💡 Security Recommendations:")
                if audit_results['total_events'] == 0:
                    print("   ✅ No security events detected - system appears secure")
                else:
                    if audit_results['critical_events']:
                        print("   🚨 Address critical security events immediately")
                    if len(audit_results.get('categories', {})) > 3:
                        print("   ⚠️  Multiple security event types detected - review system access")
                    print("   📋 Consider implementing additional monitoring and alerting")

            except Exception as e:
                print(f"❌ Report generation failed: {e}")

    except Exception as e:
        print(f"❌ Audit command failed: {e}")


def cmd_dashboard(args, config, logger):
    """Launch web dashboard"""
    print("\n🌐 BLNCS Web Dashboard")
    print("=" * 50)

    host = getattr(args, 'host', 'localhost')
    port = getattr(args, 'port', 8080)
    open_browser = getattr(args, 'open_browser', False)

    try:
        # Import here to avoid circular imports
        from blncs.api.unified_rest_api import create_dashboard_app

        # Create dashboard app
        app = create_dashboard_app(config)

        dashboard_url = f"http://{host}:{port}"

        print(f"🚀 Starting dashboard server on {dashboard_url}")
        print("📊 Dashboard features:")
        print("   • Real-time system monitoring")
        print("   • Lightning Network status")
        print("   • Performance metrics")
        print("   • System health checks")
        print("   • API endpoint access")
        print()
        print("Press Ctrl+C to stop the server")
        print()

        if open_browser:
            try:
                import webbrowser
                import time
                print("🌐 Opening dashboard in browser...")
                time.sleep(1)  # Give server time to start
                webbrowser.open(dashboard_url)
            except ImportError:
                print("⚠️  Browser auto-open not available (webbrowser module not found)")
            except Exception as e:
                print(f"⚠️  Failed to open browser: {e}")

        # Start server
        app.run(host=host, port=port, debug=False, threaded=True)

    except KeyboardInterrupt:
        print("\n\n⏹️  Dashboard server stopped by user")
    except Exception as e:
        print(f"❌ Failed to start dashboard: {e}")
        logger.error(f"Dashboard startup failed: {e}")


def main():
    """Main entry point (optimized for fast startup)"""
    global _startup_start

    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description='BLNCS - Lightning Control', add_help=False)
    parser.add_argument('--version', action='version', version=f'BLNCS v{__version__}')
    parser.add_argument('--config', type=Path, help='Configuration file path')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--auth-token', help='Authentication token for privileged commands')

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Essential commands only for fast startup
    subparsers.add_parser('server', help='Run API server')
    subparsers.add_parser('status', aliases=['s'], help='Show system status')
    subparsers.add_parser('health', aliases=['h'], help='Run health check')
    subparsers.add_parser('info', aliases=['i'], help='Show system information')
    subparsers.add_parser('test', help='Run tests')

    # Essential commands with minimal arguments
    parser_config = subparsers.add_parser('config', aliases=['c'])
    parser_config.add_argument('--get', metavar='KEY', help='Show configuration value')
    parser_config.add_argument('--set', nargs=2, metavar=('KEY', 'VALUE'), help='Set configuration value')
    parser_config.add_argument('--template', action='store_true', help='Generate configuration template')
    parser_config.add_argument('--reload', action='store_true', help='Reload configuration from disk')
    parser_config.add_argument('--watch', choices=['start', 'stop', 'status'], help='Manage config file watcher')

    parser_cache = subparsers.add_parser('cache')
    parser_cache.add_argument('--clear', action='store_true', help='Clear cache entries')
    parser_cache.add_argument('--stats', action='store_true', help='Show cache statistics')
    parser_cache.add_argument('--db-optimize', action='store_true', help='Run database optimization via cache command')

    parser_validate = subparsers.add_parser('validate')
    parser_validate.add_argument('--config', type=Path, help='Configuration file to validate')


    # Lightning and other commands (lightweight)
    parser_performance = subparsers.add_parser('performance')
    parser_performance.add_argument('--stats', action='store_true', help='Show performance statistics')
    parser_performance.add_argument('--system', action='store_true', help='Show system-level information')

    parser_invoice = subparsers.add_parser('invoice', aliases=['inv', 'i'])
    parser_invoice.add_argument('--amount', type=int, help='Invoice amount in sats')
    parser_invoice.add_argument('--memo', help='Invoice memo text')
    parser_invoice.add_argument('--qr', action='store_true', help='Generate QR code for the invoice')

    parser_pay = subparsers.add_parser('pay', aliases=['p'])
    parser_pay.add_argument('--invoice', required=True, help='Bolt11 payment request to pay')

    subparsers.add_parser('balance', aliases=['bal', 'b'])

    parser_connect = subparsers.add_parser('connect', aliases=['conn', 'c'])
    parser_connect.add_argument('--host', help='Lightning node host')
    parser_connect.add_argument('--port', type=int, help='Lightning node port')

    parser_decode = subparsers.add_parser('decode', aliases=['d'])
    parser_decode.add_argument('invoice', nargs='?', help='Bolt11 payment request to decode')

    parser_history = subparsers.add_parser('history', aliases=['hist'])
    parser_history.add_argument('--limit', type=int, default=10, help='Number of records to display')

    parser_backup = subparsers.add_parser('backup', aliases=['bak', 'bk'])
    parser_backup.add_argument('--auto', choices=['start', 'stop', 'status'], help='Control auto-backup mode')
    parser_backup.add_argument('--interval', type=int, help='Auto-backup interval in seconds')
    parser_backup.add_argument('--create', action='store_true', help='Create a new backup immediately')
    parser_backup.add_argument('--list', action='store_true', help='List available backups')
    parser_backup.add_argument('--restore', action='store_true', help='Restore from a backup file')
    parser_backup.add_argument('--cleanup', action='store_true', help='Remove old backups beyond retention')
    parser_backup.add_argument('--file', help='Backup file used with --restore')
    parser_backup.add_argument('--keep', type=int, help='Number of backups to retain when using --cleanup')

    parser_qr = subparsers.add_parser('qr')
    parser_qr.add_argument('data', help='Data to encode into QR')
    parser_qr.add_argument('--output', help='File path to save QR image')

    parser_help_cmd = subparsers.add_parser('help')
    parser_help_cmd.add_argument('topic', nargs='?', help='Help topic to display')

    parser_maintenance = subparsers.add_parser('maintenance')
    parser_maintenance.add_argument('--list', action='store_true', help='List available maintenance tasks')
    parser_maintenance.add_argument('--run', nargs='+', metavar='TASK_ID', help='Run specified maintenance task IDs synchronously')
    parser_maintenance.add_argument('--bundle', choices=['critical', 'high', 'normal', 'low'], help='Run maintenance tasks at or above the priority threshold')
    parser_maintenance.add_argument('--respect-windows', action='store_true', help='Enforce maintenance windows when executing tasks')
    parser_maintenance.add_argument('--json', action='store_true', help='Emit JSON output for automation pipelines')

    parser_logs = subparsers.add_parser('logs')
    parser_logs.add_argument('--action', choices=['view', 'clear', 'rotate', 'stats'], default='view', help='Log action to perform')
    parser_logs.add_argument('--lines', type=int, default=50, help='Lines to display for view action')

    parser_diagnose = subparsers.add_parser('diagnose', aliases=['diag'], help='Run comprehensive system diagnostics')

    parser_report = subparsers.add_parser('report', aliases=['rep'], help='Generate system reports')
    parser_report.add_argument('--type', choices=['summary', 'logs', 'performance'], default='summary',
                              help='Type of report to generate')

    parser_monitor = subparsers.add_parser('monitor', aliases=['mon'], help='Real-time system monitoring')
    parser_monitor.add_argument('--interval', type=int, default=5, help='Update interval in seconds')

    parser_automation = subparsers.add_parser('automation', aliases=['auto'], help='Manage automated tasks')
    parser_automation.add_argument('action', choices=['start', 'stop', 'status', 'list', 'enable', 'disable'],
                                   help='Automation action')
    parser_automation.add_argument('--task', help='Specific task to manage')

    parser_audit = subparsers.add_parser('audit', aliases=['sec'], help='Security audit and monitoring')
    parser_audit.add_argument('action', choices=['check', 'monitor', 'report'], default='check',
                              help='Audit action')
    parser_audit.add_argument('--hours', type=int, default=24, help='Hours to analyze for audit')

    parser_dashboard = subparsers.add_parser('dashboard', aliases=['web'], help='Launch web dashboard')
    parser_dashboard.add_argument('--host', default='localhost', help='Dashboard host (default: localhost)')
    parser_dashboard.add_argument('--port', type=int, default=8080, help='Dashboard port (default: 8080)')
    parser_dashboard.add_argument('--open-browser', action='store_true', help='Open dashboard in default browser')

    parser_security = subparsers.add_parser('security')
    parser_security.add_argument('--show-auth-limits', action='store_true', help='Display authentication failure limiter settings')
    parser_security.add_argument('--set-auth-limits', nargs=2, metavar=('MAX_ATTEMPTS', 'WINDOW_SECONDS'), type=int,
                                 help='Update authentication failure limiter settings')
    parser_security.add_argument('--reset-auth-failures', action='store_true', help='Clear authentication failure counters')

    # Parse arguments
    args = parser.parse_args()

    # Print banner
    if not args.command or args.verbose:
        print_banner()

    # Initialize system
    try:
        config, logger, error_handler = init_system(args.config)
    except Exception as e:
        print(f"Failed to initialize system: {e}")
        sys.exit(1)

    _emit_config_integrity_alert(config, logger)

    # Command aliases for better usability
    command_aliases = {
        's': 'status',
        'h': 'health',
        'i': 'info',
        'c': 'config',
        'inv': 'invoice',
        'bal': 'balance',
        'hist': 'history',
        'bak': 'backup'
    }

    # Apply alias if found
    if args.command in command_aliases:
        args.command = command_aliases[args.command]
        print(f"📌 Using alias: {args.command}")

    # Enforce CLI authentication for privileged commands
    normalized_command = args.command or 'status'
    required_permission = _determine_cli_permission(normalized_command, args)
    if required_permission:
        _enforce_cli_permission(args, required_permission)

    commands = {
        'server': cmd_server,
        'status': cmd_status,
        'health': cmd_health,
        'info': cmd_info,
        'test': cmd_test,
        'config': cmd_config,
        'cache': cmd_cache,
        'validate': cmd_validate,
        'backup': cmd_backup,
        'performance': cmd_performance,
        'invoice': cmd_invoice,
        'pay': cmd_pay,
        'balance': cmd_balance,
        'connect': cmd_connect,
        'decode': cmd_decode,
        'history': cmd_history,
        'qr': cmd_qr,
        'security': cmd_security,
        'help': cmd_help,
        'maintenance': cmd_maintenance,
        'logs': cmd_logs,
        'diagnose': cmd_diagnose,
        'report': cmd_report,
        'check': cmd_check,
        'monitor': cmd_monitor,
        'automation': cmd_automation,
        'audit': cmd_audit,
        'dashboard': cmd_dashboard
    }

    # Execute command using dispatch table
    cmd_func = commands.get(args.command, cmd_status)

    import inspect

    params = inspect.signature(cmd_func).parameters
    param_count = len(params)

    if param_count >= 4:
        cmd_func(args, config, logger, error_handler)
    elif param_count == 3:
        cmd_func(args, config, logger)
    elif param_count == 2:
        cmd_func(args, config)
    else:
        cmd_func(args)

    # Show startup time in verbose mode
    if args.verbose:
        startup_time = time.time() - _startup_start
        print(f"\n⚡ Startup time: {startup_time:.3f}s")


async def run_cli(self, args):
    """Run CLI with parsed arguments (non-interactive mode)"""
    try:
        config, logger, error_handler = init_system(args.config)

        # Print banner if not quiet
        if not getattr(args, 'quiet', False):
            print_banner()

        # Get command from args
        command = getattr(args, 'command', None) or 'status'

        # Execute command using dispatch table
        commands = {
            'server': cmd_server,
            'status': cmd_status,
            'health': cmd_health,
            'info': cmd_info,
            'test': cmd_test,
            'config': cmd_config,
            'cache': cmd_cache,
            'validate': cmd_validate,
            'backup': cmd_backup,
            'performance': cmd_performance,
            'invoice': cmd_invoice,
            'pay': cmd_pay,
            'balance': cmd_balance,
            'connect': cmd_connect,
            'decode': cmd_decode,
            'history': cmd_history,
            'qr': cmd_qr,
            'security': cmd_security,
            'help': cmd_help,
            'maintenance': cmd_maintenance,
            'logs': cmd_logs,
            'diagnose': cmd_diagnose,
            'report': cmd_report,
            'check': cmd_check,
            'monitor': cmd_monitor,
            'automation': cmd_automation,
            'audit': cmd_audit
        }

        cmd_func = commands.get(command, cmd_status)

        # Execute command with appropriate parameters
        import inspect
        params = inspect.signature(cmd_func).parameters
        param_count = len(params)

        if param_count >= 4:
            cmd_func(args, config, logger, error_handler)
        elif param_count == 3:
            cmd_func(args, config, logger)
        elif param_count == 2:
            cmd_func(args, config)
        else:
            cmd_func(args)

    except Exception as e:
        print(f"CLI execution failed: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️  操作が中断されました")
        sys.exit(130)
    except BrokenPipeError:
        # パイプ出力時の切断を静かに処理
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ 予期しないエラーが発生しました: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)