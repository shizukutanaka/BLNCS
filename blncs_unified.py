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

__version__ = "2.0.0"

_startup_start = time.time()

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
        self.logger.info("Initializing BLNCS Application")

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
                self.logger.info("Database connected")
            else:
                self.logger.warning("Database connection failed")

            # Initialize cache
            self.cache = get_simple_cache()
            self.logger.info("Cache initialized")

            # Initialize performance optimizer
            self.performance_optimizer = get_performance_optimizer()
            self.performance_optimizer.register_cache(self.cache)
            self.logger.info("Performance optimizer initialized")

            # Initialize security manager
            self.security_manager = get_security_manager()
            self.logger.info("Security manager initialized")

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
                self.logger.info("Lightning Network client connected")
            else:
                self.logger.warning("Lightning Network client connection failed")

            self.logger.info("System initialization completed successfully")

        except Exception as e:
            self.logger.critical(f"System initialization failed: {e}", exc_info=True)
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
        self.logger.info(f"Starting server on {host}:{port}")

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
                self.logger.info("Shutdown signal received")
                server.should_exit = True

            loop = asyncio.get_event_loop()
            for sig in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(sig, signal_handler)

            await server.serve()

        except Exception as e:
            self.logger.error(f"Server error: {e}")
            raise

    def run_cli_status(self):
        """ステータス表示"""
        print(f"BLNCS v{__version__} - Bitcoin Lightning Network Control System")
        print("=" * 60)

        health = self.get_health_status()

        print(f"Overall Status: {health['status'].upper()}")
        print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(health['timestamp']))}")
        print()

        for component, status in health['components'].items():
            emoji = "✅" if status == 'ok' else "⚠️" if status == 'warning' else "❌"
            print(f"{emoji} {component.capitalize()}: {status.upper()}")

        print()

        # Lightning info
        if self.lightning_client:
            try:
                info = self.lightning_client.get_info()
                print("Lightning Network:")
                print(f"  Node ID: {info.get('node_id', 'N/A')[:20]}...")
                print(f"  Alias: {info.get('alias', 'N/A')}")
                print(f"  Network: {info.get('network', 'N/A')}")
                print(f"  Block Height: {info.get('block_height', 'N/A')}")
            except Exception as e:
                print(f"Lightning Network: Error - {e}")

        print()

        # Performance metrics
        if self.performance_optimizer:
            try:
                report = self.performance_optimizer.get_performance_report()
                if 'current_metrics' in report:
                    metrics = report['current_metrics']
                    print("Performance Metrics:")
                    print(f"  CPU Usage: {metrics.get('cpu_percent', 0):.1f}%")
                    print(f"  Memory Usage: {metrics.get('memory_percent', 0):.1f}%")
                    print(f"  Active Threads: {metrics.get('thread_count', 0)}")
            except Exception as e:
                print(f"Performance Metrics: Error - {e}")

    async def run_cli_interactive(self):
        """インタラクティブCLIモード"""
        print(f"BLNCS v{__version__} - Interactive Mode")
        print("Type 'help' for commands or 'quit' to exit")
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
                    print(f"Health Status: {health['status']}")
                    for component, status in health['components'].items():
                        print(f"  {component}: {status}")
                elif command.startswith('invoice'):
                    parts = command.split()
                    if len(parts) >= 2:
                        amount = int(parts[1])
                        self.create_invoice(amount)
                    else:
                        print("Usage: invoice <amount>")
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
                elif command == 'optimize':
                    await self.run_optimization()
                else:
                    print(f"Unknown command: {command}")

            except KeyboardInterrupt:
                print("\nUse 'quit' to exit")
            except Exception as e:
                print(f"Error: {e}")

    def print_help(self):
        """ヘルプ表示"""
        print("Available Commands:")
        print("  help        - Show this help")
        print("  status      - Show system status")
        print("  health      - Show health check")
        print("  balance     - Show wallet balance")
        print("  channels    - Show Lightning channels")
        print("  node        - Show node information")
        print("  performance - Show performance metrics")
        print("  security    - Show security status")
        print("  optimize    - Run system optimization")
        print("  invoice     - Create Lightning invoice")
        print("  quit        - Exit application")

    def print_balance(self):
        """残高表示"""
        print("\n--- Wallet Balance ---")
        try:
            balance = self.lightning_client.get_balance()
            for key, value in balance.items():
                print(f"{key.replace('_', ' ').title()}: {value:,} sats")
        except Exception as e:
            print(f"Error getting balance: {e}")

    def print_channels(self):
        """チャネル表示"""
        print("\n--- Lightning Channels ---")
        try:
            channels = self.lightning_client.list_channels()
            if not channels:
                print("No channels found")
                return

            for i, channel in enumerate(channels, 1):
                print(f"{i}. Channel ID: {channel.get('channel_id', 'N/A')}")
                print(f"   Peer: {channel.get('peer_id', 'N/A')[:16]}...")
                print(f"   Capacity: {channel.get('capacity', 0):,} sats")
                print(f"   Local: {channel.get('local_balance', 0):,} sats")
                print(f"   Remote: {channel.get('remote_balance', 0):,} sats")
                print(f"   Active: {channel.get('active', False)}")
                print()
        except Exception as e:
            print(f"Error getting channels: {e}")

    def print_node_info(self):
        """ノード情報表示"""
        print("\n--- Node Information ---")
        try:
            info = self.lightning_client.get_info()
            for key, value in info.items():
                if key == 'node_id':
                    print(f"{key}: {value[:16]}...{value[-16:]}")
                else:
                    print(f"{key}: {value}")
        except Exception as e:
            print(f"Error getting node info: {e}")

    def print_performance(self):
        """パフォーマンス表示"""
        print("\n--- Performance Metrics ---")
        try:
            report = self.performance_optimizer.get_performance_report()
            system_health = report.get('system_health', {})

            print(f"CPU Usage: {system_health.get('cpu_percent', 'N/A')}%")
            print(f"Memory Usage: {system_health.get('memory_percent', 'N/A')}%")
            print(f"Disk Usage: {system_health.get('disk_percent', 'N/A')}%")
            print(f"Memory Available: {system_health.get('memory_available_gb', 'N/A'):.1f} GB")

            profiler_stats = report.get('profiler_stats', {})
            if profiler_stats:
                print("\nOperation Statistics:")
                for op, stats in profiler_stats.items():
                    print(f"  {op}: {stats.get('count', 0)} calls, avg {stats.get('avg_time', 0):.3f}s")

        except Exception as e:
            print(f"Error getting performance metrics: {e}")

    def print_security(self):
        """セキュリティ表示"""
        print("\n--- Security Status ---")
        try:
            report = self.security_manager.get_security_report()
            print(f"Active Tokens: {report.get('active_tokens', 0)}")
            print(f"Locked Accounts: {report.get('locked_accounts', 0)}")
            print(f"Failed Login Attempts: {report.get('failed_login_attempts', 0)}")

            events = report.get('security_events', {})
            severity_counts = events.get('severity_counts', {})
            if severity_counts:
                print("Recent Security Events:")
                for severity, count in severity_counts.items():
                    print(f"  {severity}: {count}")

        except Exception as e:
            print(f"Error getting security status: {e}")

    def create_invoice(self, amount: int):
        """インボイス作成"""
        print(f"\n--- Creating Invoice for {amount} sats ---")
        try:
            invoice = self.lightning_client.create_invoice(
                amount=amount,
                description=f"BLNCS invoice for {amount} sats"
            )
            print(f"Payment Hash: {invoice.get('payment_hash', 'N/A')}")
            print(f"Payment Request: {invoice.get('payment_request', 'N/A')}")
            print(f"Amount: {invoice.get('amount', 0):,} sats")
            print(f"Status: {invoice.get('status', 'N/A')}")
        except Exception as e:
            print(f"Error creating invoice: {e}")

    async def run_optimization(self):
        """最適化実行"""
        print("\n--- Running System Optimization ---")
        try:
            result = self.performance_optimizer.optimize_system()
            print("Optimization completed:")

            cache_opt = result.get('cache_optimization', {})
            if cache_opt:
                print("Cache Optimization:")
                for cache_name, action in cache_opt.items():
                    print(f"  {cache_name}: {action}")

            db_recommendations = result.get('database_recommendations', [])
            if db_recommendations:
                print("Database Recommendations:")
                for rec in db_recommendations:
                    print(f"  - {rec}")

        except Exception as e:
            print(f"Error during optimization: {e}")

    async def start(self):
        """アプリケーション開始"""
        self.running = True
        await self.initialize()

    async def stop(self):
        """アプリケーション停止"""
        self.logger.info("Shutting down BLNCS Application")
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
        self.logger.info("BLNCS Application shutdown completed")

def setup_signal_handlers(app: BLNCSApplication):
    """シグナルハンドラーの設定"""
    def signal_handler(signum, frame):
        print(f"\nReceived signal {signum}, shutting down...")
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
            await app.run_cli_interactive()

    except KeyboardInterrupt:
        print("\nShutdown requested")
    except Exception as e:
        app.logger.critical(f"Application failed: {e}", exc_info=True)
        return 1
    finally:
        await app.stop()

    return 0

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
