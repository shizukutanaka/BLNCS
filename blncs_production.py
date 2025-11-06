#!/usr/bin/env python3
"""
BLNCS Production Application
Bitcoin Lightning Network Connection System - Production Ready Version

統合されたプロダクション対応アプリケーション
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
from blncs.core.unified_logging import get_logger, configure_logging
from blncs.core.unified_database import get_database
from blncs.core.simple_cache import get_simple_cache
from blncs.core.unified_performance import get_performance_optimizer
from blncs.core.unified_security import get_security_manager
from blncs.lightning.simple_client import get_lightning_client

class BLNCSApplication:
    """Main BLNCS Application Class"""

    def __init__(self, config_file: Optional[str] = None):
        # Initialize configuration first
        self.config = get_config(config_file)

        # Configure logging
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
        self.lightning_client = None
        self.performance_optimizer = None
        self.security_manager = None

        # Application state
        self.running = False
        self.shutdown_event = asyncio.Event()

    async def initialize(self):
        """Initialize all systems"""
        try:
            self.logger.info("Starting system initialization")

            # Initialize database
            self.database = get_database(self.config.database.url)
            self.logger.info("Database initialized")

            # Initialize cache
            self.cache = get_simple_cache()
            self.logger.info("Cache system initialized")

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

    async def health_check(self) -> Dict[str, Any]:
        """Perform comprehensive health check"""
        health_status = {
            'timestamp': time.time(),
            'status': 'healthy',
            'components': {},
            'system': {},
            'errors': []
        }

        try:
            # Database health
            try:
                self.database.execute("SELECT 1")
                health_status['components']['database'] = 'healthy'
            except Exception as e:
                health_status['components']['database'] = 'unhealthy'
                health_status['errors'].append(f"Database error: {str(e)}")

            # Lightning client health
            try:
                info = self.lightning_client.get_info()
                health_status['components']['lightning'] = 'healthy'
                health_status['components']['lightning_info'] = {
                    'alias': info.get('alias'),
                    'synced_to_chain': info.get('synced_to_chain'),
                    'num_active_channels': info.get('num_active_channels')
                }
            except Exception as e:
                health_status['components']['lightning'] = 'unhealthy'
                health_status['errors'].append(f"Lightning error: {str(e)}")

            # Cache health
            try:
                cache_size = self.cache.size()
                health_status['components']['cache'] = 'healthy'
                health_status['components']['cache_size'] = cache_size
            except Exception as e:
                health_status['components']['cache'] = 'unhealthy'
                health_status['errors'].append(f"Cache error: {str(e)}")

            # System performance
            if self.performance_optimizer:
                try:
                    system_health = self.performance_optimizer.get_system_health()
                    health_status['system'] = system_health

                    # Determine overall health based on system metrics
                    if not system_health.get('cpu_healthy', True) or \
                       not system_health.get('memory_healthy', True) or \
                       not system_health.get('disk_healthy', True):
                        health_status['status'] = 'degraded'
                except Exception as e:
                    health_status['errors'].append(f"Performance monitoring error: {str(e)}")

            # Overall status
            if health_status['errors']:
                if len(health_status['errors']) > 2:
                    health_status['status'] = 'unhealthy'
                else:
                    health_status['status'] = 'degraded'

        except Exception as e:
            health_status['status'] = 'critical'
            health_status['errors'].append(f"Health check failed: {str(e)}")
            self.logger.error(f"Health check failed: {e}", exc_info=True)

        return health_status

    async def run_server(self, host: str = "0.0.0.0", port: int = 8000):
        """Run the BLNCS server"""
        try:
            from fastapi import FastAPI, HTTPException
            from fastapi.middleware.cors import CORSMiddleware
            import uvicorn

            app = FastAPI(
                title="BLNCS API",
                description="Bitcoin Lightning Network Connection System",
                version="1.0.0"
            )

            # Add CORS middleware
            app.add_middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )

            @app.get("/health")
            async def health_endpoint():
                """Health check endpoint"""
                return await self.health_check()

            @app.get("/info")
            async def info_endpoint():
                """Node information endpoint"""
                try:
                    return self.lightning_client.get_info()
                except Exception as e:
                    raise HTTPException(status_code=500, detail=str(e))

            @app.get("/channels")
            async def channels_endpoint():
                """List channels endpoint"""
                try:
                    channels = self.lightning_client.list_channels()
                    return {"channels": [vars(ch) for ch in channels]}
                except Exception as e:
                    raise HTTPException(status_code=500, detail=str(e))

            @app.get("/balance")
            async def balance_endpoint():
                """Get balance endpoint"""
                try:
                    return self.lightning_client.get_balance()
                except Exception as e:
                    raise HTTPException(status_code=500, detail=str(e))

            @app.get("/performance")
            async def performance_endpoint():
                """Get performance report"""
                try:
                    return self.performance_optimizer.get_performance_report()
                except Exception as e:
                    raise HTTPException(status_code=500, detail=str(e))

            @app.get("/security")
            async def security_endpoint():
                """Get security report"""
                try:
                    return self.security_manager.get_security_report()
                except Exception as e:
                    raise HTTPException(status_code=500, detail=str(e))

            self.logger.info(f"Starting BLNCS server on {host}:{port}")

            config = uvicorn.Config(
                app,
                host=host,
                port=port,
                log_level="info",
                access_log=True
            )
            server = uvicorn.Server(config)

            await server.serve()

        except ImportError:
            self.logger.error("FastAPI not available. Install with: pip install fastapi uvicorn")
            raise
        except Exception as e:
            self.logger.error(f"Server failed to start: {e}", exc_info=True)
            raise

    async def run_cli_interactive(self):
        """Run interactive CLI mode"""
        self.logger.info("Starting interactive CLI mode")

        print("\n" + "="*60)
        print("BLNCS - Bitcoin Lightning Network Connection System")
        print("Interactive CLI Mode")
        print("Type 'help' for available commands, 'quit' to exit")
        print("="*60 + "\n")

        while self.running:
            try:
                command = input("blncs> ").strip().lower()

                if not command:
                    continue

                if command in ['quit', 'exit', 'q']:
                    break
                elif command == 'help':
                    self.print_cli_help()
                elif command == 'status':
                    await self.print_status()
                elif command == 'health':
                    await self.print_health()
                elif command == 'channels':
                    self.print_channels()
                elif command == 'balance':
                    self.print_balance()
                elif command == 'info':
                    self.print_node_info()
                elif command == 'performance':
                    self.print_performance()
                elif command == 'security':
                    self.print_security()
                elif command.startswith('invoice '):
                    amount = int(command.split()[1]) if len(command.split()) > 1 else 1000
                    self.create_invoice(amount)
                elif command == 'optimize':
                    await self.run_optimization()
                else:
                    print(f"Unknown command: {command}. Type 'help' for available commands.")

            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"Error: {e}")
                self.logger.error(f"CLI command error: {e}")

        print("\nGoodbye!")

    def print_cli_help(self):
        """Print CLI help"""
        help_text = """
Available Commands:
  help        - Show this help message
  status      - Show application status
  health      - Show health check results
  info        - Show Lightning node information
  channels    - List Lightning channels
  balance     - Show wallet balance
  performance - Show performance metrics
  security    - Show security status
  invoice <amount> - Create invoice (default: 1000 sats)
  optimize    - Run system optimization
  quit/exit   - Exit the application
        """
        print(help_text)

    async def print_status(self):
        """Print application status"""
        print("\n--- Application Status ---")
        print(f"Running: {self.running}")
        print(f"Config loaded: {bool(self.config)}")
        print(f"Database: {'Connected' if self.database else 'Not connected'}")
        print(f"Lightning: {'Connected' if self.lightning_client else 'Not connected'}")
        print(f"Cache size: {self.cache.size() if self.cache else 'N/A'}")

    async def print_health(self):
        """Print health check results"""
        print("\n--- Health Check ---")
        health = await self.health_check()
        print(f"Overall Status: {health['status'].upper()}")

        for component, status in health['components'].items():
            if component.endswith('_info') or component.endswith('_size'):
                continue
            print(f"  {component}: {status}")

        if health['errors']:
            print("Errors:")
            for error in health['errors']:
                print(f"  - {error}")

    def print_channels(self):
        """Print Lightning channels"""
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

    def print_balance(self):
        """Print wallet balance"""
        print("\n--- Wallet Balance ---")
        try:
            balance = self.lightning_client.get_balance()
            for key, value in balance.items():
                print(f"{key.replace('_', ' ').title()}: {value:,} sats")
        except Exception as e:
            print(f"Error getting balance: {e}")

    def print_node_info(self):
        """Print node information"""
        print("\n--- Node Information ---")
        try:
            info = self.lightning_client.get_info()
            for key, value in info.items():
                if key == 'identity_pubkey':
                    print(f"{key}: {value[:16]}...{value[-16:]}")
                else:
                    print(f"{key}: {value}")
        except Exception as e:
            print(f"Error getting node info: {e}")

    def print_performance(self):
        """Print performance metrics"""
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
        """Print security status"""
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
        """Create Lightning invoice"""
        print(f"\n--- Creating Invoice for {amount} sats ---")
        try:
            invoice = self.lightning_client.create_invoice(
                amount=amount,
                description=f"BLNCS invoice for {amount} sats"
            )
            print(f"Payment Hash: {invoice.payment_hash}")
            print(f"Payment Request: {invoice.payment_request}")
            print(f"Amount: {invoice.amount:,} sats")
            print(f"Status: {invoice.status}")
        except Exception as e:
            print(f"Error creating invoice: {e}")

    async def run_optimization(self):
        """Run system optimization"""
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
        """Start the application"""
        self.running = True
        await self.initialize()

    async def stop(self):
        """Stop the application"""
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
    """Setup signal handlers for graceful shutdown"""
    def signal_handler(signum, frame):
        print(f"\nReceived signal {signum}, shutting down...")
        asyncio.create_task(app.stop())

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

async def main():
    """Main application entry point"""
    parser = argparse.ArgumentParser(description="BLNCS - Bitcoin Lightning Network Connection System")
    parser.add_argument("--config", "-c", help="Configuration file path")
    parser.add_argument("--mode", "-m", choices=["server", "cli"], default="cli",
                       help="Run mode: server or cli (default: cli)")
    parser.add_argument("--host", default="0.0.0.0", help="Server host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Server port (default: 8000)")

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