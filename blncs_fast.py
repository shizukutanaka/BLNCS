#!/usr/bin/env python3
"""
BLNCS - Bitcoin Lightning Network Connection System
Optimized Fast Entry Point with Performance Enhancements
"""

import argparse
import os
import sys
import time
import asyncio
import json
import signal
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor

# Performance monitoring
BLNCS_TIMING = os.getenv('BLNCS_TIMING', '0') == '1'
start_time = time.perf_counter() if BLNCS_TIMING else 0

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Lazy imports for faster startup
_modules_cache: Dict[str, Any] = {}

def lazy_import(module_name: str, attribute: Optional[str] = None):
    """Lazy import mechanism for performance optimization"""
    if module_name not in _modules_cache:
        if BLNCS_TIMING:
            import_start = time.perf_counter()

        if module_name == 'core':
            from blncs.core import (
                config_manager, logger, metrics, health,
                error_resilience, performance_optimizer,
                resource_manager, shutdown
            )
            _modules_cache[module_name] = {
                'config_manager': config_manager,
                'logger': logger,
                'metrics': metrics,
                'health': health,
                'error_resilience': error_resilience,
                'performance_optimizer': performance_optimizer,
                'resource_manager': resource_manager,
                'shutdown': shutdown
            }
        elif module_name == 'lightning':
            from blncs.lightning import channel_manager, payment_manager
            _modules_cache[module_name] = {
                'channel_manager': channel_manager,
                'payment_manager': payment_manager
            }
        elif module_name == 'api':
            from blncs.api import unified_rest_api, websocket_server
            _modules_cache[module_name] = {
                'unified_rest_api': unified_rest_api,
                'websocket_server': websocket_server
            }
        elif module_name == 'monitoring':
            from blncs.monitoring import dashboard
            _modules_cache[module_name] = {'dashboard': dashboard}

        if BLNCS_TIMING:
            print(f"Import {module_name}: {(time.perf_counter() - import_start)*1000:.2f}ms")

    module = _modules_cache[module_name]
    return module.get(attribute) if attribute else module

class BLNCSFastApplication:
    """Optimized BLNCS Application with Performance Enhancements"""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or "config/blncs.json"
        self.components: Dict[str, Any] = {}
        self.executors: Dict[str, Any] = {}
        self.shutdown_event = asyncio.Event()
        self.startup_time = time.perf_counter()

    async def initialize_core(self):
        """Initialize core components with optimizations"""
        try:
            # Initialize config first
            config_mgr = lazy_import('core', 'config_manager')
            self.config = await self._init_component(
                'config',
                lambda: config_mgr.UnifiedConfigManager(self.config_path)
            )

            # Parallel initialization of independent components
            init_tasks = [
                self._init_component('logger', lambda: lazy_import('core', 'logger').UnifiedLogger(self.config)),
                self._init_component('metrics', lambda: lazy_import('core', 'metrics').MetricsCollector()),
                self._init_component('health', lambda: lazy_import('core', 'health').HealthChecker()),
                self._init_component('error_handler', lambda: lazy_import('core', 'error_resilience').ErrorResilience()),
            ]

            await asyncio.gather(*init_tasks, return_exceptions=True)

            # Initialize resource-dependent components
            self.components['performance'] = lazy_import('core', 'performance_optimizer').PerformanceOptimizer()
            self.components['resources'] = lazy_import('core', 'resource_manager').ResourceManager()

            # Setup executors for CPU-bound tasks
            self.executors['thread'] = ThreadPoolExecutor(max_workers=4)
            self.executors['process'] = ProcessPoolExecutor(max_workers=2)

            if BLNCS_TIMING:
                elapsed = (time.perf_counter() - self.startup_time) * 1000
                print(f"Core initialization: {elapsed:.2f}ms")

        except Exception as e:
            print(f"Failed to initialize core: {e}")
            sys.exit(1)

    async def _init_component(self, name: str, factory):
        """Initialize a component with error handling"""
        try:
            if asyncio.iscoroutinefunction(factory):
                self.components[name] = await factory()
            else:
                self.components[name] = factory()
            return self.components[name]
        except Exception as e:
            print(f"Warning: Failed to initialize {name}: {e}")
            return None

    async def initialize_lightning(self):
        """Initialize Lightning Network components"""
        try:
            channel_mgr = lazy_import('lightning', 'channel_manager')
            payment_mgr = lazy_import('lightning', 'payment_manager')

            # Parallel initialization
            await asyncio.gather(
                self._init_component('channels', lambda: channel_mgr.ChannelManager(self.config)),
                self._init_component('payments', lambda: payment_mgr.PaymentManager(self.config))
            )

            if BLNCS_TIMING:
                elapsed = (time.perf_counter() - self.startup_time) * 1000
                print(f"Lightning initialization: {elapsed:.2f}ms")

        except Exception as e:
            print(f"Warning: Lightning components unavailable: {e}")

    async def initialize_api(self):
        """Initialize API components"""
        try:
            api = lazy_import('api', 'unified_rest_api')
            ws = lazy_import('api', 'websocket_server')

            self.components['api'] = api.UnifiedRESTAPI(
                config=self.config,
                lightning_client=self.components.get('channels'),
                metrics_collector=self.components.get('metrics')
            )

            self.components['websocket'] = ws.WebSocketServer(
                config=self.config,
                metrics=self.components.get('metrics')
            )

            if BLNCS_TIMING:
                elapsed = (time.perf_counter() - self.startup_time) * 1000
                print(f"API initialization: {elapsed:.2f}ms")

        except Exception as e:
            print(f"Warning: API components unavailable: {e}")

    async def start_services(self):
        """Start all services"""
        services = []

        # Start API server if available
        if 'api' in self.components and self.components['api']:
            services.append(self.components['api'].start())

        # Start WebSocket server if available
        if 'websocket' in self.components and self.components['websocket']:
            services.append(self.components['websocket'].start())

        # Start monitoring dashboard if configured
        if self.config.get('monitoring', {}).get('dashboard_enabled', False):
            dashboard = lazy_import('monitoring', 'dashboard')
            if dashboard:
                services.append(dashboard.start_dashboard(self.components))

        if services:
            await asyncio.gather(*services, return_exceptions=True)

        if BLNCS_TIMING:
            total_time = (time.perf_counter() - start_time) * 1000
            print(f"\nTotal startup time: {total_time:.2f}ms")
            print(f"Ready to serve requests!")

    async def shutdown(self):
        """Graceful shutdown"""
        print("\nShutting down BLNCS...")

        # Set shutdown event
        self.shutdown_event.set()

        # Shutdown components in reverse order
        shutdown_tasks = []

        for name, component in reversed(list(self.components.items())):
            if hasattr(component, 'shutdown'):
                shutdown_tasks.append(component.shutdown())

        if shutdown_tasks:
            await asyncio.gather(*shutdown_tasks, return_exceptions=True)

        # Shutdown executors
        for executor in self.executors.values():
            executor.shutdown(wait=False)

        print("BLNCS shutdown complete")

    async def run(self):
        """Main application loop"""
        # Setup signal handlers
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda s, f: asyncio.create_task(self.shutdown()))

        try:
            # Initialize components
            await self.initialize_core()
            await self.initialize_lightning()
            await self.initialize_api()

            # Start services
            await self.start_services()

            # Keep running until shutdown
            await self.shutdown_event.wait()

        except KeyboardInterrupt:
            print("\nReceived interrupt signal")
        except Exception as e:
            print(f"Fatal error: {e}")
            if self.components.get('logger'):
                self.components['logger'].error(f"Fatal error: {e}")
        finally:
            await self.shutdown()

class BLNCSCLIOptimized:
    """Optimized CLI with fast command execution"""

    def __init__(self):
        self.parser = self._create_parser()
        self._command_cache = {}

    def _create_parser(self):
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            description='BLNCS - Bitcoin Lightning Network Connection System',
            formatter_class=argparse.RawDescriptionHelpFormatter
        )

        parser.add_argument(
            '--config', '-c',
            help='Configuration file path',
            default='config/blncs.json'
        )

        subparsers = parser.add_subparsers(dest='command', help='Commands')

        # Start command
        subparsers.add_parser('start', help='Start BLNCS server')

        # Check command
        check_parser = subparsers.add_parser('check', help='Health check')
        check_parser.add_argument('--detailed', action='store_true', help='Detailed output')

        # Channel commands
        channel_parser = subparsers.add_parser('channel', help='Channel management')
        channel_parser.add_argument('action', choices=['list', 'open', 'close', 'balance'])
        channel_parser.add_argument('--peer', help='Peer public key')
        channel_parser.add_argument('--amount', type=int, help='Channel amount')

        # Payment commands
        payment_parser = subparsers.add_parser('pay', help='Make payment')
        payment_parser.add_argument('invoice', help='Lightning invoice')
        payment_parser.add_argument('--max-fee', type=int, help='Maximum fee in sats')

        # Invoice commands
        invoice_parser = subparsers.add_parser('invoice', help='Create invoice')
        invoice_parser.add_argument('amount', type=int, help='Amount in sats')
        invoice_parser.add_argument('--memo', help='Invoice memo')

        # Info command
        subparsers.add_parser('info', help='Node information')

        # Benchmark command
        subparsers.add_parser('benchmark', help='Run performance benchmark')

        # Auth management commands
        auth_parser = subparsers.add_parser('auth', help='API key management')
        auth_parser.add_argument(
            '--auth-file',
            help='Authentication storage file path (defaults to config/auth.json)'
        )
        auth_subparsers = auth_parser.add_subparsers(dest='auth_command', help='Auth commands')
        try:
            auth_subparsers.required = True
        except AttributeError:
            pass

        auth_subparsers.add_parser('list', help='List stored API tokens')

        create_parser = auth_subparsers.add_parser('create', help='Create a new API token')
        create_parser.add_argument('token_id', help='Token identifier')
        create_parser.add_argument('--permissions', help='Comma-separated permissions (read,write,admin)')
        create_parser.add_argument(
            '--expires-in',
            type=int,
            help='Expiration window in seconds'
        )
        create_parser.add_argument(
            '--expires-at',
            help='Explicit expiration (epoch seconds or ISO-8601 timestamp)'
        )

        revoke_parser = auth_subparsers.add_parser('revoke', help='Revoke an API token or key')
        revoke_parser.add_argument('identifier', help='Token identifier or API key')

        show_parser = auth_subparsers.add_parser('show', help='Display a single token summary')
        show_parser.add_argument('token_id', help='Token identifier to display')

        rotate_parser = auth_subparsers.add_parser('rotate', help='Rotate an API token')
        rotate_target = rotate_parser.add_mutually_exclusive_group(required=True)
        rotate_target.add_argument('--token-id', help='Token identifier to rotate')
        rotate_target.add_argument('--api-key', help='Existing API key to rotate')
        rotate_parser.add_argument('--permissions', help='New permissions (comma-separated)')
        rotate_parser.add_argument('--expires-in', type=int, help='New expiration window in seconds')
        rotate_parser.add_argument('--expires-at', help='New absolute expiration (epoch or ISO-8601)')

        audit_parser = auth_subparsers.add_parser('audit', help='Show recent authentication audit events')
        audit_parser.add_argument(
            '--log-file',
            default='logs/blncs.log',
            help='Audit log file path (defaults to logs/blncs.log)',
        )
        audit_parser.add_argument(
            '--limit',
            type=int,
            default=20,
            help='Maximum number of events to display (default: 20)',
        )

        stats_parser = auth_subparsers.add_parser('stats', help='Show authentication inventory summary')
        stats_parser.add_argument(
            '--window-seconds',
            type=int,
            default=86_400,
            help='Consider tokens expiring within this window (default: 86400)',
        )

        prune_parser = auth_subparsers.add_parser('prune', help='Prune expired or idle tokens')
        prune_parser.add_argument(
            '--include-expired',
            action='store_true',
            help='Remove expired tokens',
        )
        prune_parser.add_argument(
            '--idle-seconds',
            type=int,
            help='Remove tokens idle for this many seconds',
        )
        prune_parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Simulate pruning without modifying storage',
        )

        return parser

    async def execute_command(self, args):
        """Execute CLI command with optimizations"""
        if args.command == 'start':
            app = BLNCSFastApplication(args.config)
            await app.run()

        elif args.command == 'check':
            await self._health_check(args.config, args.detailed)

        elif args.command == 'channel':
            await self._channel_command(args)

        elif args.command == 'pay':
            await self._payment_command(args)

        elif args.command == 'invoice':
            await self._invoice_command(args)

        elif args.command == 'info':
            await self._info_command(args.config)

        elif args.command == 'benchmark':
            await self._benchmark_command()

        elif args.command == 'auth':
            await self._auth_command(args)

        else:
            self.parser.print_help()

    async def _health_check(self, config_path: str, detailed: bool = False):
        """Perform health check"""
        try:
            health = lazy_import('core', 'health')
            checker = health.HealthChecker()
            status = await checker.check_health()

            if detailed:
                import json
                print(json.dumps(status, indent=2))
            else:
                overall = "HEALTHY" if status.get('healthy', False) else "UNHEALTHY"
                print(f"Status: {overall}")
                if not status.get('healthy', False):
                    for check, result in status.get('checks', {}).items():
                        if not result.get('healthy', False):
                            print(f"  - {check}: {result.get('message', 'Failed')}")
        except Exception as e:
            print(f"Health check failed: {e}")
            sys.exit(1)

    async def _channel_command(self, args):
        """Handle channel commands"""
        try:
            channel_mgr = lazy_import('lightning', 'channel_manager')
            config_mgr = lazy_import('core', 'config_manager')

            config = config_mgr.UnifiedConfigManager(args.config)
            channels = channel_mgr.ChannelManager(config)

            if args.action == 'list':
                channel_list = await channels.list_channels()
                for ch in channel_list:
                    print(f"Channel {ch['channel_id']}: {ch['balance']} sats")

            elif args.action == 'open' and args.peer and args.amount:
                result = await channels.open_channel(args.peer, args.amount)
                print(f"Channel opened: {result}")

            elif args.action == 'balance':
                balance = await channels.get_total_balance()
                print(f"Total balance: {balance} sats")

        except Exception as e:
            print(f"Channel command failed: {e}")
            sys.exit(1)

    async def _payment_command(self, args):
        """Handle payment commands"""
        try:
            payment_mgr = lazy_import('lightning', 'payment_manager')
            config_mgr = lazy_import('core', 'config_manager')

            config = config_mgr.UnifiedConfigManager(args.config)
            payments = payment_mgr.PaymentManager(config)

            result = await payments.pay_invoice(
                args.invoice,
                max_fee=args.max_fee
            )

            if result['success']:
                print(f"Payment successful! Hash: {result['payment_hash']}")
            else:
                print(f"Payment failed: {result.get('error', 'Unknown error')}")

        except Exception as e:
            print(f"Payment failed: {e}")
            sys.exit(1)

    async def _invoice_command(self, args):
        """Handle invoice creation"""
        try:
            payment_mgr = lazy_import('lightning', 'payment_manager')
            config_mgr = lazy_import('core', 'config_manager')

            config = config_mgr.UnifiedConfigManager(args.config)
            payments = payment_mgr.PaymentManager(config)

            invoice = await payments.create_invoice(
                amount=args.amount,
                memo=args.memo or f"BLNCS Invoice {args.amount} sats"
            )

            print(f"Invoice created:")
            print(f"  Payment request: {invoice['payment_request']}")
            print(f"  Amount: {invoice['amount']} sats")

        except Exception as e:
            print(f"Invoice creation failed: {e}")
            sys.exit(1)

    async def _info_command(self, config_path: str):
        """Display node information"""
        try:
            config_mgr = lazy_import('core', 'config_manager')
            config = config_mgr.UnifiedConfigManager(config_path)

            info = {
                "version": "2.0.0-fast",
                "network": config.get('lightning', {}).get('network', 'mainnet'),
                "node_id": config.get('lightning', {}).get('node_id', 'Not configured'),
                "api_enabled": config.get('api', {}).get('enabled', False),
                "monitoring_enabled": config.get('monitoring', {}).get('enabled', False)
            }

            import json
            print(json.dumps(info, indent=2))

        except Exception as e:
            print(f"Info command failed: {e}")
            sys.exit(1)

    async def _benchmark_command(self):
        """Run performance benchmark"""
        print("Running BLNCS Performance Benchmark...")

        benchmarks = []

        # Startup benchmark
        start = time.perf_counter()
        app = BLNCSFastApplication()
        await app.initialize_core()
        core_time = time.perf_counter() - start
        benchmarks.append(('Core initialization', core_time * 1000))

        # Lightning benchmark
        start = time.perf_counter()
        await app.initialize_lightning()
        lightning_time = time.perf_counter() - start
        benchmarks.append(('Lightning initialization', lightning_time * 1000))

        # API benchmark
        start = time.perf_counter()
        await app.initialize_api()
        api_time = time.perf_counter() - start
        benchmarks.append(('API initialization', api_time * 1000))

        # Cleanup
        await app.shutdown()

        # Display results
        print("\nBenchmark Results:")
        print("-" * 40)
        for name, time_ms in benchmarks:
            print(f"{name:<25} {time_ms:>10.2f} ms")
        print("-" * 40)
        total = sum(t for _, t in benchmarks)
        print(f"{'Total':<25} {total:>10.2f} ms")

        # Performance rating
        if total < 100:
            rating = "⚡ EXCELLENT"
        elif total < 500:
            rating = "✅ GOOD"
        elif total < 1000:
            rating = "⚠️  ACCEPTABLE"
        else:
            rating = "❌ NEEDS OPTIMIZATION"

        print(f"\nPerformance Rating: {rating}")

    async def _auth_command(self, args):
        """Handle authentication management commands."""

        try:
            auth = self._get_simple_auth(args.auth_file)
        except Exception as exc:  # pragma: no cover - defensive
            print(f"Auth command failed: {exc}")
            sys.exit(1)

        if args.auth_command == 'list':
            tokens = auth.list_tokens()
            print(json.dumps(tokens, indent=2, ensure_ascii=False))
            return

        if args.auth_command == 'create':
            try:
                permissions = self._parse_permissions_arg(auth, args.permissions)
                expires_at = self._parse_expires_at_arg(args.expires_at)
                api_key = auth.generate_api_key(
                    args.token_id,
                    permissions=permissions,
                    expires_in=args.expires_in,
                    expires_at=expires_at,
                )
            except ValueError as exc:
                print(f"Invalid option: {exc}")
                sys.exit(1)
            except Exception as exc:  # pragma: no cover - defensive
                print(f"Failed to generate API key: {exc}")
                sys.exit(1)

            print("API key created successfully.")
            print(f"Token ID: {args.token_id}")
            print(f"API Key: {api_key}")
            return

        if args.auth_command == 'revoke':
            success = auth.revoke_api_key(args.identifier)
            if success:
                print("API key revoked successfully.")
            else:
                print("No matching API key found.")
            return

        if args.auth_command == 'show':
            summary = auth.get_token(args.token_id)
            if summary is None:
                print("Token not found.")
            else:
                print(json.dumps(summary, indent=2, ensure_ascii=False))
            return

        if args.auth_command == 'rotate':
            permissions = self._parse_permissions_arg(auth, args.permissions)
            expires_at = None
            if args.expires_at is not None:
                try:
                    expires_at = self._parse_expires_at_arg(args.expires_at)
                except ValueError as exc:
                    print(f"Invalid option: {exc}")
                    sys.exit(1)

            try:
                if args.token_id:
                    new_key = auth.rotate_api_key_by_id(
                        args.token_id,
                        permissions=permissions,
                        expires_in=args.expires_in,
                        expires_at=expires_at,
                    )
                else:
                    new_key = auth.rotate_api_key(
                        args.api_key,
                        permissions=permissions,
                        expires_in=args.expires_in,
                        expires_at=expires_at,
                    )
            except ValueError as exc:
                print(f"Invalid option: {exc}")
                sys.exit(1)

            print("API key rotated successfully.")
            print(f"New API Key: {new_key}")
            return

        if args.auth_command == 'audit':
            events = self._read_audit_events(args.log_file, args.limit)
            if not events:
                print('No audit events found.')
            else:
                print(json.dumps(events, indent=2, ensure_ascii=False))
            return

        if args.auth_command == 'stats':
            summary = auth.export_statistics(window_seconds=args.window_seconds)
            print(json.dumps(summary, indent=2, ensure_ascii=False))
            return

        if args.auth_command == 'prune':
            include_expired = args.include_expired or (args.idle_seconds is None)
            result = auth.prune_tokens(
                include_expired=include_expired,
                idle_seconds=args.idle_seconds,
                dry_run=args.dry_run,
            )
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return

    def _get_simple_auth(self, auth_file: Optional[str]):
        from blncs.core.simple_auth import SimpleAuth  # Lazy import

        storage_path = auth_file if auth_file else None
        return SimpleAuth(storage_path=storage_path)

    def _parse_permissions_arg(self, auth, raw: Optional[str]) -> Optional[Dict[str, bool]]:
        if raw is None:
            return None

        return auth._parse_permissions(raw)

    def _parse_expires_at_arg(self, raw: Optional[str]) -> Optional[float]:
        if raw is None:
            return None

        value = raw.strip()
        if not value:
            return None

        if value.isdigit():
            return float(value)

        try:
            timestamp = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("expires-at must be epoch seconds or ISO-8601 timestamp") from exc

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return timestamp.timestamp()

    def _read_audit_events(self, log_path: str, limit: int) -> List[Dict[str, Any]]:
        path = Path(log_path)
        if limit <= 0:
            limit = 1

        if not path.exists() or not path.is_file():
            return []

        try:
            matching_lines: List[str] = []
            with path.open('r', encoding='utf-8', errors='replace') as handle:
                for line in handle:
                    if 'AUTH_KEY_' in line:
                        matching_lines.append(line.strip())
            if not matching_lines:
                return []

            tail = matching_lines[-limit:]
            events: List[Dict[str, Any]] = []
            for entry in tail:
                events.append({"event": entry})
            return events
        except Exception as exc:  # pragma: no cover - defensive
            return [{"error": f"Failed to read log: {exc}"}]

def main():
    """Main entry point"""
    cli = BLNCSCLIOptimized()
    args = cli.parser.parse_args()

    # Set up event loop with optimizations
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        loop.run_until_complete(cli.execute_command(args))
    finally:
        loop.close()

if __name__ == '__main__':
    main()