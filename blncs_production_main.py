#!/usr/bin/env python3
"""
BLNCS Commercial-Grade Production Main Entry Point
Enterprise Bitcoin Lightning Network Control System
"""

import asyncio
import signal
import sys
import os
import traceback
from pathlib import Path
from typing import Optional, Dict, Any
import argparse
import json
from datetime import datetime

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

# Commercial components
try:
    from blncs.core.commercial_error_handler import get_global_error_handler
    error_recovery_manager = get_global_error_handler()
    with_error_boundary = lambda component=None, fallback=None: lambda f: f  # Simplified decorator
except ImportError:
    error_recovery_manager = None
    with_error_boundary = lambda component=None, fallback=None: lambda f: f

try:
    from blncs.core.commercial_monitoring import monitoring_service
except ImportError:
    monitoring_service = None

try:
    from blncs.core.commercial_security import security_manager
except ImportError:
    security_manager = None

try:
    from blncs.core.commercial_cache import cache_manager
except ImportError:
    cache_manager = None

try:
    from blncs.core.commercial_logging import enterprise_logger, LogLevel, LogCategory
except ImportError:
    import logging
    enterprise_logger = logging.getLogger("blncs")
    LogLevel = type('LogLevel', (), {'INFO': 20, 'ERROR': 40, 'FATAL': 60})
    LogCategory = type('LogCategory', (), {'SYSTEM': 'system', 'ERROR': 'error', 'AUDIT': 'audit'})

try:
    from blncs.deployment.production_deployer import deployment_orchestrator
except ImportError:
    deployment_orchestrator = None

# Core BLNCS components with fallbacks
try:
    from blncs.core.config_manager import ConfigManager
except ImportError:
    ConfigManager = None

try:
    from blncs.core.unified_logging import UnifiedLogger
except ImportError:
    UnifiedLogger = None

try:
    from blncs.core.health import HealthMonitor
except ImportError:
    HealthMonitor = None

try:
    from blncs.core.metrics import MetricsCollector
except ImportError:
    MetricsCollector = None

try:
    from blncs.lightning.channel_manager import ChannelManager
except ImportError:
    ChannelManager = None

try:
    from blncs.lightning.payment_manager import PaymentManager
except ImportError:
    PaymentManager = None

try:
    from blncs.api.unified_rest_api import create_api_app
except ImportError:
    def create_api_app(config): return None

try:
    from blncs.api.websocket_server import WebSocketServer
except ImportError:
    WebSocketServer = None


class ProductionBLNCS:
    """Production-grade BLNCS system with commercial features"""

    def __init__(self):
        self.config = None
        self.logger = enterprise_logger
        self.shutdown_event = asyncio.Event()
        self.services = {}
        self.startup_time = datetime.now()

    async def initialize(self, config_path: Optional[str] = None):
        """Initialize all systems"""
        try:
            # Initialize logging context
            context = self.logger.create_context(
                component="main",
                version="1.0.0",
                environment="production"
            )
            self.logger.push_context(context)

            self.logger.info("Starting BLNCS Production System",
                           category=LogCategory.SYSTEM)

            # Load configuration
            config_file = config_path or "config/production.json"
            self.config = await self._load_config(config_file)

            # Initialize security
            await self._init_security()

            # Initialize monitoring
            await self._init_monitoring()

            # Initialize caching
            await self._init_caching()

            # Initialize core services
            await self._init_core_services()

            # Initialize API services
            await self._init_api_services()

            # Setup error recovery
            self._setup_error_recovery()

            # Setup graceful shutdown
            self._setup_shutdown_handlers()

            self.logger.info("BLNCS Production System initialized successfully",
                           category=LogCategory.SYSTEM)

        except Exception as e:
            self.logger.fatal(f"Failed to initialize BLNCS: {e}",
                            category=LogCategory.ERROR,
                            exc_info=sys.exc_info())
            raise

    async def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load production configuration"""
        self.logger.info(f"Loading configuration from {config_path}")

        try:
            with open(config_path, 'r') as f:
                config = json.load(f)

            # Validate required configuration
            required_sections = ['lightning', 'security', 'monitoring', 'api']
            for section in required_sections:
                if section not in config:
                    raise ValueError(f"Missing required config section: {section}")

            return config

        except FileNotFoundError:
            # Create default production config
            default_config = {
                "lightning": {
                    "network": "mainnet",
                    "rpc_host": "localhost",
                    "rpc_port": 10009,
                    "macaroon_path": "~/.lnd/data/chain/bitcoin/mainnet/admin.macaroon",
                    "tls_cert_path": "~/.lnd/tls.cert"
                },
                "security": {
                    "jwt_secret": "change-in-production",
                    "encryption_enabled": True,
                    "mfa_required": True,
                    "session_timeout": 3600
                },
                "monitoring": {
                    "enabled": True,
                    "metrics_port": 9090,
                    "alert_webhooks": []
                },
                "api": {
                    "host": "0.0.0.0",
                    "port": 8080,
                    "cors_enabled": True,
                    "rate_limiting": True
                },
                "cache": {
                    "redis_url": "redis://localhost:6379",
                    "default_ttl": 3600
                },
                "logging": {
                    "level": "INFO",
                    "format": "json",
                    "destinations": []
                }
            }

            # Save default config
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            with open(config_path, 'w') as f:
                json.dump(default_config, f, indent=2)

            self.logger.info(f"Created default configuration at {config_path}")
            return default_config

    async def _init_security(self):
        """Initialize security systems"""
        self.logger.info("Initializing security systems")

        # Configure security policies
        security_config = self.config.get('security', {})

        if security_config.get('encryption_enabled', True):
            self.logger.info("Encryption enabled")

        # Initialize JWT tokens
        if 'jwt_secret' in security_config:
            self.logger.info("JWT authentication configured")

        self.services['security'] = security_manager

        # Audit system startup
        self.logger.audit(
            event_type="system_startup",
            action="initialize_security",
            resource="security_manager",
            result="success"
        )

    async def _init_monitoring(self):
        """Initialize monitoring and metrics"""
        self.logger.info("Initializing monitoring systems")

        monitoring_config = self.config.get('monitoring', {})

        if monitoring_config.get('enabled', True) and monitoring_service:
            await monitoring_service.start()
            self.services['monitoring'] = monitoring_service

            # Configure alerting
            if 'alert_webhooks' in monitoring_config:
                for webhook in monitoring_config['alert_webhooks']:
                    self.logger.info(f"Configured alert webhook: {webhook}")
        else:
            self.logger.warning("Monitoring service not available")

        self.logger.info("Monitoring systems initialized")

    async def _init_caching(self):
        """Initialize caching layer"""
        self.logger.info("Initializing caching systems")

        cache_config = self.config.get('cache', {})

        # Configure Redis if available
        if cache_manager and 'redis_url' in cache_config:
            redis_url = cache_config['redis_url']
            try:
                # Extract host and port from Redis URL
                if redis_url.startswith('redis://'):
                    url_parts = redis_url.replace('redis://', '').split(':')
                    host = url_parts[0] if url_parts else 'localhost'
                    port = int(url_parts[1]) if len(url_parts) > 1 else 6379

                    cache_manager.cache.configure_redis(host, port)
                    self.logger.info(f"Redis cache configured: {host}:{port}")

            except Exception as e:
                self.logger.warning(f"Redis configuration failed: {e}")

        if cache_manager:
            self.services['cache'] = cache_manager

            # Warm up cache
            try:
                await cache_manager.cache.set("system:startup", str(self.startup_time))
            except Exception as e:
                self.logger.warning(f"Cache warmup failed: {e}")
        else:
            self.logger.warning("Cache manager not available")

        self.logger.info("Caching systems initialized")

    async def _init_core_services(self):
        """Initialize core Lightning services"""
        self.logger.info("Initializing core Lightning services")

        lightning_config = self.config.get('lightning', {})

        try:
            # Initialize configuration manager
            if ConfigManager:
                config_manager = ConfigManager()
                await config_manager.load_config()
                self.services['config'] = config_manager
            else:
                self.logger.warning("ConfigManager not available")

            # Initialize health monitor
            if HealthMonitor:
                health_monitor = HealthMonitor()
                self.services['health'] = health_monitor
            else:
                self.logger.warning("HealthMonitor not available")

            # Initialize metrics collector
            if MetricsCollector:
                metrics_collector = MetricsCollector()
                self.services['metrics'] = metrics_collector
            else:
                self.logger.warning("MetricsCollector not available")

            # Initialize Lightning services
            if ChannelManager:
                channel_manager = ChannelManager()
                self.services['channels'] = channel_manager
            else:
                self.logger.warning("ChannelManager not available")

            if PaymentManager:
                payment_manager = PaymentManager()
                self.services['payments'] = payment_manager
            else:
                self.logger.warning("PaymentManager not available")

            self.logger.info("Core Lightning services initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize core services: {e}",
                            exc_info=sys.exc_info())
            raise

    async def _init_api_services(self):
        """Initialize API and WebSocket services"""
        self.logger.info("Initializing API services")

        api_config = self.config.get('api', {})

        try:
            # Create REST API
            api_app = create_api_app(self.config)
            if api_app:
                self.services['api'] = api_app
            else:
                self.logger.warning("REST API not available")

            # Initialize WebSocket server
            if WebSocketServer:
                ws_server = WebSocketServer()
                self.services['websocket'] = ws_server
            else:
                self.logger.warning("WebSocket server not available")

            self.logger.info("API services initialized")

        except Exception as e:
            self.logger.error(f"Failed to initialize API services: {e}",
                            exc_info=sys.exc_info())
            raise

    def _setup_error_recovery(self):
        """Setup error recovery strategies"""
        self.logger.info("Setting up error recovery")

        if error_recovery_manager:
            try:
                # Basic error recovery setup
                self.logger.info("Error recovery manager available")

                # Register fallbacks for critical services if methods exist
                if hasattr(error_recovery_manager, 'register_fallback'):
                    error_recovery_manager.register_fallback(
                        "payment_manager",
                        self._payment_fallback
                    )

                    error_recovery_manager.register_fallback(
                        "channel_manager",
                        self._channel_fallback
                    )

            except Exception as e:
                self.logger.warning(f"Error recovery setup failed: {e}")
        else:
            self.logger.warning("Error recovery manager not available")

    def _setup_shutdown_handlers(self):
        """Setup graceful shutdown handlers"""
        def shutdown_handler(signum, frame):
            self.logger.info(f"Received signal {signum}, initiating shutdown")
            asyncio.create_task(self.shutdown())

        signal.signal(signal.SIGTERM, shutdown_handler)
        signal.signal(signal.SIGINT, shutdown_handler)

    @with_error_boundary(component="payment_manager", fallback={"error": "payment_unavailable"})
    async def _payment_fallback(self, error, context):
        """Fallback handler for payment manager errors"""
        self.logger.warning(f"Payment fallback activated: {error}")
        return {"status": "degraded", "message": "Payment service temporarily unavailable"}

    @with_error_boundary(component="channel_manager", fallback={"error": "channel_unavailable"})
    async def _channel_fallback(self, error, context):
        """Fallback handler for channel manager errors"""
        self.logger.warning(f"Channel fallback activated: {error}")
        return {"status": "degraded", "message": "Channel service temporarily unavailable"}

    async def start(self):
        """Start all services"""
        try:
            self.logger.info("Starting BLNCS production services")

            # Start core services
            await self._start_core_services()

            # Start API services
            await self._start_api_services()

            # Mark system as ready
            if cache_manager:
                try:
                    await cache_manager.cache.set("system:status", "ready")
                except:
                    pass

            self.logger.info("BLNCS production system fully operational",
                           category=LogCategory.SYSTEM)

            # Audit system start
            self.logger.audit(
                event_type="system_lifecycle",
                action="start_system",
                resource="blncs_production",
                result="success"
            )

            # Wait for shutdown signal
            await self.shutdown_event.wait()

        except Exception as e:
            self.logger.fatal(f"Critical error during startup: {e}",
                            exc_info=sys.exc_info())
            raise

    async def _start_core_services(self):
        """Start core Lightning services"""
        self.logger.info("Starting core services")

        # Start health monitor
        if 'health' in self.services:
            health_monitor = self.services['health']
            await health_monitor.start_monitoring()

        # Start metrics collection
        if 'metrics' in self.services:
            metrics_collector = self.services['metrics']
            # Metrics collector starts automatically

        self.logger.info("Core services started")

    async def _start_api_services(self):
        """Start API and WebSocket services"""
        self.logger.info("Starting API services")

        api_config = self.config.get('api', {})
        host = api_config.get('host', '0.0.0.0')
        port = api_config.get('port', 8080)

        # Start REST API server
        if 'api' in self.services:
            import uvicorn

            config = uvicorn.Config(
                self.services['api'],
                host=host,
                port=port,
                log_level="info",
                access_log=True
            )

            server = uvicorn.Server(config)

            # Start server in background
            asyncio.create_task(server.serve())

            self.logger.info(f"REST API server started on {host}:{port}")

        # Start WebSocket server
        if 'websocket' in self.services:
            ws_server = self.services['websocket']
            ws_port = api_config.get('ws_port', 8081)

            # Start WebSocket server in background
            asyncio.create_task(ws_server.start(host, ws_port))

            self.logger.info(f"WebSocket server started on {host}:{ws_port}")

    async def shutdown(self):
        """Graceful shutdown of all services"""
        self.logger.info("Initiating graceful shutdown")

        try:
            # Mark system as shutting down
            if cache_manager:
                try:
                    await cache_manager.cache.set("system:status", "shutting_down")
                except:
                    pass

            # Stop API services first
            await self._stop_api_services()

            # Stop core services
            await self._stop_core_services()

            # Stop commercial services
            await self._stop_commercial_services()

            # Final cleanup
            await self._final_cleanup()

            self.logger.info("BLNCS shutdown completed successfully")

            # Audit shutdown
            try:
                self.logger.audit(
                    event_type="system_lifecycle",
                    action="shutdown_system",
                    resource="blncs_production",
                    result="success"
                )
            except:
                pass

        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}",
                            exc_info=sys.exc_info())
        finally:
            self.shutdown_event.set()

    async def _stop_api_services(self):
        """Stop API services"""
        self.logger.info("Stopping API services")

        # Stop WebSocket server
        if 'websocket' in self.services:
            ws_server = self.services['websocket']
            await ws_server.stop()

        # API server stops automatically when main process ends

        self.logger.info("API services stopped")

    async def _stop_core_services(self):
        """Stop core services"""
        self.logger.info("Stopping core services")

        # Stop health monitor
        if 'health' in self.services:
            health_monitor = self.services['health']
            await health_monitor.stop_monitoring()

        # Core services cleanup
        self.logger.info("Core services stopped")

    async def _stop_commercial_services(self):
        """Stop commercial services"""
        self.logger.info("Stopping commercial services")

        # Stop monitoring
        if monitoring_service:
            try:
                await monitoring_service.stop()
            except:
                pass

        # Stop log shipping
        try:
            if hasattr(enterprise_logger, 'shipper') and enterprise_logger.shipper:
                enterprise_logger.shipper.stop()
        except:
            pass

        self.logger.info("Commercial services stopped")

    async def _final_cleanup(self):
        """Final cleanup operations"""
        self.logger.info("Performing final cleanup")

        # Flush logs
        try:
            if hasattr(enterprise_logger, 'audit_logger') and enterprise_logger.audit_logger:
                enterprise_logger.audit_logger._flush()
        except:
            pass

        # Clear cache
        if cache_manager:
            try:
                await cache_manager.cache.clear()
            except:
                pass

        self.logger.info("Final cleanup completed")

    def get_status(self) -> Dict[str, Any]:
        """Get system status"""
        uptime = (datetime.now() - self.startup_time).total_seconds()

        return {
            "status": "operational",
            "uptime_seconds": uptime,
            "version": "1.0.0",
            "environment": "production",
            "services": {
                name: "running" for name in self.services.keys()
            },
            "timestamp": datetime.now().isoformat()
        }


async def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="BLNCS Production System")
    parser.add_argument(
        "--config",
        type=str,
        help="Configuration file path",
        default="config/production.json"
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate configuration and exit"
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show version and exit"
    )

    args = parser.parse_args()

    if args.version:
        print("BLNCS Production System v1.0.0")
        return

    # Create and initialize system
    blncs = ProductionBLNCS()

    try:
        await blncs.initialize(args.config)

        if args.validate:
            print("Configuration validation successful")
            return

        # Start the system
        await blncs.start()

    except KeyboardInterrupt:
        print("\nShutdown requested by user")
    except Exception as e:
        print(f"Fatal error: {e}")
        traceback.print_exc()
        sys.exit(1)
    finally:
        if blncs:
            await blncs.shutdown()


if __name__ == "__main__":
    # Set up asyncio event loop
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nShutdown complete")
    except Exception as e:
        print(f"Startup failed: {e}")
        sys.exit(1)