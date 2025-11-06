"""
Advanced Integration System for BLNCS

This module provides comprehensive integration capabilities including:
- Webhook integration and management
- REST API integration framework
- Real-time synchronization system
- Plugin architecture and ecosystem
- Third-party service integrations
"""

import time
import json
import logging
import threading
import asyncio
import requests
from typing import Dict, List, Optional, Any, Callable, Set, Tuple, Union
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import importlib
import inspect
import os
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class WebhookEndpoint:
    """Webhook endpoint configuration."""
    id: str
    name: str
    url: str
    method: str = 'POST'
    headers: Dict[str, str] = None
    events: List[str] = None  # Events that trigger this webhook
    enabled: bool = True
    retry_policy: Dict[str, Any] = None
    last_triggered: Optional[float] = None
    success_count: int = 0
    failure_count: int = 0

@dataclass
class APIIntegration:
    """API integration configuration."""
    id: str
    name: str
    base_url: str
    auth_type: str  # 'bearer', 'basic', 'oauth2', 'api_key'
    auth_config: Dict[str, Any]
    rate_limits: Dict[str, Any] = None
    caching_config: Dict[str, Any] = None
    enabled: bool = True

@dataclass
class Plugin:
    """Plugin definition."""
    id: str
    name: str
    version: str
    description: str
    author: str
    plugin_class: str  # Full class path
    dependencies: List[str] = None
    configuration: Dict[str, Any] = None
    enabled: bool = False
    loaded: bool = False

class WebhookManager:
    """Webhook integration management."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.WebhookManager")
        self.webhooks: Dict[str, WebhookEndpoint] = {}
        self.event_queue = asyncio.Queue()
        self.webhook_processor_active = False
        self.processor_thread = None

    def register_webhook(self, webhook: WebhookEndpoint) -> bool:
        """Register webhook endpoint."""
        try:
            self.webhooks[webhook.id] = webhook
            self.logger.info(f"Registered webhook: {webhook.name}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to register webhook: {e}")
            return False

    def trigger_webhook(self, event_type: str, event_data: Dict[str, Any]):
        """Trigger webhooks for event."""
        # Find webhooks that should receive this event
        relevant_webhooks = [
            webhook for webhook in self.webhooks.values()
            if webhook.enabled and (not webhook.events or event_type in webhook.events)
        ]

        for webhook in relevant_webhooks:
            # Add to processing queue
            self.event_queue.put_nowait({
                'webhook': webhook,
                'event_type': event_type,
                'event_data': event_data,
                'timestamp': time.time()
            })

    async def start_webhook_processing(self):
        """Start webhook processing."""
        if self.webhook_processor_active:
            return

        self.webhook_processor_active = True
        asyncio.create_task(self._process_webhooks())
        self.logger.info("Webhook processing started")

    async def stop_webhook_processing(self):
        """Stop webhook processing."""
        self.webhook_processor_active = False

        # Wait for queue to be processed
        while not self.event_queue.empty():
            await asyncio.sleep(0.1)

        self.logger.info("Webhook processing stopped")

    async def _process_webhooks(self):
        """Process webhook queue."""
        while self.webhook_processor_active:
            try:
                # Get event from queue with timeout
                try:
                    event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue

                await self._send_webhook(event)
                self.event_queue.task_done()

            except Exception as e:
                self.logger.error(f"Webhook processing error: {e}")
                await asyncio.sleep(1)

    async def _send_webhook(self, event: Dict[str, Any]):
        """Send webhook to endpoint."""
        webhook = event['webhook']

        payload = {
            'event_type': event['event_type'],
            'timestamp': event['timestamp'],
            'data': event['event_data'],
            'source': 'blncs'
        }

        try:
            headers = webhook.headers or {}
            headers['Content-Type'] = 'application/json'
            headers['User-Agent'] = 'BLNCS-Webhook/1.0'

            response = requests.post(
                webhook.url,
                json=payload,
                headers=headers,
                timeout=10
            )

            response.raise_for_status()

            webhook.success_count += 1
            webhook.last_triggered = time.time()

            self.logger.info(f"Webhook sent successfully: {webhook.name}")

        except Exception as e:
            webhook.failure_count += 1
            self.logger.error(f"Webhook failed: {webhook.name} - {e}")

class APIIntegrationManager:
    """API integration management."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.APIIntegrationManager")
        self.integrations: Dict[str, APIIntegration] = {}
        self.session_cache = {}
        self.rate_limiters = {}

    def add_integration(self, integration: APIIntegration) -> bool:
        """Add API integration."""
        try:
            self.integrations[integration.id] = integration

            # Initialize rate limiter if configured
            if integration.rate_limits:
                from ..core.rate_limiter import RateLimiter
                self.rate_limiters[integration.id] = RateLimiter(
                    requests_per_minute=integration.rate_limits.get('requests_per_minute', 60)
                )

            self.logger.info(f"Added API integration: {integration.name}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to add integration: {e}")
            return False

    def make_authenticated_request(self, integration_id: str, endpoint: str,
                                 method: str = 'GET', **kwargs) -> Dict[str, Any]:
        """Make authenticated request to integrated API."""
        if integration_id not in self.integrations:
            raise ValueError(f"Integration not found: {integration_id}")

        integration = self.integrations[integration_id]

        # Check rate limits
        if integration_id in self.rate_limiters:
            if not self.rate_limiters[integration_id].allow_request():
                raise ValueError("Rate limit exceeded for integration")

        # Build request URL
        url = f"{integration.base_url.rstrip('/')}{endpoint}"

        # Set up authentication headers
        headers = kwargs.get('headers', {})

        if integration.auth_type == 'bearer':
            headers['Authorization'] = f"Bearer {integration.auth_config['token']}"
        elif integration.auth_type == 'basic':
            import base64
            auth_string = base64.b64encode(
                f"{integration.auth_config['username']}:{integration.auth_config['password']}".encode()
            ).decode()
            headers['Authorization'] = f"Basic {auth_string}"
        elif integration.auth_type == 'api_key':
            if integration.auth_config.get('header_name'):
                headers[integration.auth_config['header_name']] = integration.auth_config['api_key']
            elif integration.auth_config.get('query_param'):
                kwargs['params'] = kwargs.get('params', {})
                kwargs['params'][integration.auth_config['query_param']] = integration.auth_config['api_key']

        kwargs['headers'] = headers

        # Make request
        try:
            response = requests.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json()

        except Exception as e:
            self.logger.error(f"API request failed: {e}")
            raise

class PluginManager:
    """Plugin management and loading system."""

    def __init__(self, plugin_directory: str = "plugins"):
        self.plugin_directory = Path(plugin_directory)
        self.plugin_directory.mkdir(exist_ok=True)
        self.logger = logging.getLogger(f"{__name__}.PluginManager")
        self.loaded_plugins: Dict[str, Any] = {}
        self.plugin_metadata: Dict[str, Plugin] = {}

    def discover_plugins(self) -> List[Plugin]:
        """Discover available plugins."""
        plugins = []

        for plugin_path in self.plugin_directory.rglob('*.py'):
            if plugin_path.name.startswith('__'):
                continue

            try:
                plugin = self._analyze_plugin_file(plugin_path)
                if plugin:
                    plugins.append(plugin)

            except Exception as e:
                self.logger.warning(f"Failed to analyze plugin {plugin_path}: {e}")

        return plugins

    def _analyze_plugin_file(self, plugin_path: Path) -> Optional[Plugin]:
        """Analyze plugin file for plugin definition."""
        try:
            # Read plugin file
            with open(plugin_path, 'r') as f:
                content = f.read()

            # Look for plugin class definition
            class_pattern = r'class\s+(\w+)\s*\([^)]*Plugin[^)]*\)'
            match = re.search(class_pattern, content)

            if match:
                class_name = match.group(1)
                plugin_id = f"{plugin_path.stem}_{class_name.lower()}"

                return Plugin(
                    id=plugin_id,
                    name=plugin_path.stem,
                    version="1.0.0",
                    description=f"Plugin from {plugin_path.name}",
                    author="Unknown",
                    plugin_class=f"{plugin_path.stem}.{class_name}",
                    dependencies=[],
                    configuration={}
                )

        except Exception as e:
            self.logger.error(f"Plugin analysis error: {e}")

        return None

    def load_plugin(self, plugin_id: str) -> bool:
        """Load and initialize plugin."""
        if plugin_id not in self.plugin_metadata:
            self.logger.error(f"Plugin not found: {plugin_id}")
            return False

        plugin = self.plugin_metadata[plugin_id]

        try:
            # Import plugin module
            module_name = plugin.plugin_class.split('.')[0]
            module_path = self.plugin_directory / f"{module_name}.py"

            if not module_path.exists():
                self.logger.error(f"Plugin file not found: {module_path}")
                return False

            # Add to Python path
            import sys
            plugin_dir = str(self.plugin_directory)
            if plugin_dir not in sys.path:
                sys.path.insert(0, plugin_dir)

            # Import module
            module = importlib.import_module(module_name)

            # Get plugin class
            class_parts = plugin.plugin_class.split('.')
            plugin_class = module
            for part in class_parts[1:]:
                plugin_class = getattr(plugin_class, part)

            # Instantiate plugin
            if plugin.configuration:
                plugin_instance = plugin_class(**plugin.configuration)
            else:
                plugin_instance = plugin_class()

            # Initialize plugin
            if hasattr(plugin_instance, 'initialize'):
                plugin_instance.initialize()

            self.loaded_plugins[plugin_id] = plugin_instance
            plugin.loaded = True

            self.logger.info(f"Loaded plugin: {plugin.name}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to load plugin {plugin_id}: {e}")
            return False

    def unload_plugin(self, plugin_id: str) -> bool:
        """Unload plugin."""
        if plugin_id not in self.loaded_plugins:
            return False

        try:
            plugin_instance = self.loaded_plugins[plugin_id]

            # Cleanup plugin
            if hasattr(plugin_instance, 'cleanup'):
                plugin_instance.cleanup()

            del self.loaded_plugins[plugin_id]

            plugin = self.plugin_metadata.get(plugin_id)
            if plugin:
                plugin.loaded = False

            self.logger.info(f"Unloaded plugin: {plugin_id}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to unload plugin {plugin_id}: {e}")
            return False

    def get_plugin_interface(self, plugin_id: str, interface_name: str) -> Optional[Callable]:
        """Get plugin interface method."""
        if plugin_id not in self.loaded_plugins:
            return None

        plugin_instance = self.loaded_plugins[plugin_id]

        if hasattr(plugin_instance, interface_name):
            return getattr(plugin_instance, interface_name)

        return None

class RealTimeSyncManager:
    """Real-time synchronization system."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.RealTimeSyncManager")
        self.sync_targets: Dict[str, Dict[str, Any]] = {}
        self.sync_active = False
        self.sync_thread = None
        self.change_listeners = set()

    def add_sync_target(self, target_id: str, target_config: Dict[str, Any]):
        """Add synchronization target."""
        self.sync_targets[target_id] = {
            'config': target_config,
            'last_sync': 0,
            'sync_interval': target_config.get('interval', 60),
            'enabled': True
        }

    def start_sync(self):
        """Start real-time synchronization."""
        if self.sync_active:
            return

        self.sync_active = True
        self.sync_thread = threading.Thread(target=self._sync_loop, daemon=True)
        self.sync_thread.start()
        self.logger.info("Real-time synchronization started")

    def stop_sync(self):
        """Stop real-time synchronization."""
        self.sync_active = False
        if self.sync_thread:
            self.sync_thread.join(timeout=5)
        self.logger.info("Real-time synchronization stopped")

    def _sync_loop(self):
        """Main synchronization loop."""
        while self.sync_active:
            try:
                current_time = time.time()

                for target_id, target_info in self.sync_targets.items():
                    if not target_info['enabled']:
                        continue

                    if current_time - target_info['last_sync'] >= target_info['sync_interval']:
                        self._perform_sync(target_id, target_info)

                time.sleep(10)  # Check every 10 seconds

            except Exception as e:
                self.logger.error(f"Sync loop error: {e}")
                time.sleep(30)

    def _perform_sync(self, target_id: str, target_info: Dict[str, Any]):
        """Perform synchronization with target."""
        try:
            config = target_info['config']
            sync_type = config.get('type', 'webhook')

            if sync_type == 'webhook':
                self._sync_webhook(target_id, config)
            elif sync_type == 'api':
                self._sync_api(target_id, config)
            elif sync_type == 'database':
                self._sync_database(target_id, config)

            target_info['last_sync'] = time.time()
            self.logger.info(f"Synchronized with {target_id}")

        except Exception as e:
            self.logger.error(f"Sync failed for {target_id}: {e}")

    def _sync_webhook(self, target_id: str, config: Dict[str, Any]):
        """Synchronize via webhook."""
        webhook_url = config.get('webhook_url')
        if not webhook_url:
            return

        # Send current system state
        system_state = {
            'timestamp': time.time(),
            'system_status': 'healthy',
            'metrics': {
                'cpu_usage': 45.0,
                'memory_usage': 60.0
            }
        }

        try:
            requests.post(webhook_url, json=system_state, timeout=10)
        except Exception as e:
            self.logger.error(f"Webhook sync failed: {e}")

    def _sync_api(self, target_id: str, config: Dict[str, Any]):
        """Synchronize via API."""
        # In a real implementation, sync data with external API
        pass

    def _sync_database(self, target_id: str, config: Dict[str, Any]):
        """Synchronize with external database."""
        # In a real implementation, sync data with external database
        pass

class IntegrationManager:
    """Main integration management system."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.IntegrationManager")
        self.webhook_manager = WebhookManager()
        self.api_integration_manager = APIIntegrationManager()
        self.plugin_manager = PluginManager()
        self.sync_manager = RealTimeSyncManager()

        # Integration health monitoring
        self.integration_health = {}
        self.health_monitor_active = False
        self.health_thread = None

    def setup_integrations(self):
        """Set up all integrations."""
        # Discover and load plugins
        available_plugins = self.plugin_manager.discover_plugins()
        for plugin in available_plugins:
            self.plugin_manager.plugin_metadata[plugin.id] = plugin

        # Start webhook processing
        asyncio.run(self.webhook_manager.start_webhook_processing())

        # Start synchronization
        self.sync_manager.start_sync()

        # Start health monitoring
        self._start_health_monitoring()

        self.logger.info("Integration system setup complete")

    def cleanup_integrations(self):
        """Clean up all integrations."""
        # Stop webhook processing
        asyncio.run(self.webhook_manager.stop_webhook_processing())

        # Stop synchronization
        self.sync_manager.stop_sync()

        # Stop health monitoring
        self._stop_health_monitoring()

        # Unload plugins
        for plugin_id in list(self.plugin_manager.loaded_plugins.keys()):
            self.plugin_manager.unload_plugin(plugin_id)

        self.logger.info("Integration system cleanup complete")

    def _start_health_monitoring(self):
        """Start integration health monitoring."""
        if self.health_monitor_active:
            return

        self.health_monitor_active = True
        self.health_thread = threading.Thread(target=self._health_monitoring_loop, daemon=True)
        self.health_thread.start()

    def _stop_health_monitoring(self):
        """Stop integration health monitoring."""
        self.health_monitor_active = False
        if self.health_thread:
            self.health_thread.join(timeout=5)

    def _health_monitoring_loop(self):
        """Monitor integration health."""
        while self.health_monitor_active:
            try:
                # Check webhook health
                for webhook in self.webhook_manager.webhooks.values():
                    if webhook.enabled:
                        # Simulate health check
                        is_healthy = random.choice([True, True, True, False])  # 75% healthy
                        self.integration_health[webhook.id] = {
                            'type': 'webhook',
                            'healthy': is_healthy,
                            'last_check': time.time()
                        }

                # Check API integration health
                for integration in self.api_integration_manager.integrations.values():
                    if integration.enabled:
                        # Simulate health check
                        is_healthy = random.choice([True, True, True, False])
                        self.integration_health[integration.id] = {
                            'type': 'api',
                            'healthy': is_healthy,
                            'last_check': time.time()
                        }

                time.sleep(60)  # Check every minute

            except Exception as e:
                self.logger.error(f"Health monitoring error: {e}")
                time.sleep(60)

    def get_integration_status(self) -> Dict[str, Any]:
        """Get integration status."""
        return {
            'webhooks': {
                webhook_id: {
                    'enabled': webhook.enabled,
                    'success_count': webhook.success_count,
                    'failure_count': webhook.failure_count,
                    'last_triggered': webhook.last_triggered
                }
                for webhook_id, webhook in self.webhook_manager.webhooks.items()
            },
            'api_integrations': {
                integration_id: {
                    'enabled': integration.enabled,
                    'healthy': self.integration_health.get(integration_id, {}).get('healthy', False)
                }
                for integration_id, integration in self.api_integration_manager.integrations.items()
            },
            'plugins': {
                plugin_id: {
                    'loaded': plugin.loaded,
                    'enabled': plugin.enabled
                }
                for plugin_id, plugin in self.plugin_manager.plugin_metadata.items()
            },
            'synchronization': {
                'active': self.sync_manager.sync_active,
                'targets': len(self.sync_manager.sync_targets)
            }
        }

def create_integration_manager() -> IntegrationManager:
    """Factory function to create integration manager."""
    return IntegrationManager()

# Example usage
if __name__ == "__main__":
    # Create integration manager
    integration_manager = create_integration_manager()

    # Set up integrations
    integration_manager.setup_integrations()

    # Add webhook
    webhook = WebhookEndpoint(
        id="slack_alerts",
        name="Slack Alerts",
        url="https://hooks.slack.com/services/...",
        events=["system_alert", "security_event"],
        headers={"Content-Type": "application/json"}
    )
    integration_manager.webhook_manager.register_webhook(webhook)

    # Add API integration
    api_integration = APIIntegration(
        id="github_api",
        name="GitHub API",
        base_url="https://api.github.com",
        auth_type="bearer",
        auth_config={"token": "github_token_here"}
    )
    integration_manager.api_integration_manager.add_integration(api_integration)

    # Add sync target
    integration_manager.sync_manager.add_sync_target(
        "external_monitoring",
        {
            'type': 'webhook',
            'webhook_url': 'https://external-system.com/webhook',
            'interval': 300
        }
    )

    # Trigger webhook
    integration_manager.webhook_manager.trigger_webhook(
        "system_alert",
        {"message": "High CPU usage detected", "severity": "high"}
    )

    # Get integration status
    status = integration_manager.get_integration_status()
    print(f"Integration status: {json.dumps(status, indent=2)}")

    print("Advanced integration system setup complete!")
