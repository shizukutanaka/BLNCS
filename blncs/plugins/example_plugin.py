#!/usr/bin/env python3
"""
Example BLNCS Plugin
Demonstrates plugin development patterns and best practices
"""

import asyncio
import logging
from typing import Dict, Any

from blncs.plugins import BasePlugin, PluginMetadata, PluginType, register_plugin

@register_plugin
class ExamplePlugin(BasePlugin):
    """Example plugin demonstrating BLNCS plugin capabilities"""
    
    def __init__(self, container=None):
        super().__init__(container)
        self.background_task = None
        self.message_count = 0
    
    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        """Get plugin metadata"""
        return PluginMetadata(
            name="example_plugin",
            version="1.0.0",
            description="Example plugin demonstrating BLNCS plugin capabilities",
            author="BLNCS Team",
            plugin_type=PluginType.EXTENSION,
            dependencies=[],
            conflicts=[],
            hot_reloadable=True,
            auto_start=True,
            permissions=["lightning.read", "system.log"]
        )
    
    async def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize the plugin"""
        self.logger.info("Initializing Example Plugin")
        
        # Setup plugin configuration
        self.config = config
        self.interval = config.get('interval', 30)
        self.enabled = config.get('enabled', True)
        
        # Add plugin hooks
        message_hook = self.add_hook('example.message')
        message_hook.add_handler(self._handle_example_message)
        
        self.logger.info("Example Plugin initialized successfully")
        return True
    
    async def start(self) -> bool:
        """Start the plugin"""
        if not self.enabled:
            self.logger.info("Example Plugin disabled, not starting")
            return True
        
        self.logger.info("Starting Example Plugin")
        
        # Start background task
        self.background_task = self.add_task(self._background_worker())
        
        self.logger.info("Example Plugin started successfully")
        return True
    
    async def stop(self) -> bool:
        """Stop the plugin"""
        self.logger.info("Stopping Example Plugin")
        
        # Background task will be cancelled by parent cleanup
        
        self.logger.info("Example Plugin stopped successfully")
        return True
    
    async def _background_worker(self):
        """Background worker task"""
        while True:
            try:
                await asyncio.sleep(self.interval)
                
                # Example work
                self.message_count += 1
                message = f"Background message #{self.message_count}"
                
                self.logger.debug(message)
                
                # Emit to hook
                if 'example.message' in self.hooks:
                    await self.hooks['example.message'].emit(message)
                
            except asyncio.CancelledError:
                self.logger.info("Background worker cancelled")
                break
            except Exception as e:
                self.logger.error(f"Error in background worker: {e}")
                await asyncio.sleep(5)
    
    async def _handle_example_message(self, message: str):
        """Handle example message from hook"""
        self.logger.debug(f"Handling message: {message}")
        
        # Example message processing
        if self.message_count % 10 == 0:
            self.logger.info(f"Processed {self.message_count} messages")
    
    async def get_status(self) -> Dict[str, Any]:
        """Get plugin status"""
        return {
            'enabled': self.enabled,
            'message_count': self.message_count,
            'interval': self.interval,
            'background_task_running': self.background_task and not self.background_task.done()
        }
    
    async def handle_lightning_event(self, event_type: str, event_data: Dict[str, Any]):
        """Handle Lightning Network events"""
        self.logger.info(f"Received Lightning event: {event_type}")
        
        if event_type == 'payment_received':
            amount = event_data.get('amount', 0)
            self.logger.info(f"Payment received: {amount} sats")
            
        elif event_type == 'channel_opened':
            channel_id = event_data.get('channel_id', 'unknown')
            self.logger.info(f"Channel opened: {channel_id}")
    
    async def process_command(self, command: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Process plugin-specific commands"""
        if command == 'status':
            return await self.get_status()
        
        elif command == 'set_interval':
            new_interval = args.get('interval', 30)
            self.interval = max(5, min(300, new_interval))  # Between 5-300 seconds
            return {'success': True, 'new_interval': self.interval}
        
        elif command == 'toggle':
            self.enabled = not self.enabled
            return {'success': True, 'enabled': self.enabled}
        
        else:
            return {'error': f'Unknown command: {command}'}

# Example of a monitoring plugin
@register_plugin 
class MonitorPlugin(BasePlugin):
    """Plugin for monitoring system metrics"""
    
    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="monitor_plugin",
            version="1.0.0", 
            description="System monitoring plugin",
            author="BLNCS Team",
            plugin_type=PluginType.MONITOR,
            hot_reloadable=True,
            auto_start=True
        )
    
    async def initialize(self, config: Dict[str, Any]) -> bool:
        self.monitor_interval = config.get('interval', 60)
        return True
    
    async def start(self) -> bool:
        self.add_task(self._monitor_loop())
        return True
    
    async def stop(self) -> bool:
        return True
    
    async def _monitor_loop(self):
        """Monitor system metrics"""
        while True:
            try:
                # Example monitoring
                import psutil
                
                cpu_percent = psutil.cpu_percent()
                memory_percent = psutil.virtual_memory().percent
                
                if cpu_percent > 80:
                    self.logger.warning(f"High CPU usage: {cpu_percent}%")
                
                if memory_percent > 85:
                    self.logger.warning(f"High memory usage: {memory_percent}%")
                
                await asyncio.sleep(self.monitor_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Monitor error: {e}")
                await asyncio.sleep(10)