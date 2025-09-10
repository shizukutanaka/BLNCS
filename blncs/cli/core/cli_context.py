"""
CLI context management for BLNCS
Handles configuration, client initialization, and shared CLI state.
"""

import click
from typing import Optional, Dict, Any, Callable
from pathlib import Path

from ...core.config_manager import get_config_manager
from ...core.logger import get_logger
from ...core.error_handler import get_error_handler
from ...lightning.client import LightningClient


class CLIContext:
    """Centralized CLI context management"""
    
    def __init__(self):
        self.config: Dict[str, Any] = {}
        self.verbose: bool = False
        self.quiet: bool = False
        self.logger = get_logger(__name__)
        self.error_handler = get_error_handler()
        
        # Lazy-loaded components
        self._client: Optional[LightningClient] = None
        self._config_manager = None
    
    @property
    def client(self) -> LightningClient:
        """Get or create Lightning client on demand"""
        if self._client is None:
            self._client = LightningClient(self.config)
        return self._client
    
    @property
    def config_manager(self):
        """Get configuration manager"""
        if self._config_manager is None:
            self._config_manager = get_config_manager()
        return self._config_manager
    
    def load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """Load configuration from file or defaults"""
        try:
            if config_path and Path(config_path).exists():
                self.config = self.config_manager.load_from_file(config_path)
            else:
                self.config = self.config_manager.get_all()
            
            return self.config
            
        except Exception as e:
            self.error_handler.handle_error(e, suppress=True)
            # Return minimal default config
            return {
                'lightning': {
                    'host': 'localhost',
                    'port': 8080,
                    'network': 'testnet'
                }
            }
    
    def set_verbosity(self, verbose: bool, quiet: bool):
        """Set logging verbosity levels"""
        self.verbose = verbose
        self.quiet = quiet
        
        # Configure logger based on verbosity
        import logging
        if quiet:
            self.logger.setLevel(logging.ERROR)
        elif verbose:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)
    
    def validate_connection(self) -> bool:
        """Validate Lightning node connection"""
        try:
            return self.client.connect()
        except Exception as e:
            if not self.quiet:
                click.echo(f"Connection validation failed: {e}", err=True)
            return False
    
    def cleanup(self):
        """Cleanup resources"""
        if self._client:
            try:
                self._client.disconnect()
            except Exception:
                pass


def create_cli_context(config_path: Optional[str] = None, verbose: bool = False, quiet: bool = False) -> CLIContext:
    """Factory function to create CLI context"""
    context = CLIContext()
    context.load_config(config_path)
    context.set_verbosity(verbose, quiet)
    return context


def pass_cli_context(func: Callable) -> Callable:
    """Decorator to pass CLI context to command functions"""
    def wrapper(*args, **kwargs):
        ctx = click.get_current_context()
        cli_context = ctx.obj.get('cli_context')
        if cli_context is None:
            cli_context = create_cli_context()
            ctx.obj['cli_context'] = cli_context
        
        return func(cli_context, *args, **kwargs)
    
    return wrapper


# Legacy compatibility functions
def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration using unified config system"""
    context = CLIContext()
    return context.load_config(config_path)


def get_lightning_client(config: Dict[str, Any]) -> LightningClient:
    """Create Lightning client from config"""
    return LightningClient(config)


def get_client(ctx) -> LightningClient:
    """Legacy function to get client from click context"""
    if 'cli_context' in ctx.obj:
        return ctx.obj['cli_context'].client
    
    # Fallback to legacy method
    if ctx.obj.get('_client') is None:
        ctx.obj['_client'] = get_lightning_client(ctx.obj.get('config', {}))
    return ctx.obj['_client']


__all__ = [
    'CLIContext',
    'create_cli_context',
    'pass_cli_context',
    'load_config',
    'get_lightning_client',
    'get_client'
]