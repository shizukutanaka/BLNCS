"""
Asynchronous CLI wrapper for BLNCS
Provides async support for CLI commands while maintaining click compatibility.
"""

import asyncio
import functools
import click
from typing import Callable, Any, Optional, Dict
import sys
import time
from datetime import datetime

from .logger import get_logger
from .error_handler import get_error_handler, ErrorContext
from .async_metrics import get_metrics_collector, measure_time


class AsyncCLIWrapper:
    """Wrapper to run async functions in CLI context"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.error_handler = get_error_handler()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._metrics_collector = None
    
    def run_async(self, coro_func: Callable) -> Callable:
        """Decorator to run async function in CLI context"""
        @functools.wraps(coro_func)
        def wrapper(*args, **kwargs):
            return asyncio.run(self._execute_async(coro_func, *args, **kwargs))
        return wrapper
    
    async def _execute_async(self, coro_func: Callable, *args, **kwargs):
        """Execute async function with proper error handling and metrics"""
        start_time = time.time()
        function_name = coro_func.__name__
        
        try:
            # Initialize metrics collector if not already done
            if self._metrics_collector is None:
                try:
                    self._metrics_collector = await get_metrics_collector()
                except Exception as e:
                    self.logger.warning(f"Failed to initialize metrics collector: {e}")
            
            # Execute function with timing
            async with measure_time(f"cli_command_duration", {"command": function_name}):
                result = await coro_func(*args, **kwargs)
            
            # Record successful command execution
            if self._metrics_collector:
                await self._metrics_collector.record_counter(
                    "cli_commands_total",
                    labels={"command": function_name, "status": "success"}
                )
            
            return result
            
        except Exception as e:
            # Record failed command execution
            if self._metrics_collector:
                await self._metrics_collector.record_counter(
                    "cli_commands_total",
                    labels={"command": function_name, "status": "error"}
                )
                await self._metrics_collector.record_histogram(
                    "cli_command_errors",
                    1.0,
                    labels={"command": function_name, "error_type": type(e).__name__}
                )
            
            # Handle error with context
            context = ErrorContext(
                component="cli",
                operation=function_name,
                metadata={
                    "args_count": len(args),
                    "kwargs_keys": list(kwargs.keys()),
                    "execution_time": time.time() - start_time
                }
            )
            
            self.error_handler.handle_error(e, context, suppress=True)
            
            # Re-raise for CLI error handling
            raise


# Global async CLI wrapper instance
_async_cli_wrapper: Optional[AsyncCLIWrapper] = None


def get_async_cli_wrapper() -> AsyncCLIWrapper:
    """Get global async CLI wrapper instance"""
    global _async_cli_wrapper
    if _async_cli_wrapper is None:
        _async_cli_wrapper = AsyncCLIWrapper()
    return _async_cli_wrapper


def async_command(func: Callable) -> Callable:
    """Decorator to make click commands async-compatible"""
    wrapper = get_async_cli_wrapper()
    return wrapper.run_async(func)


def async_cli_context():
    """Context manager for async CLI operations"""
    class AsyncCLIContext:
        def __init__(self):
            self.start_time = None
            self.metrics_collector = None
        
        async def __aenter__(self):
            self.start_time = time.time()
            try:
                self.metrics_collector = await get_metrics_collector()
            except:
                pass
            return self
        
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            if self.metrics_collector:
                execution_time = time.time() - self.start_time
                await self.metrics_collector.record_histogram(
                    "cli_session_duration",
                    execution_time
                )
    
    return AsyncCLIContext()


class AsyncClickGroup(click.Group):
    """Custom Click Group that supports async commands"""
    
    def command(self, *args, **kwargs):
        """Override to add async support"""
        def decorator(func):
            if asyncio.iscoroutinefunction(func):
                func = async_command(func)
            return super(AsyncClickGroup, self).command(*args, **kwargs)(func)
        return decorator


class AsyncClickCommand(click.Command):
    """Custom Click Command that supports async functions"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.callback and asyncio.iscoroutinefunction(self.callback):
            self.callback = async_command(self.callback)


# Enhanced CLI utilities

def handle_cli_error(error: Exception, context: str = "command") -> None:
    """Handle CLI errors with proper formatting"""
    error_handler = get_error_handler()
    
    # Format error for CLI display
    if hasattr(error, 'cli_message'):
        message = error.cli_message
    else:
        message = str(error)
    
    # Color coding for different error types
    if 'ConnectionError' in str(type(error)):
        click.echo(click.style(f"❌ Connection Error: {message}", fg='red'), err=True)
    elif 'ValidationError' in str(type(error)):
        click.echo(click.style(f"⚠️  Validation Error: {message}", fg='yellow'), err=True)
    elif 'SecurityError' in str(type(error)):
        click.echo(click.style(f"🔒 Security Error: {message}", fg='red', bold=True), err=True)
    else:
        click.echo(click.style(f"❌ Error: {message}", fg='red'), err=True)
    
    # Log error for debugging
    logger = get_logger(__name__)
    logger.error(f"CLI {context} error: {error}", exc_info=True)


def success_message(message: str) -> None:
    """Display success message"""
    click.echo(click.style(f"✅ {message}", fg='green'))


def info_message(message: str) -> None:
    """Display info message"""
    click.echo(click.style(f"ℹ️  {message}", fg='blue'))


def warning_message(message: str) -> None:
    """Display warning message"""
    click.echo(click.style(f"⚠️  {message}", fg='yellow'))


def format_table(data: list, headers: list) -> str:
    """Format data as a table for CLI display"""
    if not data:
        return "No data available"
    
    # Calculate column widths
    widths = []
    for i, header in enumerate(headers):
        max_width = len(header)
        for row in data:
            if i < len(row):
                max_width = max(max_width, len(str(row[i])))
        widths.append(max_width + 2)
    
    # Build table
    lines = []
    
    # Header
    header_line = "┌" + "┬".join("─" * w for w in widths) + "┐"
    lines.append(header_line)
    
    header_row = "│" + "│".join(f" {headers[i]:<{widths[i]-1}}" for i in range(len(headers))) + "│"
    lines.append(header_row)
    
    separator = "├" + "┼".join("─" * w for w in widths) + "┤"
    lines.append(separator)
    
    # Data rows
    for row in data:
        data_row = "│" + "│".join(
            f" {str(row[i]) if i < len(row) else '':<{widths[i]-1}}" 
            for i in range(len(headers))
        ) + "│"
        lines.append(data_row)
    
    # Footer
    footer = "└" + "┴".join("─" * w for w in widths) + "┘"
    lines.append(footer)
    
    return "\n".join(lines)


def format_json_output(data: Any, indent: int = 2) -> str:
    """Format data as JSON for CLI output"""
    import json
    try:
        return json.dumps(data, indent=indent, default=str, ensure_ascii=False)
    except (TypeError, ValueError) as e:
        return f"Error formatting JSON: {e}"


def progress_bar(iterable, length=None, label="Processing", show_eta=True):
    """Create progress bar for long operations"""
    return click.progressbar(
        iterable,
        length=length,
        label=label,
        show_eta=show_eta,
        color='green'
    )


class CLISpinner:
    """Simple CLI spinner for async operations"""
    
    def __init__(self, message: str = "Processing"):
        self.message = message
        self.spinner_chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        self.current = 0
        self.running = False
        self._task = None
    
    async def start(self):
        """Start spinner"""
        self.running = True
        self._task = asyncio.create_task(self._spin())
    
    async def stop(self):
        """Stop spinner"""
        self.running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        
        # Clear spinner line
        click.echo("\r" + " " * (len(self.message) + 5) + "\r", nl=False)
    
    async def _spin(self):
        """Spinner animation"""
        try:
            while self.running:
                char = self.spinner_chars[self.current % len(self.spinner_chars)]
                click.echo(f"\r{char} {self.message}...", nl=False)
                self.current += 1
                await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            pass


async def with_spinner(coro, message: str = "Processing"):
    """Execute coroutine with spinner"""
    spinner = CLISpinner(message)
    try:
        await spinner.start()
        result = await coro
        return result
    finally:
        await spinner.stop()


# Async context managers for CLI operations

class AsyncCLITransaction:
    """Transaction context for CLI operations with rollback"""
    
    def __init__(self, description: str):
        self.description = description
        self.operations = []
        self.logger = get_logger(__name__)
    
    async def __aenter__(self):
        info_message(f"Starting: {self.description}")
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            warning_message(f"Operation failed: {self.description}")
            await self.rollback()
        else:
            success_message(f"Completed: {self.description}")
    
    def add_rollback_operation(self, operation: Callable):
        """Add operation to rollback stack"""
        self.operations.append(operation)
    
    async def rollback(self):
        """Execute rollback operations in reverse order"""
        warning_message("Performing rollback...")
        
        for operation in reversed(self.operations):
            try:
                if asyncio.iscoroutinefunction(operation):
                    await operation()
                else:
                    operation()
            except Exception as e:
                self.logger.error(f"Rollback operation failed: {e}")


# Enhanced click option decorators

def async_option(*args, **kwargs):
    """Async-compatible option decorator"""
    return click.option(*args, **kwargs)


def config_option(config_key: str, default=None, **kwargs):
    """Option that loads default from config"""
    def decorator(func):
        def callback(ctx, param, value):
            if value is None:
                try:
                    from blncs.core.config_manager import get_config_manager
                    config = get_config_manager().get_all()
                    value = config.get(config_key, default)
                except Exception:
                    value = default
            return value
        
        kwargs.setdefault('callback', callback)
        kwargs.setdefault('default', default)
        
        return click.option(*args, **kwargs)(func)
    
    return decorator


def validate_option(validator: Callable[[Any], bool], error_message: str = "Invalid value"):
    """Option validator decorator"""
    def decorator(func):
        def callback(ctx, param, value):
            if value is not None and not validator(value):
                raise click.BadParameter(error_message)
            return value
        
        return click.option(callback=callback)(func)
    
    return decorator


__all__ = [
    'AsyncCLIWrapper',
    'AsyncClickGroup',
    'AsyncClickCommand',
    'get_async_cli_wrapper',
    'async_command',
    'async_cli_context',
    'handle_cli_error',
    'success_message',
    'info_message',
    'warning_message',
    'format_table',
    'format_json_output',
    'progress_bar',
    'CLISpinner',
    'with_spinner',
    'AsyncCLITransaction',
    'async_option',
    'config_option',
    'validate_option'
]