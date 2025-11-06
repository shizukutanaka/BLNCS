#!/usr/bin/env python3
"""
BLNCS CLI - Bitcoin Lightning Network Control System Command Line Interface

Enterprise-grade CLI following Pike's principles: simple, direct, and composable.
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import click
import rich
from rich.console import Console
from rich.table import Table

from ..core.config import get_config
from ..core.logger import get_logger
from ..core.health import get_system_health
from ..version import __version__

console = Console()
logger = get_logger()


@click.group()
@click.version_option(__version__)
@click.option('--config', '-c', help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--debug', '-d', is_flag=True, help='Enable debug mode')
@click.pass_context
def main(ctx: click.Context, config: Optional[str], verbose: bool, debug: bool) -> None:
    """BLNCS - Bitcoin Lightning Network Control System

    Enterprise-grade Lightning Network management system.
    """
    ctx.ensure_object(dict)

    # Initialize configuration
    try:
        if config:
            cfg = get_config(config_path=config)
        else:
            cfg = get_config()
        ctx.obj['config'] = cfg
    except Exception as e:
        console.print(f"[red]Configuration error: {e}[/red]")
        sys.exit(1)

    # Set logging level
    if debug:
        ctx.obj['log_level'] = 'DEBUG'
    elif verbose:
        ctx.obj['log_level'] = 'INFO'
    else:
        ctx.obj['log_level'] = 'WARNING'

    logger.info("BLNCS CLI initialized")


@main.command()
@click.pass_context
def version(ctx: click.Context) -> None:
    """Show BLNCS version and system information."""
    try:
        health = get_system_health()

        table = Table(title="BLNCS System Information")
        table.add_column("Component", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Version", style="yellow")

        table.add_row("BLNCS Core", "✓ Active", __version__)
        table.add_row("Configuration", "✓ Loaded", ctx.obj['config'].version or "1.0.0")
        table.add_row("Health Check", health.get('status', 'unknown'), "Current")

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error getting version info: {e}[/red]")


@main.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show system status and health."""
    try:
        health = get_system_health()

        if health.get('status') == 'healthy':
            console.print("[green]✓ System is healthy[/green]")
        else:
            console.print("[red]✗ System has issues[/red]")

        # Show health details
        details = health.get('details', {})
        if details:
            table = Table(title="Health Details")
            table.add_column("Check", style="cyan")
            table.add_column("Status", style="green")

            for check, result in details.items():
                status = "✓ Pass" if result == 'ok' else "✗ Fail"
                table.add_row(check, status)

            console.print(table)

    except Exception as e:
        console.print(f"[red]Error getting status: {e}[/red]")


@main.command()
@click.argument('command', required=False)
@click.pass_context
def config(ctx: click.Context, command: Optional[str]) -> None:
    """Manage configuration. Use 'show' to display current config."""
    try:
        cfg = ctx.obj['config']

        if not command or command == 'show':
            # Display current configuration
            config_data = {
                'version': cfg.version,
                'environment': cfg.environment,
                'api': {
                    'host': cfg.api_host,
                    'port': cfg.api_port,
                    'enabled': cfg.api_enabled,
                },
                'lightning': {
                    'network': cfg.lightning_network,
                    'host': cfg.lightning_host,
                    'port': cfg.lightning_port,
                },
                'database': {
                    'url': cfg.database_url,
                },
                'logging': {
                    'level': cfg.log_level,
                    'file': cfg.log_file,
                }
            }

            console.print("[bold]Current Configuration:[/bold]")
            console.print(json.dumps(config_data, indent=2))

        else:
            console.print(f"[yellow]Unknown config command: {command}[/yellow]")

    except Exception as e:
        console.print(f"[red]Configuration error: {e}[/red]")


@main.command()
@click.pass_context
def health(ctx: click.Context) -> None:
    """Detailed health check with diagnostics."""
    try:
        health = get_system_health()

        console.print(f"[bold]Health Status: {health.get('status', 'unknown')}[/bold]")

        # Show detailed checks
        checks = health.get('checks', {})
        if checks:
            table = Table(title="Health Checks")
            table.add_column("Component", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Details", style="yellow")

            for component, status in checks.items():
                status_icon = "✓" if status == 'ok' else "✗"
                table.add_row(component, status_icon, str(status))

            console.print(table)

        # Show performance metrics if available
        metrics = health.get('metrics', {})
        if metrics:
            console.print("\n[bold]Performance Metrics:[/bold]")
            for metric, value in metrics.items():
                console.print(f"  {metric}: {value}")

    except Exception as e:
        console.print(f"[red]Health check failed: {e}[/red]")


@main.command()
@click.option('--output', '-o', help='Output file path')
@click.pass_context
def diagnostics(ctx: click.Context, output: Optional[str]) -> None:
    """Run comprehensive system diagnostics."""
    try:
        console.print("[bold]Running diagnostics...[/bold]")

        # Get comprehensive system information
        health = get_system_health()

        # Add system info
        import platform
        import psutil
        from datetime import datetime

        diagnostic_data = {
            'timestamp': datetime.now().isoformat(),
            'platform': platform.platform(),
            'python_version': platform.python_version(),
            'blncs_version': __version__,
            'health': health,
            'memory_usage': {
                'total': psutil.virtual_memory().total,
                'available': psutil.virtual_memory().available,
                'percent': psutil.virtual_memory().percent,
            },
            'disk_usage': {
                'total': psutil.disk_usage('/').total,
                'free': psutil.disk_usage('/').free,
                'percent': psutil.disk_usage('/').percent,
            }
        }

        if output:
            Path(output).write_text(json.dumps(diagnostic_data, indent=2))
            console.print(f"[green]Diagnostics saved to: {output}[/green]")
        else:
            console.print(json.dumps(diagnostic_data, indent=2))

    except Exception as e:
        console.print(f"[red]Diagnostics failed: {e}[/red]")


@main.command()
@click.pass_context
def optimize(ctx: click.Context) -> None:
    """Run system optimization routines."""
    try:
        console.print("[bold]Running optimization...[/bold]")

        # Import and run optimization modules
        from ..core.performance_optimizer import PerformanceOptimizer
        from ..core.database_optimizer import DatabaseOptimizer

        optimizer = PerformanceOptimizer()
        db_optimizer = DatabaseOptimizer()

        # Run optimizations
        console.print("Optimizing performance...")
        perf_results = optimizer.optimize()

        console.print("Optimizing database...")
        db_results = db_optimizer.optimize()

        console.print("[green]✓ Optimization complete[/green]")

        # Show results
        if perf_results:
            console.print("Performance optimizations applied")
        if db_results:
            console.print("Database optimizations applied")

    except ImportError as e:
        console.print(f"[yellow]Some optimization modules not available: {e}[/yellow]")
    except Exception as e:
        console.print(f"[red]Optimization failed: {e}[/red]")


@main.command()
@click.pass_context
def logs(ctx: click.Context) -> None:
    """Show recent system logs."""
    try:
        cfg = ctx.obj['config']
        log_level = ctx.obj.get('log_level', 'INFO')

        log_file = cfg.log_file if hasattr(cfg, 'log_file') else 'logs/blncs.log'

        if Path(log_file).exists():
            console.print(f"[bold]Recent logs from: {log_file}[/bold]")

            # Show last 20 lines
            with open(log_file, 'r') as f:
                lines = f.readlines()[-20:]
                for line in lines:
                    console.print(line.rstrip())
        else:
            console.print(f"[yellow]Log file not found: {log_file}[/yellow]")
            console.print("Run the system first to generate logs.")

    except Exception as e:
        console.print(f"[red]Error reading logs: {e}[/red]")


if __name__ == '__main__':
    main()
