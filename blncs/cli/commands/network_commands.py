"""
Network diagnostic commands
Simple connectivity testing and network troubleshooting.
"""

import click
from typing import Dict, Any

from ...utils.network_test import (
    run_network_diagnostics, 
    format_diagnostic_results,
    test_internet_connection,
    test_lightning_port,
    test_bitcoin_node_rpc
)
from ...utils.system_info import (
    get_comprehensive_system_report,
    format_system_report
)
from ...core.exceptions import format_error_for_cli


@click.command('nettest')
@click.option('--quick', '-q', is_flag=True, help='Quick connectivity test')
@click.option('--host', default='localhost', help='Lightning node host to test')
@click.option('--port', default=9735, type=int, help='Lightning node port to test')
def network_test(quick: bool, host: str, port: int) -> None:
    """Test network connectivity for Lightning Network"""
    try:
        if quick:
            click.echo("Quick Network Test")
            click.echo("-" * 30)
            
            # Test internet only
            internet_result = test_internet_connection(timeout=3)
            if internet_result["status"] == "connected":
                click.echo("[OK] Internet: Connected")
            else:
                click.echo(f"[ERROR] Internet: {internet_result.get('error', 'Unknown error')}")
            
            # Test Lightning port
            ln_result = test_lightning_port(host, port, timeout=2)
            if ln_result["status"] == "open":
                click.echo(f"[OK] Lightning: {host}:{port} reachable")
            else:
                click.echo(f"[ERROR] Lightning: {host}:{port} - {ln_result['status']}")
                
        else:
            # Full diagnostic
            results = run_network_diagnostics()
            formatted_output = format_diagnostic_results(results)
            click.echo(formatted_output)
            
    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)


@click.command('ping')
@click.argument('target', required=False, default='localhost')
@click.option('--port', '-p', default=9735, type=int, help='Port to test')
@click.option('--timeout', '-t', default=3, type=int, help='Connection timeout')
def lightning_ping(target: str, port: int, timeout: int) -> None:
    """Ping a Lightning Network node"""
    try:
        click.echo(f"Pinging {target}:{port}...")
        
        result = test_lightning_port(target, port, timeout)
        
        if result["status"] == "open":
            response_time = result.get("response_time", 0)
            click.echo(f"[OK] {target}:{port} is reachable ({response_time:.3f}s)")
        elif result["status"] == "closed":
            click.echo(f"[ERROR] {target}:{port} connection refused")
        else:
            click.echo(f"[ERROR] {target}:{port} - {result.get('error', 'Unknown error')}")
            
    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)

@click.command('sysinfo')
@click.option('--json', 'output_json', is_flag=True, help='Output in JSON format')
def system_info(output_json: bool) -> None:
    """Display system information and resource usage"""
    try:
        report = get_comprehensive_system_report()
        
        if output_json:
            import json
            click.echo(json.dumps(report, indent=2))
        else:
            formatted_output = format_system_report(report)
            click.echo(formatted_output)
            
    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)
