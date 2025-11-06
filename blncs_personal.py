#!/usr/bin/env python3
"""
BLNCS Personal - Simplified CLI for personal use
個人使用向け簡易CLI
"""

import os
import sys
import click
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


@click.group()
@click.version_option(version='1.0.0')
def cli():
    """BLNCS Personal - Lightning Network management for personal use"""
    pass


@cli.command()
@click.option('--port', default=3000, help='API server port')
@click.option('--no-auth', is_flag=True, help='Disable authentication (localhost only)')
@click.option('--mock', is_flag=True, help='Use mock Lightning client')
def start(port, no_auth, mock):
    """Start BLNCS server with personal optimizations"""
    from blncs.core.config_manager import UnifiedConfigManager
    from blncs.api.unified_rest_api import create_app
    from blncs.core.personal_auth import get_personal_auth

    console.print(Panel.fit(
        "[bold cyan]BLNCS Personal[/bold cyan]\n"
        "Lightning Network Control System",
        border_style="cyan"
    ))

    # Load personal configuration
    config_path = "config/personal.json"
    if not Path(config_path).exists():
        console.print("[yellow]Creating personal configuration...[/yellow]")
        config_path = "config/development.json"

    config = UnifiedConfigManager(config_path, enable_file_watching=True)

    # Override with CLI options
    if no_auth:
        os.environ['BLNCS_REQUIRE_AUTH'] = 'false'
        console.print("[yellow]⚠ Authentication disabled (localhost only)[/yellow]")

    if mock:
        os.environ['BLNCS_LIGHTNING_MOCK_MODE'] = 'true'
        console.print("[yellow]Using mock Lightning client[/yellow]")

    # Initialize personal auth
    auth = get_personal_auth()

    # Display startup info
    console.print(f"\n[green]✓[/green] Server starting on http://127.0.0.1:{port}")
    console.print(f"[green]✓[/green] Configuration: {config_path}")
    console.print(f"[green]✓[/green] Auth tokens: {len(auth.list_tokens())}")

    if auth.localhost_bypass and not auth.require_auth:
        console.print("[yellow]⚠ Localhost bypass enabled - no auth required from 127.0.0.1[/yellow]")

    console.print("\n[bold]Quick Start:[/bold]")
    console.print(f"  Health check: curl http://127.0.0.1:{port}/health")

    if auth.tokens:
        first_token = list(auth.tokens.values())[0]
        console.print(f"  With auth: curl -H 'Authorization: Bearer {first_token.token}' http://127.0.0.1:{port}/api/lightning/info")

    console.print("\n[dim]Press Ctrl+C to stop[/dim]\n")

    # Create and run app
    app = create_app(config)

    try:
        import uvicorn
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
    except ImportError:
        # Fallback to Flask development server
        app.run(host="127.0.0.1", port=port, debug=False)


@cli.command()
@click.argument('name', default='personal')
@click.option('--read-only', is_flag=True, help='Create read-only token')
@click.option('--expires', type=int, help='Expiration in days')
def token(name, read_only, expires):
    """Generate a new personal access token"""
    from blncs.core.personal_auth import get_personal_auth

    auth = get_personal_auth()

    permissions = 'read_only' if read_only else 'full'
    token = auth.generate_token(
        name=name,
        permissions=permissions,
        expires_in_days=expires,
        never_expire=(expires is None)
    )

    console.print(Panel.fit(
        f"[bold green]Token Created[/bold green]\n\n"
        f"Name: {name}\n"
        f"Permissions: {permissions}\n"
        f"Expires: {'Never' if expires is None else f'{expires} days'}\n\n"
        f"[bold cyan]Token:[/bold cyan]\n{token}\n\n"
        f"[dim]Use with: curl -H 'Authorization: Bearer {token}' ...[/dim]",
        border_style="green"
    ))


@cli.command()
def tokens():
    """List all personal access tokens"""
    from blncs.core.personal_auth import get_personal_auth

    auth = get_personal_auth()
    token_list = auth.list_tokens()

    if not token_list:
        console.print("[yellow]No tokens found. Create one with: blncs_personal.py token[/yellow]")
        return

    table = Table(title="Personal Access Tokens", show_header=True)
    table.add_column("Name", style="cyan")
    table.add_column("Token Preview", style="dim")
    table.add_column("Permissions", style="green")
    table.add_column("Created", style="blue")
    table.add_column("Expires", style="yellow")
    table.add_column("Last Used", style="magenta")

    for token_info in token_list:
        table.add_row(
            token_info['name'],
            token_info['token_preview'],
            token_info['permissions'],
            token_info['created_at'][:10],
            token_info['expires_at'][:10] if token_info['expires_at'] != 'never' else 'Never',
            token_info['last_used'][:10] if token_info['last_used'] != 'never' else 'Never'
        )

    console.print(table)


@cli.command()
@click.argument('name')
def revoke(name):
    """Revoke a personal access token by name"""
    from blncs.core.personal_auth import get_personal_auth

    auth = get_personal_auth()
    token = auth.get_token_by_name(name)

    if not token:
        console.print(f"[red]Token '{name}' not found[/red]")
        return

    if click.confirm(f"Revoke token '{name}'?"):
        auth.revoke_token(token)
        console.print(f"[green]✓ Token '{name}' revoked[/green]")


@cli.command()
def status():
    """Show BLNCS status and health"""
    import requests
    from blncs.core.personal_auth import get_personal_auth

    console.print("[bold]Checking BLNCS status...[/bold]\n")

    # Check auth setup
    auth = get_personal_auth()
    console.print(f"[green]✓[/green] Auth tokens: {len(auth.list_tokens())}")
    console.print(f"[green]✓[/green] Auth required: {auth.require_auth}")
    console.print(f"[green]✓[/green] Localhost bypass: {auth.localhost_bypass}")

    # Try to connect to API
    try:
        response = requests.get("http://127.0.0.1:3000/health", timeout=2)
        if response.status_code == 200:
            data = response.json()
            console.print(f"\n[green]✓[/green] API Server: Online")
            console.print(f"[green]✓[/green] Status: {data.get('status', 'unknown')}")

            checks = data.get('checks', {})
            for name, status in checks.items():
                symbol = "✓" if status in ['ok', 'available'] else "✗"
                color = "green" if status in ['ok', 'available'] else "yellow"
                console.print(f"[{color}]{symbol}[/{color}] {name}: {status}")
        else:
            console.print(f"[yellow]⚠[/yellow] API Server: Response code {response.status_code}")
    except requests.ConnectionError:
        console.print(f"[yellow]⚠[/yellow] API Server: Not running")
        console.print(f"[dim]Start with: python blncs_personal.py start[/dim]")
    except Exception as e:
        console.print(f"[red]✗[/red] Error: {e}")


@cli.command()
def setup():
    """Interactive setup wizard for personal use"""
    from blncs.core.config_manager import UnifiedConfigManager
    from blncs.core.personal_auth import get_personal_auth
    import json

    console.print(Panel.fit(
        "[bold cyan]BLNCS Personal Setup Wizard[/bold cyan]\n"
        "Let's configure BLNCS for your personal use",
        border_style="cyan"
    ))

    # Check if already set up
    auth_file = Path.home() / ".blncs" / "auth.json"
    if auth_file.exists():
        if not click.confirm("\nBLNCS is already set up. Reconfigure?"):
            return

    console.print("\n[bold]1. Lightning Node Configuration[/bold]")

    use_mock = click.confirm("Use mock Lightning client for testing?", default=True)

    if not use_mock:
        network = click.prompt("Network", default="testnet", type=click.Choice(['mainnet', 'testnet', 'regtest']))
        host = click.prompt("Lightning node host", default="localhost")
        port = click.prompt("Lightning node port", default=10009, type=int)

        lnd_dir = Path.home() / ".lnd"
        macaroon_path = click.prompt("Admin macaroon path",
            default=str(lnd_dir / "data/chain/bitcoin" / network / "admin.macaroon"))
        tls_cert_path = click.prompt("TLS certificate path",
            default=str(lnd_dir / "tls.cert"))
    else:
        network = "testnet"
        host = "localhost"
        port = 10009
        macaroon_path = ""
        tls_cert_path = ""

    console.print("\n[bold]2. API Configuration[/bold]")
    api_port = click.prompt("API port", default=3000, type=int)

    console.print("\n[bold]3. Security Configuration[/bold]")
    require_auth = click.confirm("Require authentication?", default=True)
    localhost_bypass = click.confirm("Allow localhost without auth?", default=True)

    # Create configuration
    config_dir = Path("config")
    config_dir.mkdir(exist_ok=True)

    personal_config = {
        "version": "2.0.0",
        "environment": "personal",
        "lightning": {
            "network": network,
            "host": host,
            "port": port,
            "mock_mode": use_mock,
            "macaroon_path": macaroon_path if not use_mock else "",
            "tls_cert_path": tls_cert_path if not use_mock else ""
        },
        "api": {
            "enabled": True,
            "host": "127.0.0.1",
            "port": api_port,
            "cors_enabled": True,
            "authentication": {
                "enabled": require_auth,
                "type": "personal",
                "localhost_bypass": localhost_bypass
            }
        },
        "security": {
            "trusted_hosts": ["localhost", "127.0.0.1"],
            "enforce_https": False
        },
        "database": {
            "url": f"sqlite:///{Path.home()}/.blncs/blncs.db"
        },
        "logging": {
            "level": "INFO",
            "output": "both",
            "log_dir": f"{Path.home()}/.blncs/logs"
        }
    }

    config_path = config_dir / "personal.json"
    with open(config_path, 'w') as f:
        json.dump(personal_config, f, indent=2)

    console.print(f"\n[green]✓[/green] Configuration saved to {config_path}")

    # Set up authentication
    if require_auth:
        console.print("\n[bold]4. Generating Access Token[/bold]")

        os.environ['BLNCS_REQUIRE_AUTH'] = 'true' if require_auth else 'false'
        os.environ['BLNCS_LOCALHOST_BYPASS'] = 'true' if localhost_bypass else 'false'

        auth = get_personal_auth()

        console.print(f"\n[green]✓[/green] Access token created")
        console.print(f"[green]✓[/green] Token file: {auth.auth_file}")

    console.print(Panel.fit(
        "[bold green]Setup Complete![/bold green]\n\n"
        f"Start server: python blncs_personal.py start\n"
        f"Check status: python blncs_personal.py status\n"
        f"View tokens: python blncs_personal.py tokens",
        border_style="green"
    ))


@cli.command()
def info():
    """Display BLNCS lightning node information"""
    from blncs.lightning.simple_client import SimpleLightningClient
    import requests
    from blncs.core.personal_auth import get_personal_auth

    try:
        # Get first token
        auth = get_personal_auth()
        tokens = auth.list_tokens()

        if not tokens and auth.require_auth:
            console.print("[red]No auth tokens found. Create one with: python blncs_personal.py token[/red]")
            return

        # Get token value
        token = None
        if tokens:
            token_name = tokens[0]['name']
            token = auth.get_token_by_name(token_name)

        headers = {}
        if token:
            headers['Authorization'] = f'Bearer {token}'

        response = requests.get("http://127.0.0.1:3000/api/lightning/info", headers=headers, timeout=5)

        if response.status_code == 200:
            data = response.json()

            table = Table(title="Lightning Node Information", show_header=False)
            table.add_column("Property", style="cyan")
            table.add_column("Value", style="green")

            table.add_row("Node ID", data.get('node_id', 'N/A'))
            table.add_row("Alias", data.get('alias', 'N/A'))
            table.add_row("Network", data.get('network', 'N/A'))
            table.add_row("Channels", str(data.get('num_channels', 0)))
            table.add_row("Active Channels", str(data.get('num_active_channels', 0)))
            table.add_row("Block Height", str(data.get('block_height', 0)))
            table.add_row("Synced", "Yes" if data.get('synced_to_chain') else "No")

            console.print(table)
        else:
            console.print(f"[red]Error: {response.status_code}[/red]")
            console.print(response.text)

    except requests.ConnectionError:
        console.print("[red]Cannot connect to BLNCS API. Is the server running?[/red]")
        console.print("[dim]Start with: python blncs_personal.py start[/dim]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@cli.command()
@click.argument('amount', type=int)
@click.argument('memo', default='')
def invoice(amount, memo):
    """Create a Lightning invoice"""
    import requests
    from blncs.core.personal_auth import get_personal_auth

    try:
        auth = get_personal_auth()
        tokens = auth.list_tokens()

        token = None
        if tokens:
            token = auth.get_token_by_name(tokens[0]['name'])

        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = f'Bearer {token}'

        response = requests.post(
            "http://127.0.0.1:3000/api/lightning/invoice",
            headers=headers,
            json={'amount': amount, 'memo': memo},
            timeout=5
        )

        if response.status_code == 200:
            data = response.json()

            console.print(Panel.fit(
                f"[bold green]Invoice Created[/bold green]\n\n"
                f"Amount: {amount} sats\n"
                f"Memo: {memo or 'None'}\n\n"
                f"[bold cyan]Payment Request:[/bold cyan]\n{data.get('payment_request', 'N/A')}\n\n"
                f"Payment Hash: {data.get('payment_hash', 'N/A')[:16]}...",
                border_style="green"
            ))
        else:
            console.print(f"[red]Error: {response.status_code}[/red]")
            console.print(response.json())

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@cli.command()
def balance():
    """Show Lightning wallet balance"""
    import requests
    from blncs.core.personal_auth import get_personal_auth

    try:
        auth = get_personal_auth()
        tokens = auth.list_tokens()

        token = None
        if tokens:
            token = auth.get_token_by_name(tokens[0]['name'])

        headers = {}
        if token:
            headers['Authorization'] = f'Bearer {token}'

        response = requests.get("http://127.0.0.1:3000/api/lightning/balance", headers=headers, timeout=5)

        if response.status_code == 200:
            data = response.json()

            table = Table(title="Lightning Wallet Balance", show_header=False)
            table.add_column("Type", style="cyan")
            table.add_column("Amount", style="green")

            total = data.get('total_balance', 0)
            confirmed = data.get('confirmed_balance', 0)
            unconfirmed = data.get('unconfirmed_balance', 0)

            table.add_row("Total", f"{total:,} sats ({total/100_000_000:.8f} BTC)")
            table.add_row("Confirmed", f"{confirmed:,} sats")
            table.add_row("Unconfirmed", f"{unconfirmed:,} sats")

            console.print(table)
        else:
            console.print(f"[red]Error: {response.status_code}[/red]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


@cli.command()
def logs():
    """Show recent logs"""
    log_file = Path.home() / ".blncs" / "logs" / "blncs.log"

    if not log_file.exists():
        console.print("[yellow]No logs found[/yellow]")
        return

    console.print(f"[bold]Recent logs from {log_file}[/bold]\n")

    with open(log_file, 'r') as f:
        lines = f.readlines()
        for line in lines[-50:]:  # Last 50 lines
            console.print(line.rstrip())


if __name__ == '__main__':
    cli()
