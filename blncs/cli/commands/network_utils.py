"""
Network Utility Commands
Network connectivity, diagnostics, and Lightning network tools.
"""

import click
import socket
import time
from typing import List, Tuple

def check_host_port(host: str, port: int, timeout: float = 3.0) -> Tuple[bool, str]:
    """Check if a host:port is reachable"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            return True, "Connected"
        else:
            return False, f"Connection failed (error {result})"
    except socket.gaierror as e:
        return False, f"DNS resolution failed: {e}"
    except Exception as e:
        return False, f"Error: {e}"

def ping_host(host: str, count: int = 4) -> List[Tuple[bool, float, str]]:
    """Simple connectivity test using socket connection"""
    results = []
    
    for i in range(count):
        start_time = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((host, 80))  # Try HTTP port
            sock.close()
            
            end_time = time.time()
            latency = (end_time - start_time) * 1000  # Convert to ms
            
            if result == 0:
                results.append((True, latency, "OK"))
            else:
                results.append((False, latency, f"Failed (error {result})"))
        except Exception as e:
            end_time = time.time()
            latency = (end_time - start_time) * 1000
            results.append((False, latency, str(e)))
        
        if i < count - 1:  # Don't sleep after last iteration
            time.sleep(1)
    
    return results

@click.command()
@click.option('--host', default='8.8.8.8', help='Host to test')
@click.option('--count', default=4, help='Number of tests')
def nettest(host, count):
    """Test network connectivity"""
    try:
        click.echo(f"🌐 Network Connectivity Test")
        click.echo("=" * 50)
        click.echo(f"Target: {host}")
        click.echo(f"Tests: {count}")
        click.echo()
        
        results = ping_host(host, count)
        
        success_count = 0
        total_latency = 0
        min_latency = float('inf')
        max_latency = 0
        
        for i, (success, latency, message) in enumerate(results, 1):
            status = "✅" if success else "❌"
            click.echo(f"{status} Test {i}: {latency:.1f}ms - {message}")
            
            if success:
                success_count += 1
                total_latency += latency
                min_latency = min(min_latency, latency)
                max_latency = max(max_latency, latency)
        
        # Summary
        click.echo()
        click.echo("📊 Summary:")
        click.echo(f"Success: {success_count}/{count} ({(success_count/count)*100:.1f}%)")
        
        if success_count > 0:
            avg_latency = total_latency / success_count
            click.echo(f"Latency: min={min_latency:.1f}ms avg={avg_latency:.1f}ms max={max_latency:.1f}ms")
            
            # Network quality assessment
            if avg_latency < 50:
                click.echo("🟢 Network Quality: Excellent")
            elif avg_latency < 150:
                click.echo("🟡 Network Quality: Good")
            elif avg_latency < 300:
                click.echo("🟠 Network Quality: Fair")
            else:
                click.echo("🔴 Network Quality: Poor")
        
    except Exception as e:
        click.echo(f"❌ Network test failed: {e}", err=True)

@click.command()
def lightning_network():
    """Show Lightning Network information"""
    try:
        click.echo("⚡ Lightning Network Status")
        click.echo("=" * 50)
        
        # Test common Lightning node ports
        lightning_hosts = [
            ("localhost", 8080, "Local Lightning REST"),
            ("localhost", 10009, "Local Lightning gRPC"),
            ("localhost", 9735, "Local Lightning P2P"),
        ]
        
        click.echo("🔍 Checking common Lightning ports:")
        for host, port, description in lightning_hosts:
            success, message = check_host_port(host, port, timeout=2.0)
            status = "✅" if success else "❌"
            click.echo(f"  {status} {host}:{port} ({description}) - {message}")
        
        click.echo()
        
        # Check internet connectivity to Lightning network
        click.echo("🌐 Lightning Network Connectivity:")
        internet_hosts = [
            ("google.com", 80, "Internet connectivity"),
            ("github.com", 443, "GitHub (SSL)"),
            ("mempool.space", 443, "Bitcoin mempool")
        ]
        
        for host, port, description in internet_hosts:
            success, message = check_host_port(host, port, timeout=3.0)
            status = "✅" if success else "❌"
            click.echo(f"  {status} {host}:{port} ({description}) - {message}")
        
        click.echo()
        
        # Mock Lightning Network stats
        try:
            from ...lightning.client_simple import get_lightning_client
            client = get_lightning_client()
            client.connect()
            
            network_info = client.get_network_info()
            click.echo("📊 Lightning Network Statistics:")
            click.echo(f"  Nodes: {network_info.get('num_nodes', 0):,}")
            click.echo(f"  Channels: {network_info.get('num_channels', 0):,}")
            click.echo(f"  Capacity: {network_info.get('total_capacity', 0):,} sats")
            
        except Exception as e:
            click.echo(f"⚠️  Could not fetch Lightning network stats: {e}")
        
    except Exception as e:
        click.echo(f"❌ Lightning network check failed: {e}", err=True)

@click.command()
@click.argument('host')
@click.argument('port', type=int)
@click.option('--timeout', default=3.0, help='Connection timeout in seconds')
def check_port(host, port, timeout):
    """Check if a specific host:port is reachable"""
    try:
        click.echo(f"🔍 Checking {host}:{port}...")
        
        start_time = time.time()
        success, message = check_host_port(host, port, timeout)
        end_time = time.time()
        
        latency = (end_time - start_time) * 1000
        status = "✅" if success else "❌"
        
        click.echo(f"{status} {host}:{port}")
        click.echo(f"Status: {message}")
        click.echo(f"Time: {latency:.1f}ms")
        
        if success:
            click.echo("🟢 Port is open and reachable")
        else:
            click.echo("🔴 Port is not reachable")
            click.echo("💡 Possible causes:")
            click.echo("  • Service not running")
            click.echo("  • Firewall blocking connection")
            click.echo("  • Network connectivity issues")
            click.echo("  • Incorrect host/port")
        
    except Exception as e:
        click.echo(f"❌ Port check failed: {e}", err=True)

@click.command()
def network_info():
    """Show network configuration information"""
    try:
        click.echo("🌐 Network Configuration")
        click.echo("=" * 50)
        
        # Get hostname
        hostname = socket.gethostname()
        click.echo(f"Hostname: {hostname}")
        
        # Get local IP addresses
        try:
            # Connect to a remote address to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            click.echo(f"Local IP: {local_ip}")
        except:
            click.echo("Local IP: Unable to determine")
        
        click.echo()
        
        # Show current configuration
        try:
            from ...core.config_manager import get_config_manager
            config = get_config_manager()
            lightning_config = config.get('lightning', {})
            
            click.echo("⚡ Lightning Configuration:")
            click.echo(f"  Host: {lightning_config.get('host', 'localhost')}")
            click.echo(f"  Port: {lightning_config.get('port', 8080)}")
            click.echo(f"  Network: {lightning_config.get('network', 'testnet')}")
            click.echo(f"  Mock Mode: {lightning_config.get('mock_mode', True)}")
            
        except Exception as e:
            click.echo(f"⚠️  Could not load configuration: {e}")
        
    except Exception as e:
        click.echo(f"❌ Network info failed: {e}", err=True)