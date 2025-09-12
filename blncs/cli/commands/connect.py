"""
Connection Commands for BLNCS
Lightning Network connection management and testing.
"""

import click
import time
import socket
import requests
from typing import Dict, Any, Optional

@click.group(name='connect')
def connect_commands():
    """Lightning Network connection management"""
    pass

@connect_commands.command()
@click.option('--host', '-h', default='localhost', help='Lightning node host')
@click.option('--port', '-p', default=8080, help='Lightning node port')
@click.option('--timeout', '-t', default=10, help='Connection timeout in seconds')
@click.option('--retry', '-r', default=3, help='Number of retry attempts')
def test(host, port, timeout, retry):
    """Test connection to Lightning node"""
    click.echo(f"Testing connection to {host}:{port}")
    
    # Basic network connectivity test
    click.echo("1. Testing network connectivity...")
    for attempt in range(retry):
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            click.echo(f"✓ Network connection successful (attempt {attempt + 1})")
            break
        except socket.error as e:
            if attempt < retry - 1:
                click.echo(f"✗ Network connection failed (attempt {attempt + 1}): {e}")
                time.sleep(1)
            else:
                click.echo(f"✗ Network connection failed after {retry} attempts")
                return False
    
    # HTTP/REST API test
    click.echo("2. Testing REST API...")
    for attempt in range(retry):
        try:
            url = f"http://{host}:{port}/v1/getinfo"
            response = requests.get(url, timeout=timeout)
            if response.status_code == 200:
                click.echo(f"✓ REST API accessible (attempt {attempt + 1})")
                try:
                    data = response.json()
                    if 'identity_pubkey' in data:
                        click.echo(f"Node ID: {data['identity_pubkey'][:20]}...")
                    if 'alias' in data:
                        click.echo(f"Alias: {data['alias']}")
                    if 'num_active_channels' in data:
                        click.echo(f"Active Channels: {data['num_active_channels']}")
                except:
                    click.echo("✓ REST API accessible but response format unexpected")
                break
            else:
                click.echo(f"✗ REST API returned HTTP {response.status_code}")
        except requests.exceptions.RequestException as e:
            if attempt < retry - 1:
                click.echo(f"✗ REST API test failed (attempt {attempt + 1}): {e}")
                time.sleep(1)
            else:
                click.echo(f"✗ REST API test failed after {retry} attempts")
    
    click.echo("Connection test completed")

@connect_commands.command()
@click.option('--config-file', help='Save connection settings to config file')
def setup(config_file):
    """Interactive connection setup"""
    click.echo("=== Lightning Node Connection Setup ===")
    
    # Gather connection details
    host = click.prompt("Lightning node host", default="localhost")
    port = click.prompt("Lightning node port", default=8080, type=int)
    
    # Test the connection
    click.echo(f"\nTesting connection to {host}:{port}...")
    
    try:
        sock = socket.create_connection((host, port), timeout=10)
        sock.close()
        click.echo("✓ Basic network connection successful")
        
        # Test REST API
        url = f"http://{host}:{port}/v1/getinfo"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            click.echo("✓ REST API connection successful")
            
            # Try to get node info
            try:
                data = response.json()
                click.echo(f"Node Alias: {data.get('alias', 'Unknown')}")
                click.echo(f"Node ID: {data.get('identity_pubkey', 'Unknown')[:20]}...")
                click.echo(f"Network: {data.get('chains', [{}])[0].get('network', 'Unknown')}")
            except:
                click.echo("Node info format not recognized")
            
            # Save configuration if requested
            if config_file or click.confirm("Save these settings?"):
                try:
                    from blncs.core.config_manager import get_config_manager
                    config = get_config_manager()
                    config.set('lightning.host', host)
                    config.set('lightning.port', port)
                    config.save_config()
                    click.echo("✓ Configuration saved")
                except Exception as e:
                    click.echo(f"✗ Failed to save configuration: {e}")
        else:
            click.echo(f"✗ REST API returned HTTP {response.status_code}")
            
    except socket.error as e:
        click.echo(f"✗ Connection failed: {e}")
    except requests.exceptions.RequestException as e:
        click.echo(f"✗ REST API test failed: {e}")

@connect_commands.command()
def info():
    """Show current node information"""
    click.echo("=== Lightning Node Information ===")
    
    try:
        from blncs.core.config_manager import get_config_manager
        from blncs.lightning.client import SimpleClient
        
        config = get_config_manager()
        host = config.get('lightning.host', 'localhost')
        port = config.get('lightning.port', 8080)
        
        click.echo(f"Configured node: {host}:{port}")
        
        client = SimpleClient(host=host, port=port)
        if client.connect():
            click.echo("✓ Connected to Lightning node")
            
            try:
                info_data = client.get_info()
                click.echo(f"Node ID: {info_data.get('identity_pubkey', 'Unknown')}")
                click.echo(f"Alias: {info_data.get('alias', 'Unknown')}")
                click.echo(f"Active Channels: {info_data.get('num_active_channels', 0)}")
                click.echo(f"Inactive Channels: {info_data.get('num_inactive_channels', 0)}")
                click.echo(f"Pending Channels: {info_data.get('num_pending_channels', 0)}")
                click.echo(f"Block Height: {info_data.get('block_height', 'Unknown')}")
                click.echo(f"Synced: {'Yes' if info_data.get('synced_to_chain', False) else 'No'}")
            except Exception as e:
                click.echo(f"Could not retrieve node info: {e}")
        else:
            click.echo("✗ Could not connect to Lightning node")
            
    except Exception as e:
        click.echo(f"Error: {e}")

@connect_commands.command()
@click.option('--interval', '-i', default=30, help='Check interval in seconds')
@click.option('--count', '-c', default=10, help='Number of checks to perform')
def monitor(interval, count):
    """Monitor connection status"""
    click.echo(f"Monitoring connection every {interval} seconds ({count} checks)")
    
    try:
        from blncs.core.config_manager import get_config_manager
        config = get_config_manager()
        host = config.get('lightning.host', 'localhost')
        port = config.get('lightning.port', 8080)
        
        for i in range(count):
            click.echo(f"\nCheck {i + 1}/{count} at {time.strftime('%H:%M:%S')}")
            
            try:
                # Quick connectivity test
                start_time = time.time()
                sock = socket.create_connection((host, port), timeout=5)
                sock.close()
                response_time = (time.time() - start_time) * 1000
                
                click.echo(f"✓ Connection OK ({response_time:.1f}ms)")
                
                # Try to get basic info
                try:
                    url = f"http://{host}:{port}/v1/getinfo"
                    response = requests.get(url, timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        channels = data.get('num_active_channels', 0)
                        click.echo(f"  Active channels: {channels}")
                        sync_status = "Synced" if data.get('synced_to_chain', False) else "Syncing"
                        click.echo(f"  Status: {sync_status}")
                except:
                    click.echo("  (Could not get detailed status)")
                    
            except socket.error as e:
                click.echo(f"✗ Connection failed: {e}")
            except Exception as e:
                click.echo(f"✗ Error: {e}")
            
            if i < count - 1:
                time.sleep(interval)
        
        click.echo("\nMonitoring completed")
        
    except KeyboardInterrupt:
        click.echo("\nMonitoring stopped by user")
    except Exception as e:
        click.echo(f"Monitoring error: {e}")

if __name__ == '__main__':
    connect_commands()