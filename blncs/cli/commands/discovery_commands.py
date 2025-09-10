"""
Node Discovery CLI Commands
Automatic Lightning Network node discovery and recommendation.
"""

import click
from datetime import datetime
from typing import Dict, Any

from ...core.node_discovery import get_node_discovery
from ...core.exceptions import format_error_for_cli


@click.command()
@click.option('--method', default='comprehensive', 
              type=click.Choice(['quick', 'comprehensive', 'local']),
              help='Discovery method')
@click.option('--max-nodes', default=20, help='Maximum nodes to discover')
@click.option('--network', default='testnet',
              type=click.Choice(['mainnet', 'testnet', 'regtest']),
              help='Bitcoin network')
def node_discover(method: str, max_nodes: int, network: str) -> None:
    """Discover Lightning Network nodes automatically"""
    try:
        discovery = get_node_discovery()
        
        click.echo(f"Starting {method} node discovery on {network}...")
        
        scan = discovery.discover_nodes(
            method=method,
            max_nodes=max_nodes, 
            network=network
        )
        
        click.echo(f"\nDiscovery completed in {scan.scan_duration:.1f}s")
        click.echo(f"Found {scan.nodes_discovered} nodes")
        
        # Show discovery method breakdown
        if scan.discovery_methods:
            click.echo(f"\nDiscovery methods used:")
            for method_name, count in scan.discovery_methods.items():
                click.echo(f"  {method_name}: {count} nodes")
        
        # Show quality distribution
        if scan.quality_distribution:
            click.echo(f"\nNode quality distribution:")
            total = sum(scan.quality_distribution.values())
            for quality, count in scan.quality_distribution.items():
                percentage = (count / total * 100) if total > 0 else 0
                click.echo(f"  {quality.title()}: {count} ({percentage:.1f}%)")
        
        # Show top recommended nodes
        if scan.recommended_nodes:
            click.echo(f"\nTop Recommended Nodes:")
            click.echo("=" * 60)
            
            for i, node in enumerate(scan.recommended_nodes[:10], 1):
                quality = _get_node_quality_text(node)
                connection_status = "Online" if node.connectivity_score > 0.5 else "Unknown"
                
                click.echo(f"{i:2d}. {node.alias}")
                click.echo(f"    Public Key: {node.pubkey[:20]}...")
                click.echo(f"    Address: {node.host}:{node.port}")
                click.echo(f"    Channels: {node.channel_count:,}")
                click.echo(f"    Capacity: {node.capacity_btc:.3f} BTC")
                click.echo(f"    Quality: {quality} (Score: {node.connectivity_score:.2f})")
                click.echo(f"    Status: {connection_status}")
                click.echo(f"    Discovery: {node.discovery_method}")
                click.echo()
        
        # Save discovered nodes
        if scan.recommended_nodes:
            discovery.save_discovered_nodes(scan.recommended_nodes)
            click.echo(f"Saved {len(scan.recommended_nodes)} nodes for future use")
            
    except Exception as e:
        click.echo(f"Error during node discovery: {format_error_for_cli(e)}", err=True)


@click.command()
@click.option('--purpose', default='general',
              type=click.Choice(['routing', 'payments', 'general', 'liquidity']),
              help='Purpose for node recommendations')
@click.option('--count', default=10, help='Number of nodes to recommend')
@click.option('--network', default='testnet',
              type=click.Choice(['mainnet', 'testnet', 'regtest']),
              help='Bitcoin network')
def node_recommend(purpose: str, count: int, network: str) -> None:
    """Get node recommendations for specific purposes"""
    try:
        discovery = get_node_discovery()
        
        click.echo(f"Getting {purpose} node recommendations for {network}...")
        
        nodes = discovery.get_recommended_nodes(
            purpose=purpose,
            count=count,
            network=network
        )
        
        if not nodes:
            click.echo(f"No nodes found matching criteria for {purpose} on {network}")
            return
        
        click.echo(f"\nRecommended Nodes for {purpose.title()} ({len(nodes)}):")
        click.echo("=" * 60)
        
        purpose_descriptions = {
            'routing': 'High channel count and connectivity for routing payments',
            'payments': 'Reliable nodes for sending/receiving payments',
            'general': 'Well-balanced nodes for general Lightning Network usage',
            'liquidity': 'High-capacity nodes for liquidity management'
        }
        
        click.echo(f"Purpose: {purpose_descriptions.get(purpose, 'General usage')}")
        click.echo()
        
        for i, node in enumerate(nodes, 1):
            quality = _get_node_quality_text(node)
            
            click.echo(f"{i:2d}. {node.alias}")
            click.echo(f"    Public Key: {node.pubkey}")
            click.echo(f"    Address: {node.host}:{node.port}")
            click.echo(f"    Channels: {node.channel_count:,}")
            click.echo(f"    Capacity: {node.capacity_btc:.3f} BTC ({node.capacity_sats:,} sats)")
            click.echo(f"    Quality: {quality}")
            click.echo(f"    Connectivity: {node.connectivity_score:.2f}")
            
            # Show purpose-specific info
            if purpose == 'routing':
                routing_score = min(1.0, (node.channel_count / 100) * node.connectivity_score)
                click.echo(f"    Routing Score: {routing_score:.2f}")
            elif purpose == 'liquidity':
                liquidity_score = min(1.0, node.capacity_btc / 10)
                click.echo(f"    Liquidity Score: {liquidity_score:.2f}")
            
            click.echo()
        
        # Provide connection commands
        if nodes:
            click.echo("To connect to a recommended node, use:")
            top_node = nodes[0]
            click.echo(f"  quick-connect --network {network}")
            click.echo(f"  # or manually: lncli connect {top_node.pubkey}@{top_node.host}:{top_node.port}")
            
    except Exception as e:
        click.echo(f"Error getting node recommendations: {format_error_for_cli(e)}", err=True)


@click.command()
@click.option('--max-age', default=24, help='Maximum age in hours')
def node_cached(max_age: int) -> None:
    """Show previously discovered nodes from cache"""
    try:
        discovery = get_node_discovery()
        
        cached_nodes = discovery.load_cached_nodes(max_age_hours=max_age)
        
        if not cached_nodes:
            click.echo(f"No cached nodes found (max age: {max_age} hours)")
            click.echo("Run 'node-discover' to discover new nodes")
            return
        
        click.echo(f"Cached Nodes (max age: {max_age} hours):")
        click.echo("=" * 50)
        
        for i, node in enumerate(cached_nodes[:20], 1):  # Show top 20
            age_hours = (datetime.now().timestamp() - node.discovery_time) / 3600
            quality = _get_node_quality_text(node)
            
            click.echo(f"{i:2d}. {node.alias}")
            click.echo(f"    Address: {node.host}:{node.port}")
            click.echo(f"    Quality: {quality}")
            click.echo(f"    Age: {age_hours:.1f} hours")
            click.echo(f"    Discovery: {node.discovery_method}")
            click.echo()
        
        click.echo(f"Showing {min(20, len(cached_nodes))} of {len(cached_nodes)} cached nodes")
        
    except Exception as e:
        click.echo(f"Error loading cached nodes: {format_error_for_cli(e)}", err=True)


@click.command()
@click.option('--network', default='testnet',
              type=click.Choice(['mainnet', 'testnet', 'regtest']),
              help='Bitcoin network')
def node_scan_local(network: str) -> None:
    """Scan local network for Lightning nodes"""
    try:
        discovery = get_node_discovery()
        
        click.echo("Scanning local network for Lightning nodes...")
        click.echo("This will check common hosts and ports...")
        
        scan = discovery.discover_nodes(
            method="local",
            max_nodes=50,
            network=network
        )
        
        if scan.nodes_discovered == 0:
            click.echo("No Lightning nodes found on local network")
            click.echo("Check that nodes are running and ports are accessible")
            return
        
        click.echo(f"\nFound {scan.nodes_discovered} local nodes:")
        click.echo("=" * 50)
        
        for i, node in enumerate(scan.recommended_nodes, 1):
            status = "Accessible" if node.connectivity_score > 0 else "Not accessible"
            
            click.echo(f"{i}. {node.alias}")
            click.echo(f"   Address: {node.host}:{node.port}")
            click.echo(f"   Status: {status}")
            click.echo(f"   Discovery: {node.discovery_method}")
            click.echo()
        
        click.echo("Use 'connection-setup' to configure connection to a local node")
        
    except Exception as e:
        click.echo(f"Error scanning local network: {format_error_for_cli(e)}", err=True)


@click.command()
@click.argument('pubkey')
@click.option('--network', default='testnet', help='Bitcoin network')
def node_info(pubkey: str, network: str) -> None:
    """Get detailed information about a specific node"""
    try:
        discovery = get_node_discovery()
        
        # Try to find node in cache first
        cached_nodes = discovery.load_cached_nodes(max_age_hours=168)  # 1 week
        
        target_node = None
        for node in cached_nodes:
            if node.pubkey == pubkey or node.pubkey.startswith(pubkey):
                target_node = node
                break
        
        if not target_node:
            click.echo(f"Node {pubkey} not found in cache")
            click.echo("Run 'node-discover' to discover nodes first")
            return
        
        click.echo("Node Information:")
        click.echo("=" * 50)
        click.echo(f"Alias: {target_node.alias}")
        click.echo(f"Public Key: {target_node.pubkey}")
        click.echo(f"Color: {target_node.color}")
        click.echo()
        
        click.echo("Network Address:")
        click.echo(f"  Host: {target_node.host}")
        click.echo(f"  Port: {target_node.port}")
        click.echo()
        
        click.echo("Capacity & Channels:")
        click.echo(f"  Channel Count: {target_node.channel_count:,}")
        click.echo(f"  Total Capacity: {target_node.capacity_btc:.6f} BTC")
        click.echo(f"  Capacity (sats): {target_node.capacity_sats:,}")
        click.echo()
        
        quality = _get_node_quality_text(target_node)
        click.echo("Quality Metrics:")
        click.echo(f"  Overall Quality: {quality}")
        click.echo(f"  Connectivity Score: {target_node.connectivity_score:.3f}")
        click.echo(f"  Node Rank: #{target_node.node_rank}")
        click.echo()
        
        click.echo("Discovery Information:")
        click.echo(f"  Discovery Method: {target_node.discovery_method}")
        discovery_time = datetime.fromtimestamp(target_node.discovery_time)
        click.echo(f"  Discovered: {discovery_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Connection command
        click.echo(f"\nTo connect to this node:")
        click.echo(f"  lncli connect {target_node.pubkey}@{target_node.host}:{target_node.port}")
        
    except Exception as e:
        click.echo(f"Error getting node info: {format_error_for_cli(e)}", err=True)


def _get_node_quality_text(node) -> str:
    """Get human-readable quality description"""
    if node.channel_count >= 100 and node.capacity_btc >= 1.0 and node.connectivity_score >= 0.9:
        return "Excellent"
    elif node.channel_count >= 50 and node.capacity_btc >= 0.5 and node.connectivity_score >= 0.7:
        return "Good"  
    elif node.channel_count >= 20 and node.capacity_btc >= 0.1 and node.connectivity_score >= 0.5:
        return "Fair"
    else:
        return "Poor"