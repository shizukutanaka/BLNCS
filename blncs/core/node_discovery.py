"""
Automatic Lightning Node Discovery
Discover and evaluate Lightning Network nodes for connections.
"""

import socket
import threading
import time
import json
import requests
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

from .logger import get_logger
from .config_manager import get_config_manager
from .database import get_database_manager


@dataclass
class DiscoveredNode:
    """Information about a discovered Lightning node"""
    pubkey: str
    alias: str
    addresses: List[Dict[str, Any]]
    features: Dict[str, bool]
    last_update: int
    color: str
    
    # Connection info
    host: str = ""
    port: int = 9735
    
    # Quality metrics
    channel_count: int = 0
    capacity_btc: float = 0.0
    node_rank: int = 0
    connectivity_score: float = 0.0
    
    # Discovery method
    discovery_method: str = "unknown"
    discovery_time: float = 0.0
    
    @property
    def capacity_sats(self) -> int:
        """Capacity in satoshis"""
        return int(self.capacity_btc * 100_000_000)


@dataclass
class NetworkScan:
    """Results of a network scan"""
    nodes_discovered: int
    scan_duration: float
    discovery_methods: Dict[str, int]
    quality_distribution: Dict[str, int]
    recommended_nodes: List[DiscoveredNode]


class NodeDiscovery:
    """Automatic Lightning Node Discovery system"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config_manager = get_config_manager()
        self.db = get_database_manager()
        
        # Discovery settings
        self.timeout = 5.0
        self.max_concurrent = 20
        self.min_channels = 5
        self.min_capacity_sats = 1000000  # 0.01 BTC
        
        # Node quality thresholds
        self.quality_thresholds = {
            'excellent': {'channels': 100, 'capacity_btc': 1.0, 'connectivity': 0.9},
            'good': {'channels': 50, 'capacity_btc': 0.5, 'connectivity': 0.7},
            'fair': {'channels': 20, 'capacity_btc': 0.1, 'connectivity': 0.5},
            'poor': {'channels': 5, 'capacity_btc': 0.01, 'connectivity': 0.3}
        }
        
        # Discovery sources
        self.discovery_sources = [
            "https://1ml.com/node",
            "https://amboss.space/node",
            "https://ln.fiatjaf.com/node"
        ]
        
        # Well-known public nodes
        self.known_good_nodes = [
            {
                'alias': 'ACINQ',
                'pubkey': '03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f',
                'host': 'node.acinq.co',
                'port': 9735,
                'description': 'Eclair implementation team node'
            },
            {
                'alias': 'Bitrefill',
                'pubkey': '030c3f19d742ca294a55c00376b3b355c3c90d61c6b6b39554dbc7ac19b141c14f',
                'host': 'node.bitrefill.com', 
                'port': 9735,
                'description': 'Bitrefill merchant node'
            },
            {
                'alias': 'OpenNode',
                'pubkey': '03abf6f44c355dec0d5aa155bdbdd6e0c8fefe318eff402de65c6eb2e1be55dc3e',
                'host': 'node.opennode.co',
                'port': 9735,
                'description': 'OpenNode payment processor'
            }
        ]
        
        # Cache
        self.node_cache = {}
        self.cache_expiry = 3600  # 1 hour
    
    def discover_nodes(self, 
                      method: str = "comprehensive",
                      max_nodes: int = 50,
                      network: str = "mainnet") -> NetworkScan:
        """
        Discover Lightning Network nodes
        
        Args:
            method: Discovery method ('quick', 'comprehensive', 'local')
            max_nodes: Maximum nodes to discover
            network: Network to scan ('mainnet', 'testnet', 'regtest')
        
        Returns:
            NetworkScan results
        """
        start_time = time.time()
        discovered_nodes = []
        discovery_stats = {}
        
        self.logger.info(f"Starting {method} node discovery on {network}")
        
        if method == "quick":
            # Quick discovery using known good nodes
            nodes = self._discover_known_nodes(network)
            discovery_stats["known_nodes"] = len(nodes)
            discovered_nodes.extend(nodes)
            
        elif method == "local":
            # Local network discovery
            nodes = self._discover_local_nodes()
            discovery_stats["local_nodes"] = len(nodes)
            discovered_nodes.extend(nodes)
            
        elif method == "comprehensive":
            # Comprehensive discovery using multiple methods
            
            # 1. Known good nodes
            known_nodes = self._discover_known_nodes(network)
            discovery_stats["known_nodes"] = len(known_nodes)
            discovered_nodes.extend(known_nodes)
            
            # 2. Local network scan
            local_nodes = self._discover_local_nodes()
            discovery_stats["local_nodes"] = len(local_nodes)
            discovered_nodes.extend(local_nodes)
            
            # 3. Public directory lookup
            if network == "mainnet":
                directory_nodes = self._discover_from_directories()
                discovery_stats["directory_nodes"] = len(directory_nodes)
                discovered_nodes.extend(directory_nodes)
            
            # 4. Graph exploration (if we have some nodes already)
            if discovered_nodes:
                graph_nodes = self._discover_from_graph(discovered_nodes[:10])
                discovery_stats["graph_nodes"] = len(graph_nodes)
                discovered_nodes.extend(graph_nodes)
        
        # Remove duplicates and filter
        unique_nodes = self._deduplicate_nodes(discovered_nodes)
        filtered_nodes = self._filter_quality_nodes(unique_nodes, max_nodes)
        
        # Rank nodes
        ranked_nodes = self._rank_nodes(filtered_nodes)
        
        scan_duration = time.time() - start_time
        
        # Generate quality distribution
        quality_dist = self._calculate_quality_distribution(ranked_nodes)
        
        self.logger.info(f"Node discovery completed: {len(ranked_nodes)} nodes in {scan_duration:.1f}s")
        
        return NetworkScan(
            nodes_discovered=len(ranked_nodes),
            scan_duration=scan_duration,
            discovery_methods=discovery_stats,
            quality_distribution=quality_dist,
            recommended_nodes=ranked_nodes[:max_nodes]
        )
    
    def _discover_known_nodes(self, network: str) -> List[DiscoveredNode]:
        """Discover from known good nodes list"""
        nodes = []
        
        for node_info in self.known_good_nodes:
            try:
                # Test connectivity
                if self._test_node_connectivity(node_info['host'], node_info['port']):
                    node = DiscoveredNode(
                        pubkey=node_info['pubkey'],
                        alias=node_info['alias'],
                        addresses=[{'host': node_info['host'], 'port': node_info['port']}],
                        features={},
                        last_update=int(time.time()),
                        color="#000000",
                        host=node_info['host'],
                        port=node_info['port'],
                        discovery_method="known_good",
                        discovery_time=time.time()
                    )
                    nodes.append(node)
                    self.logger.debug(f"Discovered known node: {node.alias}")
                    
            except Exception as e:
                self.logger.debug(f"Failed to connect to known node {node_info['alias']}: {e}")
        
        return nodes
    
    def _discover_local_nodes(self) -> List[DiscoveredNode]:
        """Discover nodes on local network"""
        nodes = []
        local_ports = [9735, 9736, 10009]  # Common Lightning ports
        
        # Scan local network ranges
        local_ranges = [
            "192.168.1.0/24",
            "192.168.0.0/24", 
            "10.0.0.0/24"
        ]
        
        def scan_host_port(host: str, port: int) -> Optional[DiscoveredNode]:
            try:
                if self._test_node_connectivity(host, port):
                    # Try to get node info (this would require actual Lightning protocol)
                    node = DiscoveredNode(
                        pubkey=f"local_{host}_{port}",  # Placeholder
                        alias=f"Local-{host}",
                        addresses=[{'host': host, 'port': port}],
                        features={},
                        last_update=int(time.time()),
                        color="#808080",
                        host=host,
                        port=port,
                        discovery_method="local_scan",
                        discovery_time=time.time()
                    )
                    return node
            except Exception:
                pass
            return None
        
        # Scan common hosts first
        common_hosts = ["localhost", "127.0.0.1", "umbrel.local", "mynode.local"]
        
        with ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            futures = []
            
            for host in common_hosts:
                for port in local_ports:
                    future = executor.submit(scan_host_port, host, port)
                    futures.append(future)
            
            for future in as_completed(futures):
                try:
                    node = future.result(timeout=2)
                    if node:
                        nodes.append(node)
                        self.logger.debug(f"Discovered local node: {node.host}:{node.port}")
                except Exception:
                    pass
        
        return nodes
    
    def _discover_from_directories(self) -> List[DiscoveredNode]:
        """Discover nodes from public directories"""
        nodes = []
        
        # This would typically use APIs from 1ML, Amboss, etc.
        # For now, we'll simulate some directory data
        
        try:
            # Simulated directory response
            directory_nodes = [
                {
                    'pubkey': '03da6d089ad8e1f7e7d4b0ea34cb37b19b5a6e2f48c7f8b96f5b90c7f1cf6b1b8c',
                    'alias': 'DirectoryNode1',
                    'addresses': [{'host': 'node1.example.com', 'port': 9735}],
                    'channel_count': 50,
                    'capacity': 5.0
                },
                {
                    'pubkey': '02f6725c3e04f6f8b3f2d6d0a8c3b9e1f5d2c7b4e8f1a3b9c2d5e8f1a4b7c0e3',
                    'alias': 'DirectoryNode2', 
                    'addresses': [{'host': 'node2.example.com', 'port': 9735}],
                    'channel_count': 75,
                    'capacity': 10.0
                }
            ]
            
            for node_data in directory_nodes:
                node = DiscoveredNode(
                    pubkey=node_data['pubkey'],
                    alias=node_data['alias'],
                    addresses=node_data['addresses'],
                    features={},
                    last_update=int(time.time()),
                    color="#4CAF50",
                    host=node_data['addresses'][0]['host'],
                    port=node_data['addresses'][0]['port'],
                    channel_count=node_data['channel_count'],
                    capacity_btc=node_data['capacity'],
                    discovery_method="directory",
                    discovery_time=time.time()
                )
                nodes.append(node)
                
        except Exception as e:
            self.logger.warning(f"Failed to discover from directories: {e}")
        
        return nodes
    
    def _discover_from_graph(self, seed_nodes: List[DiscoveredNode]) -> List[DiscoveredNode]:
        """Discover nodes by exploring the network graph"""
        nodes = []
        
        # This would use the Lightning Network gossip protocol
        # to discover nodes connected to known nodes
        # For now, we'll simulate graph exploration
        
        try:
            for seed_node in seed_nodes[:5]:  # Limit seed nodes
                # Simulate finding connected peers
                peer_count = min(10, max(3, seed_node.channel_count // 10))
                
                for i in range(peer_count):
                    # Generate simulated peer
                    peer_pubkey = f"graph_{seed_node.pubkey[:8]}_{i:02d}"
                    peer_node = DiscoveredNode(
                        pubkey=peer_pubkey,
                        alias=f"Peer-{seed_node.alias}-{i+1}",
                        addresses=[{'host': f'peer{i}.{seed_node.host}', 'port': 9735}],
                        features={},
                        last_update=int(time.time()),
                        color="#2196F3",
                        host=f'peer{i}.{seed_node.host}',
                        port=9735,
                        channel_count=max(5, seed_node.channel_count // 3),
                        capacity_btc=max(0.01, seed_node.capacity_btc / 3),
                        discovery_method="graph_exploration",
                        discovery_time=time.time()
                    )
                    nodes.append(peer_node)
                    
        except Exception as e:
            self.logger.warning(f"Failed to discover from graph: {e}")
        
        return nodes
    
    def _test_node_connectivity(self, host: str, port: int) -> bool:
        """Test if a node is reachable"""
        try:
            with socket.create_connection((host, port), timeout=self.timeout):
                return True
        except (socket.error, OSError):
            return False
    
    def _deduplicate_nodes(self, nodes: List[DiscoveredNode]) -> List[DiscoveredNode]:
        """Remove duplicate nodes based on pubkey"""
        seen_pubkeys = set()
        unique_nodes = []
        
        for node in nodes:
            if node.pubkey not in seen_pubkeys:
                seen_pubkeys.add(node.pubkey)
                unique_nodes.append(node)
        
        return unique_nodes
    
    def _filter_quality_nodes(self, nodes: List[DiscoveredNode], max_nodes: int) -> List[DiscoveredNode]:
        """Filter nodes based on quality criteria"""
        quality_nodes = []
        
        for node in nodes:
            # Apply minimum thresholds
            if (node.channel_count >= self.min_channels and 
                node.capacity_sats >= self.min_capacity_sats):
                quality_nodes.append(node)
        
        # Sort by quality score and take top nodes
        quality_nodes.sort(key=lambda n: self._calculate_node_score(n), reverse=True)
        return quality_nodes[:max_nodes]
    
    def _rank_nodes(self, nodes: List[DiscoveredNode]) -> List[DiscoveredNode]:
        """Rank nodes by quality and connectivity"""
        for i, node in enumerate(nodes):
            node.node_rank = i + 1
            node.connectivity_score = self._calculate_connectivity_score(node)
        
        return sorted(nodes, key=lambda n: n.connectivity_score, reverse=True)
    
    def _calculate_node_score(self, node: DiscoveredNode) -> float:
        """Calculate overall node quality score"""
        # Weighted scoring
        channel_score = min(1.0, node.channel_count / 100.0) * 0.3
        capacity_score = min(1.0, node.capacity_btc / 10.0) * 0.4
        connectivity_score = self._calculate_connectivity_score(node) * 0.3
        
        return channel_score + capacity_score + connectivity_score
    
    def _calculate_connectivity_score(self, node: DiscoveredNode) -> float:
        """Calculate node connectivity score"""
        # Base score from discovery method
        method_scores = {
            'known_good': 0.9,
            'directory': 0.8,
            'graph_exploration': 0.7,
            'local_scan': 0.6,
            'unknown': 0.3
        }
        
        base_score = method_scores.get(node.discovery_method, 0.3)
        
        # Adjust based on node characteristics
        if node.channel_count > 100:
            base_score += 0.1
        if node.capacity_btc > 1.0:
            base_score += 0.1
        
        return min(1.0, base_score)
    
    def _calculate_quality_distribution(self, nodes: List[DiscoveredNode]) -> Dict[str, int]:
        """Calculate quality distribution of discovered nodes"""
        distribution = {'excellent': 0, 'good': 0, 'fair': 0, 'poor': 0}
        
        for node in nodes:
            quality = self._get_node_quality(node)
            distribution[quality] += 1
        
        return distribution
    
    def _get_node_quality(self, node: DiscoveredNode) -> str:
        """Get node quality rating"""
        for quality, thresholds in self.quality_thresholds.items():
            if (node.channel_count >= thresholds['channels'] and
                node.capacity_btc >= thresholds['capacity_btc'] and
                node.connectivity_score >= thresholds['connectivity']):
                return quality
        
        return 'poor'
    
    def get_recommended_nodes(self, 
                            purpose: str = "general",
                            count: int = 10,
                            network: str = "mainnet") -> List[DiscoveredNode]:
        """
        Get recommended nodes for specific purposes
        
        Args:
            purpose: 'routing', 'payments', 'general', 'liquidity'
            count: Number of nodes to return
            network: Network type
        
        Returns:
            List of recommended nodes
        """
        # Run discovery if needed
        scan = self.discover_nodes("comprehensive", count * 2, network)
        nodes = scan.recommended_nodes
        
        # Filter based on purpose
        if purpose == "routing":
            # Prefer nodes with many channels and good connectivity
            nodes = [n for n in nodes if n.channel_count >= 50 and n.connectivity_score >= 0.7]
            
        elif purpose == "payments":
            # Prefer well-known nodes with high reliability
            nodes = [n for n in nodes if n.discovery_method == "known_good" or n.connectivity_score >= 0.8]
            
        elif purpose == "liquidity":
            # Prefer nodes with high capacity
            nodes = [n for n in nodes if n.capacity_btc >= 1.0]
        
        return nodes[:count]
    
    def save_discovered_nodes(self, nodes: List[DiscoveredNode]):
        """Save discovered nodes to database for future use"""
        try:
            for node in nodes:
                self.db.execute_query("""
                    INSERT OR REPLACE INTO discovered_nodes 
                    (pubkey, alias, host, port, channel_count, capacity_btc, 
                     connectivity_score, discovery_method, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    node.pubkey, node.alias, node.host, node.port,
                    node.channel_count, node.capacity_btc,
                    node.connectivity_score, node.discovery_method,
                    int(time.time())
                ))
            self.logger.info(f"Saved {len(nodes)} discovered nodes to database")
        except Exception as e:
            self.logger.error(f"Failed to save discovered nodes: {e}")
    
    def load_cached_nodes(self, max_age_hours: int = 24) -> List[DiscoveredNode]:
        """Load previously discovered nodes from cache"""
        try:
            cutoff_time = int(time.time() - (max_age_hours * 3600))
            
            results = self.db.execute_query("""
                SELECT pubkey, alias, host, port, channel_count, capacity_btc,
                       connectivity_score, discovery_method, last_seen
                FROM discovered_nodes 
                WHERE last_seen > ?
                ORDER BY connectivity_score DESC
            """, (cutoff_time,))
            
            nodes = []
            for row in results:
                node = DiscoveredNode(
                    pubkey=row[0],
                    alias=row[1], 
                    addresses=[{'host': row[2], 'port': row[3]}],
                    features={},
                    last_update=row[8],
                    color="#666666",
                    host=row[2],
                    port=row[3],
                    channel_count=row[4],
                    capacity_btc=row[5],
                    connectivity_score=row[6],
                    discovery_method=row[7],
                    discovery_time=row[8]
                )
                nodes.append(node)
            
            self.logger.info(f"Loaded {len(nodes)} cached nodes from database")
            return nodes
            
        except Exception as e:
            self.logger.error(f"Failed to load cached nodes: {e}")
            return []


def get_node_discovery() -> NodeDiscovery:
    """Get singleton NodeDiscovery instance"""
    return NodeDiscovery()