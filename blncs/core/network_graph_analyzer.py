"""
Network Graph Analyzer - Lightning Network topology analysis and insights
"""

import json
import logging
import math
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class NetworkNodeMetrics:
    """Metrics for a Lightning Network node"""
    pubkey: str
    alias: str
    channel_count: int
    total_capacity: int
    avg_channel_size: float
    betweenness_centrality: float
    closeness_centrality: float
    eigenvector_centrality: float
    pagerank_score: float
    hub_score: float
    authority_score: float
    strategic_value: float
    node_age_days: int
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'pubkey': self.pubkey,
            'alias': self.alias,
            'channel_count': self.channel_count,
            'total_capacity': self.total_capacity,
            'avg_channel_size': self.avg_channel_size,
            'centrality_score': self.betweenness_centrality,
            'closeness_centrality': self.closeness_centrality,
            'eigenvector_centrality': self.eigenvector_centrality,
            'pagerank_score': self.pagerank_score,
            'hub_score': self.hub_score,
            'authority_score': self.authority_score,
            'strategic_value': self.strategic_value,
            'node_age_days': self.node_age_days
        }

@dataclass 
class PaymentPath:
    """Represents a payment path through the network"""
    route: List[str]
    route_aliases: List[str]
    hops: int
    success_probability: float
    estimated_fee: int
    total_delay: float
    bottleneck_channel: Optional[Dict[str, Any]] = None

class NetworkGraphAnalyzer:
    """Analyzes Lightning Network graph topology and provides insights"""
    
    def __init__(self):
        self.graph_data = {}
        self.node_metrics = {}
        self.last_update = None
        self.cache_duration = 3600  # 1 hour cache
        
        # Mock network data for demonstration
        self._initialize_mock_network()
    
    def _initialize_mock_network(self):
        """Initialize with mock network data for demonstration"""
        # This would normally connect to a Lightning Network graph provider
        # For now, create a realistic mock network
        
        nodes = [
            {"pubkey": "03" + "a" * 64, "alias": "ACINQ", "channels": 1500, "capacity": 50000000000, "age_days": 1200},
            {"pubkey": "03" + "b" * 64, "alias": "Bitrefill", "channels": 800, "capacity": 30000000000, "age_days": 1000},
            {"pubkey": "03" + "c" * 64, "alias": "CoinGate", "channels": 600, "capacity": 25000000000, "age_days": 900},
            {"pubkey": "03" + "d" * 64, "alias": "Dunder", "channels": 400, "capacity": 15000000000, "age_days": 800},
            {"pubkey": "03" + "e" * 64, "alias": "ElectrumLN", "channels": 1200, "capacity": 40000000000, "age_days": 1100},
            {"pubkey": "03" + "f" * 64, "alias": "FoldApp", "channels": 300, "capacity": 12000000000, "age_days": 700},
            {"pubkey": "03" + "0" * 64, "alias": "OpenNode", "channels": 500, "capacity": 20000000000, "age_days": 850},
            {"pubkey": "03" + "1" * 64, "alias": "River", "channels": 350, "capacity": 18000000000, "age_days": 750},
        ]
        
        # Create adjacency list representation
        self.graph_data = {
            'nodes': {node['pubkey']: node for node in nodes},
            'edges': defaultdict(list),
            'total_nodes': len(nodes),
            'total_channels': sum(node['channels'] for node in nodes) // 2,  # Each channel counted twice
            'total_capacity': sum(node['capacity'] for node in nodes) // 2,
            'last_updated': datetime.utcnow().isoformat()
        }
        
        # Create some sample connections
        connections = [
            ("03" + "a" * 64, "03" + "b" * 64, 5000000000),
            ("03" + "a" * 64, "03" + "c" * 64, 3000000000),
            ("03" + "a" * 64, "03" + "e" * 64, 8000000000),
            ("03" + "b" * 64, "03" + "c" * 64, 2000000000),
            ("03" + "b" * 64, "03" + "d" * 64, 1500000000),
            ("03" + "c" * 64, "03" + "f" * 64, 1000000000),
            ("03" + "d" * 64, "03" + "0" * 64, 2500000000),
            ("03" + "e" * 64, "03" + "0" * 64, 4000000000),
            ("03" + "f" * 64, "03" + "1" * 64, 1200000000),
            ("03" + "0" * 64, "03" + "1" * 64, 1800000000),
        ]
        
        for node1, node2, capacity in connections:
            self.graph_data['edges'][node1].append({
                'peer': node2,
                'capacity': capacity,
                'fee_rate': 0.001
            })
            self.graph_data['edges'][node2].append({
                'peer': node1,
                'capacity': capacity,
                'fee_rate': 0.001
            })
        
        self.last_update = datetime.utcnow()
        logger.info("Initialized mock Lightning Network graph")
    
    def _should_refresh_cache(self) -> bool:
        """Check if cache should be refreshed"""
        if not self.last_update:
            return True
        return (datetime.utcnow() - self.last_update).seconds > self.cache_duration
    
    def analyze_topology(self) -> Dict[str, Any]:
        """Analyze overall network topology"""
        if self._should_refresh_cache():
            self._refresh_network_data()
        
        nodes = self.graph_data['nodes']
        edges = self.graph_data['edges']
        
        # Basic metrics
        total_nodes = len(nodes)
        total_channels = sum(len(peers) for peers in edges.values()) // 2
        total_capacity = sum(node['capacity'] for node in nodes.values())
        avg_channel_capacity = total_capacity / total_channels if total_channels > 0 else 0
        
        # Network structure analysis
        degree_distribution = self._calculate_degree_distribution()
        capacity_distribution = self._calculate_capacity_distribution()
        
        # Network health metrics
        network_diameter = self._calculate_network_diameter()
        avg_path_length = self._calculate_average_path_length()
        clustering_coefficient = self._calculate_clustering_coefficient()
        connected_components = self._count_connected_components()
        
        # Growth metrics (simulated)
        growth_metrics = self._calculate_growth_metrics()
        
        return {
            'total_nodes': total_nodes,
            'total_channels': total_channels,
            'total_capacity': total_capacity,
            'avg_channel_capacity': avg_channel_capacity,
            'network_diameter': network_diameter,
            'avg_path_length': avg_path_length,
            'clustering_coefficient': clustering_coefficient,
            'connected_components': connected_components,
            'degree_distribution': degree_distribution,
            'capacity_distribution': capacity_distribution,
            'growth_metrics': growth_metrics,
            'analysis_timestamp': datetime.utcnow().isoformat()
        }
    
    def identify_network_hubs(self, limit: int = 20, metric: str = 'centrality') -> List[NetworkNodeMetrics]:
        """Identify key network hubs"""
        if self._should_refresh_cache():
            self._refresh_network_data()
        
        node_metrics = []
        nodes = self.graph_data['nodes']
        edges = self.graph_data['edges']
        
        # Calculate centrality metrics for all nodes
        centrality_scores = self._calculate_centrality_metrics()
        
        for pubkey, node_data in nodes.items():
            channels = len(edges.get(pubkey, []))
            total_capacity = sum(edge['capacity'] for edge in edges.get(pubkey, []))
            avg_channel_size = total_capacity / channels if channels > 0 else 0
            
            metrics = NetworkNodeMetrics(
                pubkey=pubkey,
                alias=node_data['alias'],
                channel_count=channels,
                total_capacity=total_capacity,
                avg_channel_size=avg_channel_size,
                betweenness_centrality=centrality_scores.get(pubkey, {}).get('betweenness', 0),
                closeness_centrality=centrality_scores.get(pubkey, {}).get('closeness', 0),
                eigenvector_centrality=centrality_scores.get(pubkey, {}).get('eigenvector', 0),
                pagerank_score=centrality_scores.get(pubkey, {}).get('pagerank', 0),
                hub_score=centrality_scores.get(pubkey, {}).get('hub', 0),
                authority_score=centrality_scores.get(pubkey, {}).get('authority', 0),
                strategic_value=centrality_scores.get(pubkey, {}).get('strategic', 0),
                node_age_days=node_data.get('age_days', 0)
            )
            node_metrics.append(metrics)
        
        # Sort by specified metric
        if metric == 'centrality':
            node_metrics.sort(key=lambda x: x.betweenness_centrality, reverse=True)
        elif metric == 'capacity':
            node_metrics.sort(key=lambda x: x.total_capacity, reverse=True)
        elif metric == 'channels':
            node_metrics.sort(key=lambda x: x.channel_count, reverse=True)
        elif metric == 'age':
            node_metrics.sort(key=lambda x: x.node_age_days, reverse=True)
        
        return node_metrics[:limit]
    
    def analyze_node_position(self, pubkey: str, detailed: bool = False) -> Optional[Dict[str, Any]]:
        """Analyze a specific node's network position"""
        if pubkey not in self.graph_data['nodes']:
            return None
        
        node_data = self.graph_data['nodes'][pubkey]
        edges = self.graph_data['edges'].get(pubkey, [])
        
        # Basic metrics
        channel_count = len(edges)
        total_capacity = sum(edge['capacity'] for edge in edges)
        avg_channel_size = total_capacity / channel_count if channel_count > 0 else 0
        
        # Calculate centrality metrics
        centrality_scores = self._calculate_centrality_metrics()
        node_centrality = centrality_scores.get(pubkey, {})
        
        analysis = {
            'pubkey': pubkey,
            'alias': node_data['alias'],
            'channel_count': channel_count,
            'total_capacity': total_capacity,
            'avg_channel_size': avg_channel_size,
            'node_age_days': node_data.get('age_days', 0),
            'betweenness_centrality': node_centrality.get('betweenness', 0),
            'closeness_centrality': node_centrality.get('closeness', 0),
            'eigenvector_centrality': node_centrality.get('eigenvector', 0),
            'pagerank_score': node_centrality.get('pagerank', 0),
            'hub_score': node_centrality.get('hub', 0),
            'authority_score': node_centrality.get('authority', 0),
            'strategic_value': node_centrality.get('strategic', 0)
        }
        
        if detailed:
            # Peer analysis
            analysis['peer_analysis'] = self._analyze_node_peers(pubkey)
            
            # Channel distribution
            analysis['channel_distribution'] = self._analyze_channel_distribution(edges)
            
            # Routing potential
            analysis['routing_metrics'] = self._calculate_routing_potential(pubkey)
        
        return analysis
    
    def find_payment_paths(self, source: str, target: str, amount: int, max_paths: int = 5) -> List[PaymentPath]:
        """Find viable payment paths between two nodes"""
        if source not in self.graph_data['nodes'] or target not in self.graph_data['nodes']:
            return []
        
        # Use modified Dijkstra's algorithm to find multiple paths
        paths = []
        edges = self.graph_data['edges']
        
        # For simplicity, use a basic pathfinding approach
        # In a real implementation, this would consider channel liquidity, fees, etc.
        
        def find_path_bfs(start: str, end: str, visited: Set[str] = None) -> Optional[List[str]]:
            if visited is None:
                visited = set()
            
            if start == end:
                return [start]
            
            if start in visited:
                return None
            
            visited.add(start)
            queue = deque([(start, [start])])
            
            while queue:
                current, path = queue.popleft()
                
                if len(path) > 6:  # Limit path length
                    continue
                
                for edge in edges.get(current, []):
                    peer = edge['peer']
                    if peer == end:
                        return path + [peer]
                    
                    if peer not in visited and edge['capacity'] >= amount:
                        queue.append((peer, path + [peer]))
            
            return None
        
        # Find multiple paths by temporarily removing nodes
        temp_removed = set()
        
        for i in range(max_paths):
            path = find_path_bfs(source, target)
            if not path:
                break
            
            # Calculate path metrics
            hops = len(path) - 1
            success_probability = max(0.1, 1.0 - (hops * 0.1))  # Simple heuristic
            estimated_fee = hops * 1000  # Simple fee estimation
            total_delay = hops * 1.5  # Simple delay estimation
            
            # Get route aliases
            route_aliases = []
            for pubkey in path:
                alias = self.graph_data['nodes'].get(pubkey, {}).get('alias', 'Unknown')
                route_aliases.append(alias)
            
            payment_path = PaymentPath(
                route=path,
                route_aliases=route_aliases,
                hops=hops,
                success_probability=success_probability,
                estimated_fee=estimated_fee,
                total_delay=total_delay
            )
            
            paths.append(payment_path)
            
            # Temporarily remove a middle node to find alternative paths
            if len(path) > 2:
                temp_removed.add(path[len(path) // 2])
        
        return paths
    
    def analyze_path_diversity(self) -> Dict[str, Any]:
        """Analyze general path diversity in the network"""
        # Sample some random node pairs and analyze paths
        nodes = list(self.graph_data['nodes'].keys())
        
        if len(nodes) < 2:
            return {}
        
        path_lengths = []
        max_length = 0
        
        # Sample analysis (in practice, this would be more comprehensive)
        for i in range(min(50, len(nodes))):
            for j in range(i + 1, min(i + 6, len(nodes))):
                paths = self.find_payment_paths(nodes[i], nodes[j], 100000, 1)
                if paths:
                    length = paths[0].hops
                    path_lengths.append(length)
                    max_length = max(max_length, length)
        
        avg_path_length = sum(path_lengths) / len(path_lengths) if path_lengths else 0
        
        # Calculate redundancy score (simplified)
        redundancy_score = 0.8  # Mock value
        
        # Identify critical nodes
        centrality_scores = self._calculate_centrality_metrics()
        critical_nodes = []
        for pubkey, scores in centrality_scores.items():
            if scores.get('betweenness', 0) > 0.01:  # Threshold for criticality
                node_data = self.graph_data['nodes'].get(pubkey, {})
                critical_nodes.append({
                    'pubkey': pubkey,
                    'alias': node_data.get('alias', 'Unknown'),
                    'betweenness': scores.get('betweenness', 0)
                })
        
        critical_nodes.sort(key=lambda x: x['betweenness'], reverse=True)
        
        return {
            'avg_path_length': avg_path_length,
            'max_path_length': max_length,
            'redundancy_score': redundancy_score,
            'critical_nodes': critical_nodes,
            'sample_size': len(path_lengths)
        }
    
    def analyze_network_changes(self, days: int = 7) -> Dict[str, Any]:
        """Analyze network changes over time (simulated for demo)"""
        # In a real implementation, this would compare historical graph snapshots
        
        # Simulate some realistic changes
        import random
        
        base_nodes = len(self.graph_data['nodes'])
        base_channels = self.graph_data['total_channels']
        base_capacity = self.graph_data['total_capacity']
        
        # Simulate growth patterns
        node_growth_rate = 0.02  # 2% weekly growth
        channel_growth_rate = 0.05  # 5% weekly growth  
        capacity_growth_rate = 0.03  # 3% weekly growth
        
        new_nodes = int(base_nodes * node_growth_rate * (days / 7))
        new_channels = int(base_channels * channel_growth_rate * (days / 7))
        new_capacity = int(base_capacity * capacity_growth_rate * (days / 7))
        
        # Add some randomness and departures
        departed_nodes = max(0, new_nodes - random.randint(5, 15))
        closed_channels = max(0, new_channels - random.randint(20, 50))
        removed_capacity = max(0, new_capacity - random.randint(1000000000, 5000000000))
        
        # Simulate top growing nodes
        node_aliases = [node['alias'] for node in self.graph_data['nodes'].values()]
        top_growing_nodes = []
        for i in range(min(5, len(node_aliases))):
            alias = random.choice(node_aliases)
            top_growing_nodes.append({
                'alias': alias,
                'new_channels': random.randint(5, 25),
                'new_capacity': random.randint(1000000000, 10000000000)
            })
        
        # Health trend simulation
        health_trend = {
            'connectivity_change': random.uniform(-0.05, 0.1),
            'decentralization_change': random.uniform(-0.02, 0.03),
            'robustness_change': random.uniform(-0.03, 0.05)
        }
        
        return {
            'node_changes': {
                'new_nodes': new_nodes,
                'departed_nodes': departed_nodes,
                'net_change': new_nodes - departed_nodes
            },
            'channel_changes': {
                'new_channels': new_channels,
                'closed_channels': closed_channels,
                'net_change': new_channels - closed_channels
            },
            'capacity_changes': {
                'added_capacity': new_capacity,
                'removed_capacity': removed_capacity,
                'net_change': new_capacity - removed_capacity
            },
            'top_growing_nodes': top_growing_nodes,
            'health_trend': health_trend,
            'analysis_period_days': days
        }
    
    def get_network_benchmarks(self, metric: str = 'centrality', limit: int = 10) -> Dict[str, Any]:
        """Get network benchmarks for comparison"""
        nodes = self.graph_data['nodes']
        edges = self.graph_data['edges']
        
        # Collect values for the specified metric
        values = []
        
        if metric == 'centrality':
            centrality_scores = self._calculate_centrality_metrics()
            values = [scores.get('betweenness', 0) for scores in centrality_scores.values()]
        elif metric == 'capacity':
            for pubkey, node_data in nodes.items():
                total_capacity = sum(edge['capacity'] for edge in edges.get(pubkey, []))
                values.append(total_capacity)
        elif metric == 'channels':
            values = [len(edges.get(pubkey, [])) for pubkey in nodes.keys()]
        elif metric == 'age':
            values = [node_data.get('age_days', 0) for node_data in nodes.values()]
        
        if not values:
            return {}
        
        values.sort(reverse=True)
        n = len(values)
        
        # Calculate percentiles
        percentiles = {
            'p90': values[int(n * 0.1)] if n > 0 else 0,
            'p75': values[int(n * 0.25)] if n > 0 else 0,
            'p50': values[int(n * 0.5)] if n > 0 else 0,
            'p25': values[int(n * 0.75)] if n > 0 else 0
        }
        
        # Calculate statistics
        mean_val = sum(values) / len(values)
        median_val = values[len(values) // 2]
        
        # Calculate standard deviation
        variance = sum((x - mean_val) ** 2 for x in values) / len(values)
        std_val = math.sqrt(variance)
        
        # Calculate Gini coefficient (inequality measure)
        gini = self._calculate_gini_coefficient(values)
        
        # Get top performers
        top_performers = []
        hubs = self.identify_network_hubs(limit=limit, metric=metric)
        for i, hub in enumerate(hubs):
            if metric == 'centrality':
                value = hub.betweenness_centrality
            elif metric == 'capacity':
                value = hub.total_capacity
            elif metric == 'channels':
                value = hub.channel_count
            elif metric == 'age':
                value = hub.node_age_days
            else:
                value = 0
            
            percentile = (1 - (i / len(values))) * 100 if values else 0
            
            top_performers.append({
                'alias': hub.alias,
                'value': value,
                'percentile': percentile
            })
        
        # Generate recommendations
        recommendations = []
        if metric == 'centrality':
            recommendations.append("Focus on connecting to well-connected nodes")
            recommendations.append("Consider geographic diversity in peer selection")
        elif metric == 'capacity':
            recommendations.append("Gradually increase channel sizes")
            recommendations.append("Balance between many small and few large channels")
        elif metric == 'channels':
            recommendations.append("Add channels strategically to improve routing")
            recommendations.append("Monitor channel utilization before opening new ones")
        
        return {
            'percentiles': percentiles,
            'statistics': {
                'mean': mean_val,
                'median': median_val,
                'std': std_val,
                'gini': gini
            },
            'top_performers': top_performers,
            'recommendations': recommendations
        }
    
    def export_network_data(self, format: str = 'json', include_metrics: bool = False) -> Any:
        """Export network data for external analysis"""
        nodes_data = []
        edges_data = []
        
        # Prepare node data
        centrality_scores = self._calculate_centrality_metrics() if include_metrics else {}
        
        for pubkey, node_info in self.graph_data['nodes'].items():
            node_data = {
                'id': pubkey,
                'pubkey': pubkey,
                'alias': node_info['alias'],
                'channels': len(self.graph_data['edges'].get(pubkey, [])),
                'total_capacity': sum(edge['capacity'] for edge in self.graph_data['edges'].get(pubkey, [])),
                'age_days': node_info.get('age_days', 0)
            }
            
            if include_metrics and pubkey in centrality_scores:
                node_data.update(centrality_scores[pubkey])
            
            nodes_data.append(node_data)
        
        # Prepare edge data
        processed_edges = set()
        
        for node1, edges in self.graph_data['edges'].items():
            for edge in edges:
                node2 = edge['peer']
                edge_id = tuple(sorted([node1, node2]))
                
                if edge_id not in processed_edges:
                    processed_edges.add(edge_id)
                    edges_data.append({
                        'source': node1,
                        'target': node2,
                        'capacity': edge['capacity'],
                        'fee_rate': edge.get('fee_rate', 0.001)
                    })
        
        if format == 'json':
            return {
                'nodes': nodes_data,
                'edges': edges_data,
                'metadata': {
                    'export_timestamp': datetime.utcnow().isoformat(),
                    'total_nodes': len(nodes_data),
                    'total_edges': len(edges_data),
                    'include_metrics': include_metrics
                }
            }
        elif format == 'graphml':
            # Generate GraphML format
            graphml = ['<?xml version="1.0" encoding="UTF-8"?>']
            graphml.append('<graphml xmlns="http://graphml.graphdrawing.org/xmlns">')
            graphml.append('  <graph id="LightningNetwork" edgedefault="undirected">')
            
            # Add nodes
            for node in nodes_data:
                graphml.append(f'    <node id="{node["id"]}">')
                graphml.append(f'      <data key="alias">{node["alias"]}</data>')
                graphml.append(f'      <data key="channels">{node["channels"]}</data>')
                graphml.append(f'      <data key="capacity">{node["total_capacity"]}</data>')
                graphml.append('    </node>')
            
            # Add edges
            for i, edge in enumerate(edges_data):
                graphml.append(f'    <edge id="e{i}" source="{edge["source"]}" target="{edge["target"]}">')
                graphml.append(f'      <data key="capacity">{edge["capacity"]}</data>')
                graphml.append('    </edge>')
            
            graphml.append('  </graph>')
            graphml.append('</graphml>')
            
            return '\n'.join(graphml)
        
        return {'nodes': nodes_data, 'edges': edges_data}
    
    def _refresh_network_data(self):
        """Refresh network data from Lightning Network"""
        # In a real implementation, this would fetch from LN graph APIs
        # For now, just update timestamp
        self.last_update = datetime.utcnow()
        logger.info("Network data refreshed")
    
    def _calculate_degree_distribution(self) -> Dict[str, int]:
        """Calculate node degree distribution"""
        degrees = [len(edges) for edges in self.graph_data['edges'].values()]
        
        distribution = {
            '1-10': len([d for d in degrees if 1 <= d <= 10]),
            '11-50': len([d for d in degrees if 11 <= d <= 50]),
            '51-100': len([d for d in degrees if 51 <= d <= 100]),
            '101-500': len([d for d in degrees if 101 <= d <= 500]),
            '500+': len([d for d in degrees if d > 500])
        }
        
        return distribution
    
    def _calculate_capacity_distribution(self) -> Dict[str, Dict[str, Any]]:
        """Calculate channel capacity distribution"""
        all_edges = []
        for edges in self.graph_data['edges'].values():
            all_edges.extend(edges)
        
        # Avoid double counting
        unique_edges = {}
        for edge in all_edges:
            edge_id = tuple(sorted([edge['peer'], str(edge['capacity'])]))
            unique_edges[edge_id] = edge['capacity']
        
        capacities = list(unique_edges.values())
        
        distribution = {}
        ranges = [
            ('< 1M', 0, 1000000),
            ('1M-10M', 1000000, 10000000),
            ('10M-100M', 10000000, 100000000),
            ('100M+', 100000000, float('inf'))
        ]
        
        for range_name, min_cap, max_cap in ranges:
            range_channels = [c for c in capacities if min_cap <= c < max_cap]
            distribution[range_name] = {
                'channels': len(range_channels),
                'total_capacity': sum(range_channels)
            }
        
        return distribution
    
    def _calculate_network_diameter(self) -> int:
        """Calculate network diameter (longest shortest path)"""
        # Simplified calculation - in practice would use proper graph algorithms
        return 6  # Mock value based on typical LN network
    
    def _calculate_average_path_length(self) -> float:
        """Calculate average shortest path length"""
        # Simplified calculation
        return 3.2  # Mock value
    
    def _calculate_clustering_coefficient(self) -> float:
        """Calculate network clustering coefficient"""
        # Simplified calculation
        return 0.15  # Mock value
    
    def _count_connected_components(self) -> int:
        """Count connected components in the graph"""
        # Simplified - assume single large component
        return 1
    
    def _calculate_growth_metrics(self) -> Dict[str, int]:
        """Calculate growth metrics (simulated)"""
        import random
        
        return {
            'new_nodes': random.randint(50, 150),
            'new_channels': random.randint(200, 600),
            'capacity_change': random.randint(1000000000, 10000000000)
        }
    
    def _calculate_centrality_metrics(self) -> Dict[str, Dict[str, float]]:
        """Calculate various centrality metrics for all nodes"""
        # Simplified centrality calculations
        # In practice, would use proper graph algorithms (NetworkX, etc.)
        
        centrality_scores = {}
        nodes = self.graph_data['nodes']
        edges = self.graph_data['edges']
        
        for pubkey in nodes.keys():
            degree = len(edges.get(pubkey, []))
            total_capacity = sum(edge['capacity'] for edge in edges.get(pubkey, []))
            
            # Mock centrality calculations based on degree and capacity
            betweenness = min(1.0, degree / 100.0)  # Normalize by max degree
            closeness = min(1.0, degree / 50.0)
            eigenvector = min(1.0, total_capacity / 50000000000.0)  # Normalize by high capacity
            pagerank = min(1.0, (degree * total_capacity) / 1000000000000.0)
            
            # Hub and authority scores (simplified HITS algorithm)
            hub = min(1.0, degree / 75.0)
            authority = min(1.0, total_capacity / 40000000000.0)
            
            # Strategic value combines multiple factors
            strategic = (betweenness + closeness + eigenvector) / 3.0
            
            centrality_scores[pubkey] = {
                'betweenness': betweenness,
                'closeness': closeness,
                'eigenvector': eigenvector,
                'pagerank': pagerank,
                'hub': hub,
                'authority': authority,
                'strategic': strategic
            }
        
        return centrality_scores
    
    def _analyze_node_peers(self, pubkey: str) -> Dict[str, Any]:
        """Analyze a node's peer relationships"""
        edges = self.graph_data['edges'].get(pubkey, [])
        
        high_capacity_peers = 0
        well_connected_peers = 0
        
        for edge in edges:
            peer_pubkey = edge['peer']
            peer_edges = self.graph_data['edges'].get(peer_pubkey, [])
            
            if edge['capacity'] > 10000000000:  # > 0.1 BTC
                high_capacity_peers += 1
            
            if len(peer_edges) > 100:  # Well connected
                well_connected_peers += 1
        
        # Diversity score based on peer distribution
        diversity_score = min(1.0, len(edges) / 50.0)
        
        return {
            'high_capacity_peers': high_capacity_peers,
            'well_connected_peers': well_connected_peers,
            'diversity_score': diversity_score
        }
    
    def _analyze_channel_distribution(self, edges: List[Dict[str, Any]]) -> Dict[str, int]:
        """Analyze channel size distribution for a node"""
        distribution = {
            'Small (< 1M)': 0,
            'Medium (1M-10M)': 0,
            'Large (10M-100M)': 0,
            'Very Large (100M+)': 0
        }
        
        for edge in edges:
            capacity = edge['capacity']
            if capacity < 1000000:
                distribution['Small (< 1M)'] += 1
            elif capacity < 10000000:
                distribution['Medium (1M-10M)'] += 1
            elif capacity < 100000000:
                distribution['Large (10M-100M)'] += 1
            else:
                distribution['Very Large (100M+)'] += 1
        
        return distribution
    
    def _calculate_routing_potential(self, pubkey: str) -> Dict[str, Any]:
        """Calculate routing potential for a node"""
        # Simplified routing metrics
        edges = self.graph_data['edges'].get(pubkey, [])
        
        # Estimate based on capacity and connectivity
        total_capacity = sum(edge['capacity'] for edge in edges)
        connectivity = len(edges)
        
        estimated_daily_volume = min(total_capacity * 0.01, connectivity * 1000000)  # Rough estimate
        route_success_rate = min(0.95, 0.5 + (connectivity / 200.0))  # Better connected = higher success
        optimal_routes = min(connectivity * 2, 100)  # Routes this node participates in optimally
        
        return {
            'estimated_daily_volume': estimated_daily_volume,
            'route_success_rate': route_success_rate,
            'optimal_routes': optimal_routes
        }
    
    def _calculate_gini_coefficient(self, values: List[float]) -> float:
        """Calculate Gini coefficient for inequality measurement"""
        if not values:
            return 0.0
        
        values = sorted(values)
        n = len(values)
        
        total = sum(values)
        if total == 0:
            return 0.0
        
        # Calculate Gini coefficient
        weighted_sum = sum((i + 1) * value for i, value in enumerate(values))
        gini = (2 * weighted_sum) / (n * total) - (n + 1) / n
        
        return gini

# Global network analyzer instance
_network_analyzer = None

def get_network_analyzer() -> NetworkGraphAnalyzer:
    """Get global network analyzer instance"""
    global _network_analyzer
    if _network_analyzer is None:
        _network_analyzer = NetworkGraphAnalyzer()
    return _network_analyzer