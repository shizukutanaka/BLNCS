"""
BLNCS Lightning Routing Manager
Practical routing and payment pathfinding for Lightning Network
"""

import time
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import heapq
from enum import Enum


class RouteStrategy(Enum):
    """Routing strategy types"""
    CHEAPEST = "cheapest"
    FASTEST = "fastest"
    MOST_RELIABLE = "most_reliable"
    BALANCED = "balanced"


@dataclass
class RouteHop:
    """Single hop in a payment route"""
    channel_id: str
    node_pubkey: str
    amount_sats: int
    fee_sats: int
    delay_blocks: int
    probability: float = 1.0


@dataclass
class PaymentRoute:
    """Complete payment route"""
    route_id: str
    hops: List[RouteHop]
    total_amount_sats: int
    total_fee_sats: int
    total_delay_blocks: int
    success_probability: float
    created_at: float
    strategy: RouteStrategy

    def get_fee_rate(self) -> float:
        """Get fee rate as percentage"""
        if self.total_amount_sats == 0:
            return 0.0
        return (self.total_fee_sats / self.total_amount_sats) * 100

    def is_economical(self, max_fee_rate: float = 1.0) -> bool:
        """Check if route is economical"""
        return self.get_fee_rate() <= max_fee_rate

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['strategy'] = self.strategy.value
        return data


@dataclass
class NetworkNode:
    """Lightning network node information"""
    pubkey: str
    alias: str
    channels: List[str]
    last_seen: float
    reliability_score: float = 1.0  # 0-1
    avg_fee_rate: float = 0.0

    def is_online(self, timeout_hours: int = 24) -> bool:
        """Check if node is recently online"""
        return time.time() - self.last_seen < (timeout_hours * 3600)


class RoutingManager:
    """Lightning payment routing and pathfinding system"""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)

        self.routes: Dict[str, PaymentRoute] = {}
        self.nodes: Dict[str, NetworkNode] = {}
        self.channels: Dict[str, Dict[str, Any]] = {}

        self.routes_file = self.data_dir / "routes.json"
        self.nodes_file = self.data_dir / "network_nodes.json"

        self.logger = logging.getLogger("BLNCS_RoutingManager")

        # Default routing parameters
        self.max_hops = 10
        self.max_fee_rate = 1.0  # 1%
        self.timeout_seconds = 30

        self._load_data()

    def _load_data(self):
        """Load routing data from storage"""
        # Load routes
        if self.routes_file.exists():
            try:
                with open(self.routes_file, 'r') as f:
                    data = json.load(f)
                    for route_id, route_data in data.items():
                        route_data['strategy'] = RouteStrategy(route_data['strategy'])
                        route_data['hops'] = [RouteHop(**hop) for hop in route_data['hops']]
                        self.routes[route_id] = PaymentRoute(**route_data)

                self.logger.info(f"Loaded {len(self.routes)} routes")
            except Exception as e:
                self.logger.error(f"Failed to load routes: {e}")

        # Load network nodes
        if self.nodes_file.exists():
            try:
                with open(self.nodes_file, 'r') as f:
                    data = json.load(f)
                    for pubkey, node_data in data.items():
                        self.nodes[pubkey] = NetworkNode(**node_data)

                self.logger.info(f"Loaded {len(self.nodes)} network nodes")
            except Exception as e:
                self.logger.error(f"Failed to load nodes: {e}")

    def _save_routes(self):
        """Save routes to storage"""
        try:
            data = {route_id: route.to_dict() for route_id, route in self.routes.items()}
            with open(self.routes_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save routes: {e}")

    def _save_nodes(self):
        """Save network nodes to storage"""
        try:
            data = {pubkey: asdict(node) for pubkey, node in self.nodes.items()}
            with open(self.nodes_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save nodes: {e}")

    def add_network_node(self, pubkey: str, alias: str = "", channels: List[str] = None) -> NetworkNode:
        """Add or update network node"""
        if channels is None:
            channels = []

        current_time = time.time()

        node = NetworkNode(
            pubkey=pubkey,
            alias=alias or f"Node_{pubkey[:8]}",
            channels=channels,
            last_seen=current_time
        )

        self.nodes[pubkey] = node
        self._save_nodes()

        self.logger.info(f"Added network node: {alias} ({pubkey[:16]}...)")
        return node

    def update_channel_info(self, channel_id: str, node1: str, node2: str,
                           capacity_sats: int, fee_rate: float = 0.001):
        """Update channel information for routing"""
        self.channels[channel_id] = {
            'node1': node1,
            'node2': node2,
            'capacity_sats': capacity_sats,
            'fee_rate': fee_rate,
            'last_update': time.time(),
            'enabled': True
        }

    def find_route(self, source: str, destination: str, amount_sats: int,
                   strategy: RouteStrategy = RouteStrategy.BALANCED) -> Optional[PaymentRoute]:
        """Find optimal route between nodes"""
        try:
            start_time = time.time()

            # Use simplified pathfinding algorithm
            route_hops = self._find_path_dijkstra(source, destination, amount_sats, strategy)

            if not route_hops:
                return None

            # Calculate route metrics
            total_fee = sum(hop.fee_sats for hop in route_hops)
            total_delay = sum(hop.delay_blocks for hop in route_hops)
            success_prob = min(hop.probability for hop in route_hops)

            route_id = f"route_{int(time.time())}_{source[:8]}_{destination[:8]}"

            route = PaymentRoute(
                route_id=route_id,
                hops=route_hops,
                total_amount_sats=amount_sats,
                total_fee_sats=total_fee,
                total_delay_blocks=total_delay,
                success_probability=success_prob,
                created_at=start_time,
                strategy=strategy
            )

            # Cache successful route
            self.routes[route_id] = route
            self._save_routes()

            execution_time = time.time() - start_time
            self.logger.info(f"Found route: {len(route_hops)} hops, {total_fee} sats fee, {execution_time:.3f}s")

            return route

        except Exception as e:
            self.logger.error(f"Route finding failed: {e}")
            return None

    def _find_path_dijkstra(self, source: str, destination: str, amount_sats: int,
                           strategy: RouteStrategy) -> List[RouteHop]:
        """Simplified Dijkstra pathfinding"""
        # Priority queue: (cost, current_node, path)
        heap = [(0, source, [])]
        visited = set()

        while heap:
            cost, current, path = heapq.heappop(heap)

            if current in visited:
                continue

            visited.add(current)

            if current == destination:
                return path

            if len(path) >= self.max_hops:
                continue

            # Find connected channels
            for channel_id, channel_info in self.channels.items():
                next_node = None
                if channel_info['node1'] == current:
                    next_node = channel_info['node2']
                elif channel_info['node2'] == current:
                    next_node = channel_info['node1']

                if not next_node or next_node in visited:
                    continue

                # Check capacity
                if channel_info['capacity_sats'] < amount_sats:
                    continue

                # Calculate hop cost based on strategy
                hop_cost = self._calculate_hop_cost(channel_info, amount_sats, strategy)

                hop = RouteHop(
                    channel_id=channel_id,
                    node_pubkey=next_node,
                    amount_sats=amount_sats,
                    fee_sats=int(amount_sats * channel_info['fee_rate']),
                    delay_blocks=6,  # Default
                    probability=0.95  # Default reliability
                )

                new_cost = cost + hop_cost
                new_path = path + [hop]

                heapq.heappush(heap, (new_cost, next_node, new_path))

        return []  # No path found

    def _calculate_hop_cost(self, channel_info: Dict[str, Any], amount_sats: int,
                           strategy: RouteStrategy) -> float:
        """Calculate hop cost based on routing strategy"""
        base_fee = amount_sats * channel_info['fee_rate']

        if strategy == RouteStrategy.CHEAPEST:
            return base_fee
        elif strategy == RouteStrategy.FASTEST:
            return 1.0  # Minimize hops
        elif strategy == RouteStrategy.MOST_RELIABLE:
            # Prefer well-connected nodes
            return base_fee + (1.0 / max(1, len(self.nodes.get(channel_info['node1'], NetworkNode('', '', [])).channels)))
        else:  # BALANCED
            return base_fee + 0.5  # Balance fee and reliability

    def get_route_alternatives(self, source: str, destination: str, amount_sats: int,
                              max_alternatives: int = 3) -> List[PaymentRoute]:
        """Find multiple route alternatives"""
        alternatives = []

        for strategy in RouteStrategy:
            route = self.find_route(source, destination, amount_sats, strategy)
            if route and route.is_economical(self.max_fee_rate):
                alternatives.append(route)

            if len(alternatives) >= max_alternatives:
                break

        # Sort by success probability and fee
        alternatives.sort(key=lambda r: (r.success_probability, -r.total_fee_sats), reverse=True)

        return alternatives[:max_alternatives]

    def update_route_success(self, route_id: str, success: bool, actual_fee: int = None):
        """Update route performance metrics"""
        route = self.routes.get(route_id)
        if not route:
            return

        # Update node reliability scores
        for hop in route.hops:
            node = self.nodes.get(hop.node_pubkey)
            if node:
                if success:
                    node.reliability_score = min(1.0, node.reliability_score + 0.01)
                else:
                    node.reliability_score = max(0.1, node.reliability_score - 0.05)

        self._save_nodes()

        self.logger.info(f"Updated route {route_id}: {'success' if success else 'failure'}")

    def get_routing_stats(self) -> Dict[str, Any]:
        """Get routing performance statistics"""
        if not self.routes:
            return {"total_routes": 0}

        routes = list(self.routes.values())

        avg_hops = sum(len(r.hops) for r in routes) / len(routes)
        avg_fee_rate = sum(r.get_fee_rate() for r in routes) / len(routes)
        avg_success_prob = sum(r.success_probability for r in routes) / len(routes)

        return {
            "total_routes": len(routes),
            "total_nodes": len(self.nodes),
            "total_channels": len(self.channels),
            "avg_hops": avg_hops,
            "avg_fee_rate": avg_fee_rate,
            "avg_success_probability": avg_success_prob,
            "strategies_used": {
                strategy.value: sum(1 for r in routes if r.strategy == strategy)
                for strategy in RouteStrategy
            }
        }

    def cleanup_old_routes(self, older_than_hours: int = 24) -> int:
        """Remove old cached routes"""
        cutoff_time = time.time() - (older_than_hours * 3600)
        old_routes = [
            route_id for route_id, route in self.routes.items()
            if route.created_at < cutoff_time
        ]

        for route_id in old_routes:
            del self.routes[route_id]

        if old_routes:
            self._save_routes()
            self.logger.info(f"Cleaned up {len(old_routes)} old routes")

        return len(old_routes)

    def optimize_network_topology(self):
        """Analyze and suggest network improvements"""
        suggestions = []

        # Find poorly connected nodes
        for pubkey, node in self.nodes.items():
            if len(node.channels) < 3 and node.reliability_score > 0.8:
                suggestions.append({
                    "type": "add_channels",
                    "node": pubkey,
                    "reason": "Well-performing node needs more channels",
                    "current_channels": len(node.channels)
                })

        # Find high-fee channels
        high_fee_channels = [
            (channel_id, info) for channel_id, info in self.channels.items()
            if info['fee_rate'] > 0.01  # > 1%
        ]

        for channel_id, info in high_fee_channels[:5]:  # Top 5
            suggestions.append({
                "type": "reduce_fees",
                "channel": channel_id,
                "reason": "High fee channel reducing routing efficiency",
                "current_fee_rate": info['fee_rate']
            })

        return suggestions


def create_routing_manager(data_dir: str = "data") -> RoutingManager:
    """Create routing manager instance"""
    return RoutingManager(data_dir)


if __name__ == "__main__":
    # Test routing manager
    print("🛣️ Testing Lightning Routing Manager...")

    manager = create_routing_manager("test_data")

    # Add test nodes
    node1 = manager.add_network_node(
        "0234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12",
        "TestNode1"
    )

    node2 = manager.add_network_node(
        "0345678901bcdef01234567890abcdef1234567890abcdef1234567890abcdef123",
        "TestNode2"
    )

    node3 = manager.add_network_node(
        "0456789012cdef012234567890abcdef1234567890abcdef1234567890abcdef1234",
        "TestNode3"
    )

    # Add test channels
    manager.update_channel_info("channel1", node1.pubkey, node2.pubkey, 1000000, 0.001)
    manager.update_channel_info("channel2", node2.pubkey, node3.pubkey, 500000, 0.002)

    print(f"✅ Created {len(manager.nodes)} nodes and {len(manager.channels)} channels")

    # Test routing
    route = manager.find_route(node1.pubkey, node3.pubkey, 100000)
    if route:
        print(f"🛣️ Found route: {len(route.hops)} hops, {route.total_fee_sats} sats fee")
        print(f"💰 Fee rate: {route.get_fee_rate():.3f}%")

    # Test alternatives
    alternatives = manager.get_route_alternatives(node1.pubkey, node3.pubkey, 100000)
    print(f"🔄 Route alternatives: {len(alternatives)}")

    # Get statistics
    stats = manager.get_routing_stats()
    print(f"📊 Routing stats: {stats['total_routes']} routes, {stats['total_nodes']} nodes")

    # Test optimization suggestions
    suggestions = manager.optimize_network_topology()
    print(f"💡 Optimization suggestions: {len(suggestions)}")

    # Cleanup
    import shutil
    shutil.rmtree("test_data", ignore_errors=True)

    print("✅ Routing manager test completed!")