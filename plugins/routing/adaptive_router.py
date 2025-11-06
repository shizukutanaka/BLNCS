"""
Sample Routing Plugin: Adaptive Router
Implements dynamic routing strategies that adapt based on network conditions.
"""

from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import random

from blncs.core.plugin_system import RoutingPlugin, PluginMetadata


@dataclass
class RouteScore:
    """Scoring information for a route"""
    total_score: float
    latency_score: float
    fee_score: float
    reliability_score: float
    liquidity_score: float


@dataclass
class NetworkCondition:
    """Current network condition assessment"""
    congestion_level: str  # low, medium, high
    avg_fee_rate: float
    success_rate: float
    active_channels: int
    timestamp: datetime


class AdaptiveRouterPlugin(RoutingPlugin):
    """
    Advanced adaptive routing plugin that adjusts routing strategies
    based on real-time network conditions and historical performance.
    """
    
    def __init__(self):
        metadata = PluginMetadata(
            name="Adaptive Router",
            version="1.2.0",
            description="Dynamic routing with adaptive strategies based on network conditions",
            author="BLNCS Team",
            category="routing",
            tags=["routing", "adaptive", "optimization", "ml"],
            dependencies=[],
            min_api_version="1.0.0"
        )
        super().__init__(metadata)
        
        # Routing state
        self.route_history: List[Dict] = []
        self.network_conditions: List[NetworkCondition] = []
        self.node_reputation: Dict[str, float] = {}
        self.channel_performance: Dict[str, Dict] = {}
        
        # Adaptive parameters
        self.adaptation_rate = 0.1  # How quickly to adapt to conditions
        self.min_samples = 10  # Minimum samples before adaptation
        
    def find_route(self, source: str, destination: str, amount: int, 
                   constraints: Optional[Dict] = None) -> Dict[str, Any]:
        """Find optimal route with adaptive strategy selection"""
        try:
            # Assess current network conditions
            current_conditions = self._assess_network_conditions()
            
            # Select routing strategy based on conditions
            strategy = self._select_strategy(current_conditions, amount)
            
            # Find routes using selected strategy
            routes = self._find_routes_with_strategy(
                source, destination, amount, strategy, constraints
            )
            
            # Score and rank routes
            scored_routes = []
            for route in routes:
                score = self._score_route(route, current_conditions)
                scored_routes.append({
                    'route': route,
                    'score': score,
                    'strategy': strategy,
                    'conditions': current_conditions.__dict__
                })
            
            # Sort by score (higher is better)
            scored_routes.sort(key=lambda x: x['score'].total_score, reverse=True)
            
            # Return best route with metadata
            if scored_routes:
                best_route = scored_routes[0]
                return {
                    'plugin': self.metadata.name,
                    'source': source,
                    'destination': destination,
                    'amount': amount,
                    'strategy': strategy,
                    'route': best_route['route'],
                    'score': {
                        'total': best_route['score'].total_score,
                        'latency': best_route['score'].latency_score,
                        'fee': best_route['score'].fee_score,
                        'reliability': best_route['score'].reliability_score,
                        'liquidity': best_route['score'].liquidity_score
                    },
                    'alternatives': len(scored_routes) - 1,
                    'network_conditions': current_conditions.__dict__,
                    'timestamp': datetime.now().isoformat()
                }
            else:
                return {
                    'plugin': self.metadata.name,
                    'error': 'No viable routes found',
                    'strategy': strategy,
                    'conditions': current_conditions.__dict__
                }
                
        except Exception as e:
            self.logger.error(f"Route finding failed: {e}")
            return {'error': str(e), 'plugin': self.metadata.name}
    
    def optimize_route(self, route_data: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize existing route based on current conditions"""
        try:
            # Extract route information
            source = route_data.get('source')
            destination = route_data.get('destination')
            amount = route_data.get('amount')
            current_route = route_data.get('route', {})
            
            if not all([source, destination, amount]):
                return {'error': 'Missing required route data', 'plugin': self.metadata.name}
            
            # Get current network conditions
            conditions = self._assess_network_conditions()
            
            # Find alternative routes
            alternatives = self.find_route(source, destination, amount)
            
            if 'error' in alternatives:
                return alternatives
            
            # Compare with current route
            current_score = self._score_route(current_route, conditions)
            new_score = RouteScore(
                alternatives['score']['total'],
                alternatives['score']['latency'],
                alternatives['score']['fee'],
                alternatives['score']['reliability'],
                alternatives['score']['liquidity']
            )
            
            improvement = new_score.total_score - current_score.total_score
            
            return {
                'plugin': self.metadata.name,
                'optimization_type': 'route_comparison',
                'current_route': current_route,
                'optimized_route': alternatives['route'],
                'improvement': improvement,
                'improvement_percentage': (improvement / current_score.total_score * 100) if current_score.total_score > 0 else 0,
                'scores': {
                    'current': {
                        'total': current_score.total_score,
                        'latency': current_score.latency_score,
                        'fee': current_score.fee_score,
                        'reliability': current_score.reliability_score,
                        'liquidity': current_score.liquidity_score
                    },
                    'optimized': alternatives['score']
                },
                'recommendation': 'switch' if improvement > 0.1 else 'keep_current',
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Route optimization failed: {e}")
            return {'error': str(e), 'plugin': self.metadata.name}
    
    def _assess_network_conditions(self) -> NetworkCondition:
        """Assess current network conditions"""
        try:
            # In a real implementation, this would query actual network data
            # For demo purposes, we'll simulate conditions based on recent history
            
            recent_routes = self.route_history[-50:] if self.route_history else []
            
            if not recent_routes:
                # Default conditions when no history
                return NetworkCondition(
                    congestion_level="medium",
                    avg_fee_rate=0.5,
                    success_rate=0.85,
                    active_channels=1000,
                    timestamp=datetime.now()
                )
            
            # Calculate metrics from recent routes
            successful_routes = [r for r in recent_routes if r.get('success', True)]
            success_rate = len(successful_routes) / len(recent_routes)
            
            fees = [r.get('total_fee', 0) for r in recent_routes]
            amounts = [r.get('amount', 1) for r in recent_routes]
            
            avg_fee_rate = 0.5  # Default
            if fees and amounts:
                total_fees = sum(fees)
                total_amounts = sum(amounts)
                avg_fee_rate = (total_fees / total_amounts * 100) if total_amounts > 0 else 0.5
            
            # Determine congestion level
            if avg_fee_rate > 1.0 or success_rate < 0.8:
                congestion_level = "high"
            elif avg_fee_rate > 0.5 or success_rate < 0.9:
                congestion_level = "medium"
            else:
                congestion_level = "low"
            
            # Estimate active channels (would be queried from network in real implementation)
            active_channels = max(500, 1000 + random.randint(-200, 200))
            
            condition = NetworkCondition(
                congestion_level=congestion_level,
                avg_fee_rate=avg_fee_rate,
                success_rate=success_rate,
                active_channels=active_channels,
                timestamp=datetime.now()
            )
            
            # Store for history
            self.network_conditions.append(condition)
            if len(self.network_conditions) > 100:
                self.network_conditions = self.network_conditions[-100:]
            
            return condition
            
        except Exception as e:
            self.logger.error(f"Network assessment failed: {e}")
            # Return safe default
            return NetworkCondition(
                congestion_level="medium",
                avg_fee_rate=0.5,
                success_rate=0.85,
                active_channels=1000,
                timestamp=datetime.now()
            )
    
    def _select_strategy(self, conditions: NetworkCondition, amount: int) -> str:
        """Select routing strategy based on conditions and amount"""
        try:
            # Strategy selection logic based on network conditions
            if conditions.congestion_level == "high":
                if amount < 10000:  # Small payments
                    return "low_latency"  # Prioritize speed over fees for small amounts
                else:
                    return "multi_path"  # Split large payments to avoid congestion
            
            elif conditions.congestion_level == "low":
                if amount > 100000:  # Large payments
                    return "single_path_optimal"  # Use optimal single path when network is clear
                else:
                    return "balanced"  # Balance fee and reliability
            
            else:  # Medium congestion
                if conditions.success_rate < 0.85:
                    return "reliability_focused"  # Prioritize success rate
                else:
                    return "balanced"  # Standard balanced approach
                    
        except Exception as e:
            self.logger.error(f"Strategy selection failed: {e}")
            return "balanced"  # Safe default
    
    def _find_routes_with_strategy(self, source: str, destination: str, 
                                   amount: int, strategy: str, 
                                   constraints: Optional[Dict] = None) -> List[Dict]:
        """Find routes using the specified strategy"""
        # This would interface with actual routing algorithms
        # For demo purposes, we'll generate sample routes
        
        try:
            routes = []
            
            # Generate 2-3 sample routes based on strategy
            if strategy == "multi_path":
                # Create multiple smaller routes
                split_amount = amount // 3
                for i in range(3):
                    routes.append(self._generate_sample_route(
                        source, destination, split_amount, f"path_{i+1}"
                    ))
            
            elif strategy == "low_latency":
                # Single direct route with minimal hops
                routes.append(self._generate_sample_route(
                    source, destination, amount, "direct", hops=2
                ))
            
            elif strategy == "reliability_focused":
                # Routes through well-known reliable nodes
                routes.append(self._generate_sample_route(
                    source, destination, amount, "reliable", reliability=0.95
                ))
            
            else:  # balanced or single_path_optimal
                # Standard route finding
                routes.append(self._generate_sample_route(
                    source, destination, amount, "balanced"
                ))
                routes.append(self._generate_sample_route(
                    source, destination, amount, "alternative"
                ))
            
            return routes
            
        except Exception as e:
            self.logger.error(f"Route generation failed: {e}")
            return []
    
    def _generate_sample_route(self, source: str, destination: str, 
                               amount: int, route_type: str, 
                               hops: int = 3, reliability: float = 0.9) -> Dict:
        """Generate a sample route for demonstration"""
        # In real implementation, this would query actual network topology
        
        route_id = f"{route_type}_{random.randint(1000, 9999)}"
        
        # Generate sample path
        path = [source]
        for i in range(hops - 1):
            path.append(f"node_{random.randint(100, 999)}")
        path.append(destination)
        
        # Calculate estimated metrics based on route type
        base_fee = amount * 0.001  # 0.1% base fee
        
        if route_type == "direct":
            total_fee = base_fee * 0.5  # Lower fees for direct routes
            estimated_time = 2000  # 2 seconds
        elif route_type == "reliable":
            total_fee = base_fee * 1.2  # Higher fees for reliable routes
            estimated_time = 3000  # 3 seconds
            reliability = 0.95
        elif route_type == "multi_path":
            total_fee = base_fee * 0.8  # Slightly lower fees
            estimated_time = 4000  # 4 seconds
        else:  # balanced/alternative
            total_fee = base_fee
            estimated_time = 3000 + random.randint(-500, 1000)
        
        return {
            'route_id': route_id,
            'path': path,
            'amount': amount,
            'total_fee': int(total_fee),
            'estimated_time_ms': estimated_time,
            'reliability_score': reliability,
            'hop_count': len(path) - 1,
            'route_type': route_type
        }
    
    def _score_route(self, route: Dict, conditions: NetworkCondition) -> RouteScore:
        """Score a route based on current conditions"""
        try:
            if not route:
                return RouteScore(0, 0, 0, 0, 0)
            
            # Extract route metrics
            total_fee = route.get('total_fee', 0)
            amount = route.get('amount', 1)
            estimated_time = route.get('estimated_time_ms', 5000)
            reliability = route.get('reliability_score', 0.8)
            hop_count = route.get('hop_count', 3)
            
            # Calculate component scores (0-1 scale)
            
            # Fee score (lower fees = higher score)
            fee_rate = (total_fee / amount) * 100 if amount > 0 else 1.0
            fee_score = max(0, 1.0 - (fee_rate / 2.0))  # Normalize against 2% max
            
            # Latency score (lower time = higher score)
            latency_score = max(0, 1.0 - (estimated_time / 10000))  # Normalize against 10s max
            
            # Reliability score (use provided reliability)
            reliability_score = reliability
            
            # Liquidity score (fewer hops = better liquidity assumption)
            liquidity_score = max(0, 1.0 - (hop_count / 10))  # Normalize against 10 hops max
            
            # Weight scores based on network conditions
            if conditions.congestion_level == "high":
                # Prioritize reliability and latency in high congestion
                weights = [0.2, 0.3, 0.35, 0.15]  # [fee, latency, reliability, liquidity]
            elif conditions.congestion_level == "low":
                # Prioritize fees and liquidity in low congestion
                weights = [0.4, 0.2, 0.2, 0.2]
            else:  # medium
                # Balanced weighting
                weights = [0.25, 0.25, 0.25, 0.25]
            
            # Calculate total score
            total_score = (
                fee_score * weights[0] +
                latency_score * weights[1] +
                reliability_score * weights[2] +
                liquidity_score * weights[3]
            )
            
            return RouteScore(
                total_score=total_score,
                latency_score=latency_score,
                fee_score=fee_score,
                reliability_score=reliability_score,
                liquidity_score=liquidity_score
            )
            
        except Exception as e:
            self.logger.error(f"Route scoring failed: {e}")
            return RouteScore(0, 0, 0, 0, 0)


# Plugin registration
def create_plugin():
    """Plugin factory function"""
    return AdaptiveRouterPlugin()