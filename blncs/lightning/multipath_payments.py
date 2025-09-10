#!/usr/bin/env python3
"""
Multi-Path Payment System for BLNCS
Implements advanced multi-path payment (MPP) routing for Lightning Network transactions
"""

import asyncio
import hashlib
import secrets
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple
import logging
import math
from collections import defaultdict, deque

from blncs.core.async_memory_manager import track_async_task, lightning_operation_context
from blncs.core.exceptions import LightningError
from blncs.lightning.bolt_implementation import NodeId, ChannelId, Invoice

logger = logging.getLogger(__name__)

class PaymentStatus(Enum):
    """Multi-path payment status"""
    PENDING = "pending"
    IN_FLIGHT = "in_flight"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PARTIAL_SUCCESS = "partial_success"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"

class PathStatus(Enum):
    """Individual path status"""
    PENDING = "pending"
    ATTEMPTING = "attempting"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMEOUT = "timeout"

@dataclass
class PaymentPath:
    """Individual payment path in multi-path payment"""
    path_id: str
    route: List[Dict[str, Any]]
    amount_msat: int
    probability: float
    expected_fee_msat: int
    expected_delay: int
    status: PathStatus = PathStatus.PENDING
    attempt_count: int = 0
    last_attempt: Optional[float] = None
    failure_reason: Optional[str] = None
    htlc_id: Optional[int] = None
    preimage: Optional[bytes] = None

@dataclass
class MultiPathPayment:
    """Multi-path payment representation"""
    payment_id: str
    invoice: Invoice
    total_amount_msat: int
    total_fee_budget_msat: int
    paths: List[PaymentPath]
    status: PaymentStatus = PaymentStatus.PENDING
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    paid_amount_msat: int = 0
    total_fee_msat: int = 0
    timeout_seconds: int = 60
    max_path_count: int = 10
    payment_secret: Optional[bytes] = None

@dataclass
class RoutingHint:
    """Routing hint for path finding"""
    source_node: NodeId
    target_node: NodeId
    channel_id: int
    fee_base_msat: int
    fee_proportional_millionths: int
    cltv_expiry_delta: int
    htlc_minimum_msat: int
    htlc_maximum_msat: Optional[int] = None

class PathOptimizer:
    """Optimize payment paths for multi-path payments"""
    
    def __init__(self):
        self.channel_graph: Dict[str, Dict[str, Any]] = {}
        self.node_channels: Dict[str, Set[int]] = defaultdict(set)
        self.channel_policies: Dict[int, Tuple[Dict[str, Any], Dict[str, Any]]] = {}
        self.historical_success_rates: Dict[Tuple[str, str], float] = {}
        
    def add_channel(self, channel_id: int, node1: NodeId, node2: NodeId, 
                   capacity: int, policy1: Dict[str, Any], policy2: Dict[str, Any]):
        """Add channel to routing graph"""
        node1_str = str(node1)
        node2_str = str(node2)
        
        # Add to graph
        if node1_str not in self.channel_graph:
            self.channel_graph[node1_str] = {}
        if node2_str not in self.channel_graph:
            self.channel_graph[node2_str] = {}
        
        self.channel_graph[node1_str][node2_str] = {
            'channel_id': channel_id,
            'capacity': capacity,
            'policy': policy1
        }
        self.channel_graph[node2_str][node1_str] = {
            'channel_id': channel_id,
            'capacity': capacity,
            'policy': policy2
        }
        
        # Track node channels
        self.node_channels[node1_str].add(channel_id)
        self.node_channels[node2_str].add(channel_id)
        
        # Store policies
        self.channel_policies[channel_id] = (policy1, policy2)
    
    def update_success_rate(self, source: NodeId, target: NodeId, success: bool):
        """Update historical success rate for node pair"""
        key = (str(source), str(target))
        current_rate = self.historical_success_rates.get(key, 0.5)
        
        # Exponential moving average
        alpha = 0.1
        new_rate = alpha * (1.0 if success else 0.0) + (1 - alpha) * current_rate
        self.historical_success_rates[key] = new_rate
    
    def calculate_path_probability(self, route: List[Dict[str, Any]]) -> float:
        """Calculate success probability for a path"""
        if not route:
            return 0.0
        
        # Start with base probability
        probability = 1.0
        
        for i in range(len(route) - 1):
            source = route[i]['pubkey']
            target = route[i + 1]['pubkey']
            
            # Get historical success rate
            key = (source.hex() if isinstance(source, bytes) else str(source),
                   target.hex() if isinstance(target, bytes) else str(target))
            success_rate = self.historical_success_rates.get(key, 0.8)  # Default 80%
            
            # Adjust for channel capacity and amount
            channel_id = route[i]['short_channel_id']
            if channel_id in self.channel_policies:
                policy1, policy2 = self.channel_policies[channel_id]
                # Use the policy in the direction we're routing
                policy = policy1  # Simplified - would check direction
                
                # Reduce probability for channels near capacity
                capacity_factor = 1.0  # Simplified - would calculate based on known capacity
                probability *= success_rate * capacity_factor
            else:
                probability *= success_rate
        
        return max(0.01, min(1.0, probability))  # Clamp between 1% and 100%
    
    async def find_multiple_paths(self, source: NodeId, destination: NodeId, 
                                 amount_msat: int, max_paths: int = 5) -> List[List[Dict[str, Any]]]:
        """Find multiple diverse paths for multi-path payment"""
        all_paths = []
        excluded_channels: Set[int] = set()
        
        # Find paths iteratively, excluding previously used channels for diversity
        for attempt in range(max_paths * 2):  # Try up to double max_paths
            if len(all_paths) >= max_paths:
                break
            
            path = await self._find_single_path(
                source, destination, amount_msat // max_paths, excluded_channels
            )
            
            if not path:
                break
            
            all_paths.append(path)
            
            # Exclude channels from this path to encourage diversity
            for hop in path:
                excluded_channels.add(hop['short_channel_id'])
            
            # If we have enough good paths, stop early
            if len(all_paths) >= max_paths:
                break
        
        # Sort by path quality (probability * inverse of fee)
        all_paths.sort(key=lambda p: self._calculate_path_quality(p), reverse=True)
        
        return all_paths[:max_paths]
    
    async def _find_single_path(self, source: NodeId, destination: NodeId, 
                               amount_msat: int, excluded_channels: Set[int]) -> List[Dict[str, Any]]:
        """Find single path using modified Dijkstra's algorithm"""
        source_str = str(source)
        dest_str = str(destination)
        
        if source_str not in self.channel_graph or dest_str not in self.channel_graph:
            return []
        
        # Dijkstra's algorithm with modifications for Lightning routing
        distances = {source_str: 0}
        previous = {}
        unvisited = {node: float('inf') for node in self.channel_graph.keys()}
        unvisited[source_str] = 0
        
        while unvisited:
            # Find unvisited node with minimum distance
            current_node = min(unvisited, key=unvisited.get)
            current_distance = unvisited[current_node]
            
            if current_distance == float('inf'):
                break  # No more reachable nodes
            
            if current_node == dest_str:
                # Found path to destination
                path = []
                while current_node in previous:
                    edge_info = previous[current_node]
                    path.append(edge_info)
                    current_node = edge_info['from_node']
                
                path.reverse()
                return path
            
            # Remove current node from unvisited
            del unvisited[current_node]
            
            # Check neighbors
            for neighbor, edge_info in self.channel_graph[current_node].items():
                if neighbor not in unvisited:
                    continue
                
                channel_id = edge_info['channel_id']
                if channel_id in excluded_channels:
                    continue
                
                # Calculate edge weight (combination of fees and reliability)
                edge_weight = self._calculate_edge_weight(
                    edge_info, amount_msat, current_node, neighbor
                )
                
                tentative_distance = current_distance + edge_weight
                
                if tentative_distance < unvisited[neighbor]:
                    unvisited[neighbor] = tentative_distance
                    distances[neighbor] = tentative_distance
                    previous[neighbor] = {
                        'from_node': current_node,
                        'to_node': neighbor,
                        'pubkey': neighbor.encode() if isinstance(neighbor, str) else neighbor,
                        'short_channel_id': channel_id,
                        'fee_base_msat': edge_info['policy'].get('fee_base_msat', 1000),
                        'fee_proportional_millionths': edge_info['policy'].get('fee_proportional_millionths', 100),
                        'cltv_expiry_delta': edge_info['policy'].get('cltv_expiry_delta', 40)
                    }
        
        return []  # No path found
    
    def _calculate_edge_weight(self, edge_info: Dict[str, Any], amount_msat: int,
                              from_node: str, to_node: str) -> float:
        """Calculate edge weight for routing"""
        policy = edge_info['policy']
        
        # Calculate fees
        fee_base_msat = policy.get('fee_base_msat', 1000)
        fee_proportional = policy.get('fee_proportional_millionths', 100)
        total_fee = fee_base_msat + (amount_msat * fee_proportional) // 1_000_000
        
        # Get success probability
        key = (from_node, to_node)
        success_rate = self.historical_success_rates.get(key, 0.8)
        
        # Calculate capacity factor (simplified)
        capacity = edge_info.get('capacity', 1_000_000_000)  # Default 10M sats
        capacity_factor = min(1.0, capacity / (amount_msat / 1000))  # Convert to sats
        
        # Combine factors into weight (lower is better)
        # Weight = fee / (success_rate * capacity_factor)
        weight = total_fee / (success_rate * capacity_factor)
        
        return max(1.0, weight)
    
    def _calculate_path_quality(self, path: List[Dict[str, Any]]) -> float:
        """Calculate overall path quality score"""
        if not path:
            return 0.0
        
        # Calculate total fees
        total_fee = sum(hop.get('fee_base_msat', 0) for hop in path)
        
        # Calculate path probability
        probability = self.calculate_path_probability(path)
        
        # Quality = probability / (1 + fee_factor)
        fee_factor = total_fee / 1000.0  # Normalize fees
        return probability / (1 + fee_factor)

class MultiPathRouter:
    """Multi-path payment routing engine"""
    
    def __init__(self, path_optimizer: PathOptimizer):
        self.path_optimizer = path_optimizer
        self.active_payments: Dict[str, MultiPathPayment] = {}
        self.payment_shards: Dict[str, Set[str]] = defaultdict(set)  # payment_secret -> shard_ids
        
    @track_async_task("create_multipath_payment")
    async def create_multipath_payment(self, invoice: Invoice, 
                                      fee_budget_msat: Optional[int] = None,
                                      max_paths: int = 5) -> MultiPathPayment:
        """Create multi-path payment plan"""
        async with lightning_operation_context("create_multipath_payment"):
            payment_id = str(uuid.uuid4())
            amount_msat = invoice.amount_msat or 0
            
            if amount_msat == 0:
                raise LightningError("Invoice amount required for multi-path payment")
            
            # Default fee budget is 1% of amount or 1000 msat minimum
            if not fee_budget_msat:
                fee_budget_msat = max(1000, amount_msat // 100)
            
            # Generate payment secret if not provided in invoice
            payment_secret = invoice.payment_secret or secrets.token_bytes(32)
            
            # Create base payment
            payment = MultiPathPayment(
                payment_id=payment_id,
                invoice=invoice,
                total_amount_msat=amount_msat,
                total_fee_budget_msat=fee_budget_msat,
                paths=[],
                payment_secret=payment_secret,
                max_path_count=max_paths
            )
            
            # Find optimal paths
            await self._plan_payment_paths(payment)
            
            # Register payment
            self.active_payments[payment_id] = payment
            
            logger.info(f"Created multi-path payment {payment_id} with {len(payment.paths)} paths")
            return payment
    
    async def _plan_payment_paths(self, payment: MultiPathPayment):
        """Plan optimal paths for multi-path payment"""
        invoice = payment.invoice
        amount_msat = payment.total_amount_msat
        fee_budget = payment.total_fee_budget_msat
        
        # Determine source and destination
        # In real implementation, source would be our node
        source_node = NodeId(secrets.token_bytes(33))  # Placeholder
        dest_node = invoice.payee_pubkey or NodeId(secrets.token_bytes(33))
        
        # Find multiple paths
        routes = await self.path_optimizer.find_multiple_paths(
            source_node, dest_node, amount_msat, payment.max_path_count
        )
        
        if not routes:
            raise LightningError("No routes found for payment")
        
        # Calculate optimal amount distribution
        path_amounts = self._calculate_optimal_distribution(
            amount_msat, routes, fee_budget
        )
        
        # Create payment paths
        for i, (route, path_amount) in enumerate(zip(routes, path_amounts)):
            if path_amount <= 0:
                continue
            
            path_fee = self._calculate_route_fee(route, path_amount)
            path_delay = self._calculate_route_delay(route)
            path_probability = self.path_optimizer.calculate_path_probability(route)
            
            path = PaymentPath(
                path_id=f"{payment.payment_id}_path_{i}",
                route=route,
                amount_msat=path_amount,
                probability=path_probability,
                expected_fee_msat=path_fee,
                expected_delay=path_delay
            )
            
            payment.paths.append(path)
    
    def _calculate_optimal_distribution(self, total_amount: int, routes: List[List[Dict[str, Any]]],
                                      fee_budget: int) -> List[int]:
        """Calculate optimal amount distribution across paths"""
        if not routes:
            return []
        
        # Simple equal distribution for now
        # Advanced implementation would use optimization algorithms
        num_paths = len(routes)
        base_amount = total_amount // num_paths
        remainder = total_amount % num_paths
        
        amounts = [base_amount] * num_paths
        
        # Distribute remainder
        for i in range(remainder):
            amounts[i] += 1
        
        # Adjust based on path quality and capacity
        # This is a simplified version - real implementation would be more sophisticated
        path_qualities = [self.path_optimizer._calculate_path_quality(route) for route in routes]
        total_quality = sum(path_qualities)
        
        if total_quality > 0:
            # Redistribute based on path quality
            for i, quality in enumerate(path_qualities):
                quality_factor = quality / total_quality
                amounts[i] = int(total_amount * quality_factor)
        
        # Ensure amounts sum to total
        current_sum = sum(amounts)
        if current_sum != total_amount:
            amounts[0] += total_amount - current_sum
        
        return amounts
    
    def _calculate_route_fee(self, route: List[Dict[str, Any]], amount_msat: int) -> int:
        """Calculate total fee for route"""
        total_fee = 0
        current_amount = amount_msat
        
        # Calculate fees backwards from destination
        for hop in reversed(route):
            fee_base = hop.get('fee_base_msat', 1000)
            fee_rate = hop.get('fee_proportional_millionths', 100)
            
            hop_fee = fee_base + (current_amount * fee_rate) // 1_000_000
            total_fee += hop_fee
            current_amount += hop_fee
        
        return total_fee
    
    def _calculate_route_delay(self, route: List[Dict[str, Any]]) -> int:
        """Calculate total CLTV delay for route"""
        return sum(hop.get('cltv_expiry_delta', 40) for hop in route)
    
    @track_async_task("execute_multipath_payment")
    async def execute_multipath_payment(self, payment_id: str) -> bool:
        """Execute multi-path payment"""
        async with lightning_operation_context("execute_multipath_payment"):
            if payment_id not in self.active_payments:
                raise LightningError(f"Payment {payment_id} not found")
            
            payment = self.active_payments[payment_id]
            payment.status = PaymentStatus.IN_FLIGHT
            
            try:
                # Execute all paths concurrently
                path_tasks = []
                for path in payment.paths:
                    task = asyncio.create_task(self._execute_path(payment, path))
                    path_tasks.append(task)
                
                # Wait for paths to complete or timeout
                timeout = payment.timeout_seconds
                results = await asyncio.wait_for(
                    asyncio.gather(*path_tasks, return_exceptions=True),
                    timeout=timeout
                )
                
                # Analyze results
                successful_paths = 0
                total_paid = 0
                total_fee = 0
                
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        payment.paths[i].status = PathStatus.FAILED
                        payment.paths[i].failure_reason = str(result)
                    elif result:
                        successful_paths += 1
                        total_paid += payment.paths[i].amount_msat
                        total_fee += payment.paths[i].expected_fee_msat
                
                payment.paid_amount_msat = total_paid
                payment.total_fee_msat = total_fee
                payment.completed_at = time.time()
                
                # Determine final status
                if total_paid >= payment.total_amount_msat:
                    payment.status = PaymentStatus.SUCCEEDED
                    logger.info(f"Multi-path payment {payment_id} succeeded")
                    return True
                elif total_paid > 0:
                    payment.status = PaymentStatus.PARTIAL_SUCCESS
                    logger.warning(f"Multi-path payment {payment_id} partially succeeded: {total_paid}/{payment.total_amount_msat}")
                    return False
                else:
                    payment.status = PaymentStatus.FAILED
                    logger.error(f"Multi-path payment {payment_id} failed completely")
                    return False
            
            except asyncio.TimeoutError:
                payment.status = PaymentStatus.TIMEOUT
                logger.error(f"Multi-path payment {payment_id} timed out")
                return False
            except Exception as e:
                payment.status = PaymentStatus.FAILED
                logger.error(f"Multi-path payment {payment_id} error: {e}")
                return False
            finally:
                # Cleanup - cancel any remaining paths
                await self._cleanup_payment_paths(payment)
    
    async def _execute_path(self, payment: MultiPathPayment, path: PaymentPath) -> bool:
        """Execute individual payment path"""
        path.status = PathStatus.ATTEMPTING
        path.attempt_count += 1
        path.last_attempt = time.time()
        
        try:
            # Create HTLC for this path
            htlc_data = self._create_htlc_data(payment, path)
            
            # Send HTLC (simplified - would use actual Lightning client)
            # In real implementation, this would send update_add_htlc message
            await asyncio.sleep(0.1)  # Simulate network delay
            
            # Simulate success/failure based on path probability
            import random
            success = random.random() < path.probability
            
            if success:
                path.status = PathStatus.SUCCEEDED
                path.preimage = secrets.token_bytes(32)  # Mock preimage
                
                # Update success rate for optimization
                for i in range(len(path.route) - 1):
                    source = NodeId(path.route[i]['pubkey'])
                    target = NodeId(path.route[i + 1]['pubkey'])
                    self.path_optimizer.update_success_rate(source, target, True)
                
                logger.debug(f"Path {path.path_id} succeeded")
                return True
            else:
                path.status = PathStatus.FAILED
                path.failure_reason = "Payment failed at intermediate node"
                
                # Update failure rate
                for i in range(len(path.route) - 1):
                    source = NodeId(path.route[i]['pubkey'])
                    target = NodeId(path.route[i + 1]['pubkey'])
                    self.path_optimizer.update_success_rate(source, target, False)
                
                logger.debug(f"Path {path.path_id} failed")
                return False
        
        except Exception as e:
            path.status = PathStatus.FAILED
            path.failure_reason = str(e)
            logger.error(f"Path {path.path_id} error: {e}")
            return False
    
    def _create_htlc_data(self, payment: MultiPathPayment, path: PaymentPath) -> Dict[str, Any]:
        """Create HTLC data for path"""
        return {
            'amount_msat': path.amount_msat,
            'payment_hash': payment.invoice.payment_hash,
            'payment_secret': payment.payment_secret,
            'total_msat': payment.total_amount_msat,
            'cltv_expiry': int(time.time()) + 144,  # Current block + safety margin
            'route': path.route
        }
    
    async def _cleanup_payment_paths(self, payment: MultiPathPayment):
        """Cleanup payment paths after completion"""
        cleanup_tasks = []
        
        for path in payment.paths:
            if path.status == PathStatus.ATTEMPTING:
                # Cancel in-flight HTLC
                task = asyncio.create_task(self._cancel_path_htlc(path))
                cleanup_tasks.append(task)
        
        if cleanup_tasks:
            await asyncio.gather(*cleanup_tasks, return_exceptions=True)
    
    async def _cancel_path_htlc(self, path: PaymentPath):
        """Cancel HTLC for path"""
        try:
            # In real implementation, would send update_fail_htlc
            path.status = PathStatus.FAILED
            path.failure_reason = "Cancelled due to payment completion"
            logger.debug(f"Cancelled HTLC for path {path.path_id}")
        except Exception as e:
            logger.error(f"Error cancelling HTLC for path {path.path_id}: {e}")
    
    def get_payment_status(self, payment_id: str) -> Optional[Dict[str, Any]]:
        """Get payment status"""
        if payment_id not in self.active_payments:
            return None
        
        payment = self.active_payments[payment_id]
        
        return {
            'payment_id': payment.payment_id,
            'status': payment.status.value,
            'total_amount_msat': payment.total_amount_msat,
            'paid_amount_msat': payment.paid_amount_msat,
            'total_fee_msat': payment.total_fee_msat,
            'path_count': len(payment.paths),
            'successful_paths': len([p for p in payment.paths if p.status == PathStatus.SUCCEEDED]),
            'created_at': payment.created_at,
            'completed_at': payment.completed_at,
            'paths': [
                {
                    'path_id': path.path_id,
                    'status': path.status.value,
                    'amount_msat': path.amount_msat,
                    'probability': path.probability,
                    'expected_fee_msat': path.expected_fee_msat,
                    'attempt_count': path.attempt_count,
                    'failure_reason': path.failure_reason
                }
                for path in payment.paths
            ]
        }
    
    def list_active_payments(self) -> List[Dict[str, Any]]:
        """List all active payments"""
        return [
            {
                'payment_id': pid,
                'status': payment.status.value,
                'total_amount_msat': payment.total_amount_msat,
                'path_count': len(payment.paths),
                'created_at': payment.created_at
            }
            for pid, payment in self.active_payments.items()
        ]
    
    async def cancel_payment(self, payment_id: str) -> bool:
        """Cancel active payment"""
        if payment_id not in self.active_payments:
            return False
        
        payment = self.active_payments[payment_id]
        
        if payment.status not in [PaymentStatus.PENDING, PaymentStatus.IN_FLIGHT]:
            return False
        
        payment.status = PaymentStatus.CANCELLED
        await self._cleanup_payment_paths(payment)
        
        logger.info(f"Cancelled multi-path payment {payment_id}")
        return True

class MultiPathPaymentManager:
    """Main multi-path payment manager"""
    
    def __init__(self):
        self.path_optimizer = PathOptimizer()
        self.router = MultiPathRouter(self.path_optimizer)
        self.payment_history: List[MultiPathPayment] = []
        
    async def add_channel_to_graph(self, channel_id: int, node1: NodeId, node2: NodeId,
                                  capacity: int, policy1: Dict[str, Any], policy2: Dict[str, Any]):
        """Add channel to routing graph"""
        self.path_optimizer.add_channel(channel_id, node1, node2, capacity, policy1, policy2)
    
    async def send_multipath_payment(self, invoice: Invoice, 
                                   fee_budget_msat: Optional[int] = None,
                                   max_paths: int = 5) -> Dict[str, Any]:
        """Send multi-path payment"""
        # Create payment plan
        payment = await self.router.create_multipath_payment(
            invoice, fee_budget_msat, max_paths
        )
        
        # Execute payment
        success = await self.router.execute_multipath_payment(payment.payment_id)
        
        # Move to history when completed
        if payment.status in [PaymentStatus.SUCCEEDED, PaymentStatus.FAILED, 
                             PaymentStatus.TIMEOUT, PaymentStatus.CANCELLED]:
            self.payment_history.append(payment)
            del self.router.active_payments[payment.payment_id]
        
        return {
            'payment_id': payment.payment_id,
            'success': success,
            'status': payment.status.value,
            'paid_amount_msat': payment.paid_amount_msat,
            'total_fee_msat': payment.total_fee_msat,
            'path_count': len(payment.paths),
            'successful_paths': len([p for p in payment.paths if p.status == PathStatus.SUCCEEDED])
        }
    
    def get_payment_statistics(self) -> Dict[str, Any]:
        """Get payment statistics"""
        total_payments = len(self.payment_history) + len(self.router.active_payments)
        
        if total_payments == 0:
            return {'total_payments': 0}
        
        # Analyze completed payments
        completed_payments = self.payment_history
        successful_payments = [p for p in completed_payments if p.status == PaymentStatus.SUCCEEDED]
        
        success_rate = len(successful_payments) / len(completed_payments) if completed_payments else 0
        
        avg_paths = sum(len(p.paths) for p in completed_payments) / len(completed_payments) if completed_payments else 0
        
        avg_fee_rate = 0
        if successful_payments:
            fee_rates = [p.total_fee_msat / p.total_amount_msat for p in successful_payments if p.total_amount_msat > 0]
            avg_fee_rate = sum(fee_rates) / len(fee_rates) if fee_rates else 0
        
        return {
            'total_payments': total_payments,
            'completed_payments': len(completed_payments),
            'active_payments': len(self.router.active_payments),
            'success_rate': success_rate,
            'average_paths_per_payment': avg_paths,
            'average_fee_rate': avg_fee_rate,
            'total_volume_msat': sum(p.paid_amount_msat for p in successful_payments),
            'total_fees_msat': sum(p.total_fee_msat for p in successful_payments)
        }

# Factory function
async def create_multipath_payment_manager() -> MultiPathPaymentManager:
    """Create multi-path payment manager"""
    manager = MultiPathPaymentManager()
    
    # Add some sample channels for demo
    node1 = NodeId(secrets.token_bytes(33))
    node2 = NodeId(secrets.token_bytes(33))
    node3 = NodeId(secrets.token_bytes(33))
    
    await manager.add_channel_to_graph(
        channel_id=1,
        node1=node1,
        node2=node2,
        capacity=1_000_000,
        policy1={'fee_base_msat': 1000, 'fee_proportional_millionths': 100, 'cltv_expiry_delta': 40},
        policy2={'fee_base_msat': 1000, 'fee_proportional_millionths': 100, 'cltv_expiry_delta': 40}
    )
    
    await manager.add_channel_to_graph(
        channel_id=2,
        node1=node2,
        node2=node3,
        capacity=2_000_000,
        policy1={'fee_base_msat': 500, 'fee_proportional_millionths': 50, 'cltv_expiry_delta': 40},
        policy2={'fee_base_msat': 500, 'fee_proportional_millionths': 50, 'cltv_expiry_delta': 40}
    )
    
    logger.info("Created multi-path payment manager with sample routing graph")
    return manager

# Export main classes and functions
__all__ = [
    'PaymentStatus',
    'PathStatus', 
    'PaymentPath',
    'MultiPathPayment',
    'RoutingHint',
    'PathOptimizer',
    'MultiPathRouter',
    'MultiPathPaymentManager',
    'create_multipath_payment_manager'
]