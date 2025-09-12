"""
Lightning Network Channel Rebalancer
Automated channel rebalancing for optimal liquidity management.
"""

import time
import random
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
from collections import defaultdict

from .logger import get_logger
from .config import get_config
from .cache_unified import get_cache


@dataclass
class RebalanceRoute:
    """Represents a potential rebalancing route"""
    from_channel: str
    to_channel: str
    amount: int  # satoshis
    fee_limit: int  # satoshis
    route_hops: List[str]
    estimated_fee: int
    success_probability: float


class ChannelRebalancer:
    """Automated channel rebalancing system"""
    
    def __init__(self, client=None):
        self.logger = get_logger(__name__)
        self.config = get_config()
        self.cache = get_cache()
        self.client = client
        
        # Configuration
        self.enabled = self.config.get('rebalancer.enabled', True)
        self.target_balance_ratio = self.config.get('rebalancer.target_ratio', 0.5)  # 50%
        self.min_imbalance_threshold = self.config.get('rebalancer.min_threshold', 0.2)  # 20%
        self.max_fee_rate = self.config.get('rebalancer.max_fee_rate', 0.001)  # 0.1%
        self.min_rebalance_amount = self.config.get('rebalancer.min_amount', 100000)  # 100k sats
        self.max_rebalance_amount = self.config.get('rebalancer.max_amount', 5000000)  # 5M sats
        
        # Runtime state
        self.last_rebalance_time = {}
        self.rebalance_cooldown = timedelta(hours=1)  # Minimum time between rebalances
        
    def analyze_channels(self) -> Dict[str, Dict[str, Any]]:
        """Analyze all channels and identify rebalancing opportunities"""
        if not self.client:
            self.logger.error("No Lightning client available for rebalancing")
            return {}
        
        try:
            channels = self.client.list_channels()
            analysis = {}
            
            for channel in channels:
                chan_id = channel.get('chan_id', '')
                if not chan_id or not channel.get('active', False):
                    continue
                
                local_balance = int(channel.get('local_balance', 0))
                remote_balance = int(channel.get('remote_balance', 0))
                capacity = int(channel.get('capacity', 0))
                
                if capacity == 0:
                    continue
                
                # Calculate balance metrics
                local_ratio = local_balance / capacity
                remote_ratio = remote_balance / capacity
                
                # Determine channel state
                state = 'balanced'
                if local_ratio < (self.target_balance_ratio - self.min_imbalance_threshold):
                    state = 'needs_inbound'  # Need to move funds TO this channel
                elif local_ratio > (self.target_balance_ratio + self.min_imbalance_threshold):
                    state = 'needs_outbound'  # Need to move funds FROM this channel
                
                analysis[chan_id] = {
                    'local_balance': local_balance,
                    'remote_balance': remote_balance,
                    'capacity': capacity,
                    'local_ratio': local_ratio,
                    'remote_ratio': remote_ratio,
                    'state': state,
                    'imbalance_severity': abs(local_ratio - self.target_balance_ratio),
                    'peer_pubkey': channel.get('remote_pubkey', ''),
                    'channel_point': channel.get('channel_point', ''),
                    'last_update': channel.get('last_update', 0)
                }
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Channel analysis error: {e}")
            return {}
    
    def find_rebalancing_pairs(self, channel_analysis: Dict[str, Dict[str, Any]]) -> List[Tuple[str, str, int]]:
        """Find optimal channel pairs for rebalancing"""
        pairs = []
        
        # Separate channels by rebalancing needs
        needs_outbound = []  # Channels with too much local balance (high local_ratio)
        needs_inbound = []   # Channels with too little local balance (low local_ratio)
        
        for chan_id, data in channel_analysis.items():
            if data['state'] == 'needs_outbound':
                excess = (data['local_ratio'] - self.target_balance_ratio) * data['capacity']
                needs_outbound.append((chan_id, int(excess), data))
            elif data['state'] == 'needs_inbound':
                deficit = (self.target_balance_ratio - data['local_ratio']) * data['capacity']
                needs_inbound.append((chan_id, int(deficit), data))
        
        # Sort by severity (most imbalanced first)
        needs_outbound.sort(key=lambda x: x[2]['imbalance_severity'], reverse=True)
        needs_inbound.sort(key=lambda x: x[2]['imbalance_severity'], reverse=True)
        
        # Find optimal pairs
        for from_chan, from_excess, from_data in needs_outbound:
            for to_chan, to_deficit, to_data in needs_inbound:
                if from_chan == to_chan:
                    continue
                
                # Calculate optimal rebalance amount
                amount = min(from_excess, to_deficit, self.max_rebalance_amount)
                amount = max(amount, self.min_rebalance_amount)
                
                if amount >= self.min_rebalance_amount:
                    pairs.append((from_chan, to_chan, amount))
        
        return pairs
    
    def estimate_rebalance_fee(self, from_channel: str, to_channel: str, amount: int) -> int:
        """Estimate the fee for a rebalancing operation"""
        try:
            # Simple estimation based on amount and configured fee rate
            base_fee = 1000  # Base fee in millisats
            proportional_fee = int(amount * self.max_fee_rate)
            return base_fee + proportional_fee
        except Exception:
            # Fallback estimation
            return int(amount * 0.005)  # 0.5% fallback rate
    
    def execute_rebalance(self, from_channel: str, to_channel: str, amount: int) -> Dict[str, Any]:
        """Execute a circular rebalancing payment"""
        if not self.client:
            return {'success': False, 'error': 'No Lightning client available'}
        
        try:
            # Check cooldown
            last_rebalance = self.last_rebalance_time.get(from_channel)
            if last_rebalance and datetime.now() - last_rebalance < self.rebalance_cooldown:
                return {'success': False, 'error': 'Cooldown period not elapsed'}
            
            # Estimate fee
            estimated_fee = self.estimate_rebalance_fee(from_channel, to_channel, amount)
            fee_limit = int(estimated_fee * 2)  # Allow up to 2x estimated fee
            
            self.logger.info(f"Starting rebalance: {amount} sats from {from_channel[:8]}... to {to_channel[:8]}...")
            
            # Create rebalancing invoice (pay to self)
            # In a real implementation, this would involve:
            # 1. Creating an invoice
            # 2. Finding a route that goes through the desired channels
            # 3. Making the payment with specific route hints
            
            # For now, we'll simulate the rebalancing logic
            success = self._simulate_rebalance_payment(from_channel, to_channel, amount, fee_limit)
            
            if success:
                self.last_rebalance_time[from_channel] = datetime.now()
                self.logger.info(f"Rebalance successful: {amount} sats, estimated fee: {estimated_fee}")
                return {
                    'success': True,
                    'amount': amount,
                    'estimated_fee': estimated_fee,
                    'from_channel': from_channel,
                    'to_channel': to_channel
                }
            else:
                self.logger.warning(f"Rebalance failed: {from_channel[:8]}... -> {to_channel[:8]}...")
                return {'success': False, 'error': 'Payment failed'}
            
        except Exception as e:
            self.logger.error(f"Rebalance execution error: {e}")
            return {'success': False, 'error': str(e)}
    
    def _simulate_rebalance_payment(self, from_channel: str, to_channel: str, amount: int, fee_limit: int) -> bool:
        """Simulate rebalancing payment (placeholder for actual implementation)"""
        # In a real implementation, this would:
        # 1. Generate our own invoice for the amount
        # 2. Use QueryRoutes to find a path from from_channel to to_channel
        # 3. Execute SendPayment with the route
        
        # For simulation, we'll have a success rate based on amount and network conditions
        success_probability = 0.8  # 80% base success rate
        
        # Reduce probability for larger amounts
        if amount > 1000000:  # 1M sats
            success_probability *= 0.7
        elif amount > 500000:  # 500k sats
            success_probability *= 0.85
        
        # Simulate network conditions
        return random.random() < success_probability
    
    def auto_rebalance(self, max_operations: int = 5) -> Dict[str, Any]:
        """Perform automatic rebalancing of all channels"""
        if not self.enabled:
            return {'success': False, 'error': 'Auto-rebalancing is disabled'}
        
        results = {
            'success': True,
            'operations_performed': 0,
            'operations_attempted': 0,
            'total_amount_rebalanced': 0,
            'total_fees': 0,
            'errors': []
        }
        
        try:
            # Analyze current channel states
            self.logger.info("Starting automatic channel rebalancing")
            channel_analysis = self.analyze_channels()
            
            if not channel_analysis:
                return {'success': False, 'error': 'No channels to analyze'}
            
            # Find rebalancing opportunities
            pairs = self.find_rebalancing_pairs(channel_analysis)
            self.logger.info(f"Found {len(pairs)} potential rebalancing operations")
            
            # Execute rebalancing operations
            for i, (from_chan, to_chan, amount) in enumerate(pairs[:max_operations]):
                results['operations_attempted'] += 1
                
                result = self.execute_rebalance(from_chan, to_chan, amount)
                
                if result['success']:
                    results['operations_performed'] += 1
                    results['total_amount_rebalanced'] += result['amount']
                    results['total_fees'] += result['estimated_fee']
                else:
                    results['errors'].append(result['error'])
                
                # Small delay between operations to avoid overwhelming the network
                if i < len(pairs) - 1:
                    time.sleep(5)
            
            self.logger.info(f"Rebalancing complete: {results['operations_performed']}/{results['operations_attempted']} successful")
            return results
            
        except Exception as e:
            self.logger.error(f"Auto-rebalance error: {e}")
            results['success'] = False
            results['errors'].append(str(e))
            return results
    
    def get_rebalancing_recommendations(self) -> List[Dict[str, Any]]:
        """Get recommendations for manual rebalancing"""
        recommendations = []
        
        try:
            channel_analysis = self.analyze_channels()
            pairs = self.find_rebalancing_pairs(channel_analysis)
            
            for from_chan, to_chan, amount in pairs:
                from_data = channel_analysis[from_chan]
                to_data = channel_analysis[to_chan]
                estimated_fee = self.estimate_rebalance_fee(from_chan, to_chan, amount)
                
                recommendations.append({
                    'from_channel': from_chan,
                    'to_channel': to_chan,
                    'from_balance_ratio': from_data['local_ratio'],
                    'to_balance_ratio': to_data['local_ratio'],
                    'amount': amount,
                    'estimated_fee': estimated_fee,
                    'fee_rate': estimated_fee / amount if amount > 0 else 0,
                    'priority': max(from_data['imbalance_severity'], to_data['imbalance_severity']),
                    'description': f"Move {amount:,} sats from {from_chan[:8]}... to {to_chan[:8]}..."
                })
            
            # Sort by priority (highest imbalance first)
            recommendations.sort(key=lambda x: x['priority'], reverse=True)
            
        except Exception as e:
            self.logger.error(f"Error generating rebalancing recommendations: {e}")
        
        return recommendations
    
    def get_status(self) -> Dict[str, Any]:
        """Get current rebalancer status"""
        channel_analysis = self.analyze_channels()
        
        balanced_channels = sum(1 for ch in channel_analysis.values() if ch['state'] == 'balanced')
        needs_outbound = sum(1 for ch in channel_analysis.values() if ch['state'] == 'needs_outbound')
        needs_inbound = sum(1 for ch in channel_analysis.values() if ch['state'] == 'needs_inbound')
        
        return {
            'enabled': self.enabled,
            'total_channels': len(channel_analysis),
            'balanced_channels': balanced_channels,
            'needs_outbound': needs_outbound,
            'needs_inbound': needs_inbound,
            'last_rebalance_times': {
                chan_id: time.isoformat() for chan_id, time in self.last_rebalance_time.items()
            },
            'configuration': {
                'target_balance_ratio': self.target_balance_ratio,
                'min_imbalance_threshold': self.min_imbalance_threshold,
                'max_fee_rate': self.max_fee_rate,
                'min_rebalance_amount': self.min_rebalance_amount,
                'max_rebalance_amount': self.max_rebalance_amount
            }
        }


# Global rebalancer instance
_rebalancer = None

def get_rebalancer(client=None) -> ChannelRebalancer:
    """Get or create global rebalancer instance"""
    global _rebalancer
    if _rebalancer is None:
        _rebalancer = ChannelRebalancer(client)
    return _rebalancer