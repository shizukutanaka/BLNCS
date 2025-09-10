"""
Advanced Channel Management for Lightning Network
Provides comprehensive channel operations and optimization.
"""

import time
import json
import asyncio
from typing import Dict, List, Optional, Any, Tuple, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum

from .client import LightningClient
from ..core.logger import get_logger
from ..core.exceptions import LightningError, ChannelError
from ..core.metrics import get_metrics_collector
from ..core.config_manager import get_config_manager


class ChannelState(Enum):
    """Channel states"""
    OPENING = "opening"
    ACTIVE = "active" 
    INACTIVE = "inactive"
    CLOSING = "closing"
    CLOSED = "closed"
    FORCE_CLOSING = "force_closing"


@dataclass
class ChannelInfo:
    """Enhanced channel information"""
    channel_id: str
    peer_id: str
    capacity: int
    local_balance: int
    remote_balance: int
    state: ChannelState
    is_private: bool = False
    fee_rate: float = 0.0
    base_fee: int = 0
    min_htlc: int = 1000
    max_htlc: int = 0
    csv_delay: int = 144
    created_at: Optional[datetime] = None
    last_update: Optional[datetime] = None
    total_sent: int = 0
    total_received: int = 0
    commitment_fee: int = 0
    unsettled_balance: int = 0
    metrics: Dict[str, Any] = field(default_factory=dict)


@dataclass 
class ChannelRecommendation:
    """Channel optimization recommendation"""
    channel_id: str
    action: str  # "rebalance", "close", "adjust_fees", "increase_capacity"
    priority: str  # "high", "medium", "low"
    reason: str
    expected_benefit: str
    estimated_cost: int = 0
    confidence: float = 0.8


class ChannelManager:
    """Advanced channel management system"""
    
    def __init__(self, client: LightningClient):
        self.client = client
        self.logger = get_logger(__name__)
        self.metrics = get_metrics_collector()
        self.config = get_config_manager().get_all()
        
        # Channel management settings
        self.rebalance_threshold = self.config.get('channel', {}).get('rebalance_threshold', 0.1)
        self.fee_update_interval = self.config.get('channel', {}).get('fee_update_interval', 3600)
        self.monitoring_interval = self.config.get('channel', {}).get('monitoring_interval', 60)
        
        # Internal state
        self.channels_cache: Dict[str, ChannelInfo] = {}
        self.last_update = 0
        self.channel_history: Dict[str, List[Dict]] = {}
        
    def get_all_channels(self, refresh: bool = False) -> List[ChannelInfo]:
        """Get all channels with enhanced information"""
        try:
            if refresh or time.time() - self.last_update > 30:
                self._refresh_channels()
            
            return list(self.channels_cache.values())
            
        except Exception as e:
            self.logger.error(f"Failed to get channels: {e}")
            raise ChannelError(f"Channel retrieval failed: {e}")
    
    def _refresh_channels(self):
        """Refresh channel information from the Lightning node"""
        try:
            # Get basic channel list
            channels_data = self.client.list_channels()
            if not channels_data:
                return
            
            updated_channels = {}
            
            for channel_data in channels_data.get('channels', []):
                channel_id = channel_data.get('chan_id', '')
                if not channel_id:
                    continue
                
                # Convert state
                state_str = channel_data.get('state', 'unknown').lower()
                try:
                    state = ChannelState(state_str)
                except ValueError:
                    state = ChannelState.INACTIVE
                
                # Create enhanced channel info
                channel = ChannelInfo(
                    channel_id=channel_id,
                    peer_id=channel_data.get('remote_pubkey', ''),
                    capacity=int(channel_data.get('capacity', 0)),
                    local_balance=int(channel_data.get('local_balance', 0)),
                    remote_balance=int(channel_data.get('remote_balance', 0)),
                    state=state,
                    is_private=channel_data.get('private', False),
                    commitment_fee=int(channel_data.get('commit_fee', 0)),
                    unsettled_balance=int(channel_data.get('unsettled_balance', 0)),
                    last_update=datetime.now()
                )
                
                # Get additional channel details if available
                try:
                    detailed_info = self.client._make_request(f"channels/{channel_id}")
                    if detailed_info:
                        self._enrich_channel_info(channel, detailed_info)
                except:
                    pass  # Best effort
                
                updated_channels[channel_id] = channel
            
            self.channels_cache = updated_channels
            self.last_update = time.time()
            
            self.logger.info(f"Refreshed {len(updated_channels)} channels")
            
        except Exception as e:
            self.logger.error(f"Failed to refresh channels: {e}")
            raise ChannelError(f"Channel refresh failed: {e}")
    
    def _enrich_channel_info(self, channel: ChannelInfo, detailed_info: Dict[str, Any]):
        """Enrich channel info with additional details"""
        try:
            if 'fee_rate' in detailed_info:
                channel.fee_rate = float(detailed_info['fee_rate'])
            if 'base_fee' in detailed_info:
                channel.base_fee = int(detailed_info['base_fee'])
            if 'min_htlc' in detailed_info:
                channel.min_htlc = int(detailed_info['min_htlc'])
            if 'max_htlc' in detailed_info:
                channel.max_htlc = int(detailed_info['max_htlc'])
            if 'csv_delay' in detailed_info:
                channel.csv_delay = int(detailed_info['csv_delay'])
            
            # Calculate metrics
            if channel.capacity > 0:
                channel.metrics = {
                    'local_ratio': channel.local_balance / channel.capacity,
                    'remote_ratio': channel.remote_balance / channel.capacity,
                    'utilization': (channel.capacity - channel.local_balance - channel.remote_balance) / channel.capacity,
                    'balance_score': abs(0.5 - (channel.local_balance / channel.capacity))
                }
            
        except Exception as e:
            self.logger.warning(f"Failed to enrich channel {channel.channel_id}: {e}")
    
    def get_channel_by_id(self, channel_id: str) -> Optional[ChannelInfo]:
        """Get specific channel by ID"""
        channels = self.get_all_channels()
        return next((ch for ch in channels if ch.channel_id == channel_id), None)
    
    def get_channels_by_peer(self, peer_id: str) -> List[ChannelInfo]:
        """Get all channels with a specific peer"""
        channels = self.get_all_channels()
        return [ch for ch in channels if ch.peer_id == peer_id]
    
    def get_imbalanced_channels(self, threshold: float = None) -> List[ChannelInfo]:
        """Get channels that need rebalancing"""
        if threshold is None:
            threshold = self.rebalance_threshold
        
        channels = self.get_all_channels()
        imbalanced = []
        
        for channel in channels:
            if channel.state != ChannelState.ACTIVE or channel.capacity == 0:
                continue
            
            local_ratio = channel.local_balance / channel.capacity
            
            # Check if severely imbalanced
            if local_ratio < threshold or local_ratio > (1 - threshold):
                imbalanced.append(channel)
        
        return imbalanced
    
    def analyze_channel_performance(self, channel_id: str, days: int = 7) -> Dict[str, Any]:
        """Analyze channel performance over time"""
        try:
            channel = self.get_channel_by_id(channel_id)
            if not channel:
                raise ChannelError(f"Channel {channel_id} not found")
            
            # Get historical data (mock implementation)
            analysis = {
                'channel_id': channel_id,
                'period_days': days,
                'current_state': channel.state.value,
                'capacity_utilization': channel.metrics.get('utilization', 0),
                'balance_score': channel.metrics.get('balance_score', 0),
                'routing_revenue': 0,  # Would calculate from actual routing data
                'routing_failures': 0,
                'rebalance_needed': channel.metrics.get('balance_score', 0) > 0.3,
                'performance_score': 0.75,  # Composite score
                'recommendations': []
            }
            
            # Add recommendations based on analysis
            if analysis['rebalance_needed']:
                analysis['recommendations'].append({
                    'action': 'rebalance',
                    'priority': 'medium',
                    'description': 'Channel shows significant imbalance'
                })
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Channel analysis failed for {channel_id}: {e}")
            raise ChannelError(f"Analysis failed: {e}")
    
    def get_channel_recommendations(self) -> List[ChannelRecommendation]:
        """Get recommendations for channel optimization"""
        recommendations = []
        
        try:
            channels = self.get_all_channels()
            
            for channel in channels:
                if channel.state != ChannelState.ACTIVE:
                    continue
                
                # Check for rebalancing needs
                balance_score = channel.metrics.get('balance_score', 0)
                if balance_score > 0.4:
                    priority = "high" if balance_score > 0.45 else "medium"
                    recommendations.append(ChannelRecommendation(
                        channel_id=channel.channel_id,
                        action="rebalance",
                        priority=priority,
                        reason=f"Channel severely imbalanced (score: {balance_score:.2f})",
                        expected_benefit="Improved routing capacity and revenue",
                        estimated_cost=1000  # Estimated rebalancing cost in sats
                    ))
                
                # Check for low capacity utilization
                utilization = channel.metrics.get('utilization', 0)
                if utilization < 0.1 and channel.capacity > 1000000:  # Large unused channels
                    recommendations.append(ChannelRecommendation(
                        channel_id=channel.channel_id,
                        action="close",
                        priority="low",
                        reason=f"Low utilization ({utilization:.1%}) on large channel",
                        expected_benefit="Free up capital for better opportunities",
                        estimated_cost=channel.commitment_fee
                    ))
                
                # Check fee optimization opportunities
                if channel.fee_rate < 0.0001:  # Very low fees
                    recommendations.append(ChannelRecommendation(
                        channel_id=channel.channel_id,
                        action="adjust_fees",
                        priority="medium",
                        reason="Fees too low, missing revenue opportunity",
                        expected_benefit="Increased routing revenue",
                        estimated_cost=0
                    ))
            
            # Sort by priority
            priority_order = {"high": 0, "medium": 1, "low": 2}
            recommendations.sort(key=lambda x: priority_order.get(x.priority, 3))
            
            return recommendations
            
        except Exception as e:
            self.logger.error(f"Failed to generate recommendations: {e}")
            return []
    
    def open_channel(self, peer_id: str, capacity: int, push_amount: int = 0, 
                    private: bool = False, fee_rate: int = None) -> Dict[str, Any]:
        """Open a new channel"""
        try:
            self.logger.info(f"Opening channel to {peer_id} with capacity {capacity}")
            
            # Prepare channel opening request
            request_data = {
                'node_pubkey': peer_id,
                'local_funding_amount': str(capacity),
                'private': private
            }
            
            if push_amount > 0:
                request_data['push_sat'] = str(push_amount)
            
            if fee_rate:
                request_data['sat_per_byte'] = str(fee_rate)
            
            # Make the request
            result = self.client._make_request('channels', method='POST', data=request_data)
            
            if result:
                self.logger.info(f"Channel opening initiated: {result}")
                # Record metrics
                self.metrics.record_metric('channel.opened', 1, {
                    'peer_id': peer_id,
                    'capacity': capacity,
                    'private': private
                })
            
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to open channel to {peer_id}: {e}")
            raise ChannelError(f"Channel opening failed: {e}")
    
    def close_channel(self, channel_id: str, force: bool = False) -> Dict[str, Any]:
        """Close a channel"""
        try:
            self.logger.info(f"Closing channel {channel_id} (force: {force})")
            
            channel = self.get_channel_by_id(channel_id)
            if not channel:
                raise ChannelError(f"Channel {channel_id} not found")
            
            endpoint = f"channels/{channel_id}"
            if force:
                endpoint += "?force=true"
            
            result = self.client._make_request(endpoint, method='DELETE')
            
            if result:
                self.logger.info(f"Channel closure initiated: {result}")
                # Record metrics
                self.metrics.record_metric('channel.closed', 1, {
                    'channel_id': channel_id,
                    'force': force,
                    'capacity': channel.capacity
                })
            
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to close channel {channel_id}: {e}")
            raise ChannelError(f"Channel closure failed: {e}")
    
    def update_channel_policy(self, channel_id: str, fee_rate: float = None,
                             base_fee: int = None, min_htlc: int = None,
                             max_htlc: int = None) -> Dict[str, Any]:
        """Update channel fee policy"""
        try:
            self.logger.info(f"Updating policy for channel {channel_id}")
            
            update_data = {}
            if fee_rate is not None:
                update_data['fee_rate'] = str(fee_rate)
            if base_fee is not None:
                update_data['base_fee_msat'] = str(base_fee * 1000)
            if min_htlc is not None:
                update_data['min_htlc_msat'] = str(min_htlc * 1000)
            if max_htlc is not None:
                update_data['max_htlc_msat'] = str(max_htlc * 1000)
            
            if not update_data:
                raise ChannelError("No policy updates specified")
            
            update_data['chan_id'] = channel_id
            
            result = self.client._make_request('channels/policy', method='POST', data=update_data)
            
            if result:
                self.logger.info(f"Channel policy updated: {result}")
                # Refresh channel cache
                self._refresh_channels()
            
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to update policy for channel {channel_id}: {e}")
            raise ChannelError(f"Policy update failed: {e}")
    
    def rebalance_channel(self, channel_id: str, amount: int, 
                         max_fee: int = 1000) -> Dict[str, Any]:
        """Rebalance a channel using circular rebalancing"""
        try:
            channel = self.get_channel_by_id(channel_id)
            if not channel:
                raise ChannelError(f"Channel {channel_id} not found")
            
            self.logger.info(f"Rebalancing channel {channel_id} with amount {amount}")
            
            # This would implement circular rebalancing logic
            # For now, return a mock response
            result = {
                'status': 'initiated',
                'channel_id': channel_id,
                'amount': amount,
                'max_fee': max_fee,
                'estimated_time': '5-10 minutes'
            }
            
            # Record metrics
            self.metrics.record_metric('channel.rebalance', 1, {
                'channel_id': channel_id,
                'amount': amount,
                'max_fee': max_fee
            })
            
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to rebalance channel {channel_id}: {e}")
            raise ChannelError(f"Rebalancing failed: {e}")
    
    def get_channel_summary(self) -> Dict[str, Any]:
        """Get comprehensive channel summary"""
        try:
            channels = self.get_all_channels()
            
            total_capacity = sum(ch.capacity for ch in channels)
            total_local = sum(ch.local_balance for ch in channels)
            total_remote = sum(ch.remote_balance for ch in channels)
            
            active_channels = [ch for ch in channels if ch.state == ChannelState.ACTIVE]
            imbalanced_channels = self.get_imbalanced_channels()
            
            summary = {
                'total_channels': len(channels),
                'active_channels': len(active_channels),
                'total_capacity': total_capacity,
                'total_local_balance': total_local,
                'total_remote_balance': total_remote,
                'local_ratio': total_local / total_capacity if total_capacity > 0 else 0,
                'remote_ratio': total_remote / total_capacity if total_capacity > 0 else 0,
                'imbalanced_channels': len(imbalanced_channels),
                'avg_channel_size': total_capacity // len(channels) if channels else 0,
                'channel_states': {},
                'recommendations_count': len(self.get_channel_recommendations())
            }
            
            # Count by state
            for state in ChannelState:
                count = len([ch for ch in channels if ch.state == state])
                if count > 0:
                    summary['channel_states'][state.value] = count
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Failed to generate channel summary: {e}")
            return {}


def get_channel_manager(client: Optional[LightningClient] = None) -> ChannelManager:
    """Get channel manager instance"""
    if client is None:
        from .client import LightningClient
        config = get_config_manager().get_all()
        client = LightningClient(config)
    
    return ChannelManager(client)