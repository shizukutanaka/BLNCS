"""
BLNCS Lightning Channel Manager
Practical channel management for Lightning Network operations
"""

import time
import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path


class ChannelState(Enum):
    """Channel states"""
    OPENING = "opening"
    ACTIVE = "active"
    INACTIVE = "inactive"
    CLOSING = "closing"
    CLOSED = "closed"
    PENDING_CLOSE = "pending_close"


@dataclass
class Channel:
    """Lightning channel data structure"""
    channel_id: str
    remote_pubkey: str
    capacity_sats: int
    local_balance_sats: int
    remote_balance_sats: int
    state: ChannelState
    private: bool
    created_at: float
    updated_at: float
    fee_rate_ppm: int = 1000  # parts per million
    min_htlc_sats: int = 1
    max_htlc_sats: Optional[int] = None
    last_update: Optional[float] = None

    def balance_ratio(self) -> float:
        """Get local balance ratio (0-1)"""
        if self.capacity_sats == 0:
            return 0.0
        return self.local_balance_sats / self.capacity_sats

    def available_capacity(self) -> int:
        """Get available outbound capacity"""
        return max(0, self.local_balance_sats - self.min_htlc_sats)

    def inbound_capacity(self) -> int:
        """Get available inbound capacity"""
        return max(0, self.remote_balance_sats - self.min_htlc_sats)

    def is_balanced(self, threshold: float = 0.2) -> bool:
        """Check if channel is reasonably balanced"""
        ratio = self.balance_ratio()
        return threshold <= ratio <= (1 - threshold)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['state'] = self.state.value
        return data


class ChannelManager:
    """Lightning channel management system"""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)

        self.channels: Dict[str, Channel] = {}
        self.channel_file = self.data_dir / "channels.json"
        self.logger = logging.getLogger("BLNCS_ChannelManager")

        self._load_channels()

    def _load_channels(self):
        """Load channels from storage"""
        if self.channel_file.exists():
            try:
                with open(self.channel_file, 'r') as f:
                    data = json.load(f)
                    for channel_id, channel_data in data.items():
                        # Convert state back to enum
                        channel_data['state'] = ChannelState(channel_data['state'])
                        self.channels[channel_id] = Channel(**channel_data)

                self.logger.info(f"Loaded {len(self.channels)} channels")
            except Exception as e:
                self.logger.error(f"Failed to load channels: {e}")

    def _save_channels(self):
        """Save channels to storage"""
        try:
            data = {channel_id: channel.to_dict() for channel_id, channel in self.channels.items()}
            with open(self.channel_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save channels: {e}")

    def add_channel(self, channel_id: str, remote_pubkey: str, capacity_sats: int,
                   local_balance_sats: int, remote_balance_sats: int,
                   private: bool = False) -> Channel:
        """Add a new channel"""
        current_time = time.time()

        channel = Channel(
            channel_id=channel_id,
            remote_pubkey=remote_pubkey,
            capacity_sats=capacity_sats,
            local_balance_sats=local_balance_sats,
            remote_balance_sats=remote_balance_sats,
            state=ChannelState.ACTIVE,
            private=private,
            created_at=current_time,
            updated_at=current_time
        )

        self.channels[channel_id] = channel
        self._save_channels()

        self.logger.info(f"Added channel: {channel_id[:16]}... capacity: {capacity_sats} sats")
        return channel

    def update_channel_balance(self, channel_id: str, local_balance_sats: int,
                              remote_balance_sats: int) -> bool:
        """Update channel balance"""
        channel = self.channels.get(channel_id)
        if not channel:
            return False

        channel.local_balance_sats = local_balance_sats
        channel.remote_balance_sats = remote_balance_sats
        channel.updated_at = time.time()

        self._save_channels()
        return True

    def set_channel_state(self, channel_id: str, state: ChannelState) -> bool:
        """Set channel state"""
        channel = self.channels.get(channel_id)
        if not channel:
            return False

        channel.state = state
        channel.updated_at = time.time()

        self._save_channels()
        self.logger.info(f"Channel {channel_id[:16]}... state: {state.value}")
        return True

    def close_channel(self, channel_id: str) -> bool:
        """Close a channel"""
        return self.set_channel_state(channel_id, ChannelState.CLOSING)

    def get_channel(self, channel_id: str) -> Optional[Channel]:
        """Get channel by ID"""
        return self.channels.get(channel_id)

    def list_channels(self, state: Optional[ChannelState] = None,
                     active_only: bool = False) -> List[Channel]:
        """List channels with optional filters"""
        channels = list(self.channels.values())

        if state:
            channels = [ch for ch in channels if ch.state == state]

        if active_only:
            channels = [ch for ch in channels if ch.state == ChannelState.ACTIVE]

        # Sort by capacity (largest first)
        channels.sort(key=lambda x: x.capacity_sats, reverse=True)

        return channels

    def get_total_capacity(self, active_only: bool = True) -> Dict[str, int]:
        """Get total capacity statistics"""
        channels = self.list_channels(active_only=active_only)

        total_capacity = sum(ch.capacity_sats for ch in channels)
        local_balance = sum(ch.local_balance_sats for ch in channels)
        remote_balance = sum(ch.remote_balance_sats for ch in channels)

        return {
            "total_capacity_sats": total_capacity,
            "local_balance_sats": local_balance,
            "remote_balance_sats": remote_balance,
            "outbound_capacity_sats": sum(ch.available_capacity() for ch in channels),
            "inbound_capacity_sats": sum(ch.inbound_capacity() for ch in channels),
            "channel_count": len(channels)
        }

    def get_unbalanced_channels(self, threshold: float = 0.2) -> List[Channel]:
        """Get channels that need rebalancing"""
        active_channels = self.list_channels(active_only=True)
        return [ch for ch in active_channels if not ch.is_balanced(threshold)]

    def suggest_rebalancing(self) -> List[Dict[str, Any]]:
        """Suggest rebalancing operations"""
        unbalanced = self.get_unbalanced_channels()
        suggestions = []

        for channel in unbalanced:
            ratio = channel.balance_ratio()

            if ratio < 0.2:  # Too much remote balance
                suggestions.append({
                    "channel_id": channel.channel_id,
                    "type": "receive",
                    "reason": "Low local balance",
                    "local_ratio": ratio,
                    "suggested_amount_sats": int(channel.capacity_sats * 0.3 - channel.local_balance_sats)
                })
            elif ratio > 0.8:  # Too much local balance
                suggestions.append({
                    "channel_id": channel.channel_id,
                    "type": "send",
                    "reason": "High local balance",
                    "local_ratio": ratio,
                    "suggested_amount_sats": int(channel.local_balance_sats - channel.capacity_sats * 0.7)
                })

        return suggestions

    def find_route_capacity(self, amount_sats: int) -> List[Channel]:
        """Find channels that can route the specified amount"""
        active_channels = self.list_channels(active_only=True)
        suitable_channels = []

        for channel in active_channels:
            if channel.available_capacity() >= amount_sats:
                suitable_channels.append(channel)

        # Sort by available capacity (highest first)
        suitable_channels.sort(key=lambda x: x.available_capacity(), reverse=True)

        return suitable_channels

    def get_channel_stats(self) -> Dict[str, Any]:
        """Get comprehensive channel statistics"""
        all_channels = list(self.channels.values())
        active_channels = self.list_channels(active_only=True)

        if not all_channels:
            return {"total_channels": 0}

        # State distribution
        state_counts = {}
        for channel in all_channels:
            state = channel.state.value
            state_counts[state] = state_counts.get(state, 0) + 1

        # Balance analysis
        balanced_channels = [ch for ch in active_channels if ch.is_balanced()]
        avg_balance_ratio = sum(ch.balance_ratio() for ch in active_channels) / len(active_channels) if active_channels else 0

        capacity_stats = self.get_total_capacity()

        return {
            "total_channels": len(all_channels),
            "active_channels": len(active_channels),
            "state_distribution": state_counts,
            "balanced_channels": len(balanced_channels),
            "avg_balance_ratio": avg_balance_ratio,
            "capacity_stats": capacity_stats,
            "rebalancing_needed": len(self.get_unbalanced_channels())
        }

    def cleanup_closed_channels(self, older_than_days: int = 30) -> int:
        """Remove old closed channels"""
        cutoff_time = time.time() - (older_than_days * 24 * 3600)
        removed_count = 0

        closed_channels = [
            channel_id for channel_id, channel in self.channels.items()
            if channel.state == ChannelState.CLOSED and channel.updated_at < cutoff_time
        ]

        for channel_id in closed_channels:
            del self.channels[channel_id]
            removed_count += 1

        if removed_count > 0:
            self._save_channels()
            self.logger.info(f"Cleaned up {removed_count} old closed channels")

        return removed_count


def create_channel_manager(data_dir: str = "data") -> ChannelManager:
    """Create channel manager instance"""
    return ChannelManager(data_dir)


if __name__ == "__main__":
    # Test channel manager
    print("⚡ Testing Lightning Channel Manager...")

    manager = create_channel_manager("test_data")

    # Add test channels
    channel1 = manager.add_channel(
        channel_id="123456789012345678901234567890123456789012345678901234567890abcd",
        remote_pubkey="0234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12",
        capacity_sats=1000000,  # 1M sats
        local_balance_sats=800000,  # 80% local
        remote_balance_sats=200000  # 20% remote
    )

    channel2 = manager.add_channel(
        channel_id="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        remote_pubkey="0567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234",
        capacity_sats=500000,  # 500k sats
        local_balance_sats=100000,  # 20% local
        remote_balance_sats=400000  # 80% remote
    )

    print(f"✅ Created {len(manager.channels)} channels")

    # Test capacity stats
    capacity = manager.get_total_capacity()
    print(f"📊 Total capacity: {capacity['total_capacity_sats']} sats")
    print(f"💰 Local balance: {capacity['local_balance_sats']} sats")

    # Test rebalancing suggestions
    suggestions = manager.suggest_rebalancing()
    print(f"⚖️ Rebalancing suggestions: {len(suggestions)}")

    for suggestion in suggestions:
        print(f"  - {suggestion['type']}: {suggestion['suggested_amount_sats']} sats")

    # Test routing capacity
    route_channels = manager.find_route_capacity(50000)
    print(f"🛣️ Channels for 50k sats: {len(route_channels)}")

    # Get comprehensive stats
    stats = manager.get_channel_stats()
    print(f"📈 Channel stats: {stats['total_channels']} total, {stats['active_channels']} active")

    # Cleanup
    import shutil
    shutil.rmtree("test_data", ignore_errors=True)

    print("✅ Channel manager test completed!")