#!/usr/bin/env python3
"""
Lightning Network Helper Utilities
Practical utilities for Lightning Network operations and management.
"""

import json
import time
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta


def format_channel_id(channel_id: str, short: bool = False) -> str:
    """Format channel ID for display"""
    if not channel_id:
        return "Unknown"
    
    if short:
        return f"{channel_id[:8]}...{channel_id[-8:]}"
    return channel_id


def calculate_channel_balance_percentage(local_balance: int, capacity: int) -> float:
    """Calculate channel balance as percentage"""
    if capacity == 0:
        return 0.0
    return (local_balance / capacity) * 100


def format_satoshis(sats: int, unit: str = "sats") -> str:
    """Format satoshis with commas and unit"""
    if sats >= 100_000_000:  # >= 1 BTC
        btc = sats / 100_000_000
        return f"{btc:.8f} BTC ({sats:,} sats)"
    elif sats >= 1_000:
        return f"{sats:,} {unit}"
    else:
        return f"{sats} {unit}"


def calculate_channel_health_score(channel: Dict[str, Any]) -> Tuple[int, str]:
    """Calculate health score for a channel (0-100)"""
    score = 100
    issues = []
    
    # Check if active
    if not channel.get('active', False):
        score -= 50
        issues.append("Inactive")
    
    # Check balance distribution
    local_balance = channel.get('local_balance', 0)
    capacity = channel.get('capacity', 1)
    balance_pct = calculate_channel_balance_percentage(local_balance, capacity)
    
    if balance_pct < 10 or balance_pct > 90:
        score -= 20
        issues.append("Unbalanced")
    
    # Check capacity size
    if capacity < 100_000:  # Less than 100k sats
        score -= 10
        issues.append("Small capacity")
    
    # Check for recent activity (if available)
    last_update = channel.get('last_update', 0)
    if last_update > 0:
        days_since_update = (time.time() - last_update) / (24 * 3600)
        if days_since_update > 30:
            score -= 10
            issues.append("Inactive for 30+ days")
    
    return max(0, score), ", ".join(issues) if issues else "Healthy"


def recommend_channel_actions(channels: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Generate recommendations for channel management"""
    recommendations = []
    
    if not channels:
        recommendations.append({
            "action": "Open first channel",
            "reason": "No channels found",
            "priority": "high"
        })
        return recommendations
    
    active_channels = [ch for ch in channels if ch.get('active', False)]
    total_capacity = sum(ch.get('capacity', 0) for ch in active_channels)
    total_local = sum(ch.get('local_balance', 0) for ch in active_channels)
    
    # Check overall balance
    if total_capacity > 0:
        overall_balance_pct = (total_local / total_capacity) * 100
        
        if overall_balance_pct < 20:
            recommendations.append({
                "action": "Rebalance channels",
                "reason": f"Only {overall_balance_pct:.1f}% local balance",
                "priority": "medium"
            })
    
    # Check for inactive channels
    inactive_count = len(channels) - len(active_channels)
    if inactive_count > 0:
        recommendations.append({
            "action": "Check inactive channels",
            "reason": f"{inactive_count} inactive channels detected",
            "priority": "medium"
        })
    
    # Check for very small channels
    small_channels = [ch for ch in channels if ch.get('capacity', 0) < 50_000]
    if small_channels:
        recommendations.append({
            "action": "Consider consolidating small channels",
            "reason": f"{len(small_channels)} channels with <50k sats capacity",
            "priority": "low"
        })
    
    return recommendations


def estimate_routing_fee(amount_sats: int, hop_count: int = 2) -> Dict[str, Any]:
    """Estimate routing fees for Lightning payment"""
    # Base fee per hop (typical values)
    base_fee = 1000  # 1000 msat = 1 sat
    fee_rate_ppm = 1000  # 1000 ppm = 0.1%
    
    # Calculate fee per hop
    proportional_fee = (amount_sats * fee_rate_ppm) / 1_000_000
    total_fee_per_hop = base_fee + proportional_fee
    
    # Total for all hops
    total_fee_sats = (total_fee_per_hop * hop_count) / 1000  # Convert msat to sat
    
    return {
        "amount_sats": amount_sats,
        "estimated_fee_sats": int(total_fee_sats),
        "hop_count": hop_count,
        "fee_percentage": (total_fee_sats / amount_sats) * 100 if amount_sats > 0 else 0
    }


def generate_payment_hash() -> Tuple[str, str]:
    """Generate a random payment hash and preimage"""
    # Generate random preimage (32 bytes)
    import os
    preimage = os.urandom(32)
    
    # Calculate payment hash (SHA256 of preimage)
    payment_hash = hashlib.sha256(preimage).digest()
    
    return preimage.hex(), payment_hash.hex()


def check_node_connectivity(node_info: Dict[str, Any]) -> Dict[str, Any]:
    """Check node connectivity status"""
    status = {
        "chain_synced": node_info.get('synced_to_chain', False),
        "graph_synced": node_info.get('synced_to_graph', False),
        "peer_count": node_info.get('num_peers', 0),
        "channel_count": node_info.get('num_channels', 0),
        "block_height": node_info.get('block_height', 0),
        "overall_status": "unknown"
    }
    
    # Determine overall status
    if status['chain_synced'] and status['graph_synced'] and status['peer_count'] > 0:
        status['overall_status'] = "healthy"
    elif status['chain_synced'] and status['peer_count'] > 0:
        status['overall_status'] = "partial"
    else:
        status['overall_status'] = "offline"
    
    return status


def format_node_connectivity_report(connectivity: Dict[str, Any]) -> str:
    """Format node connectivity report for display"""
    output = []
    output.append("Node Connectivity Report")
    output.append("=" * 40)
    
    # Overall status
    status_icons = {
        "healthy": "[OK]",
        "partial": "[WARNING]", 
        "offline": "[ERROR]",
        "unknown": "[?]"
    }
    
    overall_status = connectivity['overall_status']
    icon = status_icons.get(overall_status, "[?]")
    output.append(f"Status: {icon} {overall_status.title()}")
    output.append("")
    
    # Details
    output.append("Synchronization:")
    output.append(f"  Chain: {'[OK]' if connectivity['chain_synced'] else '[ERROR]'}")
    output.append(f"  Graph: {'[OK]' if connectivity['graph_synced'] else '[ERROR]'}")
    output.append("")
    
    output.append("Network:")
    output.append(f"  Peers: {connectivity['peer_count']}")
    output.append(f"  Channels: {connectivity['channel_count']}")
    output.append(f"  Block Height: {connectivity['block_height']:,}")
    
    return "\n".join(output)


def analyze_payment_failure(error_message: str) -> Dict[str, str]:
    """Analyze payment failure and suggest solutions"""
    error_lower = error_message.lower()
    
    analysis = {
        "category": "unknown",
        "description": "Unknown payment failure",
        "suggestion": "Check Lightning node logs for details"
    }
    
    if "insufficient" in error_lower and "balance" in error_lower:
        analysis.update({
            "category": "insufficient_balance",
            "description": "Not enough local balance in channels",
            "suggestion": "Add funds to channels or rebalance existing channels"
        })
    
    elif "no route" in error_lower or "route not found" in error_lower:
        analysis.update({
            "category": "routing_failure", 
            "description": "No route found to destination",
            "suggestion": "Open more channels or wait for network graph updates"
        })
    
    elif "timeout" in error_lower:
        analysis.update({
            "category": "timeout",
            "description": "Payment attempt timed out",
            "suggestion": "Try again with higher fee or different route"
        })
    
    elif "fee" in error_lower and "insufficient" in error_lower:
        analysis.update({
            "category": "insufficient_fees",
            "description": "Routing fees too low",
            "suggestion": "Increase fee limit and retry payment"
        })
    
    return analysis


if __name__ == "__main__":
    # Demo usage
    print("Lightning Network Helper Utilities")
    print("=" * 40)
    
    # Demo channel health scoring
    demo_channel = {
        "channel_id": "123456789012345678",
        "capacity": 1000000,
        "local_balance": 800000,
        "active": True,
        "last_update": time.time() - 86400  # 1 day ago
    }
    
    score, issues = calculate_channel_health_score(demo_channel)
    print(f"Demo channel health score: {score}/100")
    if issues != "Healthy":
        print(f"Issues: {issues}")
    
    # Demo fee estimation
    fee_estimate = estimate_routing_fee(100000, 3)
    print(f"Routing 100k sats via 3 hops: ~{fee_estimate['estimated_fee_sats']} sats ({fee_estimate['fee_percentage']:.3f}%)")