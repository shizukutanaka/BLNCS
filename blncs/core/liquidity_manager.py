"""
Lightweight Liquidity Management for Lightning Network
Practical tools for channel balance optimization.
"""

import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta

from .logger import get_logger
from .config import get_config
from .exceptions import LightningError


@dataclass
class ChannelBalance:
    """チャネル残高情報"""
    channel_id: str
    local_balance: int
    remote_balance: int
    capacity: int
    active: bool
    
    @property
    def local_ratio(self) -> float:
        """ローカル残高比率"""
        return self.local_balance / self.capacity if self.capacity > 0 else 0.0
    
    @property
    def remote_ratio(self) -> float:
        """リモート残高比率"""
        return self.remote_balance / self.capacity if self.capacity > 0 else 0.0
    
    @property
    def needs_rebalancing(self) -> bool:
        """リバランスが必要かどうか"""
        return self.local_ratio < 0.2 or self.local_ratio > 0.8


class LiquidityManager:
    """軽量流動性管理システム"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config()
        
        # 流動性管理設定
        self.min_balance_ratio = self.config.get('channel.min_balance_ratio', 0.2)
        self.max_balance_ratio = self.config.get('channel.max_balance_ratio', 0.8)
        self.target_balance_ratio = 0.5  # 理想的なバランス
        
        # リバランス制限
        self.max_rebalance_amount = self.config.get('liquidity.max_rebalance_amount', 1000000)  # 1M sats
        self.min_rebalance_amount = self.config.get('liquidity.min_rebalance_amount', 10000)   # 10K sats
        
    def analyze_liquidity(self, channels: List[Dict[str, Any]]) -> Dict[str, Any]:
        """流動性状況を分析"""
        channel_balances = []
        total_capacity = 0
        total_local = 0
        total_remote = 0
        unbalanced_channels = 0
        
        for ch in channels:
            balance = ChannelBalance(
                channel_id=ch.get('channel_id', ''),
                local_balance=ch.get('local_balance', 0),
                remote_balance=ch.get('remote_balance', 0),
                capacity=ch.get('capacity', 0),
                active=ch.get('active', False)
            )
            
            if balance.active:
                channel_balances.append(balance)
                total_capacity += balance.capacity
                total_local += balance.local_balance
                total_remote += balance.remote_balance
                
                if balance.needs_rebalancing:
                    unbalanced_channels += 1
        
        overall_balance_ratio = total_local / total_capacity if total_capacity > 0 else 0
        
        return {
            'total_channels': len(channel_balances),
            'unbalanced_channels': unbalanced_channels,
            'total_capacity': total_capacity,
            'total_local_balance': total_local,
            'total_remote_balance': total_remote,
            'overall_balance_ratio': overall_balance_ratio,
            'liquidity_health': self._calculate_liquidity_health(overall_balance_ratio),
            'rebalancing_needed': unbalanced_channels > 0,
            'channel_details': [
                {
                    'channel_id': cb.channel_id,
                    'local_ratio': cb.local_ratio,
                    'remote_ratio': cb.remote_ratio,
                    'needs_rebalancing': cb.needs_rebalancing,
                    'capacity': cb.capacity
                }
                for cb in channel_balances
            ]
        }
    
    def _calculate_liquidity_health(self, balance_ratio: float) -> str:
        """流動性健康度を計算"""
        if 0.4 <= balance_ratio <= 0.6:
            return "excellent"
        elif 0.3 <= balance_ratio <= 0.7:
            return "good"
        elif 0.2 <= balance_ratio <= 0.8:
            return "fair"
        else:
            return "poor"
    
    def suggest_rebalancing(self, channels: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """リバランス提案を生成"""
        analysis = self.analyze_liquidity(channels)
        suggestions = []
        
        for ch_detail in analysis['channel_details']:
            if not ch_detail['needs_rebalancing']:
                continue
            
            suggestion = {
                'channel_id': ch_detail['channel_id'],
                'current_ratio': ch_detail['local_ratio'],
                'target_ratio': self.target_balance_ratio,
                'priority': self._calculate_rebalancing_priority(ch_detail)
            }
            
            if ch_detail['local_ratio'] < self.min_balance_ratio:
                # 流入が必要
                needed_amount = int(ch_detail['capacity'] * self.target_balance_ratio - 
                                  ch_detail['capacity'] * ch_detail['local_ratio'])
                suggestion.update({
                    'action': 'inbound_needed',
                    'amount': min(needed_amount, self.max_rebalance_amount),
                    'description': f"流入が必要: {needed_amount:,} sats"
                })
            else:
                # 流出が必要
                excess_amount = int(ch_detail['capacity'] * ch_detail['local_ratio'] - 
                                  ch_detail['capacity'] * self.target_balance_ratio)
                suggestion.update({
                    'action': 'outbound_needed',
                    'amount': min(excess_amount, self.max_rebalance_amount),
                    'description': f"流出が必要: {excess_amount:,} sats"
                })
            
            if suggestion['amount'] >= self.min_rebalance_amount:
                suggestions.append(suggestion)
        
        # 優先度でソート
        suggestions.sort(key=lambda x: x['priority'], reverse=True)
        return suggestions
    
    def _calculate_rebalancing_priority(self, channel_detail: Dict[str, Any]) -> int:
        """リバランス優先度を計算"""
        ratio = channel_detail['local_ratio']
        capacity = channel_detail['capacity']
        
        # 極端な不均衡ほど高優先度
        imbalance_score = max(abs(ratio - 0.5) * 2, 0)  # 0-1の範囲
        
        # 容量が大きいほど高優先度
        capacity_score = min(capacity / 10000000, 1)  # 10M satsで正規化
        
        return int((imbalance_score * 50) + (capacity_score * 50))
    
    def estimate_rebalancing_cost(self, amount: int, hops: int = 3) -> Dict[str, Any]:
        """リバランス費用を見積もり"""
        base_fee = 1000  # 1 sat base fee
        fee_rate = 500   # 500 ppm (0.05%)
        
        estimated_fee = base_fee + (amount * fee_rate // 1000000)
        
        # ホップ数による調整
        estimated_fee *= hops
        
        return {
            'amount': amount,
            'estimated_fee': estimated_fee,
            'fee_rate_ppm': (estimated_fee * 1000000) // amount if amount > 0 else 0,
            'cost_ratio': estimated_fee / amount if amount > 0 else 0,
            'recommended': estimated_fee < (amount * 0.01)  # 1%以下なら推奨
        }
    
    def get_liquidity_recommendations(self, channels: List[Dict[str, Any]]) -> Dict[str, Any]:
        """流動性改善の推奨事項"""
        analysis = self.analyze_liquidity(channels)
        suggestions = self.suggest_rebalancing(channels)
        
        recommendations = []
        
        if analysis['liquidity_health'] == 'poor':
            recommendations.append("緊急: 流動性の大幅な改善が必要です")
        
        if analysis['unbalanced_channels'] > len(analysis['channel_details']) * 0.5:
            recommendations.append("多数のチャネルでリバランスが必要です")
        
        if analysis['overall_balance_ratio'] < 0.1:
            recommendations.append("流入容量の増加を検討してください")
        elif analysis['overall_balance_ratio'] > 0.9:
            recommendations.append("流出容量の増加を検討してください")
        
        return {
            'analysis': analysis,
            'rebalancing_suggestions': suggestions[:5],  # 上位5件
            'recommendations': recommendations,
            'next_action': self._get_next_action(analysis, suggestions)
        }
    
    def _get_next_action(self, analysis: Dict[str, Any], suggestions: List[Dict[str, Any]]) -> str:
        """次に取るべきアクション"""
        if not suggestions:
            return "流動性は良好です。監視を継続してください。"
        
        priority_suggestion = suggestions[0]
        
        if priority_suggestion['priority'] > 70:
            return f"優先: {priority_suggestion['description']}"
        elif priority_suggestion['priority'] > 40:
            return f"推奨: {priority_suggestion['description']}"
        else:
            return "必要に応じてリバランスを検討してください。"


# Global instance
_liquidity_manager_instance = None

def get_liquidity_manager() -> LiquidityManager:
    """グローバル流動性マネージャー取得"""
    global _liquidity_manager_instance
    if _liquidity_manager_instance is None:
        _liquidity_manager_instance = LiquidityManager()
    return _liquidity_manager_instance