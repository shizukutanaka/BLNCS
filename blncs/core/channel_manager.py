"""
BLNCS チャネル管理モジュール
Lightning Networkチャネルの自動管理と最適化機能。
"""

import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

from .logger import get_logger
from .config import get_config
from .history import record_transaction


@dataclass
class ChannelRecommendation:
    """チャネル推奨アクション"""
    action: str  # 'open', 'close', 'rebalance'
    target: str  # ノードID または チャネルID
    amount: int  # satoshi
    reason: str
    priority: int  # 1=高, 2=中, 3=低


class ChannelManager:
    """Lightning Networkチャネルの自動管理"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config()
        
        # チャネル管理設定
        self.min_channel_size = self.config.get('channel.min_size', 100000)  # 100k sats
        self.max_channel_size = self.config.get('channel.max_size', 16777215)  # max LN
        self.target_channels = self.config.get('channel.target_count', 5)
        self.min_balance_ratio = self.config.get('channel.min_balance_ratio', 0.1)  # 10%
        self.max_balance_ratio = self.config.get('channel.max_balance_ratio', 0.9)  # 90%
        
        # 自動管理フラグ
        self.auto_rebalance = self.config.get('channel.auto_rebalance', False)
        self.auto_close_inactive = self.config.get('channel.auto_close_inactive', False)
        
        # 統計データ
        self.channel_stats = {}
        self.last_analysis = None
    
    def analyze_channels(self, client) -> Dict[str, Any]:
        """チャネル状態を分析"""
        try:
            channels = client.list_channels()
            balance = client.get_balance()
            
            analysis = {
                'timestamp': datetime.now(),
                'total_channels': len(channels),
                'active_channels': len([ch for ch in channels if ch.get('active', False)]),
                'total_capacity': sum(ch.get('capacity', 0) for ch in channels),
                'local_balance': sum(ch.get('local_balance', 0) for ch in channels),
                'remote_balance': sum(ch.get('remote_balance', 0) for ch in channels),
                'wallet_balance': balance.get('total', 0),
                'channels': []
            }
            
            # 各チャネルの詳細分析
            for ch in channels:
                channel_analysis = self._analyze_single_channel(ch)
                analysis['channels'].append(channel_analysis)
            
            # 全体的な健全性スコア
            analysis['health_score'] = self._calculate_health_score(analysis)
            
            # 推奨アクション
            analysis['recommendations'] = self._generate_recommendations(analysis)
            
            self.last_analysis = analysis
            self.logger.info(f"チャネル分析完了: {analysis['total_channels']}チャネル, 健全性: {analysis['health_score']}/100")
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"チャネル分析エラー: {e}")
            return {'error': str(e)}
    
    def _analyze_single_channel(self, channel: Dict[str, Any]) -> Dict[str, Any]:
        """単一チャネルの詳細分析"""
        capacity = channel.get('capacity', 0)
        local_balance = channel.get('local_balance', 0)
        remote_balance = channel.get('remote_balance', 0)
        
        # バランス比率
        local_ratio = local_balance / capacity if capacity > 0 else 0
        remote_ratio = remote_balance / capacity if capacity > 0 else 0
        
        # チャネルの健全性評価
        health_issues = []
        
        if not channel.get('active', False):
            health_issues.append('非アクティブ')
        
        if local_ratio < self.min_balance_ratio:
            health_issues.append('ローカル残高不足')
        elif local_ratio > self.max_balance_ratio:
            health_issues.append('ローカル残高過多')
        
        if capacity < self.min_channel_size:
            health_issues.append('容量不足')
        
        return {
            'channel_id': channel.get('channel_id', ''),
            'capacity': capacity,
            'local_balance': local_balance,
            'remote_balance': remote_balance,
            'local_ratio': local_ratio,
            'remote_ratio': remote_ratio,
            'active': channel.get('active', False),
            'private': channel.get('private', False),
            'remote_pubkey': channel.get('remote_pubkey', ''),
            'health_issues': health_issues,
            'health_score': max(0, 100 - len(health_issues) * 20)
        }
    
    def _calculate_health_score(self, analysis: Dict[str, Any]) -> int:
        """全体的な健全性スコアを計算"""
        if analysis['total_channels'] == 0:
            return 0
        
        score = 100
        
        # アクティブチャネル比率
        if analysis['total_channels'] > 0:
            active_ratio = analysis['active_channels'] / analysis['total_channels']
            if active_ratio < 0.8:
                score -= 20
        
        # チャネル数の適正性
        if analysis['total_channels'] < self.target_channels:
            score -= 10 * (self.target_channels - analysis['total_channels'])
        elif analysis['total_channels'] > self.target_channels * 2:
            score -= 10
        
        # 全体的なバランス
        total_capacity = analysis['total_capacity']
        if total_capacity > 0:
            overall_balance = analysis['local_balance'] / total_capacity
            if overall_balance < 0.3 or overall_balance > 0.7:
                score -= 15
        
        # 個別チャネルの健全性
        if analysis['channels']:
            avg_channel_health = sum(ch['health_score'] for ch in analysis['channels']) / len(analysis['channels'])
            score = int(score * 0.7 + avg_channel_health * 0.3)
        
        return max(0, min(100, score))
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[ChannelRecommendation]:
        """推奨アクションを生成"""
        recommendations = []
        
        # チャネル不足の場合
        if analysis['total_channels'] < self.target_channels:
            recommendations.append(ChannelRecommendation(
                action='open',
                target='new_peer',
                amount=self.min_channel_size,
                reason=f"チャネル数不足 ({analysis['total_channels']}/{self.target_channels})",
                priority=1
            ))
        
        # 個別チャネルの問題
        for ch in analysis['channels']:
            if not ch['active']:
                recommendations.append(ChannelRecommendation(
                    action='close',
                    target=ch['channel_id'],
                    amount=0,
                    reason="非アクティブチャネル",
                    priority=2
                ))
            
            elif ch['local_ratio'] < self.min_balance_ratio:
                recommendations.append(ChannelRecommendation(
                    action='rebalance',
                    target=ch['channel_id'],
                    amount=int(ch['capacity'] * 0.5 - ch['local_balance']),
                    reason=f"ローカル残高不足 ({ch['local_ratio']:.1%})",
                    priority=2
                ))
            
            elif ch['local_ratio'] > self.max_balance_ratio:
                recommendations.append(ChannelRecommendation(
                    action='rebalance',
                    target=ch['channel_id'],
                    amount=int(ch['local_balance'] - ch['capacity'] * 0.5),
                    reason=f"ローカル残高過多 ({ch['local_ratio']:.1%})",
                    priority=3
                ))
        
        # 優先度順にソート
        recommendations.sort(key=lambda x: x.priority)
        
        return recommendations
    
    def execute_recommendation(self, client, recommendation: ChannelRecommendation) -> bool:
        """推奨アクションを実行"""
        try:
            self.logger.info(f"推奨アクション実行: {recommendation.action} - {recommendation.reason}")
            
            if recommendation.action == 'close':
                return self._close_channel(client, recommendation.target, recommendation.reason)
            elif recommendation.action == 'rebalance':
                return self._rebalance_channel(client, recommendation.target, recommendation.amount)
            elif recommendation.action == 'open':
                # 新しいチャネルの場合は推奨ピアを提案
                self.logger.info(f"新しいチャネルの開設を推奨: {recommendation.amount} sats")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"推奨アクション実行エラー: {e}")
            return False
    
    def _close_channel(self, client, channel_id: str, reason: str) -> bool:
        """チャネルを閉じる"""
        try:
            if self.auto_close_inactive:
                result = client.close_channel(channel_id, force=False)
                if result:
                    record_transaction('channel_close', {
                        'channel_id': channel_id,
                        'reason': reason,
                        'automatic': True
                    })
                    self.logger.info(f"チャネル自動クローズ: {channel_id} - {reason}")
                return result
            else:
                self.logger.info(f"チャネルクローズ推奨: {channel_id} - {reason} (自動実行無効)")
                return True
        except Exception as e:
            self.logger.error(f"チャネルクローズエラー: {e}")
            return False
    
    def _rebalance_channel(self, client, channel_id: str, amount: int) -> bool:
        """チャネルをリバランス（簡易実装）"""
        try:
            if self.auto_rebalance:
                # 実際のリバランスは複雑なため、ここでは推奨のみ
                self.logger.info(f"チャネルリバランス推奨: {channel_id} - {amount} sats")
                record_transaction('channel_rebalance_recommended', {
                    'channel_id': channel_id,
                    'amount': amount,
                    'automatic': self.auto_rebalance
                })
                return True
            else:
                self.logger.info(f"チャネルリバランス推奨: {channel_id} - {amount} sats (自動実行無効)")
                return True
        except Exception as e:
            self.logger.error(f"チャネルリバランスエラー: {e}")
            return False
    
    def get_channel_summary(self) -> Dict[str, Any]:
        """チャネルサマリーを取得"""
        if not self.last_analysis:
            return {'status': 'no_analysis'}
        
        analysis = self.last_analysis
        
        return {
            'total_channels': analysis['total_channels'],
            'active_channels': analysis['active_channels'],
            'total_capacity_sats': analysis['total_capacity'],
            'local_balance_sats': analysis['local_balance'],
            'remote_balance_sats': analysis['remote_balance'],
            'health_score': analysis['health_score'],
            'recommendations_count': len(analysis.get('recommendations', [])),
            'last_analysis': analysis['timestamp'].isoformat(),
            'auto_rebalance': self.auto_rebalance,
            'auto_close_inactive': self.auto_close_inactive
        }


# グローバルインスタンス
_global_channel_manager = None

def get_channel_manager() -> ChannelManager:
    """グローバルチャネルマネージャーを取得"""
    global _global_channel_manager
    if _global_channel_manager is None:
        _global_channel_manager = ChannelManager()
    return _global_channel_manager