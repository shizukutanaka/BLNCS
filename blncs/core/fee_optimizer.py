"""
BLNCS 手数料最適化モジュール
Lightning NetworkとOn-chainトランザクションの手数料最適化。
"""

import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

from .logger import get_logger
from .config import get_config
from .cache import get_cache


@dataclass
class FeeRecommendation:
    """手数料推奨"""
    fee_rate: int  # sat/vbyte for on-chain, ppm for lightning
    confirmation_time: str  # 'fast', 'medium', 'slow'
    estimated_cost: int  # satoshi
    network: str  # 'lightning', 'onchain'


class FeeOptimizer:
    """手数料最適化管理"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config()
        self.cache = get_cache()
        
        # 手数料設定
        self.default_target_conf = self.config.get('fees.target_confirmation', 6)
        self.max_fee_rate = self.config.get('fees.max_fee_rate', 100)  # sat/vbyte
        self.min_fee_rate = self.config.get('fees.min_fee_rate', 1)   # sat/vbyte
        
        # Lightning手数料設定
        self.default_ln_fee_ppm = self.config.get('fees.lightning_fee_ppm', 1000)  # 0.1%
        self.max_ln_fee_ppm = self.config.get('fees.max_lightning_fee_ppm', 5000)  # 0.5%
        
        # 手数料履歴
        self.fee_history = []
        self.max_history = 100
    
    def get_onchain_fee_recommendation(self, priority: str = 'medium', tx_size: int = 250) -> FeeRecommendation:
        """On-chain手数料推奨を取得"""
        # キャッシュチェック
        cache_key = f"onchain_fees_{priority}"
        cached = self.cache.get(cache_key)
        if cached:
            return FeeRecommendation(**cached)
        
        try:
            # 簡易的な手数料計算（実際のmempoolAPIを使用する場合はここを拡張）
            base_rates = {
                'fast': 20,    # 1-2 blocks
                'medium': 10,  # 3-6 blocks  
                'slow': 3      # 6+ blocks
            }
            
            fee_rate = base_rates.get(priority, 10)
            
            # 最大・最小制限
            fee_rate = max(self.min_fee_rate, min(self.max_fee_rate, fee_rate))
            
            estimated_cost = fee_rate * tx_size
            
            # 確認時間の推定
            conf_times = {
                'fast': '10-20分',
                'medium': '30-60分', 
                'slow': '1-3時間'
            }
            
            recommendation = FeeRecommendation(
                fee_rate=fee_rate,
                confirmation_time=conf_times.get(priority, '30-60分'),
                estimated_cost=estimated_cost,
                network='onchain'
            )
            
            # キャッシュに保存（5分間）
            self.cache.set(cache_key, {
                'fee_rate': recommendation.fee_rate,
                'confirmation_time': recommendation.confirmation_time,
                'estimated_cost': recommendation.estimated_cost,
                'network': recommendation.network
            }, 300)
            
            self.logger.debug(f"On-chain手数料推奨: {fee_rate} sat/vbyte ({priority})")
            
            return recommendation
            
        except Exception as e:
            self.logger.error(f"On-chain手数料計算エラー: {e}")
            # フォールバック
            return FeeRecommendation(
                fee_rate=10,
                confirmation_time='不明',
                estimated_cost=tx_size * 10,
                network='onchain'
            )
    
    def get_lightning_fee_recommendation(self, amount: int, route_hints: Optional[List] = None) -> FeeRecommendation:
        """Lightning Network手数料推奨を取得"""
        try:
            # 基本手数料計算（amount * ppm / 1000000）
            base_fee_ppm = self.default_ln_fee_ppm
            
            # 金額ベースの調整
            if amount > 1000000:  # 1M sats以上
                base_fee_ppm = max(500, base_fee_ppm // 2)  # 手数料を下げる
            elif amount < 10000:  # 10k sats以下
                base_fee_ppm = min(self.max_ln_fee_ppm, base_fee_ppm * 2)  # 手数料を上げる
            
            estimated_fee = int(amount * base_fee_ppm / 1000000)
            
            # 最小手数料（1 sat）
            estimated_fee = max(1, estimated_fee)
            
            recommendation = FeeRecommendation(
                fee_rate=base_fee_ppm,
                confirmation_time='即座',
                estimated_cost=estimated_fee,
                network='lightning'
            )
            
            self.logger.debug(f"Lightning手数料推奨: {base_fee_ppm} ppm ({estimated_fee} sats)")
            
            return recommendation
            
        except Exception as e:
            self.logger.error(f"Lightning手数料計算エラー: {e}")
            # フォールバック
            return FeeRecommendation(
                fee_rate=1000,
                confirmation_time='即座',
                estimated_cost=max(1, amount // 1000),
                network='lightning'
            )
    
    def optimize_payment_method(self, amount: int, urgent: bool = False) -> Dict[str, Any]:
        """最適な支払い方法を推奨"""
        try:
            # Lightning推奨を取得
            ln_rec = self.get_lightning_fee_recommendation(amount)
            
            # On-chain推奨を取得
            priority = 'fast' if urgent else 'medium'
            onchain_rec = self.get_onchain_fee_recommendation(priority)
            
            # コスト比較
            ln_cost = ln_rec.estimated_cost
            onchain_cost = onchain_rec.estimated_cost
            
            # 推奨決定
            if ln_cost < onchain_cost * 0.1:  # Lightning が10倍以上安い
                recommended = 'lightning'
                savings = onchain_cost - ln_cost
                reason = f"Lightning が {savings} sats 節約"
            elif amount < 100000 and not urgent:  # 小額かつ非緊急
                recommended = 'lightning'
                reason = "小額支払いに最適"
            elif urgent:
                if ln_cost < onchain_cost:
                    recommended = 'lightning'
                    reason = "即座確認 + 低手数料"
                else:
                    recommended = 'onchain'
                    reason = "確実な確認"
            else:
                # デフォルトはコスト比較
                if ln_cost <= onchain_cost:
                    recommended = 'lightning'
                    reason = f"手数料 {onchain_cost - ln_cost} sats 節約"
                else:
                    recommended = 'onchain'
                    reason = "On-chainがより経済的"
            
            return {
                'recommended_method': recommended,
                'reason': reason,
                'lightning_fee': ln_cost,
                'onchain_fee': onchain_cost,
                'savings': abs(onchain_cost - ln_cost) if recommended == 'lightning' else 0,
                'lightning_confirmation': ln_rec.confirmation_time,
                'onchain_confirmation': onchain_rec.confirmation_time
            }
            
        except Exception as e:
            self.logger.error(f"支払い方法最適化エラー: {e}")
            return {
                'recommended_method': 'lightning',
                'reason': 'デフォルト推奨',
                'error': str(e)
            }
    
    def record_fee_usage(self, network: str, amount: int, fee_paid: int, success: bool):
        """手数料使用履歴を記録"""
        try:
            record = {
                'timestamp': datetime.now(),
                'network': network,
                'amount': amount,
                'fee_paid': fee_paid,
                'fee_rate': (fee_paid * 1000000 // amount) if amount > 0 else 0,  # ppm
                'success': success
            }
            
            self.fee_history.append(record)
            
            # 履歴サイズ制限
            if len(self.fee_history) > self.max_history:
                self.fee_history = self.fee_history[-self.max_history:]
            
            self.logger.debug(f"手数料履歴記録: {network} - {fee_paid} sats")
            
        except Exception as e:
            self.logger.error(f"手数料履歴記録エラー: {e}")
    
    def get_fee_statistics(self, days: int = 7) -> Dict[str, Any]:
        """手数料統計を取得"""
        try:
            cutoff_time = datetime.now() - timedelta(days=days)
            recent_fees = [f for f in self.fee_history if f['timestamp'] >= cutoff_time]
            
            if not recent_fees:
                return {'status': 'no_data'}
            
            # Lightning統計
            ln_fees = [f for f in recent_fees if f['network'] == 'lightning' and f['success']]
            onchain_fees = [f for f in recent_fees if f['network'] == 'onchain' and f['success']]
            
            stats = {
                'period_days': days,
                'total_transactions': len(recent_fees),
                'successful_transactions': len([f for f in recent_fees if f['success']]),
                'total_fees_paid': sum(f['fee_paid'] for f in recent_fees if f['success']),
            }
            
            # Lightning統計
            if ln_fees:
                ln_total = sum(f['fee_paid'] for f in ln_fees)
                ln_avg = ln_total / len(ln_fees)
                ln_amount_total = sum(f['amount'] for f in ln_fees)
                ln_avg_rate = (ln_total * 1000000 // ln_amount_total) if ln_amount_total > 0 else 0
                
                stats['lightning'] = {
                    'transactions': len(ln_fees),
                    'total_fees': ln_total,
                    'average_fee': int(ln_avg),
                    'average_rate_ppm': ln_avg_rate
                }
            
            # On-chain統計
            if onchain_fees:
                oc_total = sum(f['fee_paid'] for f in onchain_fees)
                oc_avg = oc_total / len(onchain_fees)
                
                stats['onchain'] = {
                    'transactions': len(onchain_fees),
                    'total_fees': oc_total,
                    'average_fee': int(oc_avg)
                }
            
            # 比較
            if ln_fees and onchain_fees:
                ln_avg_fee = stats['lightning']['average_fee']
                oc_avg_fee = stats['onchain']['average_fee']
                stats['comparison'] = {
                    'lightning_cheaper': ln_avg_fee < oc_avg_fee,
                    'savings_per_tx': abs(oc_avg_fee - ln_avg_fee)
                }
            
            return stats
            
        except Exception as e:
            self.logger.error(f"手数料統計エラー: {e}")
            return {'error': str(e)}


# グローバルインスタンス
_global_fee_optimizer = None

def get_fee_optimizer() -> FeeOptimizer:
    """グローバル手数料オプティマイザーを取得"""
    global _global_fee_optimizer
    if _global_fee_optimizer is None:
        _global_fee_optimizer = FeeOptimizer()
    return _global_fee_optimizer