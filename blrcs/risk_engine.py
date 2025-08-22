import asyncio
import json
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from enum import Enum
import statistics
import logging

logger = logging.getLogger(__name__)

class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class RiskCategory(Enum):
    LIQUIDITY = "liquidity"
    CREDIT = "credit"
    OPERATIONAL = "operational"
    MARKET = "market"
    COMPLIANCE = "compliance"
    TECHNICAL = "technical"

@dataclass
class RiskFactor:
    id: str
    category: RiskCategory
    name: str
    description: str
    weight: float
    threshold_low: float
    threshold_medium: float
    threshold_high: float
    current_value: float = 0.0
    last_updated: datetime = field(default_factory=datetime.now)

@dataclass
class RiskEvent:
    id: str
    timestamp: datetime
    category: RiskCategory
    level: RiskLevel
    source: str
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    resolved: bool = False
    resolution_timestamp: Optional[datetime] = None

@dataclass
class RiskAssessment:
    timestamp: datetime
    overall_score: float
    level: RiskLevel
    factors: Dict[str, float]
    recommendations: List[str]
    alerts: List[RiskEvent]

class LiquidityRiskCalculator:
    def __init__(self):
        self.min_liquidity_ratio = 0.2
        self.critical_channels_threshold = 0.1
        
    async def calculate_liquidity_risk(self, channels: List[Dict]) -> float:
        """流動性リスクを計算"""
        if not channels:
            return 1.0
        
        total_capacity = sum(ch['capacity'] for ch in channels)
        total_local = sum(ch['local_balance'] for ch in channels)
        total_remote = sum(ch['remote_balance'] for ch in channels)
        
        if total_capacity == 0:
            return 1.0
        
        # 全体の流動性バランス
        liquidity_ratio = min(total_local, total_remote) / total_capacity
        
        # 重要チャネルの分析
        critical_channels = [ch for ch in channels if ch['capacity'] > total_capacity * 0.1]
        critical_risk = 0.0
        
        for channel in critical_channels:
            if channel['capacity'] > 0:
                channel_ratio = min(channel['local_balance'], channel['remote_balance']) / channel['capacity']
                if channel_ratio < self.critical_channels_threshold:
                    critical_risk += 0.3
        
        # チャネル数によるリスク
        channel_count_risk = max(0, (10 - len(channels)) / 10 * 0.2)
        
        # 総合リスクスコア
        base_risk = max(0, (self.min_liquidity_ratio - liquidity_ratio) / self.min_liquidity_ratio)
        total_risk = min(1.0, base_risk + critical_risk + channel_count_risk)
        
        return total_risk

class CreditRiskCalculator:
    def __init__(self):
        self.payment_failure_threshold = 0.1
        self.exposure_limit_ratio = 0.3
        
    async def calculate_credit_risk(self, payment_history: List[Dict], 
                                  peer_exposures: Dict[str, int]) -> float:
        """信用リスクを計算"""
        if not payment_history:
            return 0.5
        
        # 支払い失敗率
        recent_payments = [p for p in payment_history 
                          if p['timestamp'] > datetime.now() - timedelta(days=7)]
        
        if recent_payments:
            failure_rate = sum(1 for p in recent_payments if not p['success']) / len(recent_payments)
        else:
            failure_rate = 0.0
        
        # 集中リスク
        total_exposure = sum(peer_exposures.values())
        if total_exposure > 0:
            max_exposure_ratio = max(peer_exposures.values()) / total_exposure
            concentration_risk = max(0, (max_exposure_ratio - self.exposure_limit_ratio) / (1 - self.exposure_limit_ratio))
        else:
            concentration_risk = 0.0
        
        # カウンターパーティリスク
        counterparty_risk = len([exp for exp in peer_exposures.values() if exp > total_exposure * 0.1]) / max(len(peer_exposures), 1) * 0.3
        
        return min(1.0, failure_rate + concentration_risk + counterparty_risk)

class OperationalRiskCalculator:
    def __init__(self):
        self.uptime_threshold = 0.99
        self.error_rate_threshold = 0.05
        
    async def calculate_operational_risk(self, system_metrics: Dict) -> float:
        """運用リスクを計算"""
        uptime = system_metrics.get('uptime', 1.0)
        error_rate = system_metrics.get('error_rate', 0.0)
        memory_usage = system_metrics.get('memory_usage', 0.0)
        cpu_usage = system_metrics.get('cpu_usage', 0.0)
        
        # アップタイムリスク
        uptime_risk = max(0, (self.uptime_threshold - uptime) / self.uptime_threshold)
        
        # エラー率リスク
        error_risk = min(1.0, error_rate / self.error_rate_threshold)
        
        # リソース使用率リスク
        resource_risk = max(memory_usage, cpu_usage) * 0.5
        
        return min(1.0, uptime_risk + error_risk + resource_risk)

class MarketRiskCalculator:
    def __init__(self):
        self.volatility_threshold = 0.05
        
    async def calculate_market_risk(self, price_data: List[Dict]) -> float:
        """市場リスクを計算"""
        if len(price_data) < 2:
            return 0.3
        
        # 価格変動率を計算
        returns = []
        for i in range(1, len(price_data)):
            prev_price = price_data[i-1]['price']
            curr_price = price_data[i]['price']
            if prev_price > 0:
                returns.append((curr_price - prev_price) / prev_price)
        
        if not returns:
            return 0.3
        
        # ボラティリティ
        volatility = statistics.stdev(returns) if len(returns) > 1 else 0
        
        # 急激な価格変動
        max_change = max(abs(r) for r in returns[-10:]) if returns else 0
        
        volatility_risk = min(1.0, volatility / self.volatility_threshold)
        shock_risk = min(1.0, max_change / 0.1)
        
        return min(1.0, volatility_risk * 0.7 + shock_risk * 0.3)

class RiskEngine:
    def __init__(self, lnd_connector, channel_manager):
        self.lnd_connector = lnd_connector
        self.channel_manager = channel_manager
        self.risk_factors: Dict[str, RiskFactor] = {}
        self.risk_events: List[RiskEvent] = []
        self.assessments_history: List[RiskAssessment] = []
        self.alert_handlers: List[Callable] = []
        
        # リスク計算機
        self.liquidity_calc = LiquidityRiskCalculator()
        self.credit_calc = CreditRiskCalculator()
        self.operational_calc = OperationalRiskCalculator()
        self.market_calc = MarketRiskCalculator()
        
        self.running = False
        self._init_risk_factors()
        
    def _init_risk_factors(self):
        """リスクファクターを初期化"""
        factors = [
            RiskFactor("liquidity_balance", RiskCategory.LIQUIDITY, 
                      "流動性バランス", "チャネルの流動性バランス", 0.3, 0.2, 0.5, 0.8),
            RiskFactor("channel_concentration", RiskCategory.LIQUIDITY,
                      "チャネル集中度", "特定チャネルへの依存度", 0.2, 0.3, 0.6, 0.8),
            RiskFactor("payment_failure_rate", RiskCategory.CREDIT,
                      "支払い失敗率", "最近の支払い失敗率", 0.25, 0.05, 0.1, 0.2),
            RiskFactor("counterparty_exposure", RiskCategory.CREDIT,
                      "カウンターパーティー露出", "取引相手への露出", 0.2, 0.2, 0.4, 0.7),
            RiskFactor("system_uptime", RiskCategory.OPERATIONAL,
                      "システム稼働率", "システムの稼働率", 0.15, 0.99, 0.95, 0.9),
            RiskFactor("error_rate", RiskCategory.OPERATIONAL,
                      "エラー率", "システムエラーの発生率", 0.1, 0.01, 0.05, 0.1),
            RiskFactor("price_volatility", RiskCategory.MARKET,
                      "価格変動性", "ビットコイン価格の変動性", 0.15, 0.02, 0.05, 0.1),
            RiskFactor("network_congestion", RiskCategory.TECHNICAL,
                      "ネットワーク混雑", "Lightningネットワークの混雑度", 0.1, 0.7, 0.85, 0.95)
        ]
        
        for factor in factors:
            self.risk_factors[factor.id] = factor
    
    async def start(self):
        """リスクエンジン開始"""
        self.running = True
        asyncio.create_task(self._continuous_assessment())
        
    async def stop(self):
        """リスクエンジン停止"""
        self.running = False
        
    async def assess_risk(self) -> RiskAssessment:
        """包括的リスク評価"""
        try:
            # データ収集
            channels = await self.lnd_connector.get_channels()
            payment_history = await self._get_payment_history()
            system_metrics = await self._get_system_metrics()
            price_data = await self._get_price_data()
            peer_exposures = await self._calculate_peer_exposures(channels)
            
            # 各リスクカテゴリーの計算
            liquidity_risk = await self.liquidity_calc.calculate_liquidity_risk(channels)
            credit_risk = await self.credit_calc.calculate_credit_risk(payment_history, peer_exposures)
            operational_risk = await self.operational_calc.calculate_operational_risk(system_metrics)
            market_risk = await self.market_calc.calculate_market_risk(price_data)
            
            # リスクファクター更新
            risk_values = {
                'liquidity_balance': liquidity_risk,
                'payment_failure_rate': credit_risk,
                'system_uptime': operational_risk,
                'price_volatility': market_risk
            }
            
            # 加重平均でスコア計算
            weighted_score = 0.0
            total_weight = 0.0
            
            for factor_id, value in risk_values.items():
                if factor_id in self.risk_factors:
                    factor = self.risk_factors[factor_id]
                    factor.current_value = value
                    factor.last_updated = datetime.now()
                    weighted_score += value * factor.weight
                    total_weight += factor.weight
            
            overall_score = weighted_score / total_weight if total_weight > 0 else 0.5
            
            # リスクレベル決定
            if overall_score < 0.3:
                level = RiskLevel.LOW
            elif overall_score < 0.6:
                level = RiskLevel.MEDIUM
            elif overall_score < 0.8:
                level = RiskLevel.HIGH
            else:
                level = RiskLevel.CRITICAL
            
            # 推奨事項生成
            recommendations = await self._generate_recommendations(risk_values, level)
            
            # アラート検出
            alerts = await self._detect_alerts(risk_values)
            
            assessment = RiskAssessment(
                timestamp=datetime.now(),
                overall_score=overall_score,
                level=level,
                factors=risk_values,
                recommendations=recommendations,
                alerts=alerts
            )
            
            self.assessments_history.append(assessment)
            
            # アラートハンドラー実行
            for alert in alerts:
                await self._handle_alert(alert)
            
            return assessment
            
        except Exception as e:
            logger.error(f"Risk assessment failed: {e}")
            return RiskAssessment(
                timestamp=datetime.now(),
                overall_score=0.5,
                level=RiskLevel.MEDIUM,
                factors={},
                recommendations=["システムエラーのため評価不可"],
                alerts=[]
            )
    
    async def _generate_recommendations(self, risk_values: Dict[str, float], 
                                       level: RiskLevel) -> List[str]:
        """リスクレベルに基づく推奨事項生成"""
        recommendations = []
        
        if risk_values.get('liquidity_balance', 0) > 0.6:
            recommendations.append("チャネルリバランスの実行を検討してください")
            recommendations.append("新しいチャネルの開設を検討してください")
        
        if risk_values.get('payment_failure_rate', 0) > 0.5:
            recommendations.append("支払いルートの見直しを行ってください")
            recommendations.append("信頼性の低いピアとのチャネルクローズを検討してください")
        
        if risk_values.get('system_uptime', 0) > 0.7:
            recommendations.append("システムの安定性チェックを実行してください")
            recommendations.append("ハードウェアリソースの増強を検討してください")
        
        if level == RiskLevel.CRITICAL:
            recommendations.append("緊急対応：高リスク状態です。即座に対策を実行してください")
            recommendations.append("新規取引の一時停止を検討してください")
        
        return recommendations
    
    async def _detect_alerts(self, risk_values: Dict[str, float]) -> List[RiskEvent]:
        """アラート検出"""
        alerts = []
        
        for factor_id, value in risk_values.items():
            if factor_id not in self.risk_factors:
                continue
                
            factor = self.risk_factors[factor_id]
            
            if value >= factor.threshold_high:
                alert = RiskEvent(
                    id=f"alert_{factor_id}_{int(datetime.now().timestamp())}",
                    timestamp=datetime.now(),
                    category=factor.category,
                    level=RiskLevel.HIGH,
                    source=factor_id,
                    description=f"{factor.name}が高リスク閾値を超えました: {value:.3f}",
                    metadata={'value': value, 'threshold': factor.threshold_high}
                )
                alerts.append(alert)
        
        return alerts
    
    async def _handle_alert(self, alert: RiskEvent):
        """アラート処理"""
        self.risk_events.append(alert)
        logger.warning(f"Risk alert: {alert.description}")
        
        # 自動対応アクション
        if alert.level == RiskLevel.HIGH and alert.category == RiskCategory.LIQUIDITY:
            await self._auto_rebalance_trigger()
        
        # 外部アラートハンドラー実行
        for handler in self.alert_handlers:
            try:
                await handler(alert)
            except Exception as e:
                logger.error(f"Alert handler failed: {e}")
    
    async def _auto_rebalance_trigger(self):
        """自動リバランス実行"""
        try:
            if hasattr(self.channel_manager, 'rebalance_engine'):
                await self.channel_manager.rebalance_engine.execute_emergency_rebalance()
                logger.info("Emergency rebalance triggered by risk engine")
        except Exception as e:
            logger.error(f"Auto rebalance failed: {e}")
    
    async def _continuous_assessment(self):
        """継続的リスク評価"""
        while self.running:
            try:
                await self.assess_risk()
                await asyncio.sleep(300)  # 5分間隔
            except Exception as e:
                logger.error(f"Continuous assessment error: {e}")
                await asyncio.sleep(60)
    
    async def _get_payment_history(self) -> List[Dict]:
        """支払い履歴取得"""
        try:
            payments = await self.lnd_connector.list_payments()
            return payments.get('payments', [])
        except:
            return []
    
    async def _get_system_metrics(self) -> Dict:
        """システムメトリクス取得"""
        try:
            info = await self.lnd_connector.get_info()
            return {
                'uptime': 0.99,  # プレースホルダー
                'error_rate': 0.01,
                'memory_usage': 0.5,
                'cpu_usage': 0.3
            }
        except:
            return {'uptime': 0.5, 'error_rate': 0.1, 'memory_usage': 0.8, 'cpu_usage': 0.8}
    
    async def _get_price_data(self) -> List[Dict]:
        """価格データ取得"""
        # プレースホルダー実装
        return [
            {'timestamp': datetime.now() - timedelta(hours=i), 'price': 50000 + i * 100}
            for i in range(24)
        ]
    
    async def _calculate_peer_exposures(self, channels: List[Dict]) -> Dict[str, int]:
        """ピア露出計算"""
        exposures = {}
        for channel in channels:
            peer_pubkey = channel.get('remote_pubkey', '')
            if peer_pubkey:
                exposures[peer_pubkey] = exposures.get(peer_pubkey, 0) + channel.get('local_balance', 0)
        return exposures
    
    def add_alert_handler(self, handler: Callable):
        """アラートハンドラー追加"""
        self.alert_handlers.append(handler)
    
    async def get_risk_report(self) -> Dict:
        """リスクレポート生成"""
        if not self.assessments_history:
            return {'error': 'No assessments available'}
        
        latest = self.assessments_history[-1]
        
        return {
            'timestamp': latest.timestamp.isoformat(),
            'overall_risk': {
                'score': latest.overall_score,
                'level': latest.level.value
            },
            'risk_factors': {
                factor_id: {
                    'current_value': factor.current_value,
                    'weight': factor.weight,
                    'level': self._get_factor_level(factor).value
                }
                for factor_id, factor in self.risk_factors.items()
            },
            'active_alerts': len([e for e in self.risk_events if not e.resolved]),
            'recommendations': latest.recommendations
        }
    
    def _get_factor_level(self, factor: RiskFactor) -> RiskLevel:
        """ファクターのリスクレベル判定"""
        if factor.current_value < factor.threshold_low:
            return RiskLevel.LOW
        elif factor.current_value < factor.threshold_medium:
            return RiskLevel.MEDIUM
        elif factor.current_value < factor.threshold_high:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL