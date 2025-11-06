"""
Sample Analytics Plugin: Transaction Analyzer
Analyzes Lightning Network transaction patterns and provides insights.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
import json

from blncs.core.plugin_system import AnalyticsPlugin, PluginMetadata, PluginType


@dataclass
class TransactionPattern:
    """Represents a detected transaction pattern"""
    pattern_type: str
    frequency: int
    avg_amount: float
    time_range: str
    confidence: float


class TransactionAnalyzerPlugin(AnalyticsPlugin):
    """
    Advanced transaction pattern analysis plugin.
    Identifies recurring patterns, unusual activities, and optimization opportunities.
    """
    
    def __init__(self):
        super().__init__()
        self.metadata = PluginMetadata(
            plugin_id="transaction_analyzer",
            name="Transaction Analyzer",
            version="1.0.0",
            description="Advanced Lightning Network transaction pattern analysis",
            author="BLNCS Team",
            plugin_type=PluginType.ANALYTICS,
            dependencies=[],
            api_version="1.0.0",
            entry_point="Plugin",
            config_schema={},
            permissions=[]
        )
        
        # Analysis state
        self.transaction_history: List[Dict] = []
        self.patterns: List[TransactionPattern] = []
        self.analysis_cache = {}
        
    def analyze_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze transaction data and identify patterns"""
        try:
            if data.get('type') == 'transaction':
                self.transaction_history.append({
                    'timestamp': datetime.now().isoformat(),
                    'amount': data.get('amount', 0),
                    'fee': data.get('fee', 0),
                    'route_length': data.get('route_length', 0),
                    'success': data.get('success', True),
                    'node_id': data.get('node_id', ''),
                    'channel_id': data.get('channel_id', '')
                })
                
                # Keep only last 1000 transactions
                if len(self.transaction_history) > 1000:
                    self.transaction_history = self.transaction_history[-1000:]
            
            # Perform pattern analysis
            patterns = self._detect_patterns()
            insights = self._generate_insights(patterns)
            
            return {
                'plugin': self.metadata.name,
                'analysis_type': 'transaction_patterns',
                'timestamp': datetime.now().isoformat(),
                'patterns_detected': len(patterns),
                'patterns': [self._pattern_to_dict(p) for p in patterns],
                'insights': insights,
                'transaction_count': len(self.transaction_history),
                'success_rate': self._calculate_success_rate()
            }
            
        except Exception as e:
            self.logger.error(f"Transaction analysis failed: {e}")
            return {'error': str(e), 'plugin': self.metadata.name}
    
    def generate_report(self, timeframe: str = "24h") -> Dict[str, Any]:
        """Generate comprehensive transaction analysis report"""
        try:
            cutoff_time = self._get_cutoff_time(timeframe)
            recent_transactions = [
                tx for tx in self.transaction_history 
                if datetime.fromisoformat(tx['timestamp']) > cutoff_time
            ]
            
            if not recent_transactions:
                return {
                    'plugin': self.metadata.name,
                    'report_type': 'transaction_analysis',
                    'timeframe': timeframe,
                    'message': 'No transactions in specified timeframe'
                }
            
            # Analyze recent transactions
            total_volume = sum(tx['amount'] for tx in recent_transactions)
            total_fees = sum(tx['fee'] for tx in recent_transactions)
            avg_amount = total_volume / len(recent_transactions)
            avg_fee_rate = (total_fees / total_volume * 100) if total_volume > 0 else 0
            
            # Detect anomalies
            anomalies = self._detect_anomalies(recent_transactions)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(recent_transactions)
            
            return {
                'plugin': self.metadata.name,
                'report_type': 'transaction_analysis',
                'timeframe': timeframe,
                'timestamp': datetime.now().isoformat(),
                'summary': {
                    'transaction_count': len(recent_transactions),
                    'total_volume': total_volume,
                    'total_fees': total_fees,
                    'average_amount': avg_amount,
                    'average_fee_rate': avg_fee_rate,
                    'success_rate': sum(1 for tx in recent_transactions if tx['success']) / len(recent_transactions)
                },
                'patterns': [self._pattern_to_dict(p) for p in self.patterns],
                'anomalies': anomalies,
                'recommendations': recommendations
            }
            
        except Exception as e:
            self.logger.error(f"Report generation failed: {e}")
            return {'error': str(e), 'plugin': self.metadata.name}
    
    def _detect_patterns(self) -> List[TransactionPattern]:
        """Detect recurring transaction patterns"""
        if len(self.transaction_history) < 10:
            return []
        
        patterns = []
        
        try:
            # Pattern 1: Regular small payments
            small_payments = [tx for tx in self.transaction_history if tx['amount'] < 10000]  # < 0.1 BTC in sats
            if len(small_payments) > len(self.transaction_history) * 0.6:
                patterns.append(TransactionPattern(
                    pattern_type="frequent_small_payments",
                    frequency=len(small_payments),
                    avg_amount=sum(tx['amount'] for tx in small_payments) / len(small_payments),
                    time_range="recent",
                    confidence=0.8
                ))
            
            # Pattern 2: Regular large payments
            large_payments = [tx for tx in self.transaction_history if tx['amount'] > 100000]  # > 1 BTC in sats
            if len(large_payments) > 5:
                patterns.append(TransactionPattern(
                    pattern_type="regular_large_payments",
                    frequency=len(large_payments),
                    avg_amount=sum(tx['amount'] for tx in large_payments) / len(large_payments),
                    time_range="recent",
                    confidence=0.7
                ))
            
            # Pattern 3: Failed payment clusters
            recent_failures = [tx for tx in self.transaction_history[-50:] if not tx['success']]
            if len(recent_failures) > 5:
                patterns.append(TransactionPattern(
                    pattern_type="payment_failure_cluster",
                    frequency=len(recent_failures),
                    avg_amount=sum(tx['amount'] for tx in recent_failures) / len(recent_failures),
                    time_range="recent",
                    confidence=0.9
                ))
            
        except Exception as e:
            self.logger.error(f"Pattern detection failed: {e}")
        
        self.patterns = patterns
        return patterns
    
    def _generate_insights(self, patterns: List[TransactionPattern]) -> List[str]:
        """Generate human-readable insights from patterns"""
        insights = []
        
        for pattern in patterns:
            if pattern.pattern_type == "frequent_small_payments":
                insights.append(
                    f"Detected frequent small payments pattern: {pattern.frequency} transactions "
                    f"averaging {pattern.avg_amount:.0f} sats. Consider optimizing for micropayments."
                )
            elif pattern.pattern_type == "regular_large_payments":
                insights.append(
                    f"Regular large payment activity detected: {pattern.frequency} transactions "
                    f"averaging {pattern.avg_amount:.0f} sats. Ensure adequate channel liquidity."
                )
            elif pattern.pattern_type == "payment_failure_cluster":
                insights.append(
                    f"Warning: {pattern.frequency} recent payment failures detected. "
                    f"Review routing strategies and channel health."
                )
        
        if not patterns:
            insights.append("No significant transaction patterns detected. Normal operation.")
        
        return insights
    
    def _detect_anomalies(self, transactions: List[Dict]) -> List[Dict]:
        """Detect anomalous transactions"""
        if len(transactions) < 5:
            return []
        
        anomalies = []
        amounts = [tx['amount'] for tx in transactions]
        avg_amount = sum(amounts) / len(amounts)
        
        try:
            # Simple anomaly detection based on amount deviation
            for tx in transactions:
                deviation = abs(tx['amount'] - avg_amount) / avg_amount if avg_amount > 0 else 0
                if deviation > 3.0:  # More than 300% deviation
                    anomalies.append({
                        'type': 'unusual_amount',
                        'transaction': tx,
                        'deviation': deviation,
                        'severity': 'high' if deviation > 5.0 else 'medium'
                    })
        
        except Exception as e:
            self.logger.error(f"Anomaly detection failed: {e}")
        
        return anomalies
    
    def _generate_recommendations(self, transactions: List[Dict]) -> List[str]:
        """Generate optimization recommendations"""
        recommendations = []
        
        if not transactions:
            return recommendations
        
        try:
            # Analyze fee efficiency
            fees = [tx['fee'] for tx in transactions]
            amounts = [tx['amount'] for tx in transactions]
            
            if fees and amounts:
                avg_fee_rate = (sum(fees) / sum(amounts)) * 100 if sum(amounts) > 0 else 0
                
                if avg_fee_rate > 1.0:  # More than 1% fee rate
                    recommendations.append(
                        f"High average fee rate detected ({avg_fee_rate:.2f}%). "
                        "Consider optimizing routing algorithms or rebalancing channels."
                    )
                
                # Analyze success rates
                success_rate = sum(1 for tx in transactions if tx['success']) / len(transactions)
                if success_rate < 0.9:  # Less than 90% success rate
                    recommendations.append(
                        f"Payment success rate is {success_rate:.1%}. "
                        "Review channel liquidity and routing strategies."
                    )
        
        except Exception as e:
            self.logger.error(f"Recommendation generation failed: {e}")
        
        if not recommendations:
            recommendations.append("Transaction patterns look healthy. No immediate optimizations needed.")
        
        return recommendations
    
    def _get_cutoff_time(self, timeframe: str) -> datetime:
        """Convert timeframe string to cutoff datetime"""
        now = datetime.now()
        
        if timeframe == "1h":
            return now - timedelta(hours=1)
        elif timeframe == "24h":
            return now - timedelta(hours=24)
        elif timeframe == "7d":
            return now - timedelta(days=7)
        elif timeframe == "30d":
            return now - timedelta(days=30)
        else:
            return now - timedelta(hours=24)  # Default to 24h
    
    def _calculate_success_rate(self) -> float:
        """Calculate overall transaction success rate"""
        if not self.transaction_history:
            return 0.0
        
        successful = sum(1 for tx in self.transaction_history if tx['success'])
        return successful / len(self.transaction_history)
    
    def _pattern_to_dict(self, pattern: TransactionPattern) -> Dict:
        """Convert pattern object to dictionary"""
        return {
            'type': pattern.pattern_type,
            'frequency': pattern.frequency,
            'avg_amount': pattern.avg_amount,
            'time_range': pattern.time_range,
            'confidence': pattern.confidence
        }
    
    # Required abstract method implementations
    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize the plugin"""
        try:
            self.config = config
            self.logger.info(f"Initializing {self.metadata.name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to initialize plugin: {e}")
            return False
    
    def activate(self) -> bool:
        """Activate the plugin"""
        try:
            self.logger.info(f"Activating {self.metadata.name}")
            self.is_active = True
            return True
        except Exception as e:
            self.logger.error(f"Failed to activate plugin: {e}")
            return False
    
    def deactivate(self) -> bool:
        """Deactivate the plugin"""
        try:
            self.logger.info(f"Deactivating {self.metadata.name}")
            self.is_active = False
            return True
        except Exception as e:
            self.logger.error(f"Failed to deactivate plugin: {e}")
            return False
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information"""
        return {
            'name': self.metadata.name,
            'version': self.metadata.version,
            'status': 'active' if self.is_active else 'inactive',
            'transactions_analyzed': len(self.transaction_history),
            'patterns_detected': len(self.patterns),
            'analysis_cache_size': len(self.analysis_cache)
        }
    
    def process_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Process data (alias for analyze_data)"""
        return self.analyze_data(data)
    
    def collect_metrics(self) -> Dict[str, Any]:
        """Collect plugin metrics"""
        return {
            'transactions_processed': len(self.transaction_history),
            'patterns_identified': len(self.patterns),
            'success_rate': self._calculate_success_rate(),
            'last_analysis': datetime.now().isoformat()
        }


# Plugin registration
def create_plugin():
    """Plugin factory function"""
    return TransactionAnalyzerPlugin()

# Make the plugin class available at module level for direct loading
Plugin = TransactionAnalyzerPlugin