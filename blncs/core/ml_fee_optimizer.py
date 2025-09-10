"""
Machine Learning-based Fee Optimization for Lightning Network
Advanced fee optimization using predictive models and historical data analysis.
"""

import numpy as np
import asyncio
import time
import json
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import statistics
import math

try:
    # scikit-learn for ML models
    from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor
    from sklearn.linear_model import LinearRegression, Ridge
    from sklearn.preprocessing import StandardScaler, MinMaxScaler
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
    from sklearn.cluster import KMeans
    import joblib
    
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    
    # Fallback stubs
    class RandomForestRegressor:
        def __init__(self, *args, **kwargs): pass
        def fit(self, X, y): pass
        def predict(self, X): return [0] * len(X)

from .structured_logging import get_structured_logger, LogCategory
from .async_database import get_async_db_manager
from .error_handler import get_error_handler, ErrorContext
from .telemetry import trace_function, TracingMixin


class FeeStrategy(Enum):
    """Fee optimization strategies"""
    CONSERVATIVE = "conservative"  # Lower fees, fewer but reliable routes
    AGGRESSIVE = "aggressive"     # Higher fees, more profit-focused
    BALANCED = "balanced"         # Balance between routing and profit
    DYNAMIC = "dynamic"           # ML-driven dynamic optimization
    MARKET_BASED = "market_based" # Based on network-wide fee analysis


@dataclass
class ChannelFeatures:
    """Features for ML model training"""
    channel_id: str
    
    # Channel characteristics
    capacity_sats: int
    local_balance_sats: int
    remote_balance_sats: int
    age_days: int
    is_private: bool
    
    # Performance metrics
    routing_volume_24h: int = 0
    routing_count_24h: int = 0
    success_rate: float = 0.0
    avg_settlement_time: float = 0.0
    
    # Fee information
    current_base_fee: int = 0
    current_fee_rate: int = 0  # ppm
    
    # Network context
    peer_centrality_score: float = 0.0
    network_liquidity_ratio: float = 0.0
    competition_level: float = 0.0
    
    # Market indicators
    btc_price_usd: float = 0.0
    network_capacity_trend: float = 0.0
    fee_market_pressure: float = 0.0
    
    # Time-based features
    hour_of_day: int = 0
    day_of_week: int = 0
    is_weekend: bool = False
    
    def to_array(self) -> np.ndarray:
        """Convert to numpy array for ML model"""
        return np.array([
            self.capacity_sats,
            self.local_balance_sats,
            self.remote_balance_sats,
            self.age_days,
            int(self.is_private),
            self.routing_volume_24h,
            self.routing_count_24h,
            self.success_rate,
            self.avg_settlement_time,
            self.current_base_fee,
            self.current_fee_rate,
            self.peer_centrality_score,
            self.network_liquidity_ratio,
            self.competition_level,
            self.btc_price_usd,
            self.network_capacity_trend,
            self.fee_market_pressure,
            self.hour_of_day,
            self.day_of_week,
            int(self.is_weekend)
        ])


@dataclass
class FeeOptimizationResult:
    """Result of fee optimization"""
    channel_id: str
    
    # Original fees
    original_base_fee: int
    original_fee_rate: int
    
    # Optimized fees
    optimal_base_fee: int
    optimal_fee_rate: int
    
    # Predictions
    predicted_volume_increase: float
    predicted_revenue_increase: float
    confidence_score: float
    
    # Model information
    model_used: str
    strategy: FeeStrategy
    optimization_timestamp: datetime = field(default_factory=datetime.now)
    
    # Performance metrics
    expected_routing_success_rate: float = 0.0
    expected_daily_revenue: float = 0.0
    risk_score: float = 0.0


class MLFeeOptimizer(TracingMixin):
    """Machine Learning-based fee optimization system"""
    
    def __init__(self):
        super().__init__()
        self.logger = get_structured_logger(__name__)
        self.error_handler = get_error_handler()
        
        if not ML_AVAILABLE:
            self.logger.warning(
                "ML libraries not available. Install with: pip install scikit-learn numpy",
                category=LogCategory.PERFORMANCE
            )
        
        # ML Models
        self.revenue_model = None
        self.volume_model = None
        self.success_rate_model = None
        self.scaler = StandardScaler()
        
        # Data storage
        self.training_data: List[Dict[str, Any]] = []
        self.feature_importance: Dict[str, float] = {}
        
        # Model performance tracking
        self.model_metrics: Dict[str, Dict[str, float]] = {}
        self.last_training_time: Optional[datetime] = None
        self.model_version = 1
        
        # Configuration
        self.min_training_samples = 100
        self.retrain_threshold_days = 7
        self.confidence_threshold = 0.7
        
        # Database
        self.db_manager = None
        
        # Fee constraints
        self.min_base_fee = 1  # 1 msat
        self.max_base_fee = 10000  # 10 sats
        self.min_fee_rate = 1  # 1 ppm
        self.max_fee_rate = 10000  # 1%
    
    async def initialize(self):
        """Initialize ML fee optimizer"""
        try:
            self.db_manager = await get_async_db_manager()
            await self._create_tables()
            await self._load_training_data()
            
            if self.training_data and len(self.training_data) >= self.min_training_samples:
                await self._train_models()
            
            self.logger.info(
                "ML fee optimizer initialized",
                category=LogCategory.PERFORMANCE,
                data={
                    "ml_available": ML_AVAILABLE,
                    "training_samples": len(self.training_data),
                    "models_trained": self.revenue_model is not None
                }
            )
            
        except Exception as e:
            self.error_handler.handle_error(
                e,
                ErrorContext(
                    component="ml_fee_optimizer",
                    operation="initialize",
                    severity="high"
                )
            )
            raise
    
    async def _create_tables(self):
        """Create database tables for fee optimization data"""
        tables = [
            """
            CREATE TABLE IF NOT EXISTS fee_optimization_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_id TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                features_json TEXT NOT NULL,
                actual_volume INTEGER NOT NULL,
                actual_revenue INTEGER NOT NULL,
                success_rate REAL NOT NULL,
                base_fee INTEGER NOT NULL,
                fee_rate INTEGER NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS fee_optimization_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel_id TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                strategy TEXT NOT NULL,
                original_base_fee INTEGER NOT NULL,
                original_fee_rate INTEGER NOT NULL,
                optimal_base_fee INTEGER NOT NULL,
                optimal_fee_rate INTEGER NOT NULL,
                predicted_volume_increase REAL NOT NULL,
                predicted_revenue_increase REAL NOT NULL,
                confidence_score REAL NOT NULL,
                model_version INTEGER NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS model_performance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_type TEXT NOT NULL,
                model_version INTEGER NOT NULL,
                training_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                training_samples INTEGER NOT NULL,
                mse REAL NOT NULL,
                mae REAL NOT NULL,
                r2_score REAL NOT NULL,
                cross_val_score REAL NOT NULL
            )
            """,
            
            # Indexes
            "CREATE INDEX IF NOT EXISTS idx_fee_data_channel ON fee_optimization_data(channel_id)",
            "CREATE INDEX IF NOT EXISTS idx_fee_data_timestamp ON fee_optimization_data(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_fee_results_channel ON fee_optimization_results(channel_id)",
            "CREATE INDEX IF NOT EXISTS idx_model_perf_version ON model_performance(model_version)"
        ]
        
        for table_sql in tables:
            await self.db_manager.execute(table_sql, fetch_results=False)
    
    async def _load_training_data(self):
        """Load historical training data"""
        try:
            rows = await self.db_manager.fetch_all(
                """
                SELECT * FROM fee_optimization_data 
                ORDER BY timestamp DESC 
                LIMIT 10000
                """
            )
            
            self.training_data = []
            for row in rows:
                features = json.loads(row['features_json'])
                data_point = {
                    'features': features,
                    'volume': row['actual_volume'],
                    'revenue': row['actual_revenue'],
                    'success_rate': row['success_rate'],
                    'base_fee': row['base_fee'],
                    'fee_rate': row['fee_rate'],
                    'timestamp': row['timestamp']
                }
                self.training_data.append(data_point)
            
            self.logger.info(f"Loaded {len(self.training_data)} training samples")
            
        except Exception as e:
            self.logger.warning(f"Failed to load training data: {e}")
    
    @trace_function("train_ml_models")
    async def _train_models(self):
        """Train ML models for fee optimization"""
        if not ML_AVAILABLE or len(self.training_data) < self.min_training_samples:
            return
        
        try:
            # Prepare training data
            X, y_volume, y_revenue, y_success = self._prepare_training_data()
            
            if len(X) < self.min_training_samples:
                self.logger.warning("Insufficient training data for ML models")
                return
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Split data
            X_train, X_test, y_vol_train, y_vol_test = train_test_split(
                X_scaled, y_volume, test_size=0.2, random_state=42
            )
            _, _, y_rev_train, y_rev_test = train_test_split(
                X_scaled, y_revenue, test_size=0.2, random_state=42
            )
            _, _, y_suc_train, y_suc_test = train_test_split(
                X_scaled, y_success, test_size=0.2, random_state=42
            )
            
            # Train volume prediction model
            self.volume_model = GradientBoostingRegressor(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=6,
                random_state=42
            )
            self.volume_model.fit(X_train, y_vol_train)
            
            # Train revenue prediction model
            self.revenue_model = RandomForestRegressor(
                n_estimators=100,
                max_depth=8,
                random_state=42
            )
            self.revenue_model.fit(X_train, y_rev_train)
            
            # Train success rate model
            self.success_rate_model = Ridge(alpha=1.0)
            self.success_rate_model.fit(X_train, y_suc_train)
            
            # Evaluate models
            await self._evaluate_models(X_test, y_vol_test, y_rev_test, y_suc_test)
            
            # Calculate feature importance
            self._calculate_feature_importance()
            
            self.last_training_time = datetime.now()
            self.model_version += 1
            
            self.logger.info(
                "ML models trained successfully",
                category=LogCategory.PERFORMANCE,
                data={
                    "training_samples": len(X),
                    "model_version": self.model_version,
                    "volume_score": self.model_metrics.get("volume", {}).get("r2", 0),
                    "revenue_score": self.model_metrics.get("revenue", {}).get("r2", 0)
                }
            )
            
        except Exception as e:
            self.error_handler.handle_error(
                e,
                ErrorContext(
                    component="ml_fee_optimizer",
                    operation="train_models",
                    severity="medium"
                )
            )
    
    def _prepare_training_data(self) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """Prepare data for model training"""
        X = []
        y_volume = []
        y_revenue = []
        y_success = []
        
        for data_point in self.training_data:
            features = data_point['features']
            
            # Convert features to array
            feature_array = self._dict_to_feature_array(features)
            X.append(feature_array)
            
            y_volume.append(data_point['volume'])
            y_revenue.append(data_point['revenue'])
            y_success.append(data_point['success_rate'])
        
        return (
            np.array(X),
            np.array(y_volume),
            np.array(y_revenue),
            np.array(y_success)
        )
    
    def _dict_to_feature_array(self, features: Dict[str, Any]) -> np.ndarray:
        """Convert feature dictionary to numpy array"""
        return np.array([
            features.get('capacity_sats', 0),
            features.get('local_balance_sats', 0),
            features.get('remote_balance_sats', 0),
            features.get('age_days', 0),
            int(features.get('is_private', False)),
            features.get('routing_volume_24h', 0),
            features.get('routing_count_24h', 0),
            features.get('success_rate', 0),
            features.get('avg_settlement_time', 0),
            features.get('current_base_fee', 0),
            features.get('current_fee_rate', 0),
            features.get('peer_centrality_score', 0),
            features.get('network_liquidity_ratio', 0),
            features.get('competition_level', 0),
            features.get('btc_price_usd', 0),
            features.get('network_capacity_trend', 0),
            features.get('fee_market_pressure', 0),
            features.get('hour_of_day', 0),
            features.get('day_of_week', 0),
            int(features.get('is_weekend', False))
        ])
    
    async def _evaluate_models(self, X_test, y_vol_test, y_rev_test, y_suc_test):
        """Evaluate model performance"""
        
        # Volume model evaluation
        if self.volume_model:
            vol_pred = self.volume_model.predict(X_test)
            vol_mse = mean_squared_error(y_vol_test, vol_pred)
            vol_mae = mean_absolute_error(y_vol_test, vol_pred)
            vol_r2 = r2_score(y_vol_test, vol_pred)
            
            self.model_metrics['volume'] = {
                'mse': vol_mse,
                'mae': vol_mae,
                'r2': vol_r2
            }
        
        # Revenue model evaluation
        if self.revenue_model:
            rev_pred = self.revenue_model.predict(X_test)
            rev_mse = mean_squared_error(y_rev_test, rev_pred)
            rev_mae = mean_absolute_error(y_rev_test, rev_pred)
            rev_r2 = r2_score(y_rev_test, rev_pred)
            
            self.model_metrics['revenue'] = {
                'mse': rev_mse,
                'mae': rev_mae,
                'r2': rev_r2
            }
        
        # Success rate model evaluation
        if self.success_rate_model:
            suc_pred = self.success_rate_model.predict(X_test)
            suc_mse = mean_squared_error(y_suc_test, suc_pred)
            suc_mae = mean_absolute_error(y_suc_test, suc_pred)
            suc_r2 = r2_score(y_suc_test, suc_pred)
            
            self.model_metrics['success_rate'] = {
                'mse': suc_mse,
                'mae': suc_mae,
                'r2': suc_r2
            }
        
        # Store metrics in database
        for model_type, metrics in self.model_metrics.items():
            await self.db_manager.insert('model_performance', {
                'model_type': model_type,
                'model_version': self.model_version,
                'training_samples': len(X_test) * 5,  # Approximate
                'mse': metrics['mse'],
                'mae': metrics['mae'],
                'r2_score': metrics['r2'],
                'cross_val_score': 0.0  # TODO: Add cross validation
            })
    
    def _calculate_feature_importance(self):
        """Calculate and store feature importance"""
        if not self.revenue_model or not hasattr(self.revenue_model, 'feature_importances_'):
            return
        
        feature_names = [
            'capacity_sats', 'local_balance_sats', 'remote_balance_sats',
            'age_days', 'is_private', 'routing_volume_24h', 'routing_count_24h',
            'success_rate', 'avg_settlement_time', 'current_base_fee',
            'current_fee_rate', 'peer_centrality_score', 'network_liquidity_ratio',
            'competition_level', 'btc_price_usd', 'network_capacity_trend',
            'fee_market_pressure', 'hour_of_day', 'day_of_week', 'is_weekend'
        ]
        
        importance_scores = self.revenue_model.feature_importances_
        
        self.feature_importance = {
            name: float(score) 
            for name, score in zip(feature_names, importance_scores)
        }
    
    async def optimize_channel_fees(
        self,
        channel_features: ChannelFeatures,
        strategy: FeeStrategy = FeeStrategy.BALANCED,
        custom_constraints: Optional[Dict[str, Any]] = None
    ) -> FeeOptimizationResult:
        """Optimize fees for a specific channel"""
        
        try:
            async with self.async_trace_operation(
                "optimize_channel_fees",
                attributes={
                    "channel_id": channel_features.channel_id,
                    "strategy": strategy.value
                }
            ):
                # Check if models need retraining
                if self._should_retrain_models():
                    await self._train_models()
                
                if strategy == FeeStrategy.DYNAMIC and self._models_available():
                    return await self._ml_optimize_fees(channel_features, custom_constraints)
                else:
                    return await self._rule_based_optimize_fees(channel_features, strategy, custom_constraints)
                    
        except Exception as e:
            self.error_handler.handle_error(
                e,
                ErrorContext(
                    component="ml_fee_optimizer",
                    operation="optimize_channel_fees",
                    metadata={"channel_id": channel_features.channel_id}
                )
            )
            
            # Return conservative fallback
            return self._get_fallback_optimization(channel_features, strategy)
    
    def _models_available(self) -> bool:
        """Check if ML models are available and trained"""
        return (
            ML_AVAILABLE and
            self.revenue_model is not None and
            self.volume_model is not None and
            self.success_rate_model is not None
        )
    
    def _should_retrain_models(self) -> bool:
        """Check if models should be retrained"""
        if not self.last_training_time:
            return True
        
        days_since_training = (datetime.now() - self.last_training_time).days
        return days_since_training >= self.retrain_threshold_days
    
    async def _ml_optimize_fees(
        self,
        features: ChannelFeatures,
        constraints: Optional[Dict[str, Any]] = None
    ) -> FeeOptimizationResult:
        """ML-based fee optimization"""
        
        # Define fee ranges to test
        base_fee_range = np.linspace(
            self.min_base_fee,
            min(self.max_base_fee, features.current_base_fee * 3),
            20
        )
        
        fee_rate_range = np.linspace(
            self.min_fee_rate,
            min(self.max_fee_rate, features.current_fee_rate * 3),
            20
        )
        
        best_score = -float('inf')
        best_base_fee = features.current_base_fee
        best_fee_rate = features.current_fee_rate
        predictions = {}
        
        # Test different fee combinations
        for base_fee in base_fee_range:
            for fee_rate in fee_rate_range:
                # Create modified features
                test_features = features
                test_features.current_base_fee = int(base_fee)
                test_features.current_fee_rate = int(fee_rate)
                
                # Get predictions
                feature_array = test_features.to_array().reshape(1, -1)
                feature_array_scaled = self.scaler.transform(feature_array)
                
                pred_volume = self.volume_model.predict(feature_array_scaled)[0]
                pred_revenue = self.revenue_model.predict(feature_array_scaled)[0]
                pred_success = self.success_rate_model.predict(feature_array_scaled)[0]
                
                # Calculate composite score based on strategy
                score = self._calculate_optimization_score(
                    pred_volume, pred_revenue, pred_success, FeeStrategy.DYNAMIC
                )
                
                if score > best_score:
                    best_score = score
                    best_base_fee = int(base_fee)
                    best_fee_rate = int(fee_rate)
                    predictions = {
                        'volume': max(0, pred_volume),
                        'revenue': max(0, pred_revenue),
                        'success_rate': max(0, min(1, pred_success))
                    }
        
        # Calculate improvements
        volume_increase = predictions.get('volume', 0) - features.routing_volume_24h
        revenue_increase = predictions.get('revenue', 0) - (
            features.routing_volume_24h * features.current_fee_rate / 1_000_000
        )
        
        # Calculate confidence based on model performance
        confidence = self._calculate_confidence_score()
        
        result = FeeOptimizationResult(
            channel_id=features.channel_id,
            original_base_fee=features.current_base_fee,
            original_fee_rate=features.current_fee_rate,
            optimal_base_fee=best_base_fee,
            optimal_fee_rate=best_fee_rate,
            predicted_volume_increase=volume_increase,
            predicted_revenue_increase=revenue_increase,
            confidence_score=confidence,
            model_used="ml_ensemble",
            strategy=FeeStrategy.DYNAMIC,
            expected_routing_success_rate=predictions.get('success_rate', 0),
            expected_daily_revenue=predictions.get('revenue', 0),
            risk_score=1.0 - confidence
        )
        
        # Store result
        await self._store_optimization_result(result)
        
        return result
    
    async def _rule_based_optimize_fees(
        self,
        features: ChannelFeatures,
        strategy: FeeStrategy,
        constraints: Optional[Dict[str, Any]] = None
    ) -> FeeOptimizationResult:
        """Rule-based fee optimization"""
        
        constraints = constraints or {}
        
        # Strategy-based fee calculation
        if strategy == FeeStrategy.CONSERVATIVE:
            # Lower fees for higher routing volume
            base_fee = max(self.min_base_fee, features.current_base_fee * 0.8)
            fee_rate = max(self.min_fee_rate, features.current_fee_rate * 0.8)
            
        elif strategy == FeeStrategy.AGGRESSIVE:
            # Higher fees for better profitability
            base_fee = min(self.max_base_fee, features.current_base_fee * 1.5)
            fee_rate = min(self.max_fee_rate, features.current_fee_rate * 1.5)
            
        elif strategy == FeeStrategy.BALANCED:
            # Balance between routing and profitability
            if features.success_rate < 0.7:  # Low success rate
                base_fee = max(self.min_base_fee, features.current_base_fee * 0.9)
                fee_rate = max(self.min_fee_rate, features.current_fee_rate * 0.9)
            elif features.routing_volume_24h > 1_000_000:  # High volume
                base_fee = min(self.max_base_fee, features.current_base_fee * 1.1)
                fee_rate = min(self.max_fee_rate, features.current_fee_rate * 1.1)
            else:
                base_fee = features.current_base_fee
                fee_rate = features.current_fee_rate
                
        else:  # MARKET_BASED
            # Estimate market rates (simplified)
            market_base_fee = 1000  # Average market base fee
            market_fee_rate = 1000  # Average market fee rate ppm
            
            base_fee = int((features.current_base_fee + market_base_fee) / 2)
            fee_rate = int((features.current_fee_rate + market_fee_rate) / 2)
        
        # Apply constraints
        if 'min_base_fee' in constraints:
            base_fee = max(constraints['min_base_fee'], base_fee)
        if 'max_base_fee' in constraints:
            base_fee = min(constraints['max_base_fee'], base_fee)
        if 'min_fee_rate' in constraints:
            fee_rate = max(constraints['min_fee_rate'], fee_rate)
        if 'max_fee_rate' in constraints:
            fee_rate = min(constraints['max_fee_rate'], fee_rate)
        
        # Simple predictions based on fee changes
        fee_change_factor = (base_fee + fee_rate) / (features.current_base_fee + features.current_fee_rate + 1)
        
        if fee_change_factor < 1.0:  # Lower fees
            volume_increase = features.routing_volume_24h * (1.2 - fee_change_factor)
            revenue_change = -features.routing_volume_24h * 0.1  # Lower revenue per tx
        else:  # Higher fees
            volume_increase = -features.routing_volume_24h * (fee_change_factor - 1.0) * 0.5
            revenue_change = features.routing_volume_24h * (fee_change_factor - 1.0) * 0.3
        
        result = FeeOptimizationResult(
            channel_id=features.channel_id,
            original_base_fee=features.current_base_fee,
            original_fee_rate=features.current_fee_rate,
            optimal_base_fee=int(base_fee),
            optimal_fee_rate=int(fee_rate),
            predicted_volume_increase=volume_increase,
            predicted_revenue_increase=revenue_change,
            confidence_score=0.6,  # Lower confidence for rule-based
            model_used="rule_based",
            strategy=strategy,
            expected_routing_success_rate=features.success_rate,
            expected_daily_revenue=0,
            risk_score=0.4
        )
        
        await self._store_optimization_result(result)
        return result
    
    def _calculate_optimization_score(
        self,
        predicted_volume: float,
        predicted_revenue: float,
        predicted_success: float,
        strategy: FeeStrategy
    ) -> float:
        """Calculate composite optimization score"""
        
        # Normalize values (0-1 range)
        volume_score = min(predicted_volume / 10_000_000, 1.0)  # Normalize to 10M sats
        revenue_score = min(predicted_revenue / 100_000, 1.0)   # Normalize to 100k sats
        success_score = max(0, min(predicted_success, 1.0))
        
        # Strategy-based weighting
        if strategy == FeeStrategy.CONSERVATIVE:
            return volume_score * 0.5 + success_score * 0.4 + revenue_score * 0.1
        elif strategy == FeeStrategy.AGGRESSIVE:
            return revenue_score * 0.6 + volume_score * 0.2 + success_score * 0.2
        elif strategy == FeeStrategy.BALANCED:
            return volume_score * 0.4 + revenue_score * 0.4 + success_score * 0.2
        else:  # DYNAMIC
            return volume_score * 0.35 + revenue_score * 0.35 + success_score * 0.3
    
    def _calculate_confidence_score(self) -> float:
        """Calculate confidence score based on model performance"""
        if not self.model_metrics:
            return 0.5
        
        # Average R² scores across models
        r2_scores = [
            metrics.get('r2', 0) for metrics in self.model_metrics.values()
        ]
        
        avg_r2 = statistics.mean(r2_scores) if r2_scores else 0
        
        # Convert R² to confidence (0-1 range)
        return max(0, min(avg_r2, 1.0))
    
    def _get_fallback_optimization(
        self,
        features: ChannelFeatures,
        strategy: FeeStrategy
    ) -> FeeOptimizationResult:
        """Get fallback optimization when ML is not available"""
        
        return FeeOptimizationResult(
            channel_id=features.channel_id,
            original_base_fee=features.current_base_fee,
            original_fee_rate=features.current_fee_rate,
            optimal_base_fee=features.current_base_fee,
            optimal_fee_rate=features.current_fee_rate,
            predicted_volume_increase=0,
            predicted_revenue_increase=0,
            confidence_score=0.3,
            model_used="fallback",
            strategy=strategy,
            risk_score=0.7
        )
    
    async def _store_optimization_result(self, result: FeeOptimizationResult):
        """Store optimization result in database"""
        try:
            await self.db_manager.insert('fee_optimization_results', {
                'channel_id': result.channel_id,
                'strategy': result.strategy.value,
                'original_base_fee': result.original_base_fee,
                'original_fee_rate': result.original_fee_rate,
                'optimal_base_fee': result.optimal_base_fee,
                'optimal_fee_rate': result.optimal_fee_rate,
                'predicted_volume_increase': result.predicted_volume_increase,
                'predicted_revenue_increase': result.predicted_revenue_increase,
                'confidence_score': result.confidence_score,
                'model_version': self.model_version
            })
        except Exception as e:
            self.logger.warning(f"Failed to store optimization result: {e}")
    
    async def record_actual_performance(
        self,
        channel_id: str,
        features: ChannelFeatures,
        actual_volume: int,
        actual_revenue: int,
        success_rate: float
    ):
        """Record actual performance for model training"""
        try:
            await self.db_manager.insert('fee_optimization_data', {
                'channel_id': channel_id,
                'features_json': json.dumps(asdict(features)),
                'actual_volume': actual_volume,
                'actual_revenue': actual_revenue,
                'success_rate': success_rate,
                'base_fee': features.current_base_fee,
                'fee_rate': features.current_fee_rate
            })
            
            # Add to training data
            self.training_data.append({
                'features': asdict(features),
                'volume': actual_volume,
                'revenue': actual_revenue,
                'success_rate': success_rate,
                'base_fee': features.current_base_fee,
                'fee_rate': features.current_fee_rate,
                'timestamp': datetime.now().isoformat()
            })
            
            # Limit training data size
            if len(self.training_data) > 15000:
                self.training_data = self.training_data[-10000:]
                
        except Exception as e:
            self.logger.warning(f"Failed to record actual performance: {e}")
    
    def get_model_statistics(self) -> Dict[str, Any]:
        """Get model performance statistics"""
        return {
            'ml_available': ML_AVAILABLE,
            'models_trained': self._models_available(),
            'last_training_time': self.last_training_time.isoformat() if self.last_training_time else None,
            'model_version': self.model_version,
            'training_samples': len(self.training_data),
            'model_metrics': self.model_metrics,
            'feature_importance': self.feature_importance,
            'confidence_threshold': self.confidence_threshold
        }


# Global ML fee optimizer
_global_ml_fee_optimizer: Optional[MLFeeOptimizer] = None


async def get_ml_fee_optimizer() -> MLFeeOptimizer:
    """Get global ML fee optimizer"""
    global _global_ml_fee_optimizer
    if _global_ml_fee_optimizer is None:
        _global_ml_fee_optimizer = MLFeeOptimizer()
        await _global_ml_fee_optimizer.initialize()
    return _global_ml_fee_optimizer


__all__ = [
    'FeeStrategy',
    'ChannelFeatures',
    'FeeOptimizationResult',
    'MLFeeOptimizer',
    'get_ml_fee_optimizer'
]