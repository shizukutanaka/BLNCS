"""
Enterprise Analytics and Machine Learning Pipeline
Advanced analytics, predictive modeling, and business intelligence for Lightning Network.
"""

import asyncio
import logging
import json
import pickle
import hashlib
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import pandas as pd
import numpy as np

try:
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.ensemble import RandomForestRegressor, RandomForestClassifier, GradientBoostingRegressor
    from sklearn.linear_model import LinearRegression, LogisticRegression
    from sklearn.metrics import mean_squared_error, mean_absolute_error, accuracy_score, precision_recall_fscore_support
    from sklearn.cluster import KMeans, DBSCAN
    import joblib
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

try:
    import tensorflow as tf
    from tensorflow import keras
    from tensorflow.keras import layers, models, optimizers
    HAS_TENSORFLOW = True
except ImportError:
    HAS_TENSORFLOW = False

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    HAS_PYTORCH = True
except ImportError:
    HAS_PYTORCH = False

logger = logging.getLogger(__name__)

class ModelType(Enum):
    """Types of machine learning models."""
    REGRESSION = "regression"
    CLASSIFICATION = "classification"
    CLUSTERING = "clustering"
    TIME_SERIES = "time_series"
    DEEP_LEARNING = "deep_learning"
    REINFORCEMENT = "reinforcement"

class AnalyticsMetric(Enum):
    """Analytics metrics to track."""
    PAYMENT_VOLUME = "payment_volume"
    CHANNEL_UTILIZATION = "channel_utilization"
    FEE_REVENUE = "fee_revenue"
    ROUTING_SUCCESS = "routing_success"
    NODE_CONNECTIVITY = "node_connectivity"
    LIQUIDITY_FLOW = "liquidity_flow"
    RISK_SCORE = "risk_score"
    USER_BEHAVIOR = "user_behavior"

class PredictionTask(Enum):
    """Prediction tasks for ML models."""
    PAYMENT_SUCCESS = "payment_success"
    OPTIMAL_FEE = "optimal_fee"
    CHANNEL_FAILURE = "channel_failure"
    FRAUD_DETECTION = "fraud_detection"
    DEMAND_FORECAST = "demand_forecast"
    ANOMALY_DETECTION = "anomaly_detection"
    ROUTE_OPTIMIZATION = "route_optimization"
    CHURN_PREDICTION = "churn_prediction"

@dataclass
class Feature:
    """Feature definition for ML models."""
    name: str
    data_type: str
    source: str
    description: str
    importance: float = 0.0
    is_derived: bool = False
    transformation: Optional[str] = None
    
    def apply_transformation(self, value: Any) -> Any:
        """Apply transformation to feature value."""
        if not self.transformation:
            return value
        
        if self.transformation == 'log':
            return np.log1p(float(value))
        elif self.transformation == 'sqrt':
            return np.sqrt(float(value))
        elif self.transformation == 'square':
            return float(value) ** 2
        elif self.transformation == 'normalize':
            # This would need context for min/max
            return value
        else:
            return value

@dataclass
class MLModel:
    """Machine learning model wrapper."""
    model_id: str
    model_type: ModelType
    task: PredictionTask
    algorithm: str
    version: int
    model_object: Any  # Actual sklearn/tf/torch model
    features: List[Feature]
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    training_date: datetime = field(default_factory=datetime.utcnow)
    last_prediction: Optional[datetime] = None
    is_deployed: bool = False
    
    def get_feature_names(self) -> List[str]:
        """Get list of feature names."""
        return [f.name for f in self.features]

@dataclass
class TrainingData:
    """Training data container."""
    features: pd.DataFrame
    target: pd.Series
    metadata: Dict[str, Any] = field(default_factory=dict)
    split_ratio: float = 0.8
    
    def split(self) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
        """Split data into train and test sets."""
        return train_test_split(
            self.features, 
            self.target, 
            test_size=1-self.split_ratio,
            random_state=42
        )

@dataclass
class PredictionResult:
    """Prediction result with confidence."""
    prediction_id: str
    model_id: str
    task: PredictionTask
    prediction: Union[float, int, str, np.ndarray]
    confidence: float
    feature_values: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.utcnow)
    explanation: Optional[Dict[str, Any]] = None

class FeatureEngineering:
    """Feature engineering for Lightning Network data."""
    
    @staticmethod
    def create_payment_features(payment_data: Dict[str, Any]) -> Dict[str, float]:
        """Create features from payment data."""
        features = {
            'amount_sats': float(payment_data.get('amount_sats', 0)),
            'amount_log': np.log1p(float(payment_data.get('amount_sats', 0))),
            'hour_of_day': datetime.fromisoformat(payment_data.get('timestamp', datetime.utcnow().isoformat())).hour,
            'day_of_week': datetime.fromisoformat(payment_data.get('timestamp', datetime.utcnow().isoformat())).weekday(),
            'is_weekend': int(datetime.fromisoformat(payment_data.get('timestamp', datetime.utcnow().isoformat())).weekday() >= 5),
            'num_hops': payment_data.get('num_hops', 0),
            'total_fees': payment_data.get('total_fees', 0),
            'fee_rate': payment_data.get('total_fees', 0) / max(payment_data.get('amount_sats', 1), 1)
        }
        
        return features
    
    @staticmethod
    def create_channel_features(channel_data: Dict[str, Any]) -> Dict[str, float]:
        """Create features from channel data."""
        capacity = channel_data.get('capacity', 0)
        local_balance = channel_data.get('local_balance', 0)
        remote_balance = channel_data.get('remote_balance', 0)
        
        features = {
            'capacity': float(capacity),
            'local_balance': float(local_balance),
            'remote_balance': float(remote_balance),
            'balance_ratio': local_balance / max(capacity, 1),
            'utilization': (local_balance + remote_balance) / max(capacity, 1),
            'age_days': (datetime.utcnow() - datetime.fromisoformat(channel_data.get('created_at', datetime.utcnow().isoformat()))).days,
            'num_updates': channel_data.get('num_updates', 0),
            'total_sent': channel_data.get('total_sent', 0),
            'total_received': channel_data.get('total_received', 0),
            'fee_rate_milli_msat': channel_data.get('fee_rate_milli_msat', 0),
            'is_active': int(channel_data.get('active', False))
        }
        
        return features
    
    @staticmethod
    def create_node_features(node_data: Dict[str, Any]) -> Dict[str, float]:
        """Create features from node data."""
        features = {
            'num_channels': node_data.get('num_channels', 0),
            'total_capacity': node_data.get('total_capacity', 0),
            'avg_channel_size': node_data.get('total_capacity', 0) / max(node_data.get('num_channels', 1), 1),
            'num_peers': node_data.get('num_peers', 0),
            'routing_success_rate': node_data.get('routing_success_rate', 0.0),
            'uptime_hours': node_data.get('uptime_hours', 0),
            'total_fees_earned': node_data.get('total_fees_earned', 0),
            'betweenness_centrality': node_data.get('betweenness_centrality', 0.0),
            'clustering_coefficient': node_data.get('clustering_coefficient', 0.0)
        }
        
        return features
    
    @staticmethod
    def create_time_series_features(time_series: pd.Series, window_sizes: List[int] = [7, 14, 30]) -> Dict[str, float]:
        """Create time series features."""
        features = {}
        
        for window in window_sizes:
            if len(time_series) >= window:
                features[f'mean_{window}d'] = time_series.tail(window).mean()
                features[f'std_{window}d'] = time_series.tail(window).std()
                features[f'min_{window}d'] = time_series.tail(window).min()
                features[f'max_{window}d'] = time_series.tail(window).max()
                features[f'trend_{window}d'] = (time_series.tail(window).iloc[-1] - time_series.tail(window).iloc[0]) / window
        
        # Recent values
        for i in range(min(7, len(time_series))):
            features[f'lag_{i+1}'] = time_series.iloc[-(i+1)] if len(time_series) > i else 0
        
        return features

class MLPipeline:
    """Enterprise machine learning pipeline."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize ML pipeline."""
        self.config = config or self._get_default_config()
        self.models: Dict[str, MLModel] = {}
        self.feature_store: Dict[str, Feature] = {}
        self.training_data: Dict[str, TrainingData] = {}
        self.predictions: List[PredictionResult] = []
        
        # Model storage
        self.model_dir = Path(self.config.get('model_directory', 'models'))
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        # Threading
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ml")
        self.training_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        
        # Feature engineering
        self.feature_engineering = FeatureEngineering()
        
        # Initialize feature definitions
        self._init_features()
        
        logger.info("ML pipeline initialized")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            'model_directory': 'models',
            'auto_retrain': True,
            'retrain_interval': 86400,  # 24 hours
            'min_training_samples': 1000,
            'validation_split': 0.2,
            'cross_validation_folds': 5,
            'feature_importance_threshold': 0.01,
            'model_performance_threshold': 0.7,
            'max_model_versions': 10,
            'enable_deep_learning': HAS_TENSORFLOW or HAS_PYTORCH,
            'enable_auto_ml': False
        }
    
    def _init_features(self) -> None:
        """Initialize feature definitions."""
        # Payment features
        payment_features = [
            Feature('amount_sats', 'float', 'payment', 'Payment amount in satoshis'),
            Feature('amount_log', 'float', 'payment', 'Log of payment amount', is_derived=True, transformation='log'),
            Feature('hour_of_day', 'int', 'payment', 'Hour of payment'),
            Feature('day_of_week', 'int', 'payment', 'Day of week'),
            Feature('is_weekend', 'int', 'payment', 'Weekend indicator'),
            Feature('num_hops', 'int', 'payment', 'Number of hops in route'),
            Feature('total_fees', 'float', 'payment', 'Total routing fees'),
            Feature('fee_rate', 'float', 'payment', 'Fee rate', is_derived=True)
        ]
        
        # Channel features
        channel_features = [
            Feature('capacity', 'float', 'channel', 'Channel capacity'),
            Feature('local_balance', 'float', 'channel', 'Local balance'),
            Feature('remote_balance', 'float', 'channel', 'Remote balance'),
            Feature('balance_ratio', 'float', 'channel', 'Balance ratio', is_derived=True),
            Feature('utilization', 'float', 'channel', 'Channel utilization', is_derived=True),
            Feature('age_days', 'int', 'channel', 'Channel age in days'),
            Feature('num_updates', 'int', 'channel', 'Number of channel updates'),
            Feature('fee_rate_milli_msat', 'float', 'channel', 'Fee rate in milli-msat')
        ]
        
        # Node features
        node_features = [
            Feature('num_channels', 'int', 'node', 'Number of channels'),
            Feature('total_capacity', 'float', 'node', 'Total node capacity'),
            Feature('avg_channel_size', 'float', 'node', 'Average channel size', is_derived=True),
            Feature('routing_success_rate', 'float', 'node', 'Routing success rate'),
            Feature('betweenness_centrality', 'float', 'node', 'Network centrality measure')
        ]
        
        # Add all features to store
        for feature in payment_features + channel_features + node_features:
            self.feature_store[feature.name] = feature
    
    async def train_model(self, task: PredictionTask, training_data: TrainingData,
                         algorithm: str = 'random_forest') -> str:
        """Train a machine learning model."""
        model_id = f"{task.value}_{algorithm}_{int(datetime.utcnow().timestamp())}"
        
        logger.info(f"Training model {model_id} for task {task.value}")
        
        # Prepare data
        X_train, X_test, y_train, y_test = training_data.split()
        
        # Determine model type
        model_type = self._get_model_type(task)
        
        # Create and train model
        if not HAS_SKLEARN:
            logger.error("scikit-learn not available for model training")
            return ""
        
        model_object = await self._create_model(algorithm, model_type)
        
        # Train model
        model_object.fit(X_train, y_train)
        
        # Evaluate model
        y_pred = model_object.predict(X_test)
        metrics = self._evaluate_model(y_test, y_pred, model_type)
        
        # Feature importance
        feature_importance = {}
        if hasattr(model_object, 'feature_importances_'):
            for i, importance in enumerate(model_object.feature_importances_):
                feature_name = training_data.features.columns[i]
                if feature_name in self.feature_store:
                    self.feature_store[feature_name].importance = importance
                feature_importance[feature_name] = importance
        
        # Create model wrapper
        model = MLModel(
            model_id=model_id,
            model_type=model_type,
            task=task,
            algorithm=algorithm,
            version=1,
            model_object=model_object,
            features=[self.feature_store[col] for col in training_data.features.columns if col in self.feature_store],
            performance_metrics=metrics
        )
        
        # Store model
        self.models[model_id] = model
        await self._save_model(model)
        
        logger.info(f"Model {model_id} trained with performance: {metrics}")
        
        return model_id
    
    def _get_model_type(self, task: PredictionTask) -> ModelType:
        """Get model type for prediction task."""
        classification_tasks = [
            PredictionTask.PAYMENT_SUCCESS,
            PredictionTask.CHANNEL_FAILURE,
            PredictionTask.FRAUD_DETECTION,
            PredictionTask.CHURN_PREDICTION
        ]
        
        if task in classification_tasks:
            return ModelType.CLASSIFICATION
        elif task == PredictionTask.ANOMALY_DETECTION:
            return ModelType.CLUSTERING
        elif task == PredictionTask.DEMAND_FORECAST:
            return ModelType.TIME_SERIES
        else:
            return ModelType.REGRESSION
    
    async def _create_model(self, algorithm: str, model_type: ModelType) -> Any:
        """Create model based on algorithm and type."""
        if model_type == ModelType.REGRESSION:
            if algorithm == 'random_forest':
                return RandomForestRegressor(n_estimators=100, random_state=42)
            elif algorithm == 'gradient_boosting':
                return GradientBoostingRegressor(n_estimators=100, random_state=42)
            else:
                return LinearRegression()
        
        elif model_type == ModelType.CLASSIFICATION:
            if algorithm == 'random_forest':
                return RandomForestClassifier(n_estimators=100, random_state=42)
            else:
                return LogisticRegression(random_state=42)
        
        elif model_type == ModelType.CLUSTERING:
            if algorithm == 'kmeans':
                return KMeans(n_clusters=5, random_state=42)
            else:
                return DBSCAN(eps=0.5, min_samples=5)
        
        else:
            # Default to random forest
            return RandomForestRegressor(n_estimators=100, random_state=42)
    
    def _evaluate_model(self, y_true: np.ndarray, y_pred: np.ndarray, 
                       model_type: ModelType) -> Dict[str, float]:
        """Evaluate model performance."""
        metrics = {}
        
        if model_type == ModelType.REGRESSION:
            metrics['mse'] = mean_squared_error(y_true, y_pred)
            metrics['mae'] = mean_absolute_error(y_true, y_pred)
            metrics['rmse'] = np.sqrt(metrics['mse'])
            metrics['r2'] = 1 - (metrics['mse'] / np.var(y_true))
        
        elif model_type == ModelType.CLASSIFICATION:
            metrics['accuracy'] = accuracy_score(y_true, y_pred)
            precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average='weighted')
            metrics['precision'] = precision
            metrics['recall'] = recall
            metrics['f1'] = f1
        
        return metrics
    
    async def predict(self, model_id: str, features: Dict[str, Any]) -> PredictionResult:
        """Make prediction using trained model."""
        model = self.models.get(model_id)
        if not model:
            raise ValueError(f"Model {model_id} not found")
        
        # Prepare features
        feature_values = []
        for feature in model.features:
            value = features.get(feature.name, 0)
            value = feature.apply_transformation(value)
            feature_values.append(value)
        
        # Make prediction
        X = np.array(feature_values).reshape(1, -1)
        prediction = model.model_object.predict(X)[0]
        
        # Calculate confidence
        confidence = 1.0  # Default confidence
        if hasattr(model.model_object, 'predict_proba'):
            probabilities = model.model_object.predict_proba(X)[0]
            confidence = max(probabilities)
        
        # Create result
        result = PredictionResult(
            prediction_id=f"pred_{int(datetime.utcnow().timestamp())}",
            model_id=model_id,
            task=model.task,
            prediction=prediction,
            confidence=confidence,
            feature_values=features
        )
        
        # Update model
        model.last_prediction = datetime.utcnow()
        
        # Store prediction
        self.predictions.append(result)
        
        return result
    
    async def _save_model(self, model: MLModel) -> None:
        """Save model to disk."""
        if not HAS_SKLEARN:
            return
        
        model_path = self.model_dir / f"{model.model_id}.pkl"
        
        # Save model object
        joblib.dump(model.model_object, model_path)
        
        # Save metadata
        metadata = {
            'model_id': model.model_id,
            'model_type': model.model_type.value,
            'task': model.task.value,
            'algorithm': model.algorithm,
            'version': model.version,
            'features': [f.name for f in model.features],
            'performance_metrics': model.performance_metrics,
            'training_date': model.training_date.isoformat()
        }
        
        metadata_path = self.model_dir / f"{model.model_id}_metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Saved model {model.model_id} to {model_path}")
    
    async def load_model(self, model_id: str) -> bool:
        """Load model from disk."""
        if not HAS_SKLEARN:
            return False
        
        model_path = self.model_dir / f"{model_id}.pkl"
        metadata_path = self.model_dir / f"{model_id}_metadata.json"
        
        if not model_path.exists() or not metadata_path.exists():
            return False
        
        try:
            # Load model object
            model_object = joblib.load(model_path)
            
            # Load metadata
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            # Create model wrapper
            model = MLModel(
                model_id=model_id,
                model_type=ModelType(metadata['model_type']),
                task=PredictionTask(metadata['task']),
                algorithm=metadata['algorithm'],
                version=metadata['version'],
                model_object=model_object,
                features=[self.feature_store[name] for name in metadata['features'] if name in self.feature_store],
                performance_metrics=metadata['performance_metrics'],
                training_date=datetime.fromisoformat(metadata['training_date'])
            )
            
            self.models[model_id] = model
            
            logger.info(f"Loaded model {model_id} from disk")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load model {model_id}: {e}")
            return False
    
    async def create_deep_learning_model(self, task: PredictionTask, 
                                        input_shape: Tuple[int, ...]) -> Optional[str]:
        """Create deep learning model using TensorFlow/PyTorch."""
        if not self.config.get('enable_deep_learning'):
            logger.warning("Deep learning not enabled")
            return None
        
        model_id = f"{task.value}_deep_{int(datetime.utcnow().timestamp())}"
        
        if HAS_TENSORFLOW:
            model = await self._create_tensorflow_model(task, input_shape)
        elif HAS_PYTORCH:
            model = await self._create_pytorch_model(task, input_shape)
        else:
            logger.error("No deep learning framework available")
            return None
        
        # Create wrapper
        ml_model = MLModel(
            model_id=model_id,
            model_type=ModelType.DEEP_LEARNING,
            task=task,
            algorithm='neural_network',
            version=1,
            model_object=model,
            features=[]  # Features handled differently for DL
        )
        
        self.models[model_id] = ml_model
        
        logger.info(f"Created deep learning model {model_id}")
        return model_id
    
    async def _create_tensorflow_model(self, task: PredictionTask, 
                                      input_shape: Tuple[int, ...]) -> Any:
        """Create TensorFlow/Keras model."""
        if not HAS_TENSORFLOW:
            return None
        
        model = keras.Sequential()
        
        # Input layer
        model.add(layers.Dense(128, activation='relu', input_shape=input_shape))
        model.add(layers.Dropout(0.2))
        
        # Hidden layers
        model.add(layers.Dense(64, activation='relu'))
        model.add(layers.Dropout(0.2))
        model.add(layers.Dense(32, activation='relu'))
        
        # Output layer
        if self._get_model_type(task) == ModelType.CLASSIFICATION:
            model.add(layers.Dense(2, activation='softmax'))
            model.compile(
                optimizer='adam',
                loss='sparse_categorical_crossentropy',
                metrics=['accuracy']
            )
        else:
            model.add(layers.Dense(1))
            model.compile(
                optimizer='adam',
                loss='mse',
                metrics=['mae']
            )
        
        return model
    
    async def _create_pytorch_model(self, task: PredictionTask, 
                                   input_shape: Tuple[int, ...]) -> Any:
        """Create PyTorch model."""
        if not HAS_PYTORCH:
            return None
        
        class LightningNet(nn.Module):
            def __init__(self, input_size, output_size=1):
                super(LightningNet, self).__init__()
                self.fc1 = nn.Linear(input_size, 128)
                self.fc2 = nn.Linear(128, 64)
                self.fc3 = nn.Linear(64, 32)
                self.fc4 = nn.Linear(32, output_size)
                self.dropout = nn.Dropout(0.2)
                self.relu = nn.ReLU()
            
            def forward(self, x):
                x = self.relu(self.fc1(x))
                x = self.dropout(x)
                x = self.relu(self.fc2(x))
                x = self.dropout(x)
                x = self.relu(self.fc3(x))
                x = self.fc4(x)
                return x
        
        output_size = 2 if self._get_model_type(task) == ModelType.CLASSIFICATION else 1
        model = LightningNet(input_shape[0], output_size)
        
        return model

class BusinessIntelligence:
    """Business intelligence and analytics."""
    
    def __init__(self, ml_pipeline: MLPipeline):
        """Initialize business intelligence."""
        self.ml_pipeline = ml_pipeline
        self.kpis: Dict[str, float] = {}
        self.trends: Dict[str, List[float]] = {}
        
    def calculate_kpis(self, data: Dict[str, Any]) -> Dict[str, float]:
        """Calculate key performance indicators."""
        kpis = {}
        
        # Revenue KPIs
        kpis['total_revenue'] = data.get('total_fees_earned', 0)
        kpis['average_fee_rate'] = data.get('total_fees_earned', 0) / max(data.get('total_volume', 1), 1)
        kpis['revenue_per_channel'] = data.get('total_fees_earned', 0) / max(data.get('num_channels', 1), 1)
        
        # Operational KPIs
        kpis['payment_success_rate'] = data.get('successful_payments', 0) / max(data.get('total_payments', 1), 1)
        kpis['average_payment_time'] = data.get('total_payment_time', 0) / max(data.get('total_payments', 1), 1)
        kpis['channel_utilization'] = data.get('used_capacity', 0) / max(data.get('total_capacity', 1), 1)
        
        # Network KPIs
        kpis['network_connectivity'] = data.get('num_peers', 0) / max(data.get('total_nodes', 1), 1)
        kpis['liquidity_efficiency'] = data.get('routed_volume', 0) / max(data.get('locked_capacity', 1), 1)
        
        # Growth KPIs
        kpis['user_growth_rate'] = (data.get('new_users', 0) - data.get('churned_users', 0)) / max(data.get('total_users', 1), 1)
        kpis['volume_growth_rate'] = (data.get('current_volume', 0) - data.get('previous_volume', 0)) / max(data.get('previous_volume', 1), 1)
        
        self.kpis = kpis
        return kpis
    
    def analyze_trends(self, time_series_data: pd.DataFrame) -> Dict[str, Any]:
        """Analyze trends in time series data."""
        trends = {}
        
        for column in time_series_data.columns:
            series = time_series_data[column]
            
            # Calculate trend metrics
            trend_metrics = {
                'direction': 'up' if series.iloc[-1] > series.iloc[0] else 'down',
                'change_percent': ((series.iloc[-1] - series.iloc[0]) / series.iloc[0] * 100) if series.iloc[0] != 0 else 0,
                'volatility': series.std(),
                'moving_average_7d': series.tail(7).mean() if len(series) >= 7 else series.mean(),
                'moving_average_30d': series.tail(30).mean() if len(series) >= 30 else series.mean()
            }
            
            # Detect anomalies (simple z-score method)
            z_scores = np.abs((series - series.mean()) / series.std())
            anomalies = series[z_scores > 3].index.tolist()
            trend_metrics['anomalies'] = anomalies
            
            trends[column] = trend_metrics
        
        return trends
    
    def generate_insights(self) -> List[str]:
        """Generate business insights from analytics."""
        insights = []
        
        # Revenue insights
        if self.kpis.get('average_fee_rate', 0) < 0.001:
            insights.append("Fee rates are below market average - consider optimization")
        
        if self.kpis.get('revenue_per_channel', 0) < 100:
            insights.append("Low revenue per channel - focus on high-value routes")
        
        # Operational insights
        if self.kpis.get('payment_success_rate', 0) < 0.95:
            insights.append("Payment success rate below target - investigate routing issues")
        
        if self.kpis.get('channel_utilization', 0) < 0.3:
            insights.append("Low channel utilization - consider rebalancing or closing underused channels")
        
        # Growth insights
        if self.kpis.get('user_growth_rate', 0) < 0:
            insights.append("Negative user growth - implement retention strategies")
        
        if self.kpis.get('volume_growth_rate', 0) > 0.5:
            insights.append("Rapid volume growth - ensure infrastructure can handle increased load")
        
        return insights
    
    async def forecast_demand(self, historical_data: pd.Series, horizon: int = 7) -> np.ndarray:
        """Forecast future demand."""
        if len(historical_data) < 30:
            # Not enough data for forecasting
            return np.array([historical_data.mean()] * horizon)
        
        # Create time series features
        features = FeatureEngineering.create_time_series_features(historical_data)
        
        # Use ML model for forecasting if available
        forecast_model_id = None
        for model_id, model in self.ml_pipeline.models.items():
            if model.task == PredictionTask.DEMAND_FORECAST and model.is_deployed:
                forecast_model_id = model_id
                break
        
        if forecast_model_id:
            # Use trained model
            predictions = []
            current_features = features
            
            for _ in range(horizon):
                result = await self.ml_pipeline.predict(forecast_model_id, current_features)
                predictions.append(result.prediction)
                
                # Update features for next prediction (simplified)
                current_features['lag_1'] = result.prediction
            
            return np.array(predictions)
        else:
            # Simple moving average forecast
            return np.array([historical_data.tail(7).mean()] * horizon)

# Global instance
_ml_pipeline: Optional[MLPipeline] = None
_business_intelligence: Optional[BusinessIntelligence] = None

def get_ml_pipeline() -> MLPipeline:
    """Get the global ML pipeline instance."""
    global _ml_pipeline
    
    if _ml_pipeline is None:
        _ml_pipeline = MLPipeline()
    
    return _ml_pipeline

def get_business_intelligence() -> BusinessIntelligence:
    """Get the global business intelligence instance."""
    global _business_intelligence, _ml_pipeline
    
    if _business_intelligence is None:
        if _ml_pipeline is None:
            _ml_pipeline = MLPipeline()
        _business_intelligence = BusinessIntelligence(_ml_pipeline)
    
    return _business_intelligence

def initialize_analytics(config: Optional[Dict[str, Any]] = None) -> Tuple[MLPipeline, BusinessIntelligence]:
    """Initialize analytics and ML systems."""
    global _ml_pipeline, _business_intelligence
    
    _ml_pipeline = MLPipeline(config)
    _business_intelligence = BusinessIntelligence(_ml_pipeline)
    
    logger.info("Initialized analytics and machine learning pipeline")
    return _ml_pipeline, _business_intelligence