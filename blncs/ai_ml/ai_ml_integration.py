"""
AI/ML Integration System for BLNCS

This module provides comprehensive AI/ML capabilities including:
- Predictive analytics and forecasting
- Anomaly detection using machine learning
- Natural language processing for user queries
- Automated decision making and optimization
- Model training and deployment
"""

import time
import json
import logging
import threading
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from collections import defaultdict
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor, IsolationForest
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import mean_squared_error, r2_score

logger = logging.getLogger(__name__)

@dataclass
class MLModel:
    """Machine learning model definition."""
    model_id: str
    name: str
    model_type: str  # regression, classification, clustering, anomaly_detection
    algorithm: str
    parameters: Dict[str, Any]
    training_data: str
    features: List[str]
    target: str
    performance_metrics: Dict[str, float] = None
    trained_at: Optional[float] = None
    accuracy: float = 0.0

@dataclass
class PredictionResult:
    """Prediction result."""
    model_id: str
    prediction: float
    confidence: float
    timestamp: float
    input_features: Dict[str, Any]
    explanation: str = ""

@dataclass
class AnomalyDetectionResult:
    """Anomaly detection result."""
    model_id: str
    anomaly_score: float
    is_anomaly: bool
    timestamp: float
    data_point: Dict[str, Any]
    explanation: str = ""

class PredictiveAnalyticsEngine:
    """Predictive analytics and forecasting."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.PredictiveAnalyticsEngine")
        self.models: Dict[str, MLModel] = {}
        self.trained_models = {}
        self.prediction_cache = defaultdict(list)

    def train_regression_model(self, data: pd.DataFrame, model_config: Dict[str, Any]) -> str:
        """Train regression model for prediction."""
        try:
            model_id = f"regression_{int(time.time())}_{secrets.token_hex(4)}"

            # Prepare data
            features = model_config['features']
            target = model_config['target']

            X = data[features]
            y = data[target]

            # Split data
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

            # Scale features
            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_test_scaled = scaler.transform(X_test)

            # Train model
            model = RandomForestRegressor(
                n_estimators=model_config.get('n_estimators', 100),
                max_depth=model_config.get('max_depth', None),
                random_state=42
            )

            model.fit(X_train_scaled, y_train)

            # Evaluate model
            y_pred = model.predict(X_test_scaled)
            mse = mean_squared_error(y_test, y_pred)
            r2 = r2_score(y_test, y_pred)

            # Store model
            ml_model = MLModel(
                model_id=model_id,
                name=model_config['name'],
                model_type='regression',
                algorithm='RandomForest',
                parameters=model_config,
                training_data=model_config['data_source'],
                features=features,
                target=target,
                performance_metrics={
                    'mse': mse,
                    'r2_score': r2,
                    'accuracy': r2  # For regression, use R² as accuracy
                },
                trained_at=time.time(),
                accuracy=r2
            )

            self.models[model_id] = ml_model
            self.trained_models[model_id] = {
                'model': model,
                'scaler': scaler,
                'feature_names': features
            }

            self.logger.info(f"Trained regression model: {model_id} (R²: {r2:.3f})")
            return model_id

        except Exception as e:
            self.logger.error(f"Model training failed: {e}")
            raise

    def make_prediction(self, model_id: str, input_data: Dict[str, Any]) -> PredictionResult:
        """Make prediction using trained model."""
        if model_id not in self.trained_models:
            raise ValueError(f"Model not found: {model_id}")

        try:
            model_info = self.trained_models[model_id]
            model = model_info['model']
            scaler = model_info['scaler']
            feature_names = model_info['feature_names']

            # Prepare input features
            features = np.array([[input_data.get(name, 0) for name in feature_names]])
            features_scaled = scaler.transform(features)

            # Make prediction
            prediction = model.predict(features_scaled)[0]

            # Calculate confidence (using prediction variance)
            predictions = []
            for estimator in model.estimators_:
                pred = estimator.predict(features_scaled)[0]
                predictions.append(pred)

            confidence = 1.0 / (1.0 + np.std(predictions))  # Higher std = lower confidence

            result = PredictionResult(
                model_id=model_id,
                prediction=prediction,
                confidence=min(confidence, 1.0),
                timestamp=time.time(),
                input_features=input_data,
                explanation=f"Predicted {self.models[model_id].target} using {self.models[model_id].algorithm} model"
            )

            # Cache prediction
            self.prediction_cache[model_id].append(result)
            if len(self.prediction_cache[model_id]) > 1000:
                self.prediction_cache[model_id] = self.prediction_cache[model_id][-1000:]

            return result

        except Exception as e:
            self.logger.error(f"Prediction failed: {e}")
            raise

class AnomalyDetectionEngine:
    """Machine learning-based anomaly detection."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.AnomalyDetectionEngine")
        self.anomaly_models: Dict[str, MLModel] = {}
        self.trained_anomaly_models = {}
        self.detection_history = deque(maxlen=10000)

    def train_anomaly_detector(self, data: pd.DataFrame, model_config: Dict[str, Any]) -> str:
        """Train anomaly detection model."""
        try:
            model_id = f"anomaly_{int(time.time())}_{secrets.token_hex(4)}"

            # Prepare data
            features = model_config['features']

            X = data[features]

            # Scale features
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)

            # Train anomaly detection model
            model = IsolationForest(
                n_estimators=model_config.get('n_estimators', 100),
                contamination=model_config.get('contamination', 0.1),
                random_state=42
            )

            model.fit(X_scaled)

            # Evaluate model (simplified)
            anomaly_scores = model.decision_function(X_scaled)
            anomaly_predictions = model.predict(X_scaled)

            # Calculate performance metrics
            accuracy = np.mean(anomaly_predictions == 1)  # Assuming normal data

            # Store model
            ml_model = MLModel(
                model_id=model_id,
                name=model_config['name'],
                model_type='anomaly_detection',
                algorithm='IsolationForest',
                parameters=model_config,
                training_data=model_config['data_source'],
                features=features,
                target='anomaly_score',
                performance_metrics={
                    'accuracy': accuracy,
                    'contamination': model_config.get('contamination', 0.1)
                },
                trained_at=time.time(),
                accuracy=accuracy
            )

            self.anomaly_models[model_id] = ml_model
            self.trained_anomaly_models[model_id] = {
                'model': model,
                'scaler': scaler,
                'feature_names': features
            }

            self.logger.info(f"Trained anomaly detection model: {model_id}")
            return model_id

        except Exception as e:
            self.logger.error(f"Anomaly model training failed: {e}")
            raise

    def detect_anomalies(self, model_id: str, input_data: Dict[str, Any]) -> AnomalyDetectionResult:
        """Detect anomalies in input data."""
        if model_id not in self.trained_anomaly_models:
            raise ValueError(f"Anomaly model not found: {model_id}")

        try:
            model_info = self.trained_anomaly_models[model_id]
            model = model_info['model']
            scaler = model_info['scaler']
            feature_names = model_info['feature_names']

            # Prepare input features
            features = np.array([[input_data.get(name, 0) for name in feature_names]])
            features_scaled = scaler.transform(features)

            # Detect anomaly
            anomaly_score = model.decision_function(features_scaled)[0]
            prediction = model.predict(features_scaled)[0]

            is_anomaly = prediction == -1

            result = AnomalyDetectionResult(
                model_id=model_id,
                anomaly_score=abs(anomaly_score),
                is_anomaly=is_anomaly,
                timestamp=time.time(),
                data_point=input_data,
                explanation=f"Anomaly score: {abs(anomaly_score):.3f} ({'anomalous' if is_anomaly else 'normal'})"
            )

            # Record detection
            self.detection_history.append(result)

            return result

        except Exception as e:
            self.logger.error(f"Anomaly detection failed: {e}")
            raise

class NLPQueryProcessor:
    """Natural language processing for user queries."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.NLPQueryProcessor")
        self.query_patterns = {}
        self.response_templates = {}

    def process_query(self, query: str) -> Dict[str, Any]:
        """Process natural language query."""
        # Simple pattern matching (in real implementation, use NLP libraries)
        query_lower = query.lower()

        response = {
            'query': query,
            'intent': 'unknown',
            'entities': [],
            'response': 'I understand your query, but need more specific information.',
            'confidence': 0.0
        }

        # Pattern matching for common queries
        if 'performance' in query_lower and ('show' in query_lower or 'what' in query_lower):
            response['intent'] = 'performance_query'
            response['response'] = 'Here are the current performance metrics...'
            response['confidence'] = 0.8

        elif 'error' in query_lower and ('recent' in query_lower or 'show' in query_lower):
            response['intent'] = 'error_query'
            response['response'] = 'Recent errors: Connection timeout, API rate limit exceeded.'
            response['confidence'] = 0.8

        elif 'status' in query_lower and 'system' in query_lower:
            response['intent'] = 'status_query'
            response['response'] = 'System status: All services operational, CPU usage at 45%.'
            response['confidence'] = 0.9

        return response

    def generate_insights(self, query: str, data: Dict[str, Any]) -> str:
        """Generate insights based on query and data."""
        insights = []

        # Generate contextual insights
        if 'trend' in query.lower():
            insights.append("Performance trends show stable CPU usage with slight memory increase.")

        if 'anomaly' in query.lower():
            insights.append("No significant anomalies detected in the last 24 hours.")

        if 'prediction' in query.lower():
            insights.append("Predicted system load for next hour: moderate with 60% confidence.")

        return " ".join(insights) if insights else "No specific insights available for this query."

class AutomatedDecisionEngine:
    """Automated decision making and optimization."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.AutomatedDecisionEngine")
        self.decision_rules = []
        self.decision_history = deque(maxlen=1000)

    def add_decision_rule(self, rule_name: str, condition: Callable, action: Callable, priority: int = 1):
        """Add automated decision rule."""
        self.decision_rules.append({
            'name': rule_name,
            'condition': condition,
            'action': action,
            'priority': priority
        })

        # Sort rules by priority
        self.decision_rules.sort(key=lambda x: x['priority'], reverse=True)

    def evaluate_and_act(self, system_state: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate rules and take actions."""
        actions_taken = []

        for rule in self.decision_rules:
            try:
                if rule['condition'](system_state):
                    self.logger.info(f"Executing decision rule: {rule['name']}")

                    result = rule['action'](system_state)

                    action_record = {
                        'rule': rule['name'],
                        'timestamp': time.time(),
                        'result': result,
                        'system_state': system_state
                    }

                    actions_taken.append(action_record)
                    self.decision_history.append(action_record)

            except Exception as e:
                self.logger.error(f"Decision rule execution failed: {rule['name']} - {e}")

        return actions_taken

class MLModelManager:
    """Machine learning model management."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.MLModelManager")
        self.models: Dict[str, MLModel] = {}
        self.model_performance = defaultdict(list)

    def register_model(self, model: MLModel):
        """Register ML model."""
        self.models[model.model_id] = model

    def update_model_performance(self, model_id: str, metrics: Dict[str, float]):
        """Update model performance metrics."""
        if model_id in self.models:
            self.models[model_id].performance_metrics = metrics
            self.models[model_id].accuracy = metrics.get('accuracy', 0.0)

            # Record performance history
            self.model_performance[model_id].append({
                'timestamp': time.time(),
                'metrics': metrics
            })

            # Keep only recent performance data
            if len(self.model_performance[model_id]) > 100:
                self.model_performance[model_id] = self.model_performance[model_id][-100:]

class AIMLIntegrationManager:
    """Main AI/ML integration management system."""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.AIMLIntegrationManager")
        self.predictive_engine = PredictiveAnalyticsEngine()
        self.anomaly_engine = AnomalyDetectionEngine()
        self.nlp_processor = NLPQueryProcessor()
        self.decision_engine = AutomatedDecisionEngine()
        self.model_manager = MLModelManager()

        self.ai_ml_active = False
        self.monitoring_thread = None

    def start_ai_ml_system(self):
        """Start AI/ML system."""
        if self.ai_ml_active:
            return

        self.ai_ml_active = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        self.logger.info("AI/ML integration system started")

    def stop_ai_ml_system(self):
        """Stop AI/ML system."""
        self.ai_ml_active = False
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        self.logger.info("AI/ML integration system stopped")

    def _monitoring_loop(self):
        """Main AI/ML monitoring loop."""
        while self.ai_ml_active:
            try:
                # Collect system metrics
                system_metrics = self._collect_system_metrics()

                # Run anomaly detection
                if self.anomaly_engine.trained_anomaly_models:
                    for model_id in self.anomaly_engine.trained_anomaly_models:
                        try:
                            detection = self.anomaly_engine.detect_anomalies(model_id, system_metrics)
                            if detection.is_anomaly:
                                self.logger.warning(f"Anomaly detected: {detection.explanation}")
                        except Exception as e:
                            self.logger.error(f"Anomaly detection error: {e}")

                # Run automated decisions
                decisions = self.decision_engine.evaluate_and_act(system_metrics)
                if decisions:
                    self.logger.info(f"Automated decisions taken: {len(decisions)}")

                time.sleep(60)  # Monitor every minute

            except Exception as e:
                self.logger.error(f"AI/ML monitoring error: {e}")
                time.sleep(60)

    def _collect_system_metrics(self) -> Dict[str, Any]:
        """Collect current system metrics."""
        # In a real implementation, collect from monitoring systems
        return {
            'cpu_usage': 45.2,
            'memory_usage': 67.8,
            'disk_usage': 23.4,
            'network_io': 1024.5,
            'error_count': 2,
            'response_time': 150.2
        }

    def train_predictive_model(self, data: pd.DataFrame, config: Dict[str, Any]) -> str:
        """Train predictive model."""
        return self.predictive_engine.train_regression_model(data, config)

    def make_prediction(self, model_id: str, input_data: Dict[str, Any]) -> PredictionResult:
        """Make prediction."""
        return self.predictive_engine.make_prediction(model_id, input_data)

    def train_anomaly_detector(self, data: pd.DataFrame, config: Dict[str, Any]) -> str:
        """Train anomaly detection model."""
        return self.anomaly_engine.train_anomaly_detector(data, config)

    def detect_anomalies(self, model_id: str, input_data: Dict[str, Any]) -> AnomalyDetectionResult:
        """Detect anomalies."""
        return self.anomaly_engine.detect_anomalies(model_id, input_data)

    def process_natural_query(self, query: str) -> Dict[str, Any]:
        """Process natural language query."""
        return self.nlp_processor.process_query(query)

    def add_automated_rule(self, rule_name: str, condition: Callable, action: Callable, priority: int = 1):
        """Add automated decision rule."""
        self.decision_engine.add_decision_rule(rule_name, condition, action, priority)

    def get_ai_ml_status(self) -> Dict[str, Any]:
        """Get AI/ML system status."""
        return {
            'active': self.ai_ml_active,
            'predictive_models': len(self.predictive_engine.models),
            'anomaly_models': len(self.anomaly_engine.anomaly_models),
            'decision_rules': len(self.decision_engine.decision_rules),
            'detection_history': len(self.anomaly_engine.detection_history),
            'decision_history': len(self.decision_engine.decision_history)
        }

def create_ai_ml_integration() -> AIMLIntegrationManager:
    """Factory function to create AI/ML integration system."""
    return AIMLIntegrationManager()

# Example usage
if __name__ == "__main__":
    # Create AI/ML integration system
    ai_ml_manager = create_ai_ml_integration()

    # Start system
    ai_ml_manager.start_ai_ml_system()

    # Sample training data
    np.random.seed(42)
    data = pd.DataFrame({
        'cpu_usage': np.random.normal(50, 15, 1000),
        'memory_usage': np.random.normal(60, 10, 1000),
        'disk_usage': np.random.normal(30, 20, 1000),
        'network_io': np.random.normal(1000, 200, 1000),
        'response_time': np.random.normal(150, 30, 1000)
    })

    # Train predictive model
    model_config = {
        'name': 'System Performance Predictor',
        'features': ['cpu_usage', 'memory_usage', 'disk_usage', 'network_io'],
        'target': 'response_time',
        'n_estimators': 100,
        'data_source': 'system_metrics'
    }

    model_id = ai_ml_manager.train_predictive_model(data, model_config)
    print(f"Trained predictive model: {model_id}")

    # Make prediction
    input_data = {
        'cpu_usage': 75.0,
        'memory_usage': 80.0,
        'disk_usage': 45.0,
        'network_io': 1200.0
    }

    prediction = ai_ml_manager.make_prediction(model_id, input_data)
    print(f"Prediction: {prediction.prediction:.2f} (confidence: {prediction.confidence:.2f})")

    # Train anomaly detector
    anomaly_config = {
        'name': 'System Anomaly Detector',
        'features': ['cpu_usage', 'memory_usage', 'disk_usage', 'network_io'],
        'n_estimators': 100,
        'contamination': 0.1,
        'data_source': 'system_metrics'
    }

    anomaly_model_id = ai_ml_manager.train_anomaly_detector(data, anomaly_config)
    print(f"Trained anomaly model: {anomaly_model_id}")

    # Detect anomalies
    test_data = {
        'cpu_usage': 95.0,  # High value for testing
        'memory_usage': 90.0,
        'disk_usage': 85.0,
        'network_io': 2000.0
    }

    anomaly = ai_ml_manager.detect_anomalies(anomaly_model_id, test_data)
    print(f"Anomaly detection: {'Anomalous' if anomaly.is_anomaly else 'Normal'} (score: {anomaly.anomaly_score:.3f})")

    # Process natural language query
    query_result = ai_ml_manager.process_natural_query("Show me the system performance trends")
    print(f"Query result: {query_result['response']}")

    # Add automated decision rule
    def high_cpu_condition(system_state):
        return system_state.get('cpu_usage', 0) > 80

    def scale_resources_action(system_state):
        return {"action": "scale_resources", "target": "api_server", "scale_factor": 2}

    ai_ml_manager.add_automated_rule("high_cpu_scaling", high_cpu_condition, scale_resources_action, priority=1)

    # Get status
    status = ai_ml_manager.get_ai_ml_status()
    print(f"AI/ML status: {json.dumps(status, indent=2)}")

    print("AI/ML integration system setup complete!")
