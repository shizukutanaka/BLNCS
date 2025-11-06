"""
Intelligent Performance Optimization for BLNCS Enterprise
Provides machine learning-based optimization, predictive scaling, and automatic tuning
"""

import time
import threading
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Any, Callable
from collections import defaultdict, deque
from datetime import datetime, timedelta
import joblib
import json
from sklearn.ensemble import RandomForestRegressor, GradientBoostingRegressor
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error, r2_score
import logging

logger = logging.getLogger(__name__)

class WorkloadPredictor:
    """Machine learning-based workload prediction"""

    def __init__(self, prediction_window: int = 24):  # Hours
        self.prediction_window = prediction_window
        self.model = None
        self.scaler = StandardScaler()
        self.feature_history = deque(maxlen=10000)
        self.prediction_history = deque(maxlen=1000)
        self.lock = threading.Lock()

    def _extract_features(self, metrics: Dict[str, Any]) -> np.ndarray:
        """Extract features for prediction model"""
        features = [
            metrics.get('cpu_usage', 0),
            metrics.get('memory_usage', 0),
            metrics.get('disk_io', 0),
            metrics.get('network_io', 0),
            metrics.get('active_users', 0),
            metrics.get('request_rate', 0),
            metrics.get('error_rate', 0),
            metrics.get('response_time', 0),
            metrics.get('cache_hit_rate', 0),
            metrics.get('database_connections', 0),
            metrics.get('hour_of_day', datetime.now().hour),
            metrics.get('day_of_week', datetime.now().weekday()),
            metrics.get('is_weekend', 1 if datetime.now().weekday() >= 5 else 0),
            metrics.get('is_holiday', 0),  # Would integrate with holiday API
        ]
        return np.array(features).reshape(1, -1)

    def record_metrics(self, metrics: Dict[str, Any]):
        """Record current system metrics"""
        features = self._extract_features(metrics)
        timestamp = time.time()

        with self.lock:
            self.feature_history.append({
                'timestamp': timestamp,
                'features': features.flatten(),
                'target': metrics.get('predicted_load', 0)
            })

    def train_model(self):
        """Train prediction model using historical data"""
        with self.lock:
            if len(self.feature_history) < 100:
                logger.warning("Insufficient data for model training")
                return False

            # Prepare training data
            data = list(self.feature_history)
            X = np.array([item['features'] for item in data])
            y = np.array([item['target'] for item in data])

            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )

            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)

            # Train model
            self.model = RandomForestRegressor(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            )

            self.model.fit(X_train_scaled, y_train)

            # Evaluate model
            train_score = self.model.score(X_train_scaled, y_train)
            test_score = self.model.score(X_test_scaled, y_test)

            logger.info(f"Trained workload prediction model - Train R²: {train_score".3f"}, Test R²: {test_score".3f"}")

            return True

    def predict_workload(self, hours_ahead: int = 1) -> Dict[str, Any]:
        """Predict system workload for future time periods"""
        if self.model is None:
            if not self.train_model():
                return {'error': 'Model training failed'}

        # Get current metrics (would integrate with actual monitoring)
        current_metrics = self._get_current_metrics()
        features = self._extract_features(current_metrics)
        features_scaled = self.scaler.transform(features)

        # Make prediction
        predicted_load = self.model.predict(features_scaled)[0]

        # Generate time-series predictions
        predictions = []
        base_time = datetime.now()

        for hour in range(hours_ahead):
            prediction_time = base_time + timedelta(hours=hour + 1)

            # Adjust prediction based on time patterns
            time_factor = 1.0
            if prediction_time.weekday() >= 5:  # Weekend
                time_factor *= 0.7
            if 9 <= prediction_time.hour <= 17:  # Business hours
                time_factor *= 1.2

            adjusted_prediction = predicted_load * time_factor
            predictions.append({
                'timestamp': prediction_time.isoformat(),
                'predicted_load': max(0, min(100, adjusted_prediction)),
                'confidence': 0.85  # Would calculate based on model uncertainty
            })

        with self.lock:
            self.prediction_history.append({
                'timestamp': time.time(),
                'predictions': predictions
            })

        return {
            'current_prediction': predictions[0] if predictions else None,
            'hourly_predictions': predictions,
            'model_confidence': 0.85
        }

    def _get_current_metrics(self) -> Dict[str, Any]:
        """Get current system metrics (integration point)"""
        # This would integrate with actual monitoring systems
        return {
            'cpu_usage': 45.0,
            'memory_usage': 60.0,
            'disk_io': 120.0,
            'network_io': 500.0,
            'active_users': 25,
            'request_rate': 100.0,
            'error_rate': 0.02,
            'response_time': 150.0,
            'cache_hit_rate': 85.0,
            'database_connections': 10
        }

class AutoScaler:
    """Intelligent automatic scaling system"""

    def __init__(self):
        self.scaling_policies = {}
        self.current_resources = {}
        self.scaling_history = deque(maxlen=1000)
        self.workload_predictor = WorkloadPredictor()
        self.lock = threading.Lock()

    def define_scaling_policy(self, resource_type: str, policy: Dict[str, Any]):
        """Define scaling policy for resource type"""
        self.scaling_policies[resource_type] = {
            'min_instances': policy.get('min_instances', 1),
            'max_instances': policy.get('max_instances', 10),
            'target_utilization': policy.get('target_utilization', 70),
            'scale_up_threshold': policy.get('scale_up_threshold', 80),
            'scale_down_threshold': policy.get('scale_down_threshold', 30),
            'cooldown_period': policy.get('cooldown_period', 300),  # 5 minutes
            'last_scale_time': 0
        }

    def evaluate_scaling(self, resource_type: str, current_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate if scaling is needed"""
        if resource_type not in self.scaling_policies:
            return {'action': 'none', 'reason': 'No policy defined'}

        policy = self.scaling_policies[resource_type]
        current_time = time.time()

        # Check cooldown period
        if current_time - policy['last_scale_time'] < policy['cooldown_period']:
            return {'action': 'none', 'reason': 'Cooldown period active'}

        # Get current utilization
        utilization = self._calculate_utilization(resource_type, current_metrics)

        # Get workload prediction
        prediction = self.workload_predictor.predict_workload(hours_ahead=1)

        # Make scaling decision
        decision = self._make_scaling_decision(
            resource_type, utilization, prediction, policy
        )

        if decision['action'] != 'none':
            policy['last_scale_time'] = current_time

            with self.lock:
                self.scaling_history.append({
                    'timestamp': current_time,
                    'resource_type': resource_type,
                    'action': decision['action'],
                    'reason': decision['reason'],
                    'utilization': utilization,
                    'target_instances': decision.get('target_instances', 0)
                })

        return decision

    def _calculate_utilization(self, resource_type: str, metrics: Dict[str, Any]) -> float:
        """Calculate resource utilization percentage"""
        if resource_type == 'cpu':
            return metrics.get('cpu_usage', 0)
        elif resource_type == 'memory':
            return metrics.get('memory_usage', 0)
        elif resource_type == 'web_server':
            return min(100, metrics.get('request_rate', 0) / 10)  # Simplified
        else:
            return 50.0  # Default

    def _make_scaling_decision(self, resource_type: str, utilization: float,
                             prediction: Dict[str, Any], policy: Dict[str, Any]) -> Dict[str, Any]:
        """Make intelligent scaling decision"""
        current_instances = self.current_resources.get(resource_type, 1)

        # Scale up logic
        if (utilization > policy['scale_up_threshold'] or
            prediction.get('current_prediction', {}).get('predicted_load', 0) > policy['target_utilization']):

            if current_instances < policy['max_instances']:
                target_instances = min(
                    policy['max_instances'],
                    current_instances + max(1, current_instances // 3)  # Scale by 33%
                )
                return {
                    'action': 'scale_up',
                    'target_instances': target_instances,
                    'reason': f'High utilization ({utilization".1f"}%) and predicted load'
                }

        # Scale down logic
        elif (utilization < policy['scale_down_threshold'] and
              prediction.get('current_prediction', {}).get('predicted_load', 0) < policy['target_utilization']):

            if current_instances > policy['min_instances']:
                target_instances = max(
                    policy['min_instances'],
                    current_instances - max(1, current_instances // 4)  # Scale down by 25%
                )
                return {
                    'action': 'scale_down',
                    'target_instances': target_instances,
                    'reason': f'Low utilization ({utilization".1f"}%) and predicted load'
                }

        return {'action': 'none', 'reason': 'No scaling needed'}

class PerformanceTuner:
    """Automatic performance tuning system"""

    def __init__(self):
        self.tuning_parameters = {}
        self.performance_models = {}
        self.tuning_history = deque(maxlen=5000)
        self.lock = threading.Lock()

    def register_tunable_parameter(self, param_name: str, param_config: Dict[str, Any]):
        """Register a parameter that can be automatically tuned"""
        self.tuning_parameters[param_name] = {
            'min_value': param_config.get('min_value', 1),
            'max_value': param_config.get('max_value', 100),
            'current_value': param_config.get('default_value', 10),
            'step_size': param_config.get('step_size', 1),
            'impact_metric': param_config.get('impact_metric', 'response_time'),
            'optimization_goal': param_config.get('optimization_goal', 'minimize')
        }

    def tune_parameters(self, performance_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Automatically tune parameters based on performance metrics"""
        tuning_results = {}

        for param_name, config in self.tuning_parameters.items():
            # Get current performance impact
            current_value = config['current_value']
            impact_metric = config['impact_metric']
            current_performance = performance_metrics.get(impact_metric, 0)

            # Determine tuning direction
            if config['optimization_goal'] == 'minimize':
                # Lower values are better
                if current_performance > self._get_performance_target(param_name):
                    # Performance is worse than target, try lower value
                    new_value = max(config['min_value'],
                                  current_value - config['step_size'])
                    action = 'decrease'
                else:
                    # Performance is good, try higher value for efficiency
                    new_value = min(config['max_value'],
                                  current_value + config['step_size'])
                    action = 'increase'
            else:
                # Higher values are better
                if current_performance < self._get_performance_target(param_name):
                    # Performance is worse than target, try higher value
                    new_value = min(config['max_value'],
                                  current_value + config['step_size'])
                    action = 'increase'
                else:
                    # Performance is good, try lower value for efficiency
                    new_value = max(config['min_value'],
                                  current_value - config['step_size'])
                    action = 'decrease'

            # Apply tuning
            config['current_value'] = new_value

            tuning_results[param_name] = {
                'old_value': current_value,
                'new_value': new_value,
                'action': action,
                'reason': f'Performance optimization for {impact_metric}',
                'expected_impact': self._calculate_expected_impact(param_name, action)
            }

            with self.lock:
                self.tuning_history.append({
                    'timestamp': time.time(),
                    'parameter': param_name,
                    'old_value': current_value,
                    'new_value': new_value,
                    'performance_metric': impact_metric,
                    'performance_value': current_performance
                })

        return tuning_results

    def _get_performance_target(self, param_name: str) -> float:
        """Get performance target for parameter"""
        # These would be configured based on SLA requirements
        targets = {
            'cache_size': 90.0,      # 90% cache hit rate
            'connection_pool': 50.0, # 50ms average response time
            'worker_threads': 100.0, # 100 requests/second
            'batch_size': 95.0       # 95% throughput efficiency
        }
        return targets.get(param_name, 80.0)

    def _calculate_expected_impact(self, param_name: str, action: str) -> str:
        """Calculate expected impact of parameter change"""
        impacts = {
            'cache_size_increase': 'Improved cache hit rate, increased memory usage',
            'cache_size_decrease': 'Reduced memory usage, potential cache misses',
            'connection_pool_increase': 'Better concurrency, higher resource usage',
            'connection_pool_decrease': 'Lower resource usage, potential bottlenecks',
            'worker_threads_increase': 'Better throughput, higher CPU usage',
            'worker_threads_decrease': 'Lower CPU usage, potential queuing'
        }
        return impacts.get(f'{param_name}_{action}', 'Unknown impact')

class ResourceOptimizer:
    """Comprehensive resource optimization system"""

    def __init__(self):
        self.auto_scaler = AutoScaler()
        self.performance_tuner = PerformanceTuner()
        self.optimization_strategies = {}
        self.lock = threading.Lock()

    def register_optimization_strategy(self, name: str, strategy_func: Callable):
        """Register custom optimization strategy"""
        self.optimization_strategies[name] = strategy_func

    def optimize_resources(self, system_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive resource optimization"""
        optimization_results = {
            'timestamp': time.time(),
            'scaling_decisions': {},
            'tuning_decisions': {},
            'custom_optimizations': {},
            'overall_assessment': {}
        }

        # Record metrics for ML prediction
        self.auto_scaler.workload_predictor.record_metrics(system_metrics)

        # Evaluate scaling for each resource type
        for resource_type in ['cpu', 'memory', 'web_server', 'database']:
            scaling_decision = self.auto_scaler.evaluate_scaling(resource_type, system_metrics)
            if scaling_decision['action'] != 'none':
                optimization_results['scaling_decisions'][resource_type] = scaling_decision

        # Perform automatic tuning
        tuning_decisions = self.performance_tuner.tune_parameters(system_metrics)
        optimization_results['tuning_decisions'] = tuning_decisions

        # Apply custom optimization strategies
        for strategy_name, strategy_func in self.optimization_strategies.items():
            try:
                custom_result = strategy_func(system_metrics)
                optimization_results['custom_optimizations'][strategy_name] = custom_result
            except Exception as e:
                logger.error(f"Error in optimization strategy {strategy_name}: {e}")

        # Generate overall assessment
        optimization_results['overall_assessment'] = self._assess_optimization_impact(optimization_results)

        return optimization_results

    def _assess_optimization_impact(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Assess the overall impact of optimizations"""
        total_actions = (
            len(results['scaling_decisions']) +
            len(results['tuning_decisions']) +
            len(results['custom_optimizations'])
        )

        assessment = {
            'optimization_level': 'none' if total_actions == 0 else 'low' if total_actions <= 2 else 'medium' if total_actions <= 5 else 'high',
            'total_actions': total_actions,
            'estimated_performance_improvement': self._estimate_performance_improvement(results),
            'estimated_resource_savings': self._estimate_resource_savings(results)
        }

        return assessment

    def _estimate_performance_improvement(self, results: Dict[str, Any]) -> float:
        """Estimate performance improvement from optimizations"""
        improvement = 0.0

        # Scaling improvements
        for decision in results['scaling_decisions'].values():
            if decision['action'] == 'scale_up':
                improvement += 15.0  # Estimated % improvement
            elif decision['action'] == 'scale_down':
                improvement -= 5.0   # Minor degradation expected

        # Tuning improvements
        for decision in results['tuning_decisions'].values():
            if decision['action'] == 'increase':
                improvement += 3.0   # Conservative estimate
            elif decision['action'] == 'decrease':
                improvement += 2.0   # Efficiency improvement

        return max(0, improvement)

    def _estimate_resource_savings(self, results: Dict[str, Any]) -> Dict[str, float]:
        """Estimate resource savings from optimizations"""
        savings = {
            'cpu_hours': 0.0,
            'memory_gb': 0.0,
            'cost_usd': 0.0
        }

        # Estimate based on scaling decisions
        for resource_type, decision in results['scaling_decisions'].items():
            if decision['action'] == 'scale_down':
                target = decision.get('target_instances', 0)
                if target > 0:
                    savings['cpu_hours'] += 2.0  # Estimated per instance
                    savings['memory_gb'] += 4.0  # Estimated per instance

        return savings

    def get_optimization_report(self) -> Dict[str, Any]:
        """Generate comprehensive optimization report"""
        with self.lock:
            recent_optimizations = list(self.auto_scaler.scaling_history)[-50:]
            recent_tuning = list(self.performance_tuner.tuning_history)[-50:]

        return {
            'summary': {
                'total_scaling_events': len(recent_optimizations),
                'total_tuning_events': len(recent_tuning),
                'optimization_rate': len(recent_optimizations) / max(1, len(recent_optimizations) + len(recent_tuning))
            },
            'scaling_history': recent_optimizations,
            'tuning_history': recent_tuning,
            'current_policies': {
                resource: policy for resource, policy in self.auto_scaler.scaling_policies.items()
            },
            'current_parameters': {
                param: config['current_value'] for param, config in self.performance_tuner.tuning_parameters.items()
            },
            'workload_predictions': self.auto_scaler.workload_predictor.predict_workload(hours_ahead=6)
        }

# Global intelligent performance instance
resource_optimizer = ResourceOptimizer()

def init_intelligent_performance():
    """Initialize intelligent performance optimization"""
    # Define default scaling policies
    resource_optimizer.auto_scaler.define_scaling_policy('web_server', {
        'min_instances': 2,
        'max_instances': 20,
        'target_utilization': 70,
        'scale_up_threshold': 80,
        'scale_down_threshold': 30
    })

    resource_optimizer.auto_scaler.define_scaling_policy('database', {
        'min_instances': 1,
        'max_instances': 5,
        'target_utilization': 60,
        'scale_up_threshold': 75,
        'scale_down_threshold': 25
    })

    # Define tunable parameters
    resource_optimizer.performance_tuner.register_tunable_parameter('cache_size', {
        'min_value': 100,
        'max_value': 10000,
        'default_value': 1000,
        'step_size': 100,
        'impact_metric': 'cache_hit_rate',
        'optimization_goal': 'maximize'
    })

    resource_optimizer.performance_tuner.register_tunable_parameter('connection_pool', {
        'min_value': 5,
        'max_value': 100,
        'default_value': 20,
        'step_size': 5,
        'impact_metric': 'response_time',
        'optimization_goal': 'minimize'
    })

    logger.info("Intelligent performance optimization initialized")

def optimize_resources(metrics: Dict[str, Any]) -> Dict[str, Any]:
    """Perform intelligent resource optimization"""
    return resource_optimizer.optimize_resources(metrics)

def get_optimization_report() -> Dict[str, Any]:
    """Get comprehensive optimization report"""
    return resource_optimizer.get_optimization_report()
