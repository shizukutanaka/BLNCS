"""
Enterprise UX Framework for BLNCS
Provides advanced dashboards, real-time collaboration, and mobile optimization
"""

import json
import time
import threading
from typing import Dict, List, Optional, Any, Callable
from collections import defaultdict, deque
from datetime import datetime, timedelta
import asyncio
import websockets
import aiohttp
import logging

logger = logging.getLogger(__name__)

class AdvancedDashboard:
    """Advanced dashboard with real-time updates and customization"""

    def __init__(self):
        self.dashboard_configs = {}
        self.widget_data = {}
        self.subscribers = defaultdict(set)
        self.lock = threading.Lock()

    def create_dashboard(self, dashboard_id: str, user_id: str, config: Dict[str, Any]) -> bool:
        """Create a new customizable dashboard"""
        with self.lock:
            self.dashboard_configs[dashboard_id] = {
                'id': dashboard_id,
                'user_id': user_id,
                'name': config.get('name', f'Dashboard {dashboard_id}'),
                'layout': config.get('layout', 'grid'),
                'widgets': config.get('widgets', []),
                'theme': config.get('theme', 'default'),
                'refresh_interval': config.get('refresh_interval', 30),
                'created_at': time.time(),
                'updated_at': time.time()
            }

            # Initialize widget data
            self.widget_data[dashboard_id] = {}

            logger.info(f"Created dashboard {dashboard_id} for user {user_id}")
            return True

    def add_widget(self, dashboard_id: str, widget_config: Dict[str, Any]) -> str:
        """Add widget to dashboard"""
        widget_id = f"widget_{int(time.time())}_{len(widget_config)}"

        with self.lock:
            if dashboard_id not in self.dashboard_configs:
                return None

            widget_config['id'] = widget_id
            widget_config['created_at'] = time.time()

            self.dashboard_configs[dashboard_id]['widgets'].append(widget_config)
            self.widget_data[dashboard_id][widget_id] = {
                'data': {},
                'last_updated': 0,
                'update_count': 0
            }

            # Update dashboard timestamp
            self.dashboard_configs[dashboard_id]['updated_at'] = time.time()

        return widget_id

    def update_widget_data(self, dashboard_id: str, widget_id: str, data: Dict[str, Any]):
        """Update widget data and notify subscribers"""
        with self.lock:
            if dashboard_id not in self.widget_data or widget_id not in self.widget_data[dashboard_id]:
                return False

            self.widget_data[dashboard_id][widget_id].update({
                'data': data,
                'last_updated': time.time(),
                'update_count': self.widget_data[dashboard_id][widget_id]['update_count'] + 1
            })

            # Notify subscribers
            subscribers = self.subscribers.get(dashboard_id, set()).copy()
            for subscriber in subscribers:
                try:
                    self._notify_subscriber(subscriber, {
                        'type': 'widget_update',
                        'dashboard_id': dashboard_id,
                        'widget_id': widget_id,
                        'data': data,
                        'timestamp': time.time()
                    })
                except Exception as e:
                    logger.error(f"Error notifying subscriber: {e}")

        return True

    def subscribe_to_dashboard(self, dashboard_id: str, callback: Callable[[Dict[str, Any]], None]) -> bool:
        """Subscribe to dashboard updates"""
        with self.lock:
            self.subscribers[dashboard_id].add(callback)
        return True

    def unsubscribe_from_dashboard(self, dashboard_id: str, callback: Callable[[Dict[str, Any]], None]) -> bool:
        """Unsubscribe from dashboard updates"""
        with self.lock:
            if dashboard_id in self.subscribers:
                self.subscribers[dashboard_id].discard(callback)
        return True

    def _notify_subscriber(self, callback: Callable, message: Dict[str, Any]):
        """Notify subscriber (async)"""
        try:
            # In production, use asyncio or threading
            callback(message)
        except Exception as e:
            logger.error(f"Error in subscriber callback: {e}")

    def get_dashboard_data(self, dashboard_id: str) -> Optional[Dict[str, Any]]:
        """Get complete dashboard data"""
        with self.lock:
            if dashboard_id not in self.dashboard_configs:
                return None

            config = self.dashboard_configs[dashboard_id]
            widgets_data = {}

            for widget in config['widgets']:
                widget_id = widget['id']
                if widget_id in self.widget_data[dashboard_id]:
                    widgets_data[widget_id] = self.widget_data[dashboard_id][widget_id]

            return {
                'config': config,
                'widgets': widgets_data,
                'last_updated': time.time()
            }

class CollaborationManager:
    """Real-time collaboration system"""

    def __init__(self):
        self.active_sessions = {}
        self.collaborative_documents = {}
        self.session_locks = {}
        self.lock = threading.Lock()

    def create_collaboration_session(self, session_id: str, document_id: str,
                                   participants: List[str]) -> bool:
        """Create a new collaboration session"""
        with self.lock:
            self.active_sessions[session_id] = {
                'id': session_id,
                'document_id': document_id,
                'participants': set(participants),
                'created_at': time.time(),
                'last_activity': time.time(),
                'operations': deque(maxlen=1000)
            }

            if document_id not in self.collaborative_documents:
                self.collaborative_documents[document_id] = {
                    'content': {},
                    'version': 0,
                    'conflicts': []
                }

            logger.info(f"Created collaboration session {session_id} for document {document_id}")
            return True

    def join_session(self, session_id: str, user_id: str) -> bool:
        """Join an existing collaboration session"""
        with self.lock:
            if session_id not in self.active_sessions:
                return False

            self.active_sessions[session_id]['participants'].add(user_id)
            self.active_sessions[session_id]['last_activity'] = time.time()

            logger.info(f"User {user_id} joined session {session_id}")
            return True

    def leave_session(self, session_id: str, user_id: str) -> bool:
        """Leave a collaboration session"""
        with self.lock:
            if session_id not in self.active_sessions:
                return False

            session = self.active_sessions[session_id]
            session['participants'].discard(user_id)

            if not session['participants']:
                # Remove empty session
                del self.active_sessions[session_id]
                logger.info(f"Removed empty collaboration session {session_id}")
            else:
                session['last_activity'] = time.time()
                logger.info(f"User {user_id} left session {session_id}")

            return True

    def apply_operation(self, session_id: str, user_id: str,
                       operation: Dict[str, Any]) -> Dict[str, Any]:
        """Apply collaborative operation with conflict resolution"""
        with self.lock:
            if session_id not in self.active_sessions:
                return {'success': False, 'error': 'Session not found'}

            session = self.active_sessions[session_id]

            if user_id not in session['participants']:
                return {'success': False, 'error': 'User not in session'}

            # Check for operation conflicts
            document_id = session['document_id']
            current_version = self.collaborative_documents[document_id]['version']

            if operation.get('version', 0) < current_version:
                return {'success': False, 'error': 'Operation version conflict'}

            # Apply operation
            try:
                result = self._apply_operation_to_document(document_id, operation)
                if result['success']:
                    # Record operation
                    operation_record = {
                        'user_id': user_id,
                        'operation': operation,
                        'timestamp': time.time(),
                        'version': current_version + 1
                    }

                    session['operations'].append(operation_record)
                    self.collaborative_documents[document_id]['version'] = current_version + 1
                    session['last_activity'] = time.time()

                    # Notify other participants
                    self._notify_session_participants(session_id, user_id, {
                        'type': 'operation_applied',
                        'operation': operation,
                        'user_id': user_id,
                        'timestamp': time.time()
                    })

                return result

            except Exception as e:
                logger.error(f"Error applying operation: {e}")
                return {'success': False, 'error': str(e)}

    def _apply_operation_to_document(self, document_id: str, operation: Dict[str, Any]) -> Dict[str, Any]:
        """Apply operation to collaborative document"""
        if document_id not in self.collaborative_documents:
            return {'success': False, 'error': 'Document not found'}

        doc = self.collaborative_documents[document_id]
        op_type = operation.get('type')

        if op_type == 'insert':
            path = operation.get('path', '')
            content = operation.get('content', '')
            self._insert_at_path(doc['content'], path, content)

        elif op_type == 'delete':
            path = operation.get('path', '')
            self._delete_at_path(doc['content'], path)

        elif op_type == 'update':
            path = operation.get('path', '')
            content = operation.get('content', '')
            self._update_at_path(doc['content'], path, content)

        return {'success': True}

    def _insert_at_path(self, content: Dict, path: str, value: Any):
        """Insert value at JSON path"""
        keys = path.split('.')
        current = content

        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]

        current[keys[-1]] = value

    def _delete_at_path(self, content: Dict, path: str):
        """Delete value at JSON path"""
        keys = path.split('.')
        current = content

        for key in keys[:-1]:
            if key not in current:
                return
            current = current[key]

        if keys[-1] in current:
            del current[keys[-1]]

    def _update_at_path(self, content: Dict, path: str, value: Any):
        """Update value at JSON path"""
        keys = path.split('.')
        current = content

        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]

        current[keys[-1]] = value

    def _notify_session_participants(self, session_id: str, exclude_user: str, message: Dict[str, Any]):
        """Notify all session participants except the sender"""
        session = self.active_sessions[session_id]
        for user_id in session['participants']:
            if user_id != exclude_user:
                # In production, send via WebSocket or message queue
                pass

    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get collaboration session information"""
        with self.lock:
            return self.active_sessions.get(session_id)

class MobileOptimizer:
    """Mobile experience optimization"""

    def __init__(self):
        self.device_profiles = {}
        self.mobile_configs = {}
        self.performance_metrics = deque(maxlen=10000)
        self.lock = threading.Lock()

    def register_device_profile(self, device_type: str, profile: Dict[str, Any]):
        """Register mobile device profile"""
        self.device_profiles[device_type] = {
            'screen_size': profile.get('screen_size', 'medium'),
            'connection_type': profile.get('connection_type', '4g'),
            'processing_power': profile.get('processing_power', 'medium'),
            'memory': profile.get('memory', '2gb'),
            'features': profile.get('features', []),
            'optimization_settings': profile.get('optimization_settings', {})
        }

    def optimize_for_device(self, device_type: str, content: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize content for specific device type"""
        if device_type not in self.device_profiles:
            return content  # No optimization available

        profile = self.device_profiles[device_type]
        optimizations = profile['optimization_settings']

        optimized_content = content.copy()

        # Apply device-specific optimizations
        if profile['connection_type'] in ['2g', '3g']:
            # Optimize for slow connections
            optimized_content = self._optimize_for_slow_connection(optimized_content)

        if profile['screen_size'] == 'small':
            # Optimize for small screens
            optimized_content = self._optimize_for_small_screen(optimized_content)

        if profile['memory'] in ['512mb', '1gb']:
            # Optimize for low memory
            optimized_content = self._optimize_for_low_memory(optimized_content)

        # Record optimization metrics
        with self.lock:
            self.performance_metrics.append({
                'timestamp': time.time(),
                'device_type': device_type,
                'optimization_type': 'mobile',
                'content_size_before': len(json.dumps(content)),
                'content_size_after': len(json.dumps(optimized_content))
            })

        return optimized_content

    def _optimize_for_slow_connection(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize content for slow network connections"""
        # Reduce image quality
        if 'images' in content:
            for img_key in content['images']:
                if isinstance(content['images'][img_key], dict):
                    content['images'][img_key]['quality'] = 'low'
                    content['images'][img_key]['lazy_load'] = True

        # Compress data
        if 'large_datasets' in content:
            content['large_datasets'] = 'compressed'

        # Disable non-essential features
        content['enable_animations'] = False
        content['enable_real_time_updates'] = False

        return content

    def _optimize_for_small_screen(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize content for small screens"""
        # Simplify layouts
        if 'layout' in content:
            content['layout'] = 'compact'

        # Reduce widget sizes
        if 'widgets' in content:
            for widget in content['widgets']:
                widget['size'] = 'small'
                widget['show_details'] = False

        # Optimize navigation
        content['navigation'] = 'bottom_tab'
        content['show_sidebar'] = False

        return content

    def _optimize_for_low_memory(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Optimize content for low memory devices"""
        # Disable memory-intensive features
        content['enable_caching'] = False
        content['max_concurrent_requests'] = 2
        content['preload_data'] = False

        # Reduce data retention
        if 'history' in content:
            content['history']['max_items'] = 50

        return content

    def get_mobile_performance_report(self) -> Dict[str, Any]:
        """Get mobile performance optimization report"""
        with self.lock:
            recent_metrics = list(self.performance_metrics)[-1000:]

        if not recent_metrics:
            return {'error': 'No performance data available'}

        # Calculate metrics by device type
        device_stats = defaultdict(list)
        for metric in recent_metrics:
            device_stats[metric['device_type']].append(metric)

        report = {
            'summary': {
                'total_optimizations': len(recent_metrics),
                'unique_devices': len(device_stats)
            },
            'device_breakdown': {},
            'performance_improvements': self._calculate_performance_improvements(recent_metrics)
        }

        for device_type, metrics in device_stats.items():
            avg_size_before = sum(m['content_size_before'] for m in metrics) / len(metrics)
            avg_size_after = sum(m['content_size_after'] for m in metrics) / len(metrics)
            improvement = ((avg_size_before - avg_size_after) / avg_size_before) * 100

            report['device_breakdown'][device_type] = {
                'optimization_count': len(metrics),
                'avg_size_before': avg_size_before,
                'avg_size_after': avg_size_after,
                'size_improvement_percent': improvement
            }

        return report

    def _calculate_performance_improvements(self, metrics: List[Dict[str, Any]]) -> Dict[str, float]:
        """Calculate performance improvements"""
        if not metrics:
            return {}

        improvements = {
            'avg_size_reduction_percent': 0.0,
            'avg_load_time_improvement_ms': 0.0,
            'memory_usage_reduction_percent': 0.0
        }

        size_improvements = []
        for metric in metrics:
            before_size = metric['content_size_before']
            after_size = metric['content_size_after']
            if before_size > 0:
                improvement = ((before_size - after_size) / before_size) * 100
                size_improvements.append(improvement)

        if size_improvements:
            improvements['avg_size_reduction_percent'] = sum(size_improvements) / len(size_improvements)

        return improvements

class UXAnalytics:
    """User experience analytics and optimization"""

    def __init__(self):
        self.user_interactions = defaultdict(list)
        self.performance_events = deque(maxlen=50000)
        self.feedback_data = deque(maxlen=10000)
        self.lock = threading.Lock()

    def record_user_interaction(self, user_id: str, interaction_type: str,
                               metadata: Dict[str, Any]):
        """Record user interaction for UX analysis"""
        interaction = {
            'user_id': user_id,
            'type': interaction_type,
            'timestamp': time.time(),
            'metadata': metadata
        }

        with self.lock:
            self.user_interactions[user_id].append(interaction)

            # Keep only recent interactions per user
            if len(self.user_interactions[user_id]) > 1000:
                self.user_interactions[user_id] = self.user_interactions[user_id][-1000:]

    def record_performance_event(self, event_type: str, duration_ms: float,
                                metadata: Dict[str, Any]):
        """Record performance event"""
        event = {
            'type': event_type,
            'duration_ms': duration_ms,
            'timestamp': time.time(),
            'metadata': metadata
        }

        with self.lock:
            self.performance_events.append(event)

    def record_user_feedback(self, user_id: str, feedback_type: str, rating: int,
                           comments: str = None):
        """Record user feedback"""
        feedback = {
            'user_id': user_id,
            'type': feedback_type,
            'rating': rating,
            'comments': comments,
            'timestamp': time.time()
        }

        with self.lock:
            self.feedback_data.append(feedback)

    def analyze_user_experience(self, user_id: str = None) -> Dict[str, Any]:
        """Analyze user experience patterns"""
        with self.lock:
            if user_id:
                interactions = self.user_interactions.get(user_id, [])
                user_feedback = [f for f in self.feedback_data if f['user_id'] == user_id]
            else:
                interactions = []
                for user_interactions in self.user_interactions.values():
                    interactions.extend(user_interactions)
                user_feedback = list(self.feedback_data)

        if not interactions and not user_feedback:
            return {'error': 'No data available for analysis'}

        # Analyze interaction patterns
        interaction_types = defaultdict(int)
        for interaction in interactions:
            interaction_types[interaction['type']] += 1

        # Calculate average session duration
        session_durations = []
        if interactions:
            # Group interactions by session (simplified)
            session_durations = [len(interactions) * 2.5]  # Estimate in seconds

        # Analyze feedback
        avg_rating = sum(f['rating'] for f in user_feedback) / len(user_feedback) if user_feedback else 0

        return {
            'interaction_summary': {
                'total_interactions': len(interactions),
                'unique_users': len(self.user_interactions),
                'top_interaction_types': dict(sorted(interaction_types.items(),
                                                   key=lambda x: x[1], reverse=True)[:10])
            },
            'performance_metrics': {
                'avg_session_duration_seconds': sum(session_durations) / len(session_durations) if session_durations else 0,
                'recent_performance_events': len(self.performance_events)
            },
            'user_satisfaction': {
                'avg_rating': avg_rating,
                'total_feedback_count': len(user_feedback),
                'rating_distribution': self._calculate_rating_distribution(user_feedback)
            },
            'recommendations': self._generate_ux_recommendations(interactions, user_feedback)
        }

    def _calculate_rating_distribution(self, feedback: List[Dict[str, Any]]) -> Dict[int, int]:
        """Calculate rating distribution"""
        distribution = defaultdict(int)
        for f in feedback:
            distribution[f['rating']] += 1
        return dict(distribution)

    def _generate_ux_recommendations(self, interactions: List[Dict[str, Any]],
                                   feedback: List[Dict[str, Any]]) -> List[str]:
        """Generate UX improvement recommendations"""
        recommendations = []

        if not interactions:
            recommendations.append("Increase user engagement through better onboarding")
            return recommendations

        # Analyze interaction frequency
        interaction_freq = defaultdict(int)
        for interaction in interactions:
            interaction_freq[interaction['type']] += 1

        most_common = max(interaction_freq.items(), key=lambda x: x[1])[0]
        recommendations.append(f"Optimize the most used feature: {most_common}")

        # Analyze feedback
        if feedback:
            low_ratings = [f for f in feedback if f['rating'] <= 2]
            if low_ratings:
                recommendations.append(f"Address {len(low_ratings)} low-rated areas")

        # Check for performance issues
        slow_events = [e for e in self.performance_events if e['duration_ms'] > 1000]
        if len(slow_events) > len(self.performance_events) * 0.1:  # More than 10% slow
            recommendations.append("Optimize performance for better user experience")

        if not recommendations:
            recommendations.append("User experience appears satisfactory")

        return recommendations

# Global enterprise UX instances
advanced_dashboard = AdvancedDashboard()
collaboration_manager = CollaborationManager()
mobile_optimizer = MobileOptimizer()
ux_analytics = UXAnalytics()

def init_enterprise_ux():
    """Initialize enterprise UX systems"""
    # Register common mobile device profiles
    mobile_optimizer.register_device_profile('smartphone_low', {
        'screen_size': 'small',
        'connection_type': '3g',
        'processing_power': 'low',
        'memory': '1gb',
        'features': ['touch', 'basic'],
        'optimization_settings': {
            'compress_images': True,
            'disable_animations': True,
            'reduce_data_usage': True
        }
    })

    mobile_optimizer.register_device_profile('smartphone_high', {
        'screen_size': 'medium',
        'connection_type': '5g',
        'processing_power': 'high',
        'memory': '8gb',
        'features': ['touch', 'advanced', 'camera'],
        'optimization_settings': {
            'enable_animations': True,
            'preload_content': True,
            'high_quality_images': True
        }
    })

    mobile_optimizer.register_device_profile('tablet', {
        'screen_size': 'large',
        'connection_type': '4g',
        'processing_power': 'medium',
        'memory': '4gb',
        'features': ['touch', 'stylus', 'multitasking'],
        'optimization_settings': {
            'enable_multitasking': True,
            'larger_widgets': True,
            'enhanced_navigation': True
        }
    })

    logger.info("Enterprise UX systems initialized")

def create_dashboard(dashboard_id: str, user_id: str, config: Dict[str, Any]) -> bool:
    """Create a new dashboard"""
    return advanced_dashboard.create_dashboard(dashboard_id, user_id, config)

def update_widget_data(dashboard_id: str, widget_id: str, data: Dict[str, Any]) -> bool:
    """Update dashboard widget data"""
    return advanced_dashboard.update_widget_data(dashboard_id, widget_id, data)

def create_collaboration_session(session_id: str, document_id: str, participants: List[str]) -> bool:
    """Create a collaboration session"""
    return collaboration_manager.create_collaboration_session(session_id, document_id, participants)

def optimize_for_mobile(device_type: str, content: Dict[str, Any]) -> Dict[str, Any]:
    """Optimize content for mobile device"""
    return mobile_optimizer.optimize_for_device(device_type, content)

def get_ux_analytics(user_id: str = None) -> Dict[str, Any]:
    """Get UX analytics data"""
    return ux_analytics.analyze_user_experience(user_id)
