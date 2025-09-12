#!/usr/bin/env python3
"""
BLNCS WebSocket Handler
Real-time communication between web dashboard and BLNCS API.
"""

import threading
import time
import json
from typing import Dict, Any, Optional
from datetime import datetime
from flask_socketio import SocketIO, emit, disconnect
from flask import request
import logging

logger = logging.getLogger(__name__)

class WebSocketHandler:
    """Handle WebSocket connections and real-time updates"""
    
    def __init__(self, socketio: SocketIO, api_client):
        self.socketio = socketio
        self.api_client = api_client
        self.active_connections = {}
        self.monitoring_thread = None
        self.monitoring_active = False
        
        # Register event handlers
        self._register_handlers()
    
    def _register_handlers(self):
        """Register WebSocket event handlers"""
        
        @self.socketio.on('connect')
        def handle_connect():
            """Handle client connection"""
            client_id = request.sid
            logger.info(f"WebSocket client connected: {client_id}")
            
            # Store connection info
            self.active_connections[client_id] = {
                'connected_at': datetime.now(),
                'subscriptions': set(),
                'last_seen': datetime.now()
            }
            
            # Send initial connection acknowledgment
            emit('connection_status', {
                'status': 'connected',
                'client_id': client_id,
                'timestamp': datetime.now().isoformat()
            })
            
            # Start monitoring if this is the first connection
            if len(self.active_connections) == 1:
                self._start_monitoring()
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection"""
            client_id = request.sid
            logger.info(f"WebSocket client disconnected: {client_id}")
            
            # Remove connection
            if client_id in self.active_connections:
                del self.active_connections[client_id]
            
            # Stop monitoring if no connections
            if len(self.active_connections) == 0:
                self._stop_monitoring()
        
        @self.socketio.on('subscribe')
        def handle_subscribe(data):
            """Handle subscription to data streams"""
            client_id = request.sid
            
            if client_id not in self.active_connections:
                emit('error', {'message': 'Not connected'})
                return
            
            channel = data.get('channel')
            if not channel:
                emit('error', {'message': 'Channel required'})
                return
            
            # Add subscription
            self.active_connections[client_id]['subscriptions'].add(channel)
            
            logger.info(f"Client {client_id} subscribed to {channel}")
            emit('subscription_confirmed', {
                'channel': channel,
                'status': 'subscribed',
                'timestamp': datetime.now().isoformat()
            })
            
            # Send initial data for the channel
            self._send_initial_data(client_id, channel)
        
        @self.socketio.on('unsubscribe')
        def handle_unsubscribe(data):
            """Handle unsubscription from data streams"""
            client_id = request.sid
            
            if client_id not in self.active_connections:
                emit('error', {'message': 'Not connected'})
                return
            
            channel = data.get('channel')
            if not channel:
                emit('error', {'message': 'Channel required'})
                return
            
            # Remove subscription
            self.active_connections[client_id]['subscriptions'].discard(channel)
            
            logger.info(f"Client {client_id} unsubscribed from {channel}")
            emit('subscription_confirmed', {
                'channel': channel,
                'status': 'unsubscribed',
                'timestamp': datetime.now().isoformat()
            })
        
        @self.socketio.on('ping')
        def handle_ping(data):
            """Handle ping requests"""
            client_id = request.sid
            
            if client_id in self.active_connections:
                self.active_connections[client_id]['last_seen'] = datetime.now()
            
            emit('pong', {
                'timestamp': datetime.now().isoformat(),
                'client_timestamp': data.get('timestamp')
            })
        
        @self.socketio.on('request_data')
        def handle_data_request(data):
            """Handle one-time data requests"""
            client_id = request.sid
            
            if client_id not in self.active_connections:
                emit('error', {'message': 'Not connected'})
                return
            
            data_type = data.get('type')
            request_id = data.get('request_id')
            
            try:
                response_data = self._get_requested_data(data_type, data.get('params', {}))
                emit('data_response', {
                    'request_id': request_id,
                    'type': data_type,
                    'data': response_data,
                    'timestamp': datetime.now().isoformat()
                })
            except Exception as e:
                logger.error(f"Error handling data request: {e}")
                emit('error', {
                    'request_id': request_id,
                    'message': str(e)
                })
    
    def _start_monitoring(self):
        """Start background monitoring thread"""
        if self.monitoring_active:
            return
        
        self.monitoring_active = True
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        logger.info("Started WebSocket monitoring thread")
    
    def _stop_monitoring(self):
        """Stop background monitoring thread"""
        self.monitoring_active = False
        logger.info("Stopped WebSocket monitoring thread")
    
    def _monitoring_loop(self):
        """Background loop for sending real-time updates"""
        last_metrics_update = 0
        last_status_update = 0
        last_activity_update = 0
        
        while self.monitoring_active:
            try:
                current_time = time.time()
                
                # Send metrics updates every 30 seconds
                if current_time - last_metrics_update > 30:
                    self._broadcast_metrics()
                    last_metrics_update = current_time
                
                # Send status updates every 60 seconds
                if current_time - last_status_update > 60:
                    self._broadcast_status()
                    last_status_update = current_time
                
                # Send activity updates every 10 seconds
                if current_time - last_activity_update > 10:
                    self._broadcast_activity()
                    last_activity_update = current_time
                
                # Clean up stale connections
                self._cleanup_stale_connections()
                
                # Sleep for 5 seconds before next iteration
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(5)
    
    def _broadcast_metrics(self):
        """Broadcast system metrics to subscribed clients"""
        subscribers = self._get_subscribers('metrics')
        if not subscribers:
            return
        
        try:
            metrics = self.api_client.get_detailed_metrics()
            
            for client_id in subscribers:
                self.socketio.emit('metrics_update', {
                    'data': metrics,
                    'timestamp': datetime.now().isoformat()
                }, room=client_id)
                
        except Exception as e:
            logger.error(f"Error broadcasting metrics: {e}")
    
    def _broadcast_status(self):
        """Broadcast system status to subscribed clients"""
        subscribers = self._get_subscribers('status')
        if not subscribers:
            return
        
        try:
            status = self.api_client.get_system_status()
            health = self.api_client.get_health_status()
            
            for client_id in subscribers:
                self.socketio.emit('status_update', {
                    'status': status,
                    'health': health,
                    'timestamp': datetime.now().isoformat()
                }, room=client_id)
                
        except Exception as e:
            logger.error(f"Error broadcasting status: {e}")
    
    def _broadcast_activity(self):
        """Broadcast recent activity to subscribed clients"""
        subscribers = self._get_subscribers('activity')
        if not subscribers:
            return
        
        try:
            activity = self.api_client.get_recent_operations(limit=5)
            
            for client_id in subscribers:
                self.socketio.emit('activity_update', {
                    'data': activity,
                    'timestamp': datetime.now().isoformat()
                }, room=client_id)
                
        except Exception as e:
            logger.error(f"Error broadcasting activity: {e}")
    
    def _get_subscribers(self, channel: str) -> list:
        """Get list of clients subscribed to a channel"""
        subscribers = []
        for client_id, conn_info in self.active_connections.items():
            if channel in conn_info['subscriptions']:
                subscribers.append(client_id)
        return subscribers
    
    def _send_initial_data(self, client_id: str, channel: str):
        """Send initial data when client subscribes to channel"""
        try:
            if channel == 'metrics':
                data = self.api_client.get_detailed_metrics()
            elif channel == 'status':
                data = {
                    'status': self.api_client.get_system_status(),
                    'health': self.api_client.get_health_status()
                }
            elif channel == 'activity':
                data = self.api_client.get_recent_operations(limit=10)
            elif channel == 'backups':
                data = self.api_client.get_backup_list(per_page=10)
            elif channel == 'schedules':
                data = self.api_client.get_schedules()
            else:
                data = {'message': f'No initial data for channel {channel}'}
            
            self.socketio.emit(f'{channel}_update', {
                'data': data,
                'timestamp': datetime.now().isoformat(),
                'initial': True
            }, room=client_id)
            
        except Exception as e:
            logger.error(f"Error sending initial data for {channel}: {e}")
    
    def _get_requested_data(self, data_type: str, params: Dict) -> Any:
        """Get data for one-time requests"""
        if data_type == 'backup_details':
            backup_id = params.get('backup_id')
            if not backup_id:
                raise ValueError('backup_id required')
            return self.api_client.get_backup_details(backup_id)
        
        elif data_type == 'dashboard_summary':
            return self.api_client.get_dashboard_summary()
        
        elif data_type == 'storage_backends':
            return self.api_client.get_storage_backends()
        
        elif data_type == 'configuration':
            return self.api_client.get_configuration()
        
        elif data_type == 'auth_stats':
            return self.api_client.get_auth_stats()
        
        else:
            raise ValueError(f'Unknown data type: {data_type}')
    
    def _cleanup_stale_connections(self):
        """Remove stale connections"""
        current_time = datetime.now()
        stale_threshold = 300  # 5 minutes
        
        stale_clients = []
        for client_id, conn_info in self.active_connections.items():
            last_seen = conn_info['last_seen']
            if (current_time - last_seen).total_seconds() > stale_threshold:
                stale_clients.append(client_id)
        
        for client_id in stale_clients:
            logger.info(f"Removing stale connection: {client_id}")
            del self.active_connections[client_id]
    
    def broadcast_operation_update(self, operation_type: str, operation_data: Dict):
        """Broadcast operation updates (called externally)"""
        subscribers = self._get_subscribers('operations')
        
        if subscribers:
            for client_id in subscribers:
                self.socketio.emit('operation_update', {
                    'type': operation_type,
                    'data': operation_data,
                    'timestamp': datetime.now().isoformat()
                }, room=client_id)
    
    def broadcast_alert(self, alert_type: str, message: str, severity: str = 'info'):
        """Broadcast system alerts to all connected clients"""
        alert_data = {
            'type': alert_type,
            'message': message,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        }
        
        self.socketio.emit('system_alert', alert_data, broadcast=True)
        logger.info(f"Broadcasted alert: {alert_type} - {message}")
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get WebSocket connection statistics"""
        return {
            'active_connections': len(self.active_connections),
            'monitoring_active': self.monitoring_active,
            'connections': [
                {
                    'client_id': client_id,
                    'connected_at': conn_info['connected_at'].isoformat(),
                    'last_seen': conn_info['last_seen'].isoformat(),
                    'subscriptions': list(conn_info['subscriptions'])
                }
                for client_id, conn_info in self.active_connections.items()
            ]
        }