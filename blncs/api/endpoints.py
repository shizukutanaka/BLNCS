#!/usr/bin/env python3
"""
BLNCS API Endpoints
Comprehensive REST API endpoints for Lightning Network management system.
"""

from flask import request, jsonify, g
from datetime import datetime
import logging
from typing import Dict, Any, Optional

from .auth import api_key_required, rate_limit, require_permission
from .responses import (
    success_response, error_response, validation_error_response,
    not_found_response, paginated_response, operation_response
)
from .validators import (
    validate_request, backup_item_validator, backup_creation_validator,
    schedule_validator, recovery_validator, storage_backend_validator,
    pagination_validator
)

logger = logging.getLogger(__name__)

def register_api_endpoints(app, components: Dict[str, Any]):
    """Register all API endpoints with component dependencies"""
    
    # Extract components
    backup_manager = components.get('backup_manager')
    recovery_engine = components.get('recovery_engine')
    scheduler = components.get('scheduler')
    config_manager = components.get('config_manager')
    health_manager = components.get('health_manager')
    monitor = components.get('monitor')
    translator = components.get('translator')
    auth_manager = components.get('auth_manager')
    
    # Store auth manager for middleware
    app.auth_manager = auth_manager
    
    # ========================================
    # BACKUP ENDPOINTS
    # ========================================
    
    @app.route('/api/v1/backup/items', methods=['GET'])
    @api_key_required
    @rate_limit()
    def list_backup_items():
        """List all backup items"""
        try:
            if not backup_manager:
                return error_response("Backup system not available", 503)
            
            items = backup_manager.list_backup_items()
            return success_response(items, "Backup items retrieved successfully")
            
        except Exception as e:
            logger.error(f"Error listing backup items: {e}")
            return error_response(f"Failed to list backup items: {str(e)}", 500)
    
    @app.route('/api/v1/backup/items', methods=['POST'])
    @api_key_required
    @rate_limit()
    @require_permission('write')
    @validate_request(backup_item_validator())
    def create_backup_item():
        """Create a new backup item"""
        try:
            if not backup_manager:
                return error_response("Backup system not available", 503)
            
            data = request.validated_data
            
            success = backup_manager.add_backup_item(
                name=data['name'],
                source_path=data['source_path'],
                backup_type=data.get('backup_type', 'incremental'),
                priority=data.get('priority', 1),
                enabled=data.get('enabled', True),
                encryption=data.get('encryption', True),
                compression=data.get('compression', True)
            )
            
            if success:
                return success_response(
                    {'name': data['name']},
                    "Backup item created successfully",
                    201
                )
            else:
                return error_response("Failed to create backup item", 400)
                
        except Exception as e:
            logger.error(f"Error creating backup item: {e}")
            return error_response(f"Failed to create backup item: {str(e)}", 500)
    
    @app.route('/api/v1/backup/create', methods=['POST'])
    @api_key_required
    @rate_limit()
    @require_permission('write')
    @validate_request(backup_creation_validator())
    def create_backup():
        """Create a new backup"""
        try:
            if not backup_manager:
                return error_response("Backup system not available", 503)
            
            data = request.validated_data
            
            # Get backup items
            if data.get('items'):
                all_items = backup_manager.list_backup_items()
                item_names = {item['name']: item for item in all_items}
                backup_items = []
                
                for item_name in data['items']:
                    if item_name in item_names:
                        backup_items.append(item_names[item_name])
                    else:
                        return error_response(f"Backup item '{item_name}' not found", 400)
            else:
                backup_items = backup_manager.list_backup_items()
            
            if not backup_items:
                return error_response("No backup items available", 400)
            
            # Create backup
            start_time = datetime.now()
            result = backup_manager.create_backup(
                backup_items=backup_items,
                backup_type=data.get('backup_type', 'incremental'),
                backup_name=data.get('backup_name')
            )
            
            duration = (datetime.now() - start_time).total_seconds()
            
            return operation_response(
                operation="backup_creation",
                success=result.success,
                result={
                    'backup_id': result.backup_id,
                    'files_backed_up': result.files_backed_up,
                    'files_failed': result.files_failed,
                    'total_size_mb': result.total_size / (1024 * 1024),
                    'warnings': result.warnings,
                    'errors': result.errors
                },
                duration=duration
            )
            
        except Exception as e:
            logger.error(f"Error creating backup: {e}")
            return error_response(f"Failed to create backup: {str(e)}", 500)
    
    @app.route('/api/v1/backup/list', methods=['GET'])
    @api_key_required
    @rate_limit()
    @validate_request(pagination_validator(), 'args')
    def list_backups():
        """List backups with pagination"""
        try:
            if not backup_manager:
                return error_response("Backup system not available", 503)
            
            # Get pagination parameters
            page = int(request.args.get('page', 1))
            per_page = int(request.args.get('per_page', 20))
            status_filter = request.args.get('status')
            
            # Get backups
            all_backups = backup_manager.list_backups(limit=1000)  # Get more for filtering
            
            # Filter by status if specified
            if status_filter:
                all_backups = [b for b in all_backups if b['status'] == status_filter]
            
            # Paginate
            total = len(all_backups)
            start = (page - 1) * per_page
            end = start + per_page
            backups = all_backups[start:end]
            
            return paginated_response(
                data=backups,
                page=page,
                per_page=per_page,
                total=total,
                message="Backups retrieved successfully"
            )
            
        except Exception as e:
            logger.error(f"Error listing backups: {e}")
            return error_response(f"Failed to list backups: {str(e)}", 500)
    
    @app.route('/api/v1/backup/<backup_id>', methods=['GET'])
    @api_key_required
    @rate_limit()
    def get_backup_details(backup_id: str):
        """Get detailed backup information"""
        try:
            if not backup_manager or not recovery_engine:
                return error_response("Backup system not available", 503)
            
            # Get backup from list
            backups = backup_manager.list_backups(limit=1000)
            backup = next((b for b in backups if b['backup_id'] == backup_id), None)
            
            if not backup:
                return not_found_response("Backup")
            
            # Get backup contents
            try:
                contents = recovery_engine.get_backup_contents(backup_id)
                backup['contents'] = contents
                backup['file_count'] = len(contents)
            except Exception as e:
                backup['contents_error'] = str(e)
            
            return success_response(backup, "Backup details retrieved successfully")
            
        except Exception as e:
            logger.error(f"Error getting backup details: {e}")
            return error_response(f"Failed to get backup details: {str(e)}", 500)
    
    @app.route('/api/v1/backup/<backup_id>/validate', methods=['POST'])
    @api_key_required
    @rate_limit()
    @require_permission('write')
    def validate_backup(backup_id: str):
        """Validate a backup"""
        try:
            # Import here to avoid circular imports
            from blncs.backup.backup_validator import BackupValidator, ValidationLevel
            
            validator = BackupValidator()
            level_map = {
                'basic': ValidationLevel.BASIC,
                'standard': ValidationLevel.STANDARD,
                'thorough': ValidationLevel.THOROUGH,
                'deep': ValidationLevel.DEEP
            }
            
            level = request.json.get('level', 'standard') if request.json else 'standard'
            validation_level = level_map.get(level, ValidationLevel.STANDARD)
            
            start_time = datetime.now()
            result = validator.validate_backup(backup_id, validation_level)
            duration = (datetime.now() - start_time).total_seconds()
            
            return operation_response(
                operation="backup_validation",
                success=result.overall_status.value in ['valid', 'warning'],
                result={
                    'backup_id': result.backup_id,
                    'validation_level': result.validation_level.value,
                    'overall_status': result.overall_status.value,
                    'valid_files': result.valid_files,
                    'invalid_files': result.invalid_files,
                    'total_files': result.total_files,
                    'total_size_mb': result.total_size / (1024 * 1024),
                    'metadata_valid': result.metadata_valid,
                    'checksum_valid': result.checksum_valid,
                    'structure_valid': result.structure_valid,
                    'restoration_test_passed': result.restoration_test_passed,
                    'issues': [
                        {
                            'severity': issue.severity.value,
                            'category': issue.category,
                            'description': issue.description,
                            'file_path': issue.file_path,
                            'recommendation': issue.recommendation
                        } for issue in result.issues
                    ]
                },
                duration=duration
            )
            
        except Exception as e:
            logger.error(f"Error validating backup: {e}")
            return error_response(f"Failed to validate backup: {str(e)}", 500)
    
    # ========================================
    # RECOVERY ENDPOINTS
    # ========================================
    
    @app.route('/api/v1/recovery/backups', methods=['GET'])
    @api_key_required
    @rate_limit()
    def list_available_backups():
        """List available backups for recovery"""
        try:
            if not recovery_engine:
                return error_response("Recovery system not available", 503)
            
            backups = recovery_engine.list_available_backups()
            return success_response(backups, "Available backups retrieved successfully")
            
        except Exception as e:
            logger.error(f"Error listing available backups: {e}")
            return error_response(f"Failed to list available backups: {str(e)}", 500)
    
    @app.route('/api/v1/recovery/execute', methods=['POST'])
    @api_key_required
    @rate_limit()
    @require_permission('write')
    @validate_request(recovery_validator())
    def execute_recovery():
        """Execute backup recovery"""
        try:
            if not recovery_engine:
                return error_response("Recovery system not available", 503)
            
            data = request.validated_data
            backup_id = data['backup_id']
            
            # Prepare recovery items
            recovery_items = []
            if data.get('items'):
                contents = recovery_engine.get_backup_contents(backup_id)
                
                for item_path in data['items']:
                    found = False
                    for content_item in contents:
                        if content_item['path'] == item_path:
                            from blncs.backup.recovery_engine import RecoveryItem
                            recovery_items.append(RecoveryItem(
                                backup_id=backup_id,
                                original_path=item_path,
                                target_path=f"{data.get('target_directory', '.')}/{item_path}",
                                overwrite_existing=data.get('overwrite_existing', False),
                                verify_integrity=data.get('verify_integrity', True)
                            ))
                            found = True
                            break
                    if not found:
                        return error_response(f"Item '{item_path}' not found in backup", 400)
            
            # Execute recovery
            start_time = datetime.now()
            result = recovery_engine.execute_recovery(
                backup_id=backup_id,
                recovery_items=recovery_items,
                target_directory=data.get('target_directory')
            )
            duration = (datetime.now() - start_time).total_seconds()
            
            return operation_response(
                operation="backup_recovery",
                success=result.success,
                result={
                    'backup_id': result.backup_id,
                    'items_recovered': result.items_recovered,
                    'items_failed': result.items_failed,
                    'total_size_mb': result.total_size / (1024 * 1024),
                    'recovered_files': result.recovered_files,
                    'warnings': result.warnings,
                    'errors': result.errors
                },
                duration=duration
            )
            
        except Exception as e:
            logger.error(f"Error executing recovery: {e}")
            return error_response(f"Failed to execute recovery: {str(e)}", 500)
    
    # ========================================
    # SCHEDULER ENDPOINTS
    # ========================================
    
    @app.route('/api/v1/schedule/list', methods=['GET'])
    @api_key_required
    @rate_limit()
    def list_schedules():
        """List backup schedules"""
        try:
            if not scheduler:
                return error_response("Scheduler not available", 503)
            
            schedules = scheduler.list_schedules()
            return success_response(schedules, "Schedules retrieved successfully")
            
        except Exception as e:
            logger.error(f"Error listing schedules: {e}")
            return error_response(f"Failed to list schedules: {str(e)}", 500)
    
    @app.route('/api/v1/schedule/create', methods=['POST'])
    @api_key_required
    @rate_limit()
    @require_permission('write')
    @validate_request(schedule_validator())
    def create_schedule():
        """Create backup schedule"""
        try:
            if not scheduler:
                return error_response("Scheduler not available", 503)
            
            data = request.validated_data
            
            from blncs.backup.backup_scheduler import ScheduleType
            
            schedule_id = scheduler.create_schedule(
                name=data['name'],
                backup_items=data['backup_items'],
                schedule_type=ScheduleType(data['schedule_type']),
                schedule_config=data['schedule_config'],
                backup_type=data.get('backup_type', 'incremental'),
                retention_days=data.get('retention_days', 30)
            )
            
            return success_response(
                {'schedule_id': schedule_id, 'name': data['name']},
                "Schedule created successfully",
                201
            )
            
        except Exception as e:
            logger.error(f"Error creating schedule: {e}")
            return error_response(f"Failed to create schedule: {str(e)}", 500)
    
    @app.route('/api/v1/schedule/<schedule_id>', methods=['DELETE'])
    @api_key_required
    @rate_limit()
    @require_permission('write')
    def delete_schedule(schedule_id: str):
        """Delete backup schedule"""
        try:
            if not scheduler:
                return error_response("Scheduler not available", 503)
            
            success = scheduler.delete_schedule(schedule_id)
            
            if success:
                return success_response(
                    {'schedule_id': schedule_id},
                    "Schedule deleted successfully"
                )
            else:
                return not_found_response("Schedule")
                
        except Exception as e:
            logger.error(f"Error deleting schedule: {e}")
            return error_response(f"Failed to delete schedule: {str(e)}", 500)
    
    @app.route('/api/v1/schedule/start', methods=['POST'])
    @api_key_required
    @rate_limit()
    @require_permission('admin')
    def start_scheduler():
        """Start backup scheduler"""
        try:
            if not scheduler:
                return error_response("Scheduler not available", 503)
            
            scheduler.start_scheduler()
            return success_response({}, "Scheduler started successfully")
            
        except Exception as e:
            logger.error(f"Error starting scheduler: {e}")
            return error_response(f"Failed to start scheduler: {str(e)}", 500)
    
    @app.route('/api/v1/schedule/stop', methods=['POST'])
    @api_key_required
    @rate_limit()
    @require_permission('admin')
    def stop_scheduler():
        """Stop backup scheduler"""
        try:
            if not scheduler:
                return error_response("Scheduler not available", 503)
            
            scheduler.stop_scheduler()
            return success_response({}, "Scheduler stopped successfully")
            
        except Exception as e:
            logger.error(f"Error stopping scheduler: {e}")
            return error_response(f"Failed to stop scheduler: {str(e)}", 500)
    
    # ========================================
    # MONITORING ENDPOINTS
    # ========================================
    
    @app.route('/api/v1/monitor/metrics', methods=['GET'])
    @api_key_required
    @rate_limit()
    def get_system_metrics():
        """Get system metrics"""
        try:
            if not monitor:
                return error_response("Monitor not available", 503)
            
            metrics = monitor.get_system_metrics()
            return success_response(metrics, "System metrics retrieved successfully")
            
        except Exception as e:
            logger.error(f"Error getting system metrics: {e}")
            return error_response(f"Failed to get system metrics: {str(e)}", 500)
    
    @app.route('/api/v1/monitor/health', methods=['GET'])
    @api_key_required
    @rate_limit()
    def get_health_status():
        """Get comprehensive health status"""
        try:
            if not health_manager:
                return error_response("Health manager not available", 503)
            
            health_results = health_manager.check_all_health()
            
            overall_health = all(result.healthy for result in health_results.values())
            
            health_data = {
                'overall_status': 'healthy' if overall_health else 'unhealthy',
                'checks': {
                    name: {
                        'status': 'healthy' if result.healthy else 'unhealthy',
                        'message': result.message,
                        'details': result.details
                    }
                    for name, result in health_results.items()
                }
            }
            
            return success_response(health_data, "Health status retrieved successfully")
            
        except Exception as e:
            logger.error(f"Error getting health status: {e}")
            return error_response(f"Failed to get health status: {str(e)}", 500)
    
    # ========================================
    # CONFIGURATION ENDPOINTS
    # ========================================
    
    @app.route('/api/v1/config', methods=['GET'])
    @api_key_required
    @rate_limit()
    @require_permission('read')
    def get_configuration():
        """Get system configuration"""
        try:
            if not config_manager:
                return error_response("Configuration manager not available", 503)
            
            # Get non-sensitive configuration
            config = config_manager.get_all()
            
            # Remove sensitive keys
            sensitive_keys = ['api_key', 'secret_key', 'password', 'macaroon']
            filtered_config = {}
            
            def filter_sensitive(obj, path=""):
                if isinstance(obj, dict):
                    result = {}
                    for key, value in obj.items():
                        current_path = f"{path}.{key}" if path else key
                        if any(sensitive in key.lower() for sensitive in sensitive_keys):
                            result[key] = "***HIDDEN***"
                        else:
                            result[key] = filter_sensitive(value, current_path)
                    return result
                return obj
            
            filtered_config = filter_sensitive(config)
            
            return success_response(filtered_config, "Configuration retrieved successfully")
            
        except Exception as e:
            logger.error(f"Error getting configuration: {e}")
            return error_response(f"Failed to get configuration: {str(e)}", 500)
    
    # ========================================
    # AUTHENTICATION ENDPOINTS
    # ========================================
    
    @app.route('/api/v1/auth/keys', methods=['POST'])
    @api_key_required
    @rate_limit()
    @require_permission('admin')
    def generate_api_key():
        """Generate new API key"""
        try:
            if not auth_manager:
                return error_response("Authentication manager not available", 503)
            
            data = request.get_json() or {}
            name = data.get('name', 'Generated Key')
            permissions = data.get('permissions', ['read'])
            
            api_key = auth_manager.generate_key(name, permissions)
            
            return success_response(
                {'api_key': api_key, 'name': name, 'permissions': permissions},
                "API key generated successfully",
                201
            )
            
        except Exception as e:
            logger.error(f"Error generating API key: {e}")
            return error_response(f"Failed to generate API key: {str(e)}", 500)
    
    @app.route('/api/v1/auth/stats', methods=['GET'])
    @api_key_required
    @rate_limit()
    @require_permission('admin')
    def get_auth_stats():
        """Get authentication statistics"""
        try:
            if not auth_manager:
                return error_response("Authentication manager not available", 503)
            
            stats = auth_manager.get_usage_stats()
            return success_response(stats, "Authentication statistics retrieved successfully")
            
        except Exception as e:
            logger.error(f"Error getting auth stats: {e}")
            return error_response(f"Failed to get auth stats: {str(e)}", 500)
    
    logger.info("API endpoints registered successfully")