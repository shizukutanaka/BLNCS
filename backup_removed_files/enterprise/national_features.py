"""
Enterprise-grade Features for BLNCS National Deployment
Provides audit logging, compliance reporting, multi-tenancy, and advanced log management
"""

import json
import sqlite3
import time
import threading
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from contextlib import contextmanager
import hashlib
import secrets
import csv
import io
from pathlib import Path
import gzip
import shutil
import uuid

logger = logging.getLogger(__name__)

class AuditLogger:
    """Comprehensive audit logging system"""

    def __init__(self, db_path: str = "audit.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_database()

    def _init_database(self):
        """Initialize audit database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    user_id TEXT,
                    action TEXT NOT NULL,
                    resource TEXT,
                    details TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    success BOOLEAN,
                    session_id TEXT,
                    request_id TEXT UNIQUE
                )
            ''')

            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                ON audit_log(timestamp)
            ''')

            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_audit_user
                ON audit_log(user_id)
            ''')

            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_audit_action
                ON audit_log(action)
            ''')

    def log_event(self, action: str, user_id: str = None, resource: str = None,
                  details: Dict = None, ip_address: str = None,
                  user_agent: str = None, success: bool = True,
                  session_id: str = None, request_id: str = None):
        """Log an audit event"""
        if request_id is None:
            request_id = str(uuid.uuid4())

        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute('''
                        INSERT INTO audit_log
                        (timestamp, user_id, action, resource, details, ip_address,
                         user_agent, success, session_id, request_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        time.time(),
                        user_id,
                        action,
                        resource,
                        json.dumps(details) if details else None,
                        ip_address,
                        user_agent,
                        success,
                        session_id,
                        request_id
                    ))

                    logger.info(f"Audit log: {action} by user {user_id} on {resource}")

            except Exception as e:
                logger.error(f"Failed to write audit log: {e}")

    def query_audit_log(self, start_time: float = None, end_time: float = None,
                       user_id: str = None, action: str = None,
                       limit: int = 1000) -> List[Dict[str, Any]]:
        """Query audit log with filters"""
        query = "SELECT * FROM audit_log WHERE 1=1"
        params = []

        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)

        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)

        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)

        if action:
            query += " AND action = ?"
            params.append(action)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(query, params)

                results = []
                for row in cursor:
                    result = dict(row)
                    if result['details']:
                        try:
                            result['details'] = json.loads(result['details'])
                        except:
                            pass  # Keep as string if not valid JSON
                    results.append(result)

                return results

        except Exception as e:
            logger.error(f"Failed to query audit log: {e}")
            return []

    def export_audit_log(self, start_time: float = None, end_time: float = None,
                        format: str = 'csv') -> str:
        """Export audit log to specified format"""
        events = self.query_audit_log(start_time, end_time, limit=100000)

        if format.lower() == 'csv':
            output = io.StringIO()
            fieldnames = ['timestamp', 'user_id', 'action', 'resource', 'details',
                         'ip_address', 'user_agent', 'success', 'session_id', 'request_id']

            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()

            for event in events:
                # Convert timestamp to readable format
                event_copy = event.copy()
                event_copy['timestamp'] = datetime.fromtimestamp(event['timestamp']).isoformat()

                # Flatten details if it's a dict
                if isinstance(event.get('details'), dict):
                    event_copy['details'] = json.dumps(event['details'])

                writer.writerow(event_copy)

            return output.getvalue()

        elif format.lower() == 'json':
            export_data = []
            for event in events:
                event_copy = event.copy()
                event_copy['timestamp'] = datetime.fromtimestamp(event['timestamp']).isoformat()
                export_data.append(event_copy)

            return json.dumps(export_data, indent=2)

        else:
            raise ValueError(f"Unsupported export format: {format}")

class ComplianceReporter:
    """Automated compliance reporting system"""

    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
        self.compliance_rules = {}

    def register_compliance_rule(self, rule_name: str, check_function: callable,
                                description: str, severity: str = 'medium'):
        """Register a compliance rule"""
        self.compliance_rules[rule_name] = {
            'check': check_function,
            'description': description,
            'severity': severity
        }

    def generate_compliance_report(self, start_time: float = None,
                                  end_time: float = None) -> Dict[str, Any]:
        """Generate comprehensive compliance report"""
        if start_time is None:
            start_time = time.time() - (30 * 24 * 3600)  # Last 30 days
        if end_time is None:
            end_time = time.time()

        report = {
            'report_id': str(uuid.uuid4()),
            'generated_at': datetime.now().isoformat(),
            'period': {
                'start': datetime.fromtimestamp(start_time).isoformat(),
                'end': datetime.fromtimestamp(end_time).isoformat()
            },
            'summary': {},
            'violations': [],
            'recommendations': []
        }

        # Get audit events for the period
        audit_events = self.audit_logger.query_audit_log(start_time, end_time)

        # Check each compliance rule
        total_rules = len(self.compliance_rules)
        passed_rules = 0

        for rule_name, rule_info in self.compliance_rules.items():
            try:
                violations = rule_info['check'](audit_events)

                if not violations:
                    passed_rules += 1
                else:
                    report['violations'].extend([{
                        'rule': rule_name,
                        'severity': rule_info['severity'],
                        'description': rule_info['description'],
                        'details': violations
                    }])

            except Exception as e:
                logger.error(f"Error checking compliance rule {rule_name}: {e}")
                report['violations'].append({
                    'rule': rule_name,
                    'severity': 'high',
                    'description': rule_info['description'],
                    'details': [f"Rule check failed: {str(e)}"]
                })

        # Calculate compliance score
        compliance_score = (passed_rules / total_rules * 100) if total_rules > 0 else 100
        report['summary'] = {
            'compliance_score': round(compliance_score, 2),
            'total_rules': total_rules,
            'passed_rules': passed_rules,
            'failed_rules': total_rules - passed_rules,
            'total_audit_events': len(audit_events)
        }

        # Generate recommendations
        report['recommendations'] = self._generate_recommendations(report)

        return report

    def _generate_recommendations(self, report: Dict[str, Any]) -> List[str]:
        """Generate compliance recommendations"""
        recommendations = []

        score = report['summary']['compliance_score']

        if score < 50:
            recommendations.append("Critical: Immediate attention required for compliance violations")
        elif score < 80:
            recommendations.append("Warning: Multiple compliance issues detected")
        else:
            recommendations.append("Good: Compliance status is acceptable")

        # Specific recommendations based on violations
        for violation in report['violations']:
            if violation['severity'] == 'high':
                recommendations.append(f"High priority: Address {violation['rule']} violations")
            elif violation['severity'] == 'medium':
                recommendations.append(f"Medium priority: Review {violation['rule']} compliance")

        if not recommendations:
            recommendations.append("No specific recommendations at this time")

        return recommendations

class MultiTenantManager:
    """Multi-tenant architecture support"""

    def __init__(self, db_path: str = "tenants.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_database()

    def _init_database(self):
        """Initialize tenant database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS tenants (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    domain TEXT UNIQUE,
                    config TEXT,
                    created_at REAL,
                    updated_at REAL,
                    status TEXT DEFAULT 'active'
                )
            ''')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS tenant_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    created_at REAL,
                    UNIQUE(tenant_id, user_id)
                )
            ''')

    def create_tenant(self, tenant_id: str, name: str, domain: str = None,
                     config: Dict = None) -> bool:
        """Create a new tenant"""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute('''
                        INSERT INTO tenants (id, name, domain, config, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        tenant_id,
                        name,
                        domain,
                        json.dumps(config) if config else None,
                        time.time(),
                        time.time()
                    ))

                    logger.info(f"Created tenant: {tenant_id}")
                    return True

            except Exception as e:
                logger.error(f"Failed to create tenant {tenant_id}: {e}")
                return False

    def get_tenant(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Get tenant information"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('SELECT * FROM tenants WHERE id = ?', (tenant_id,))
                row = cursor.fetchone()

                if row:
                    tenant = dict(row)
                    if tenant['config']:
                        tenant['config'] = json.loads(tenant['config'])
                    return tenant

        except Exception as e:
            logger.error(f"Failed to get tenant {tenant_id}: {e}")

        return None

    def add_user_to_tenant(self, tenant_id: str, user_id: str, role: str = 'user') -> bool:
        """Add user to tenant"""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute('''
                        INSERT OR REPLACE INTO tenant_users
                        (tenant_id, user_id, role, created_at)
                        VALUES (?, ?, ?, ?)
                    ''', (tenant_id, user_id, role, time.time()))

                    logger.info(f"Added user {user_id} to tenant {tenant_id}")
                    return True

            except Exception as e:
                logger.error(f"Failed to add user {user_id} to tenant {tenant_id}: {e}")
                return False

    def get_tenant_users(self, tenant_id: str) -> List[Dict[str, Any]]:
        """Get all users in a tenant"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute('''
                    SELECT * FROM tenant_users WHERE tenant_id = ?
                ''', (tenant_id,))

                return [dict(row) for row in cursor]

        except Exception as e:
            logger.error(f"Failed to get users for tenant {tenant_id}: {e}")
            return []

    def validate_tenant_access(self, user_id: str, tenant_id: str) -> bool:
        """Validate user access to tenant"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT COUNT(*) FROM tenant_users
                    WHERE tenant_id = ? AND user_id = ?
                ''', (tenant_id, user_id))

                return cursor.fetchone()[0] > 0

        except Exception as e:
            logger.error(f"Failed to validate tenant access for user {user_id}: {e}")
            return False

class AdvancedLogManager:
    """Advanced log management with rotation and archival"""

    def __init__(self, log_dir: str = "logs", max_size_mb: int = 100,
                 retention_days: int = 30):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.max_size_mb = max_size_mb
        self.retention_days = retention_days
        self.log_files = {}
        self.lock = threading.Lock()

    def register_log_file(self, name: str, filename: str):
        """Register a log file for management"""
        with self.lock:
            self.log_files[name] = {
                'path': self.log_dir / filename,
                'last_rotation': time.time(),
                'size': 0
            }

    def check_rotation_needed(self, name: str) -> bool:
        """Check if log rotation is needed"""
        if name not in self.log_files:
            return False

        log_info = self.log_files[name]
        current_size = log_info['path'].stat().st_size if log_info['path'].exists() else 0

        return current_size > (self.max_size_mb * 1024 * 1024)

    def rotate_log(self, name: str):
        """Rotate log file"""
        if name not in self.log_files:
            return

        log_info = self.log_files[name]
        log_path = log_info['path']

        if not log_path.exists():
            return

        # Create compressed archive
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_name = f"{log_path.stem}_{timestamp}.gz"
        archive_path = self.log_dir / archive_name

        try:
            with open(log_path, 'rb') as f_in:
                with gzip.open(archive_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

            # Clear original log file
            log_path.write_text("")

            log_info['last_rotation'] = time.time()
            log_info['size'] = 0

            logger.info(f"Rotated log {name} to {archive_name}")

        except Exception as e:
            logger.error(f"Failed to rotate log {name}: {e}")

    def cleanup_old_logs(self):
        """Clean up old log archives"""
        cutoff_time = time.time() - (self.retention_days * 24 * 3600)

        try:
            for log_file in self.log_dir.glob("*.gz"):
                if log_file.stat().st_mtime < cutoff_time:
                    log_file.unlink()
                    logger.info(f"Removed old log archive: {log_file.name}")

        except Exception as e:
            logger.error(f"Failed to cleanup old logs: {e}")

    def get_log_summary(self) -> Dict[str, Any]:
        """Get log management summary"""
        with self.lock:
            summary = {}

            for name, info in self.log_files.items():
                path = info['path']
                if path.exists():
                    stat = path.stat()
                    summary[name] = {
                        'size_mb': stat.st_size / 1024 / 1024,
                        'last_modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        'last_rotation': datetime.fromtimestamp(info['last_rotation']).isoformat()
                    }

            # Count archive files
            archive_count = len(list(self.log_dir.glob("*.gz")))
            summary['archive_count'] = archive_count

            return summary

# Global enterprise instances
audit_logger = AuditLogger()
compliance_reporter = ComplianceReporter(audit_logger)
tenant_manager = MultiTenantManager()
log_manager = AdvancedLogManager()

def init_enterprise_systems():
    """Initialize all enterprise systems"""
    # Register default compliance rules
    compliance_reporter.register_compliance_rule(
        'failed_login_attempts',
        lambda events: [
            event for event in events
            if event['action'] == 'login' and not event['success']
        ],
        'Failed login attempts should be monitored',
        'medium'
    )

    compliance_reporter.register_compliance_rule(
        'unauthorized_access',
        lambda events: [
            event for event in events
            if 'unauthorized' in event['action'].lower()
        ],
        'Unauthorized access attempts detected',
        'high'
    )

    # Register log files for management
    log_manager.register_log_file('main', 'blncs.log')
    log_manager.register_log_file('audit', 'audit.log')

def get_tenant_context(tenant_id: str = None) -> Dict[str, Any]:
    """Get current tenant context for operations"""
    if not tenant_id:
        return {'tenant_id': None, 'is_multitenant': False}

    tenant = tenant_manager.get_tenant(tenant_id)
    if not tenant:
        raise ValueError(f"Tenant {tenant_id} not found")

    return {
        'tenant_id': tenant_id,
        'tenant_name': tenant['name'],
        'tenant_config': tenant.get('config', {}),
        'is_multitenant': True
    }

@contextmanager
def tenant_context(tenant_id: str):
    """Context manager for tenant-specific operations"""
    context = get_tenant_context(tenant_id)
    try:
        yield context
    finally:
        pass  # Cleanup if needed

def audit_log_action(action: str, resource: str = None, details: Dict = None):
    """Decorator for automatic audit logging"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Generate request context
            request_id = str(uuid.uuid4())
            user_id = getattr(threading.current_thread(), 'current_user_id', None)
            session_id = getattr(threading.current_thread(), 'session_id', None)

            # Log action start
            audit_logger.log_event(
                action=f"{action}_start",
                user_id=user_id,
                resource=resource,
                details={'function': func.__name__, 'args_count': len(args), **(details or {})},
                session_id=session_id,
                request_id=request_id
            )

            try:
                result = func(*args, **kwargs)

                # Log successful completion
                audit_logger.log_event(
                    action=f"{action}_success",
                    user_id=user_id,
                    resource=resource,
                    details={'function': func.__name__, 'result_type': str(type(result))},
                    success=True,
                    session_id=session_id,
                    request_id=request_id
                )

                return result

            except Exception as e:
                # Log failure
                audit_logger.log_event(
                    action=f"{action}_failed",
                    user_id=user_id,
                    resource=resource,
                    details={'function': func.__name__, 'error': str(e)},
                    success=False,
                    session_id=session_id,
                    request_id=request_id
                )
                raise

        return wrapper
    return decorator
