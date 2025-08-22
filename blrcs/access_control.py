# BLRCS Access Control System
# Role-based access control with fine-grained permissions
import json
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Any, Union, Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from collections import defaultdict
import re
import fnmatch

class PermissionLevel(Enum):
    """Permission levels"""
    NONE = 0
    READ = 1
    WRITE = 2
    EXECUTE = 4
    DELETE = 8
    ADMIN = 15  # All permissions

class ResourceType(Enum):
    """Resource types in the system"""
    USER = "user"
    ROLE = "role"
    PERMISSION = "permission"
    SESSION = "session"
    CONFIG = "config"
    LOG = "log"
    DATABASE = "database"
    API = "api"
    FILE = "file"
    SYSTEM = "system"
    LIGHTNING = "lightning"
    WALLET = "wallet"
    TRANSACTION = "transaction"
    INVOICE = "invoice"
    CHANNEL = "channel"

class ActionType(Enum):
    """Action types"""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    APPROVE = "approve"
    REJECT = "reject"
    EXPORT = "export"
    IMPORT = "import"
    BACKUP = "backup"
    RESTORE = "restore"
    CONFIGURE = "configure"
    MONITOR = "monitor"

@dataclass
class Permission:
    """Individual permission definition"""
    id: str
    name: str
    description: str
    resource_type: ResourceType
    action: ActionType
    conditions: Dict[str, Any] = field(default_factory=dict)
    level: PermissionLevel = PermissionLevel.READ
    created_at: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        if isinstance(self.resource_type, str):
            self.resource_type = ResourceType(self.resource_type)
        if isinstance(self.action, str):
            self.action = ActionType(self.action)
        if isinstance(self.level, str):
            self.level = PermissionLevel[self.level]
        if isinstance(self.created_at, str):
            self.created_at = datetime.fromisoformat(self.created_at)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'resource_type': self.resource_type.value,
            'action': self.action.value,
            'conditions': self.conditions,
            'level': self.level.name,
            'created_at': self.created_at.isoformat()
        }

@dataclass
class Role:
    """Role with permissions"""
    id: str
    name: str
    description: str
    permissions: Set[str] = field(default_factory=set)
    parent_roles: Set[str] = field(default_factory=set)
    is_system_role: bool = False
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        if isinstance(self.permissions, list):
            self.permissions = set(self.permissions)
        if isinstance(self.parent_roles, list):
            self.parent_roles = set(self.parent_roles)
        if isinstance(self.created_at, str):
            self.created_at = datetime.fromisoformat(self.created_at)
        if isinstance(self.updated_at, str):
            self.updated_at = datetime.fromisoformat(self.updated_at)
    
    def add_permission(self, permission_id: str):
        """Add permission to role"""
        self.permissions.add(permission_id)
        self.updated_at = datetime.now()
    
    def remove_permission(self, permission_id: str):
        """Remove permission from role"""
        self.permissions.discard(permission_id)
        self.updated_at = datetime.now()
    
    def has_permission(self, permission_id: str) -> bool:
        """Check if role has permission"""
        return permission_id in self.permissions
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'permissions': list(self.permissions),
            'parent_roles': list(self.parent_roles),
            'is_system_role': self.is_system_role,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }

@dataclass
class AccessRequest:
    """Access request for permission checking"""
    user_id: str
    resource_type: ResourceType
    resource_id: str
    action: ActionType
    context: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        if isinstance(self.resource_type, str):
            self.resource_type = ResourceType(self.resource_type)
        if isinstance(self.action, str):
            self.action = ActionType(self.action)

@dataclass
class AccessResult:
    """Result of access control check"""
    granted: bool
    reason: str
    permission_id: Optional[str] = None
    conditions_met: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

class ConditionEvaluator:
    """Evaluates permission conditions"""
    
    def __init__(self):
        self.operators = {
            'eq': lambda a, b: a == b,
            'ne': lambda a, b: a != b,
            'gt': lambda a, b: a > b,
            'gte': lambda a, b: a >= b,
            'lt': lambda a, b: a < b,
            'lte': lambda a, b: a <= b,
            'in': lambda a, b: a in b,
            'not_in': lambda a, b: a not in b,
            'contains': lambda a, b: b in a,
            'startswith': lambda a, b: str(a).startswith(str(b)),
            'endswith': lambda a, b: str(a).endswith(str(b)),
            'regex': lambda a, b: bool(re.match(b, str(a))),
            'glob': lambda a, b: fnmatch.fnmatch(str(a), str(b))
        }
    
    def evaluate(self, conditions: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Evaluate conditions against context"""
        if not conditions:
            return True
        
        try:
            return self._evaluate_conditions(conditions, context)
        except Exception:
            return False
    
    def _evaluate_conditions(self, conditions: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Recursively evaluate conditions"""
        if 'and' in conditions:
            return all(self._evaluate_conditions(cond, context) for cond in conditions['and'])
        
        if 'or' in conditions:
            return any(self._evaluate_conditions(cond, context) for cond in conditions['or'])
        
        if 'not' in conditions:
            return not self._evaluate_conditions(conditions['not'], context)
        
        # Single condition
        for field, condition in conditions.items():
            if field in ['and', 'or', 'not']:
                continue
            
            context_value = self._get_nested_value(context, field)
            
            if isinstance(condition, dict):
                # Operator-based condition
                for op, expected_value in condition.items():
                    if op in self.operators:
                        if not self.operators[op](context_value, expected_value):
                            return False
            else:
                # Direct equality
                if context_value != condition:
                    return False
        
        return True
    
    def _get_nested_value(self, data: Dict[str, Any], path: str) -> Any:
        """Get nested value from dictionary using dot notation"""
        keys = path.split('.')
        value = data
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        
        return value

class PolicyEngine:
    """Policy-based access control engine"""
    
    def __init__(self):
        self.policies: Dict[str, Dict[str, Any]] = {}
        self.evaluator = ConditionEvaluator()
    
    def load_policy(self, policy_id: str, policy_data: Dict[str, Any]):
        """Load access control policy"""
        self.policies[policy_id] = policy_data
    
    def evaluate_policy(self, policy_id: str, request: AccessRequest) -> AccessResult:
        """Evaluate policy against access request"""
        if policy_id not in self.policies:
            return AccessResult(False, f"Policy {policy_id} not found")
        
        policy = self.policies[policy_id]
        
        # Check if policy applies to this request
        if not self._policy_applies(policy, request):
            return AccessResult(False, "Policy does not apply to this request")
        
        # Evaluate conditions
        conditions = policy.get('conditions', {})
        context = self._build_context(request)
        
        if not self.evaluator.evaluate(conditions, context):
            return AccessResult(False, "Policy conditions not met", conditions_met=False)
        
        # Check effect
        effect = policy.get('effect', 'deny')
        if effect == 'allow':
            return AccessResult(True, "Policy allows access", permission_id=policy_id)
        else:
            return AccessResult(False, "Policy denies access")
    
    def _policy_applies(self, policy: Dict[str, Any], request: AccessRequest) -> bool:
        """Check if policy applies to request"""
        # Check resource type
        if 'resource_types' in policy:
            if request.resource_type.value not in policy['resource_types']:
                return False
        
        # Check actions
        if 'actions' in policy:
            if request.action.value not in policy['actions']:
                return False
        
        # Check resource patterns
        if 'resource_patterns' in policy:
            patterns = policy['resource_patterns']
            if not any(fnmatch.fnmatch(request.resource_id, pattern) for pattern in patterns):
                return False
        
        return True
    
    def _build_context(self, request: AccessRequest) -> Dict[str, Any]:
        """Build context for condition evaluation"""
        context = {
            'user_id': request.user_id,
            'resource_type': request.resource_type.value,
            'resource_id': request.resource_id,
            'action': request.action.value,
            'timestamp': request.timestamp.isoformat(),
            'time': {
                'hour': request.timestamp.hour,
                'day_of_week': request.timestamp.weekday(),
                'is_weekend': request.timestamp.weekday() >= 5
            }
        }
        
        # Add request context
        context.update(request.context)
        
        return context

class AccessControlManager:
    """Main access control manager"""
    
    def __init__(self, database=None, logger=None):
        self.database = database
        self.logger = logger
        self.permissions: Dict[str, Permission] = {}
        self.roles: Dict[str, Role] = {}
        self.user_roles: Dict[str, Set[str]] = defaultdict(set)
        self.policy_engine = PolicyEngine()
        self.condition_evaluator = ConditionEvaluator()
        self.lock = threading.RLock()
        
        # Access cache for performance
        self.access_cache: Dict[str, tuple[AccessResult, float]] = {}
        self.cache_ttl = 300  # 5 minutes
        
        # Access monitoring
        self.access_attempts: List[Dict[str, Any]] = []
        self.max_access_history = 10000
        
        # Initialize system permissions and roles
        self._initialize_system_permissions()
        self._initialize_system_roles()
        
        # Load existing data
        self._load_data()
    
    def _initialize_system_permissions(self):
        """Initialize system permissions"""
        system_permissions = [
            # User management
            ('user.create', 'Create Users', ResourceType.USER, ActionType.CREATE),
            ('user.read', 'Read Users', ResourceType.USER, ActionType.READ),
            ('user.update', 'Update Users', ResourceType.USER, ActionType.UPDATE),
            ('user.delete', 'Delete Users', ResourceType.USER, ActionType.DELETE),
            
            # Role management
            ('role.create', 'Create Roles', ResourceType.ROLE, ActionType.CREATE),
            ('role.read', 'Read Roles', ResourceType.ROLE, ActionType.READ),
            ('role.update', 'Update Roles', ResourceType.ROLE, ActionType.UPDATE),
            ('role.delete', 'Delete Roles', ResourceType.ROLE, ActionType.DELETE),
            
            # System configuration
            ('config.read', 'Read Configuration', ResourceType.CONFIG, ActionType.READ),
            ('config.update', 'Update Configuration', ResourceType.CONFIG, ActionType.UPDATE),
            
            # Logging
            ('log.read', 'Read Logs', ResourceType.LOG, ActionType.READ),
            ('log.export', 'Export Logs', ResourceType.LOG, ActionType.EXPORT),
            
            # Database
            ('database.read', 'Read Database', ResourceType.DATABASE, ActionType.READ),
            ('database.backup', 'Backup Database', ResourceType.DATABASE, ActionType.BACKUP),
            ('database.restore', 'Restore Database', ResourceType.DATABASE, ActionType.RESTORE),
            
            # Lightning Network
            ('lightning.read', 'Read Lightning Info', ResourceType.LIGHTNING, ActionType.READ),
            ('lightning.create', 'Create Lightning Channels', ResourceType.LIGHTNING, ActionType.CREATE),
            ('lightning.update', 'Update Lightning Settings', ResourceType.LIGHTNING, ActionType.UPDATE),
            
            # Wallet operations
            ('wallet.read', 'Read Wallet', ResourceType.WALLET, ActionType.READ),
            ('wallet.create', 'Create Transactions', ResourceType.WALLET, ActionType.CREATE),
            ('wallet.backup', 'Backup Wallet', ResourceType.WALLET, ActionType.BACKUP),
            
            # System administration
            ('system.monitor', 'Monitor System', ResourceType.SYSTEM, ActionType.MONITOR),
            ('system.configure', 'Configure System', ResourceType.SYSTEM, ActionType.CONFIGURE),
            ('system.execute', 'Execute System Commands', ResourceType.SYSTEM, ActionType.EXECUTE)
        ]
        
        for perm_id, name, resource_type, action in system_permissions:
            permission = Permission(
                id=perm_id,
                name=name,
                description=f"System permission: {name}",
                resource_type=resource_type,
                action=action
            )
            self.permissions[perm_id] = permission
    
    def _initialize_system_roles(self):
        """Initialize system roles"""
        # Super Admin - all permissions
        super_admin = Role(
            id='super_admin',
            name='Super Administrator',
            description='Full system access',
            permissions=set(self.permissions.keys()),
            is_system_role=True
        )
        self.roles['super_admin'] = super_admin
        
        # Admin - most permissions except system execute
        admin_perms = {p for p in self.permissions.keys() if 'system.execute' not in p}
        admin = Role(
            id='admin',
            name='Administrator',
            description='System administrator with most privileges',
            permissions=admin_perms,
            is_system_role=True
        )
        self.roles['admin'] = admin
        
        # Operator - read and operational permissions
        operator_perms = {
            'user.read', 'role.read', 'config.read', 'log.read',
            'lightning.read', 'lightning.create', 'lightning.update',
            'wallet.read', 'wallet.create', 'system.monitor'
        }
        operator = Role(
            id='operator',
            name='Operator',
            description='Lightning network operator',
            permissions=operator_perms,
            is_system_role=True
        )
        self.roles['operator'] = operator
        
        # Viewer - read-only permissions
        viewer_perms = {
            'user.read', 'role.read', 'config.read', 'log.read',
            'lightning.read', 'wallet.read', 'system.monitor'
        }
        viewer = Role(
            id='viewer',
            name='Viewer',
            description='Read-only access',
            permissions=viewer_perms,
            is_system_role=True
        )
        self.roles['viewer'] = viewer
        
        # Guest - minimal permissions
        guest = Role(
            id='guest',
            name='Guest',
            description='Minimal access for guests',
            permissions={'lightning.read'},
            is_system_role=True
        )
        self.roles['guest'] = guest
    
    def _load_data(self):
        """Load existing data from database"""
        if not self.database:
            return
        
        try:
            # Load custom permissions
            perm_data = self.database.select('permissions')
            for row in perm_data:
                permission = Permission(**row)
                self.permissions[permission.id] = permission
            
            # Load custom roles
            role_data = self.database.select('roles')
            for row in role_data:
                role = Role(**row)
                self.roles[role.id] = role
            
            # Load user roles
            user_role_data = self.database.select('user_roles')
            for row in user_role_data:
                user_id = row['user_id']
                role_id = row['role_id']
                self.user_roles[user_id].add(role_id)
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Failed to load access control data: {e}")
    
    def check_access(self, user_id: str, resource_type: Union[ResourceType, str], 
                    resource_id: str, action: Union[ActionType, str], 
                    context: Dict[str, Any] = None) -> AccessResult:
        """Check if user has access to resource"""
        with self.lock:
            try:
                # Convert string enums
                if isinstance(resource_type, str):
                    resource_type = ResourceType(resource_type)
                if isinstance(action, str):
                    action = ActionType(action)
                
                # Create access request
                request = AccessRequest(
                    user_id=user_id,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    action=action,
                    context=context or {}
                )
                
                # Check cache
                cache_key = self._get_cache_key(request)
                if cache_key in self.access_cache:
                    result, timestamp = self.access_cache[cache_key]
                    if time.time() - timestamp < self.cache_ttl:
                        return result
                
                # Check access
                result = self._check_access_internal(request)
                
                # Cache result
                self.access_cache[cache_key] = (result, time.time())
                
                # Log access attempt
                self._log_access_attempt(request, result)
                
                return result
                
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Access check failed: {e}")
                return AccessResult(False, f"Access check error: {str(e)}")
    
    def _check_access_internal(self, request: AccessRequest) -> AccessResult:
        """Internal access checking logic"""
        # Get user roles
        user_role_ids = self.user_roles.get(request.user_id, set())
        if not user_role_ids:
            return AccessResult(False, "User has no roles assigned")
        
        # Collect all permissions from user roles (including inherited)
        user_permissions = set()
        for role_id in user_role_ids:
            role_permissions = self._get_role_permissions(role_id)
            user_permissions.update(role_permissions)
        
        # Check permissions
        for permission_id in user_permissions:
            permission = self.permissions.get(permission_id)
            if not permission:
                continue
            
            # Check if permission matches request
            if (permission.resource_type == request.resource_type and
                permission.action == request.action):
                
                # Check conditions
                context = self._build_permission_context(request)
                if self.condition_evaluator.evaluate(permission.conditions, context):
                    return AccessResult(
                        True, 
                        f"Access granted via permission: {permission.name}",
                        permission_id=permission_id
                    )
        
        # Check policies
        for policy_id in self.policy_engine.policies:
            result = self.policy_engine.evaluate_policy(policy_id, request)
            if result.granted:
                return result
        
        return AccessResult(False, "No matching permissions or policies found")
    
    def _get_role_permissions(self, role_id: str, visited: Set[str] = None) -> Set[str]:
        """Get all permissions for role including inherited ones"""
        if visited is None:
            visited = set()
        
        if role_id in visited:
            return set()  # Prevent circular inheritance
        
        visited.add(role_id)
        
        role = self.roles.get(role_id)
        if not role:
            return set()
        
        permissions = role.permissions.copy()
        
        # Add inherited permissions
        for parent_role_id in role.parent_roles:
            parent_permissions = self._get_role_permissions(parent_role_id, visited)
            permissions.update(parent_permissions)
        
        return permissions
    
    def _build_permission_context(self, request: AccessRequest) -> Dict[str, Any]:
        """Build context for permission condition evaluation"""
        return {
            'user_id': request.user_id,
            'resource_type': request.resource_type.value,
            'resource_id': request.resource_id,
            'action': request.action.value,
            'timestamp': request.timestamp.isoformat(),
            'request': request.context
        }
    
    def _get_cache_key(self, request: AccessRequest) -> str:
        """Generate cache key for access request"""
        context_hash = hash(json.dumps(request.context, sort_keys=True))
        return f"{request.user_id}:{request.resource_type.value}:{request.resource_id}:{request.action.value}:{context_hash}"
    
    def _log_access_attempt(self, request: AccessRequest, result: AccessResult):
        """Log access attempt"""
        attempt = {
            'user_id': request.user_id,
            'resource_type': request.resource_type.value,
            'resource_id': request.resource_id,
            'action': request.action.value,
            'granted': result.granted,
            'reason': result.reason,
            'timestamp': request.timestamp.isoformat(),
            'context': request.context
        }
        
        self.access_attempts.append(attempt)
        if len(self.access_attempts) > self.max_access_history:
            self.access_attempts.pop(0)
        
        if self.database:
            self.database.insert('access_attempts', attempt)
        
        if self.logger:
            level = 'info' if result.granted else 'warning'
            getattr(self.logger, level)(
                f"Access {('granted' if result.granted else 'denied')}: "
                f"User {request.user_id} {request.action.value} {request.resource_type.value}:{request.resource_id}"
            )
    
    # Role management methods
    def assign_role(self, user_id: str, role_id: str) -> tuple[bool, str]:
        """Assign role to user"""
        with self.lock:
            try:
                if role_id not in self.roles:
                    return False, f"Role {role_id} not found"
                
                self.user_roles[user_id].add(role_id)
                
                # Save to database
                if self.database:
                    self.database.insert('user_roles', {
                        'user_id': user_id,
                        'role_id': role_id,
                        'assigned_at': datetime.now().isoformat()
                    })
                
                # Clear cache for user
                self._clear_user_cache(user_id)
                
                if self.logger:
                    self.logger.info(f"Role {role_id} assigned to user {user_id}")
                
                return True, "Role assigned successfully"
                
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Failed to assign role: {e}")
                return False, f"Failed to assign role: {str(e)}"
    
    def revoke_role(self, user_id: str, role_id: str) -> tuple[bool, str]:
        """Revoke role from user"""
        with self.lock:
            try:
                if role_id not in self.user_roles[user_id]:
                    return False, f"User does not have role {role_id}"
                
                self.user_roles[user_id].discard(role_id)
                
                # Remove from database
                if self.database:
                    self.database.delete('user_roles', {
                        'user_id': user_id,
                        'role_id': role_id
                    })
                
                # Clear cache for user
                self._clear_user_cache(user_id)
                
                if self.logger:
                    self.logger.info(f"Role {role_id} revoked from user {user_id}")
                
                return True, "Role revoked successfully"
                
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Failed to revoke role: {e}")
                return False, f"Failed to revoke role: {str(e)}"
    
    def get_user_permissions(self, user_id: str) -> Set[str]:
        """Get all permissions for user"""
        user_roles = self.user_roles.get(user_id, set())
        permissions = set()
        
        for role_id in user_roles:
            role_permissions = self._get_role_permissions(role_id)
            permissions.update(role_permissions)
        
        return permissions
    
    def create_role(self, role_id: str, name: str, description: str, 
                   permissions: List[str] = None) -> tuple[bool, str]:
        """Create new role"""
        with self.lock:
            try:
                if role_id in self.roles:
                    return False, f"Role {role_id} already exists"
                
                role = Role(
                    id=role_id,
                    name=name,
                    description=description,
                    permissions=set(permissions or [])
                )
                
                self.roles[role_id] = role
                
                # Save to database
                if self.database:
                    self.database.insert('roles', role.to_dict())
                
                if self.logger:
                    self.logger.info(f"Role created: {role_id}")
                
                return True, "Role created successfully"
                
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Failed to create role: {e}")
                return False, f"Failed to create role: {str(e)}"
    
    def _clear_user_cache(self, user_id: str):
        """Clear access cache for user"""
        keys_to_remove = [key for key in self.access_cache.keys() if key.startswith(f"{user_id}:")]
        for key in keys_to_remove:
            del self.access_cache[key]
    
    def clear_cache(self):
        """Clear all access cache"""
        self.access_cache.clear()
    
    def get_access_stats(self) -> Dict[str, Any]:
        """Get access control statistics"""
        total_attempts = len(self.access_attempts)
        granted_attempts = sum(1 for a in self.access_attempts if a['granted'])
        
        return {
            'total_permissions': len(self.permissions),
            'total_roles': len(self.roles),
            'total_users_with_roles': len(self.user_roles),
            'total_access_attempts': total_attempts,
            'granted_attempts': granted_attempts,
            'denied_attempts': total_attempts - granted_attempts,
            'cache_size': len(self.access_cache),
            'policies_loaded': len(self.policy_engine.policies)
        }

# Decorator for access control
def require_permission(resource_type: Union[ResourceType, str], 
                      action: Union[ActionType, str],
                      resource_id_param: str = 'resource_id'):
    """Decorator to require permission for function access"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            # This would be used with a request context that provides user_id
            # Implementation depends on your web framework
            pass
        return wrapper
    return decorator

# Factory function
def create_access_control_manager(database=None, logger=None) -> AccessControlManager:
    """Create access control manager"""
    return AccessControlManager(database, logger)

# Export main classes
__all__ = [
    'PermissionLevel', 'ResourceType', 'ActionType',
    'Permission', 'Role', 'AccessRequest', 'AccessResult',
    'AccessControlManager', 'PolicyEngine', 'ConditionEvaluator',
    'require_permission', 'create_access_control_manager'
]