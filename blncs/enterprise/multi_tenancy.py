"""
Enterprise Multi-Tenancy System
Advanced tenant isolation, resource management, and billing for BLNCS.
"""

import asyncio
import logging
import json
import uuid
from typing import Dict, List, Optional, Any, Set, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import threading
from concurrent.futures import ThreadPoolExecutor
import sqlite3
from pathlib import Path

try:
    import jwt
    HAS_JWT = True
except ImportError:
    HAS_JWT = False
    jwt = None

try:
    from cryptography.fernet import Fernet
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False
    Fernet = None

logger = logging.getLogger(__name__)

class TenantStatus(Enum):
    """Tenant status values."""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    PENDING = "pending"
    DEACTIVATED = "deactivated"

class ResourceType(Enum):
    """Types of resources that can be limited."""
    LIGHTNING_CHANNELS = "lightning_channels"
    PAYMENT_VOLUME = "payment_volume"
    API_REQUESTS = "api_requests"
    STORAGE_BYTES = "storage_bytes"
    WEBSOCKET_CONNECTIONS = "websocket_connections"
    USERS = "users"
    NODES = "nodes"

class BillingModel(Enum):
    """Billing models for tenants."""
    FREE_TIER = "free_tier"
    PAY_AS_YOU_GO = "pay_as_you_go"
    SUBSCRIPTION = "subscription"
    ENTERPRISE = "enterprise"

@dataclass
class ResourceQuota:
    """Resource quota definition."""
    resource_type: ResourceType
    limit: int
    used: int = 0
    soft_limit: Optional[int] = None
    burst_limit: Optional[int] = None
    reset_period: timedelta = timedelta(hours=1)
    last_reset: datetime = field(default_factory=datetime.utcnow)
    
    @property
    def utilization_percent(self) -> float:
        """Get resource utilization percentage."""
        if self.limit == 0:
            return 0.0
        return (self.used / self.limit) * 100.0
    
    @property
    def is_exceeded(self) -> bool:
        """Check if quota is exceeded."""
        return self.used >= self.limit
    
    @property
    def is_soft_limit_exceeded(self) -> bool:
        """Check if soft limit is exceeded."""
        if self.soft_limit is None:
            return False
        return self.used >= self.soft_limit

@dataclass
class TenantConfiguration:
    """Tenant-specific configuration settings."""
    tenant_id: str
    custom_config: Dict[str, Any] = field(default_factory=dict)
    feature_flags: Dict[str, bool] = field(default_factory=dict)
    api_endpoints: Dict[str, bool] = field(default_factory=dict)
    webhook_urls: List[str] = field(default_factory=list)
    notification_settings: Dict[str, Any] = field(default_factory=dict)
    branding: Dict[str, str] = field(default_factory=dict)
    
    def get_config_value(self, key: str, default: Any = None) -> Any:
        """Get configuration value with fallback."""
        return self.custom_config.get(key, default)
    
    def is_feature_enabled(self, feature: str) -> bool:
        """Check if a feature is enabled for this tenant."""
        return self.feature_flags.get(feature, False)
    
    def is_endpoint_enabled(self, endpoint: str) -> bool:
        """Check if an API endpoint is enabled for this tenant."""
        return self.api_endpoints.get(endpoint, True)

@dataclass
class Tenant:
    """Enterprise tenant definition."""
    tenant_id: str
    name: str
    organization: str
    status: TenantStatus
    billing_model: BillingModel
    created_at: datetime
    updated_at: datetime
    admin_email: str
    quotas: Dict[ResourceType, ResourceQuota] = field(default_factory=dict)
    configuration: Optional[TenantConfiguration] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    parent_tenant_id: Optional[str] = None
    child_tenant_ids: Set[str] = field(default_factory=set)
    
    def __post_init__(self):
        """Initialize tenant configuration if not provided."""
        if self.configuration is None:
            self.configuration = TenantConfiguration(tenant_id=self.tenant_id)
    
    @property
    def is_active(self) -> bool:
        """Check if tenant is active."""
        return self.status == TenantStatus.ACTIVE
    
    def get_quota(self, resource_type: ResourceType) -> Optional[ResourceQuota]:
        """Get resource quota for a specific type."""
        return self.quotas.get(resource_type)
    
    def check_quota(self, resource_type: ResourceType, requested: int = 1) -> bool:
        """Check if resource request is within quota limits."""
        quota = self.get_quota(resource_type)
        if not quota:
            return True  # No quota = unlimited
        
        return (quota.used + requested) <= quota.limit
    
    def use_resource(self, resource_type: ResourceType, amount: int = 1) -> bool:
        """Use resources and update quota."""
        quota = self.get_quota(resource_type)
        if not quota:
            return True  # No quota = unlimited
        
        if quota.used + amount > quota.limit:
            return False
        
        quota.used += amount
        return True
    
    def release_resource(self, resource_type: ResourceType, amount: int = 1) -> None:
        """Release resources from quota."""
        quota = self.get_quota(resource_type)
        if quota:
            quota.used = max(0, quota.used - amount)

@dataclass
class TenantUsage:
    """Tenant resource usage tracking."""
    tenant_id: str
    period_start: datetime
    period_end: datetime
    usage_data: Dict[ResourceType, Dict[str, Union[int, float]]] = field(default_factory=dict)
    billing_amount: float = 0.0
    currency: str = "USD"
    
    def record_usage(self, resource_type: ResourceType, amount: Union[int, float], 
                    timestamp: Optional[datetime] = None) -> None:
        """Record resource usage."""
        if resource_type not in self.usage_data:
            self.usage_data[resource_type] = {"total": 0, "peak": 0, "count": 0}
        
        usage = self.usage_data[resource_type]
        usage["total"] += amount
        usage["peak"] = max(usage["peak"], amount)
        usage["count"] += 1
    
    def get_total_usage(self, resource_type: ResourceType) -> Union[int, float]:
        """Get total usage for a resource type."""
        return self.usage_data.get(resource_type, {}).get("total", 0)

class MultiTenancyManager:
    """Enterprise multi-tenancy management system."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the multi-tenancy manager."""
        self.config = config or self._get_default_config()
        self.tenants: Dict[str, Tenant] = {}
        self.tenant_cache: Dict[str, Tenant] = {}
        self.usage_tracking: Dict[str, TenantUsage] = {}
        
        # Threading
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="tenancy")
        self.quota_reset_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        
        # Database
        self.db_path = Path(self.config.get('database_path', 'tenancy.db'))
        self._init_database()
        
        # Encryption
        self.encryption_key = self._get_or_create_encryption_key()
        
        # Load existing tenants
        self._load_tenants()
        
        logger.info("Multi-tenancy manager initialized")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            'database_path': 'tenancy.db',
            'default_quotas': {
                ResourceType.LIGHTNING_CHANNELS: 10,
                ResourceType.PAYMENT_VOLUME: 1000000,  # satoshis per hour
                ResourceType.API_REQUESTS: 10000,  # per hour
                ResourceType.STORAGE_BYTES: 1024 * 1024 * 1024,  # 1GB
                ResourceType.WEBSOCKET_CONNECTIONS: 10,
                ResourceType.USERS: 5,
                ResourceType.NODES: 1
            },
            'tier_quotas': {
                BillingModel.FREE_TIER: {
                    ResourceType.LIGHTNING_CHANNELS: 5,
                    ResourceType.PAYMENT_VOLUME: 100000,
                    ResourceType.API_REQUESTS: 1000,
                    ResourceType.STORAGE_BYTES: 100 * 1024 * 1024,  # 100MB
                    ResourceType.WEBSOCKET_CONNECTIONS: 2,
                    ResourceType.USERS: 1,
                    ResourceType.NODES: 1
                },
                BillingModel.SUBSCRIPTION: {
                    ResourceType.LIGHTNING_CHANNELS: 50,
                    ResourceType.PAYMENT_VOLUME: 10000000,
                    ResourceType.API_REQUESTS: 100000,
                    ResourceType.STORAGE_BYTES: 10 * 1024 * 1024 * 1024,  # 10GB
                    ResourceType.WEBSOCKET_CONNECTIONS: 50,
                    ResourceType.USERS: 25,
                    ResourceType.NODES: 5
                },
                BillingModel.ENTERPRISE: {
                    ResourceType.LIGHTNING_CHANNELS: -1,  # Unlimited
                    ResourceType.PAYMENT_VOLUME: -1,
                    ResourceType.API_REQUESTS: -1,
                    ResourceType.STORAGE_BYTES: -1,
                    ResourceType.WEBSOCKET_CONNECTIONS: -1,
                    ResourceType.USERS: -1,
                    ResourceType.NODES: -1
                }
            },
            'quota_reset_interval': 3600,  # 1 hour
            'cache_ttl': 300,  # 5 minutes
            'default_features': {
                'advanced_analytics': False,
                'custom_branding': False,
                'webhook_notifications': True,
                'api_access': True,
                'mobile_access': True
            }
        }
    
    def _init_database(self) -> None:
        """Initialize SQLite database for tenant data."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                # Tenants table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS tenants (
                        tenant_id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        organization TEXT NOT NULL,
                        status TEXT NOT NULL,
                        billing_model TEXT NOT NULL,
                        admin_email TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        metadata TEXT,
                        parent_tenant_id TEXT,
                        encrypted_config TEXT
                    )
                ''')
                
                # Resource quotas table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS resource_quotas (
                        tenant_id TEXT NOT NULL,
                        resource_type TEXT NOT NULL,
                        limit_value INTEGER NOT NULL,
                        used_value INTEGER DEFAULT 0,
                        soft_limit INTEGER,
                        burst_limit INTEGER,
                        reset_period INTEGER DEFAULT 3600,
                        last_reset TEXT,
                        PRIMARY KEY (tenant_id, resource_type),
                        FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id)
                    )
                ''')
                
                # Usage tracking table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS usage_tracking (
                        usage_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        period_start TEXT NOT NULL,
                        period_end TEXT NOT NULL,
                        usage_data TEXT NOT NULL,
                        billing_amount REAL DEFAULT 0.0,
                        currency TEXT DEFAULT 'USD',
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (tenant_id) REFERENCES tenants (tenant_id)
                    )
                ''')
                
                # Tenant relationships table
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS tenant_relationships (
                        parent_tenant_id TEXT NOT NULL,
                        child_tenant_id TEXT NOT NULL,
                        relationship_type TEXT DEFAULT 'child',
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (parent_tenant_id, child_tenant_id),
                        FOREIGN KEY (parent_tenant_id) REFERENCES tenants (tenant_id),
                        FOREIGN KEY (child_tenant_id) REFERENCES tenants (tenant_id)
                    )
                ''')
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to initialize tenant database: {e}")
            raise
    
    def _get_or_create_encryption_key(self) -> Optional[bytes]:
        """Get or create encryption key for tenant data."""
        if not HAS_CRYPTOGRAPHY:
            logger.warning("Cryptography not available, tenant data will not be encrypted")
            return None
        
        key_file = Path('tenant_encryption.key')
        
        if key_file.exists():
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            return key
    
    def _encrypt_data(self, data: str) -> str:
        """Encrypt sensitive tenant data."""
        if not self.encryption_key or not HAS_CRYPTOGRAPHY:
            return data
        
        fernet = Fernet(self.encryption_key)
        encrypted = fernet.encrypt(data.encode())
        return encrypted.decode('latin-1')
    
    def _decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive tenant data."""
        if not self.encryption_key or not HAS_CRYPTOGRAPHY:
            return encrypted_data
        
        try:
            fernet = Fernet(self.encryption_key)
            decrypted = fernet.decrypt(encrypted_data.encode('latin-1'))
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Failed to decrypt tenant data: {e}")
            return encrypted_data
    
    def _load_tenants(self) -> None:
        """Load tenants from database."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                # Load tenant basic info
                cursor = conn.execute('''
                    SELECT tenant_id, name, organization, status, billing_model,
                           admin_email, created_at, updated_at, metadata,
                           parent_tenant_id, encrypted_config
                    FROM tenants
                ''')
                
                for row in cursor.fetchall():
                    tenant_id = row[0]
                    
                    # Decrypt configuration if available
                    config_data = {}
                    if row[10]:  # encrypted_config
                        try:
                            decrypted_config = self._decrypt_data(row[10])
                            config_data = json.loads(decrypted_config)
                        except Exception as e:
                            logger.warning(f"Failed to decrypt config for tenant {tenant_id}: {e}")
                    
                    # Create tenant object
                    tenant = Tenant(
                        tenant_id=tenant_id,
                        name=row[1],
                        organization=row[2],
                        status=TenantStatus(row[3]),
                        billing_model=BillingModel(row[4]),
                        admin_email=row[5],
                        created_at=datetime.fromisoformat(row[6]),
                        updated_at=datetime.fromisoformat(row[7]),
                        metadata=json.loads(row[8]) if row[8] else {},
                        parent_tenant_id=row[9],
                        configuration=TenantConfiguration(
                            tenant_id=tenant_id,
                            **config_data
                        )
                    )
                    
                    self.tenants[tenant_id] = tenant
                
                # Load resource quotas
                cursor = conn.execute('''
                    SELECT tenant_id, resource_type, limit_value, used_value,
                           soft_limit, burst_limit, reset_period, last_reset
                    FROM resource_quotas
                ''')
                
                for row in cursor.fetchall():
                    tenant_id = row[0]
                    if tenant_id in self.tenants:
                        resource_type = ResourceType(row[1])
                        quota = ResourceQuota(
                            resource_type=resource_type,
                            limit=row[2],
                            used=row[3],
                            soft_limit=row[4],
                            burst_limit=row[5],
                            reset_period=timedelta(seconds=row[6]),
                            last_reset=datetime.fromisoformat(row[7]) if row[7] else datetime.utcnow()
                        )
                        self.tenants[tenant_id].quotas[resource_type] = quota
                
                # Load tenant relationships
                cursor = conn.execute('''
                    SELECT parent_tenant_id, child_tenant_id
                    FROM tenant_relationships
                ''')
                
                for row in cursor.fetchall():
                    parent_id, child_id = row[0], row[1]
                    if parent_id in self.tenants and child_id in self.tenants:
                        self.tenants[parent_id].child_tenant_ids.add(child_id)
                        self.tenants[child_id].parent_tenant_id = parent_id
                
                logger.info(f"Loaded {len(self.tenants)} tenants from database")
                
        except Exception as e:
            logger.error(f"Failed to load tenants: {e}")
    
    async def create_tenant(self,
                           name: str,
                           organization: str,
                           admin_email: str,
                           billing_model: BillingModel = BillingModel.FREE_TIER,
                           parent_tenant_id: Optional[str] = None,
                           custom_quotas: Optional[Dict[ResourceType, int]] = None) -> str:
        """Create a new tenant."""
        tenant_id = str(uuid.uuid4())
        
        # Check if parent tenant exists and has permission
        if parent_tenant_id and parent_tenant_id not in self.tenants:
            raise ValueError(f"Parent tenant {parent_tenant_id} not found")
        
        # Create tenant
        tenant = Tenant(
            tenant_id=tenant_id,
            name=name,
            organization=organization,
            status=TenantStatus.ACTIVE,
            billing_model=billing_model,
            admin_email=admin_email,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            parent_tenant_id=parent_tenant_id
        )
        
        # Set up resource quotas
        quotas = custom_quotas or self.config['tier_quotas'].get(billing_model, {})
        for resource_type, limit in quotas.items():
            if limit > 0:  # -1 means unlimited
                quota = ResourceQuota(
                    resource_type=resource_type,
                    limit=limit,
                    reset_period=timedelta(hours=1)
                )
                tenant.quotas[resource_type] = quota
        
        # Set up default configuration
        tenant.configuration = TenantConfiguration(
            tenant_id=tenant_id,
            feature_flags=self.config['default_features'].copy()
        )
        
        # Add to parent's children if applicable
        if parent_tenant_id:
            self.tenants[parent_tenant_id].child_tenant_ids.add(tenant_id)
        
        # Store tenant
        self.tenants[tenant_id] = tenant
        await self._save_tenant(tenant)
        
        logger.info(f"Created tenant {tenant_id} ({name}) with billing model {billing_model.value}")
        return tenant_id
    
    async def _save_tenant(self, tenant: Tenant) -> None:
        """Save tenant to database."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                # Encrypt configuration
                config_json = json.dumps({
                    'custom_config': tenant.configuration.custom_config,
                    'feature_flags': tenant.configuration.feature_flags,
                    'api_endpoints': tenant.configuration.api_endpoints,
                    'webhook_urls': tenant.configuration.webhook_urls,
                    'notification_settings': tenant.configuration.notification_settings,
                    'branding': tenant.configuration.branding
                })
                encrypted_config = self._encrypt_data(config_json)
                
                # Save tenant
                conn.execute('''
                    INSERT OR REPLACE INTO tenants (
                        tenant_id, name, organization, status, billing_model,
                        admin_email, created_at, updated_at, metadata,
                        parent_tenant_id, encrypted_config
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    tenant.tenant_id,
                    tenant.name,
                    tenant.organization,
                    tenant.status.value,
                    tenant.billing_model.value,
                    tenant.admin_email,
                    tenant.created_at.isoformat(),
                    tenant.updated_at.isoformat(),
                    json.dumps(tenant.metadata),
                    tenant.parent_tenant_id,
                    encrypted_config
                ))
                
                # Save quotas
                for resource_type, quota in tenant.quotas.items():
                    conn.execute('''
                        INSERT OR REPLACE INTO resource_quotas (
                            tenant_id, resource_type, limit_value, used_value,
                            soft_limit, burst_limit, reset_period, last_reset
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        tenant.tenant_id,
                        resource_type.value,
                        quota.limit,
                        quota.used,
                        quota.soft_limit,
                        quota.burst_limit,
                        int(quota.reset_period.total_seconds()),
                        quota.last_reset.isoformat()
                    ))
                
                # Save relationships
                if tenant.parent_tenant_id:
                    conn.execute('''
                        INSERT OR IGNORE INTO tenant_relationships (
                            parent_tenant_id, child_tenant_id
                        ) VALUES (?, ?)
                    ''', (tenant.parent_tenant_id, tenant.tenant_id))
                
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to save tenant {tenant.tenant_id}: {e}")
            raise
    
    def get_tenant(self, tenant_id: str) -> Optional[Tenant]:
        """Get tenant by ID with caching."""
        # Check cache first
        cached_tenant = self.tenant_cache.get(tenant_id)
        if cached_tenant:
            return cached_tenant
        
        # Get from main storage
        tenant = self.tenants.get(tenant_id)
        if tenant:
            # Cache for future requests
            self.tenant_cache[tenant_id] = tenant
        
        return tenant
    
    def get_tenant_by_domain(self, domain: str) -> Optional[Tenant]:
        """Get tenant by custom domain."""
        for tenant in self.tenants.values():
            if tenant.configuration.custom_config.get('custom_domain') == domain:
                return tenant
        return None
    
    async def update_tenant_status(self, tenant_id: str, status: TenantStatus) -> bool:
        """Update tenant status."""
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            return False
        
        tenant.status = status
        tenant.updated_at = datetime.utcnow()
        
        await self._save_tenant(tenant)
        
        # Clear cache
        self.tenant_cache.pop(tenant_id, None)
        
        logger.info(f"Updated tenant {tenant_id} status to {status.value}")
        return True
    
    async def update_tenant_quotas(self, tenant_id: str, 
                                  quotas: Dict[ResourceType, int]) -> bool:
        """Update tenant resource quotas."""
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            return False
        
        for resource_type, limit in quotas.items():
            if resource_type in tenant.quotas:
                tenant.quotas[resource_type].limit = limit
            else:
                quota = ResourceQuota(
                    resource_type=resource_type,
                    limit=limit,
                    reset_period=timedelta(hours=1)
                )
                tenant.quotas[resource_type] = quota
        
        tenant.updated_at = datetime.utcnow()
        await self._save_tenant(tenant)
        
        # Clear cache
        self.tenant_cache.pop(tenant_id, None)
        
        logger.info(f"Updated quotas for tenant {tenant_id}")
        return True
    
    def check_resource_access(self, tenant_id: str, resource_type: ResourceType, 
                             amount: int = 1) -> bool:
        """Check if tenant can access resource within quota limits."""
        tenant = self.get_tenant(tenant_id)
        if not tenant or not tenant.is_active:
            return False
        
        return tenant.check_quota(resource_type, amount)
    
    async def use_resource(self, tenant_id: str, resource_type: ResourceType, 
                          amount: int = 1) -> bool:
        """Use tenant resources and update quotas."""
        tenant = self.get_tenant(tenant_id)
        if not tenant or not tenant.is_active:
            return False
        
        success = tenant.use_resource(resource_type, amount)
        
        if success:
            # Record usage for billing
            await self._record_usage(tenant_id, resource_type, amount)
            
            # Update database periodically (not on every call for performance)
            if amount > 10 or resource_type == ResourceType.PAYMENT_VOLUME:
                await self._save_tenant(tenant)
        
        return success
    
    async def release_resource(self, tenant_id: str, resource_type: ResourceType, 
                              amount: int = 1) -> None:
        """Release tenant resources."""
        tenant = self.get_tenant(tenant_id)
        if tenant:
            tenant.release_resource(resource_type, amount)
    
    async def _record_usage(self, tenant_id: str, resource_type: ResourceType, 
                           amount: Union[int, float]) -> None:
        """Record resource usage for billing."""
        current_period = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
        
        usage_key = f"{tenant_id}_{current_period.isoformat()}"
        
        if usage_key not in self.usage_tracking:
            self.usage_tracking[usage_key] = TenantUsage(
                tenant_id=tenant_id,
                period_start=current_period,
                period_end=current_period + timedelta(hours=1)
            )
        
        usage = self.usage_tracking[usage_key]
        usage.record_usage(resource_type, amount)
    
    def get_tenant_usage(self, tenant_id: str, 
                        period_start: Optional[datetime] = None,
                        period_end: Optional[datetime] = None) -> List[TenantUsage]:
        """Get tenant usage data for a period."""
        if not period_start:
            period_start = datetime.utcnow() - timedelta(days=30)
        if not period_end:
            period_end = datetime.utcnow()
        
        usage_list = []
        
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                cursor = conn.execute('''
                    SELECT usage_id, tenant_id, period_start, period_end,
                           usage_data, billing_amount, currency
                    FROM usage_tracking
                    WHERE tenant_id = ? AND period_start >= ? AND period_end <= ?
                    ORDER BY period_start
                ''', (tenant_id, period_start.isoformat(), period_end.isoformat()))
                
                for row in cursor.fetchall():
                    usage_data = json.loads(row[4])
                    
                    # Convert string keys back to ResourceType
                    converted_usage_data = {}
                    for resource_type_str, data in usage_data.items():
                        try:
                            resource_type = ResourceType(resource_type_str)
                            converted_usage_data[resource_type] = data
                        except ValueError:
                            continue
                    
                    usage = TenantUsage(
                        tenant_id=row[1],
                        period_start=datetime.fromisoformat(row[2]),
                        period_end=datetime.fromisoformat(row[3]),
                        usage_data=converted_usage_data,
                        billing_amount=row[5],
                        currency=row[6]
                    )
                    usage_list.append(usage)
                    
        except Exception as e:
            logger.error(f"Failed to get usage data for tenant {tenant_id}: {e}")
        
        return usage_list
    
    def get_tenant_hierarchy(self, tenant_id: str) -> Dict[str, Any]:
        """Get tenant hierarchy (parent and children)."""
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            return {}
        
        hierarchy = {
            'tenant': {
                'id': tenant.tenant_id,
                'name': tenant.name,
                'organization': tenant.organization,
                'status': tenant.status.value
            },
            'parent': None,
            'children': []
        }
        
        # Get parent
        if tenant.parent_tenant_id:
            parent = self.get_tenant(tenant.parent_tenant_id)
            if parent:
                hierarchy['parent'] = {
                    'id': parent.tenant_id,
                    'name': parent.name,
                    'organization': parent.organization,
                    'status': parent.status.value
                }
        
        # Get children
        for child_id in tenant.child_tenant_ids:
            child = self.get_tenant(child_id)
            if child:
                hierarchy['children'].append({
                    'id': child.tenant_id,
                    'name': child.name,
                    'organization': child.organization,
                    'status': child.status.value
                })
        
        return hierarchy
    
    def generate_tenant_token(self, tenant_id: str, user_id: str, 
                             permissions: List[str]) -> Optional[str]:
        """Generate JWT token for tenant user."""
        if not HAS_JWT:
            logger.warning("JWT not available, cannot generate tenant token")
            return None
        
        tenant = self.get_tenant(tenant_id)
        if not tenant or not tenant.is_active:
            return None
        
        payload = {
            'tenant_id': tenant_id,
            'user_id': user_id,
            'permissions': permissions,
            'iss': 'blncs-multi-tenancy',
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=24)
        }
        
        try:
            token = jwt.encode(payload, str(self.encryption_key), algorithm='HS256')
            return token
        except Exception as e:
            logger.error(f"Failed to generate token for tenant {tenant_id}: {e}")
            return None
    
    def validate_tenant_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate and decode tenant JWT token."""
        if not HAS_JWT:
            return None
        
        try:
            payload = jwt.decode(token, str(self.encryption_key), algorithms=['HS256'])
            
            # Validate tenant is still active
            tenant = self.get_tenant(payload.get('tenant_id'))
            if not tenant or not tenant.is_active:
                return None
            
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("Expired tenant token")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid tenant token: {e}")
            return None
    
    def start_quota_reset_scheduler(self) -> None:
        """Start the quota reset scheduler."""
        if self.quota_reset_thread and self.quota_reset_thread.is_alive():
            logger.warning("Quota reset scheduler already running")
            return
        
        self.stop_event.clear()
        self.quota_reset_thread = threading.Thread(
            target=self._quota_reset_loop,
            name="quota-reset",
            daemon=True
        )
        self.quota_reset_thread.start()
        
        logger.info("Started quota reset scheduler")
    
    def stop_quota_reset_scheduler(self) -> None:
        """Stop the quota reset scheduler."""
        if not self.quota_reset_thread or not self.quota_reset_thread.is_alive():
            return
        
        self.stop_event.set()
        self.quota_reset_thread.join(timeout=5.0)
        
        if self.quota_reset_thread.is_alive():
            logger.warning("Quota reset thread did not stop gracefully")
        else:
            logger.info("Stopped quota reset scheduler")
    
    def _quota_reset_loop(self) -> None:
        """Main quota reset loop."""
        reset_interval = self.config.get('quota_reset_interval', 3600)
        
        while not self.stop_event.is_set():
            try:
                current_time = datetime.utcnow()
                
                for tenant in self.tenants.values():
                    for quota in tenant.quotas.values():
                        if current_time - quota.last_reset >= quota.reset_period:
                            quota.used = 0
                            quota.last_reset = current_time
                
                # Wait for next reset interval
                if self.stop_event.wait(reset_interval):
                    break
                    
            except Exception as e:
                logger.error(f"Error in quota reset loop: {e}")
                # Wait before retrying
                if self.stop_event.wait(60):
                    break
    
    async def get_tenant_summary(self) -> Dict[str, Any]:
        """Get summary statistics for all tenants."""
        active_tenants = len([t for t in self.tenants.values() if t.is_active])
        suspended_tenants = len([t for t in self.tenants.values() if t.status == TenantStatus.SUSPENDED])
        
        billing_breakdown = {}
        for billing_model in BillingModel:
            count = len([t for t in self.tenants.values() if t.billing_model == billing_model])
            billing_breakdown[billing_model.value] = count
        
        resource_utilization = {}
        for resource_type in ResourceType:
            total_limit = sum(
                tenant.quotas.get(resource_type, ResourceQuota(resource_type, 0)).limit
                for tenant in self.tenants.values()
            )
            total_used = sum(
                tenant.quotas.get(resource_type, ResourceQuota(resource_type, 0)).used
                for tenant in self.tenants.values()
            )
            
            if total_limit > 0:
                utilization = (total_used / total_limit) * 100
            else:
                utilization = 0.0
            
            resource_utilization[resource_type.value] = {
                'total_limit': total_limit,
                'total_used': total_used,
                'utilization_percent': utilization
            }
        
        return {
            'total_tenants': len(self.tenants),
            'active_tenants': active_tenants,
            'suspended_tenants': suspended_tenants,
            'billing_breakdown': billing_breakdown,
            'resource_utilization': resource_utilization
        }
    
    async def shutdown(self) -> None:
        """Shutdown the multi-tenancy manager."""
        logger.info("Shutting down multi-tenancy manager...")
        
        self.stop_quota_reset_scheduler()
        self.executor.shutdown(wait=True, timeout=10.0)
        
        # Save any pending usage data
        for usage in self.usage_tracking.values():
            await self._save_usage_data(usage)
        
        logger.info("Multi-tenancy manager shutdown complete")
    
    async def _save_usage_data(self, usage: TenantUsage) -> None:
        """Save usage data to database."""
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                # Convert ResourceType keys to strings for JSON serialization
                serializable_usage_data = {}
                for resource_type, data in usage.usage_data.items():
                    serializable_usage_data[resource_type.value] = data
                
                conn.execute('''
                    INSERT OR REPLACE INTO usage_tracking (
                        usage_id, tenant_id, period_start, period_end,
                        usage_data, billing_amount, currency
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    f"{usage.tenant_id}_{usage.period_start.isoformat()}",
                    usage.tenant_id,
                    usage.period_start.isoformat(),
                    usage.period_end.isoformat(),
                    json.dumps(serializable_usage_data),
                    usage.billing_amount,
                    usage.currency
                ))
                conn.commit()
                
        except Exception as e:
            logger.error(f"Failed to save usage data: {e}")

# Global instance
_multi_tenancy_manager: Optional[MultiTenancyManager] = None

def get_multi_tenancy_manager() -> MultiTenancyManager:
    """Get the global multi-tenancy manager instance."""
    global _multi_tenancy_manager
    
    if _multi_tenancy_manager is None:
        _multi_tenancy_manager = MultiTenancyManager()
    
    return _multi_tenancy_manager

def initialize_multi_tenancy(config: Optional[Dict[str, Any]] = None) -> MultiTenancyManager:
    """Initialize the global multi-tenancy manager."""
    global _multi_tenancy_manager
    
    _multi_tenancy_manager = MultiTenancyManager(config)
    _multi_tenancy_manager.start_quota_reset_scheduler()
    
    logger.info("Initialized multi-tenancy manager")
    return _multi_tenancy_manager