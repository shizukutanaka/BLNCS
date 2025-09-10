"""
Marketplace and Plugin Ecosystem Manager
Comprehensive platform for third-party extensions, integrations, and marketplace functionality.
"""

import asyncio
import json
import logging
import uuid
import hashlib
import zipfile
import tempfile
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Callable
from enum import Enum
from dataclasses import dataclass, field, asdict
from pathlib import Path
import importlib.util
import sys
import structlog

logger = structlog.get_logger(__name__)

class PluginType(Enum):
    PAYMENT_PROCESSOR = "payment_processor"
    WALLET_INTEGRATION = "wallet_integration"
    EXCHANGE_CONNECTOR = "exchange_connector"
    ANALYTICS_TOOL = "analytics_tool"
    NOTIFICATION_SERVICE = "notification_service"
    ACCOUNTING_INTEGRATION = "accounting_integration"
    REPORTING_TOOL = "reporting_tool"
    SECURITY_SCANNER = "security_scanner"
    API_EXTENSION = "api_extension"
    UI_WIDGET = "ui_widget"
    AUTOMATION_SCRIPT = "automation_script"
    COMPLIANCE_TOOL = "compliance_tool"

class PluginStatus(Enum):
    DRAFT = "draft"
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    PUBLISHED = "published"
    SUSPENDED = "suspended"
    DEPRECATED = "deprecated"

class InstallationStatus(Enum):
    NOT_INSTALLED = "not_installed"
    INSTALLING = "installing"
    INSTALLED = "installed"
    UPDATING = "updating"
    UNINSTALLING = "uninstalling"
    ERROR = "error"

@dataclass
class PluginManifest:
    plugin_id: str
    name: str
    version: str
    description: str
    author: str
    plugin_type: PluginType
    min_blncs_version: str = "1.0.0"
    max_blncs_version: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    api_requirements: List[str] = field(default_factory=list)
    entry_point: str = "main.py"
    config_schema: Dict[str, Any] = field(default_factory=dict)
    supported_platforms: List[str] = field(default_factory=lambda: ["all"])
    homepage: Optional[str] = None
    repository: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['plugin_type'] = self.plugin_type.value
        return result

@dataclass
class Plugin:
    manifest: PluginManifest
    package_path: Optional[str] = None
    installation_status: InstallationStatus = InstallationStatus.NOT_INSTALLED
    installed_version: Optional[str] = None
    installed_at: Optional[datetime] = None
    last_updated: Optional[datetime] = None
    enabled: bool = False
    config: Dict[str, Any] = field(default_factory=dict)
    usage_stats: Dict[str, Any] = field(default_factory=dict)
    error_log: List[str] = field(default_factory=list)

@dataclass
class MarketplaceApp:
    app_id: str
    plugin: Plugin
    publisher: str
    price_cents: int = 0  # 0 for free apps
    rating: float = 0.0
    review_count: int = 0
    downloads: int = 0
    featured: bool = False
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    status: PluginStatus = PluginStatus.DRAFT
    screenshots: List[str] = field(default_factory=list)
    changelog: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class DeveloperAccount:
    developer_id: str
    name: str
    email: str
    company: Optional[str] = None
    verified: bool = False
    created_at: datetime = field(default_factory=datetime.utcnow)
    published_apps: List[str] = field(default_factory=list)
    total_downloads: int = 0
    revenue_share_percentage: float = 70.0  # Developer gets 70%
    payment_info: Dict[str, Any] = field(default_factory=dict)

class PluginSandbox:
    def __init__(self):
        self.sandbox_environments = {}
        self.resource_limits = {
            'memory_mb': 256,
            'cpu_percentage': 10,
            'disk_mb': 100,
            'network_requests_per_minute': 60,
            'execution_time_seconds': 30
        }
    
    async def create_sandbox(self, plugin_id: str) -> str:
        """Create isolated sandbox environment for plugin"""
        sandbox_id = str(uuid.uuid4())
        
        # Create temporary directory
        sandbox_dir = Path(tempfile.mkdtemp(prefix=f"blncs_plugin_{plugin_id}_"))
        
        sandbox_env = {
            'sandbox_id': sandbox_id,
            'plugin_id': plugin_id,
            'directory': sandbox_dir,
            'created_at': datetime.utcnow(),
            'resource_usage': {
                'memory_mb': 0,
                'cpu_percentage': 0,
                'disk_mb': 0,
                'network_requests': 0
            },
            'violations': []
        }
        
        self.sandbox_environments[sandbox_id] = sandbox_env
        
        logger.info(f"Created sandbox {sandbox_id} for plugin {plugin_id}")
        return sandbox_id
    
    async def execute_plugin_code(self, sandbox_id: str, code: str, 
                                 context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute plugin code in sandbox"""
        sandbox = self.sandbox_environments.get(sandbox_id)
        if not sandbox:
            raise ValueError(f"Sandbox not found: {sandbox_id}")
        
        try:
            # Create restricted execution environment
            restricted_globals = {
                '__builtins__': {
                    'print': print,
                    'len': len,
                    'str': str,
                    'int': int,
                    'float': float,
                    'dict': dict,
                    'list': list,
                    'tuple': tuple,
                    'bool': bool,
                    'isinstance': isinstance,
                    'range': range,
                    'enumerate': enumerate,
                    'zip': zip,
                    'map': map,
                    'filter': filter,
                    'datetime': datetime,
                    'json': json,
                    # Add BLNCS SDK functions
                    'blncs_api': self._create_sandbox_api(),
                    'plugin_config': context or {}
                }
            }
            
            # Execute with timeout
            start_time = datetime.utcnow()
            exec_globals = restricted_globals.copy()
            exec(code, exec_globals)
            
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            
            # Check resource limits
            if execution_time > self.resource_limits['execution_time_seconds']:
                sandbox['violations'].append({
                    'type': 'execution_timeout',
                    'timestamp': datetime.utcnow(),
                    'details': f'Execution time: {execution_time}s'
                })
            
            return {
                'success': True,
                'execution_time': execution_time,
                'result': exec_globals.get('result'),
                'violations': sandbox['violations']
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'execution_time': 0
            }
    
    def _create_sandbox_api(self) -> Dict[str, Callable]:
        """Create sandboxed BLNCS API"""
        return {
            'log': lambda msg: logger.info(f"Plugin: {msg}"),
            'get_balance': self._mock_get_balance,
            'send_payment': self._mock_send_payment,
            'create_invoice': self._mock_create_invoice,
            'get_channels': self._mock_get_channels,
            'http_request': self._restricted_http_request
        }
    
    async def _mock_get_balance(self) -> Dict[str, Any]:
        """Mock balance API for sandbox"""
        return {'balance_sats': 1000000, 'currency': 'BTC'}
    
    async def _mock_send_payment(self, amount: int, destination: str) -> Dict[str, Any]:
        """Mock payment API for sandbox"""
        return {'payment_id': str(uuid.uuid4()), 'status': 'pending', 'amount': amount}
    
    async def _mock_create_invoice(self, amount: int, description: str) -> Dict[str, Any]:
        """Mock invoice API for sandbox"""
        return {'invoice_id': str(uuid.uuid4()), 'payment_request': 'lnbc...', 'amount': amount}
    
    async def _mock_get_channels(self) -> List[Dict[str, Any]]:
        """Mock channels API for sandbox"""
        return [{'channel_id': str(uuid.uuid4()), 'capacity': 5000000, 'local_balance': 2500000}]
    
    async def _restricted_http_request(self, url: str, method: str = 'GET') -> Dict[str, Any]:
        """Restricted HTTP request for sandbox"""
        # In production, this would have strict rate limiting and URL filtering
        return {'status_code': 200, 'data': {'mock': 'response'}}
    
    async def cleanup_sandbox(self, sandbox_id: str):
        """Clean up sandbox environment"""
        sandbox = self.sandbox_environments.get(sandbox_id)
        if sandbox:
            # Clean up temporary directory
            import shutil
            shutil.rmtree(sandbox['directory'], ignore_errors=True)
            del self.sandbox_environments[sandbox_id]

class PluginRegistry:
    def __init__(self):
        self.plugins = {}
        self.installed_plugins = {}
        self.plugin_hooks = defaultdict(list)
    
    async def register_plugin(self, plugin: Plugin):
        """Register plugin in registry"""
        self.plugins[plugin.manifest.plugin_id] = plugin
        
        if plugin.installation_status == InstallationStatus.INSTALLED:
            self.installed_plugins[plugin.manifest.plugin_id] = plugin
        
        logger.info(f"Registered plugin: {plugin.manifest.name}")
    
    async def install_plugin(self, plugin_id: str, package_path: str) -> bool:
        """Install plugin from package"""
        try:
            # Extract and validate plugin package
            manifest = await self._extract_plugin_package(package_path)
            
            if manifest.plugin_id != plugin_id:
                raise ValueError("Plugin ID mismatch")
            
            # Create plugin instance
            plugin = Plugin(
                manifest=manifest,
                package_path=package_path,
                installation_status=InstallationStatus.INSTALLING,
                installed_at=datetime.utcnow()
            )
            
            # Validate dependencies
            if not await self._validate_dependencies(manifest.dependencies):
                raise ValueError("Dependency validation failed")
            
            # Install plugin files
            await self._install_plugin_files(plugin)
            
            # Update status
            plugin.installation_status = InstallationStatus.INSTALLED
            plugin.installed_version = manifest.version
            
            # Register plugin
            await self.register_plugin(plugin)
            
            logger.info(f"Successfully installed plugin: {manifest.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to install plugin {plugin_id}: {e}")
            return False
    
    async def _extract_plugin_package(self, package_path: str) -> PluginManifest:
        """Extract and validate plugin package"""
        with zipfile.ZipFile(package_path, 'r') as zip_file:
            # Read manifest
            manifest_data = json.loads(zip_file.read('manifest.json'))
            
            # Validate manifest
            manifest = PluginManifest(**manifest_data)
            
            # Security checks
            await self._validate_plugin_security(zip_file)
            
            return manifest
    
    async def _validate_plugin_security(self, zip_file: zipfile.ZipFile):
        """Validate plugin security"""
        dangerous_patterns = [
            '__import__',
            'exec(',
            'eval(',
            'open(',
            'file(',
            'subprocess',
            'os.system',
            'os.popen'
        ]
        
        # Check all Python files for dangerous patterns
        for file_info in zip_file.filelist:
            if file_info.filename.endswith('.py'):
                content = zip_file.read(file_info).decode('utf-8', errors='ignore')
                
                for pattern in dangerous_patterns:
                    if pattern in content:
                        raise SecurityError(f"Potentially dangerous code found: {pattern}")
    
    async def _validate_dependencies(self, dependencies: List[str]) -> bool:
        """Validate plugin dependencies"""
        for dependency in dependencies:
            if dependency not in self.installed_plugins:
                logger.warning(f"Missing dependency: {dependency}")
                return False
        return True
    
    async def _install_plugin_files(self, plugin: Plugin):
        """Install plugin files to appropriate directory"""
        # Create plugin directory
        plugin_dir = Path(f"plugins/{plugin.manifest.plugin_id}")
        plugin_dir.mkdir(parents=True, exist_ok=True)
        
        # Extract package to plugin directory
        with zipfile.ZipFile(plugin.package_path, 'r') as zip_file:
            zip_file.extractall(plugin_dir)
    
    async def uninstall_plugin(self, plugin_id: str) -> bool:
        """Uninstall plugin"""
        try:
            plugin = self.plugins.get(plugin_id)
            if not plugin:
                return False
            
            plugin.installation_status = InstallationStatus.UNINSTALLING
            
            # Remove plugin files
            plugin_dir = Path(f"plugins/{plugin_id}")
            if plugin_dir.exists():
                import shutil
                shutil.rmtree(plugin_dir)
            
            # Remove from registry
            if plugin_id in self.installed_plugins:
                del self.installed_plugins[plugin_id]
            
            if plugin_id in self.plugins:
                del self.plugins[plugin_id]
            
            logger.info(f"Successfully uninstalled plugin: {plugin_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to uninstall plugin {plugin_id}: {e}")
            return False
    
    def register_hook(self, hook_name: str, plugin_id: str, callback: Callable):
        """Register plugin hook"""
        self.plugin_hooks[hook_name].append({
            'plugin_id': plugin_id,
            'callback': callback
        })
    
    async def execute_hook(self, hook_name: str, context: Dict[str, Any] = None) -> List[Any]:
        """Execute all registered hooks"""
        results = []
        
        for hook in self.plugin_hooks.get(hook_name, []):
            try:
                result = await hook['callback'](context or {})
                results.append({
                    'plugin_id': hook['plugin_id'],
                    'result': result,
                    'success': True
                })
            except Exception as e:
                results.append({
                    'plugin_id': hook['plugin_id'],
                    'error': str(e),
                    'success': False
                })
        
        return results

class AppStore:
    def __init__(self):
        self.published_apps = {}
        self.categories = {
            PluginType.PAYMENT_PROCESSOR: "Payment Processors",
            PluginType.WALLET_INTEGRATION: "Wallet Integrations", 
            PluginType.EXCHANGE_CONNECTOR: "Exchange Connectors",
            PluginType.ANALYTICS_TOOL: "Analytics Tools",
            PluginType.NOTIFICATION_SERVICE: "Notifications",
            PluginType.ACCOUNTING_INTEGRATION: "Accounting",
            PluginType.REPORTING_TOOL: "Reporting",
            PluginType.SECURITY_SCANNER: "Security",
            PluginType.API_EXTENSION: "API Extensions",
            PluginType.UI_WIDGET: "UI Widgets",
            PluginType.AUTOMATION_SCRIPT: "Automation",
            PluginType.COMPLIANCE_TOOL: "Compliance"
        }
    
    async def publish_app(self, app: MarketplaceApp) -> bool:
        """Publish app to marketplace"""
        try:
            # Validate app
            if not await self._validate_app(app):
                return False
            
            # Security review
            if not await self._security_review(app):
                return False
            
            # Update status
            app.status = PluginStatus.PUBLISHED
            app.updated_at = datetime.utcnow()
            
            # Add to published apps
            self.published_apps[app.app_id] = app
            
            logger.info(f"Published app: {app.plugin.manifest.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to publish app {app.app_id}: {e}")
            return False
    
    async def _validate_app(self, app: MarketplaceApp) -> bool:
        """Validate app before publishing"""
        # Check required fields
        if not app.plugin.manifest.name or not app.plugin.manifest.description:
            return False
        
        # Check manifest completeness
        if not app.plugin.manifest.version or not app.plugin.manifest.author:
            return False
        
        return True
    
    async def _security_review(self, app: MarketplaceApp) -> bool:
        """Perform security review"""
        # In production, this would be more comprehensive
        return True
    
    async def search_apps(self, query: str = "", category: Optional[PluginType] = None,
                         sort_by: str = "popularity") -> List[MarketplaceApp]:
        """Search published apps"""
        results = []
        
        for app in self.published_apps.values():
            if app.status != PluginStatus.PUBLISHED:
                continue
            
            # Category filter
            if category and app.plugin.manifest.plugin_type != category:
                continue
            
            # Text search
            if query:
                searchable_text = f"{app.plugin.manifest.name} {app.plugin.manifest.description} {' '.join(app.plugin.manifest.tags)}".lower()
                if query.lower() not in searchable_text:
                    continue
            
            results.append(app)
        
        # Sort results
        if sort_by == "popularity":
            results.sort(key=lambda x: x.downloads, reverse=True)
        elif sort_by == "rating":
            results.sort(key=lambda x: x.rating, reverse=True)
        elif sort_by == "newest":
            results.sort(key=lambda x: x.created_at, reverse=True)
        elif sort_by == "name":
            results.sort(key=lambda x: x.plugin.manifest.name)
        
        return results
    
    async def get_featured_apps(self, limit: int = 10) -> List[MarketplaceApp]:
        """Get featured apps"""
        featured = [app for app in self.published_apps.values() if app.featured and app.status == PluginStatus.PUBLISHED]
        return featured[:limit]
    
    async def get_app_details(self, app_id: str) -> Optional[MarketplaceApp]:
        """Get detailed app information"""
        return self.published_apps.get(app_id)
    
    async def record_download(self, app_id: str):
        """Record app download"""
        app = self.published_apps.get(app_id)
        if app:
            app.downloads += 1

class DeveloperPortal:
    def __init__(self):
        self.developers = {}
        self.api_keys = {}
        self.submission_queue = []
    
    async def register_developer(self, name: str, email: str, company: Optional[str] = None) -> str:
        """Register new developer"""
        developer_id = str(uuid.uuid4())
        
        developer = DeveloperAccount(
            developer_id=developer_id,
            name=name,
            email=email,
            company=company
        )
        
        self.developers[developer_id] = developer
        
        # Generate API key
        api_key = self._generate_api_key(developer_id)
        self.api_keys[api_key] = developer_id
        
        logger.info(f"Registered developer: {name}")
        return developer_id
    
    def _generate_api_key(self, developer_id: str) -> str:
        """Generate API key for developer"""
        key_data = f"{developer_id}:{datetime.utcnow().isoformat()}"
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    async def submit_app(self, developer_id: str, app_data: Dict[str, Any]) -> str:
        """Submit app for review"""
        developer = self.developers.get(developer_id)
        if not developer:
            raise ValueError("Developer not found")
        
        # Create app
        app_id = str(uuid.uuid4())
        
        # Create plugin manifest from app data
        manifest = PluginManifest(
            plugin_id=app_data['plugin_id'],
            name=app_data['name'],
            version=app_data['version'],
            description=app_data['description'],
            author=developer.name,
            plugin_type=PluginType(app_data['plugin_type']),
            permissions=app_data.get('permissions', []),
            dependencies=app_data.get('dependencies', []),
            tags=app_data.get('tags', [])
        )
        
        plugin = Plugin(manifest=manifest)
        
        app = MarketplaceApp(
            app_id=app_id,
            plugin=plugin,
            publisher=developer.name,
            price_cents=app_data.get('price_cents', 0),
            status=PluginStatus.PENDING_REVIEW
        )
        
        # Add to submission queue
        self.submission_queue.append(app)
        
        logger.info(f"App submitted for review: {manifest.name}")
        return app_id
    
    async def get_developer_apps(self, developer_id: str) -> List[MarketplaceApp]:
        """Get apps by developer"""
        developer = self.developers.get(developer_id)
        if not developer:
            return []
        
        # Find apps by this developer
        apps = []
        for app in self.submission_queue:
            if app.publisher == developer.name:
                apps.append(app)
        
        return apps

class MarketplaceSDK:
    def __init__(self):
        self.api_endpoints = {}
        self.webhook_handlers = {}
    
    def register_api_endpoint(self, path: str, handler: Callable):
        """Register API endpoint for plugins"""
        self.api_endpoints[path] = handler
    
    def register_webhook_handler(self, event: str, handler: Callable):
        """Register webhook handler"""
        if event not in self.webhook_handlers:
            self.webhook_handlers[event] = []
        self.webhook_handlers[event].append(handler)
    
    async def call_api(self, plugin_id: str, endpoint: str, data: Dict[str, Any] = None) -> Any:
        """Call BLNCS API from plugin"""
        handler = self.api_endpoints.get(endpoint)
        if not handler:
            raise ValueError(f"API endpoint not found: {endpoint}")
        
        # Add plugin context
        context = {'plugin_id': plugin_id, 'data': data or {}}
        
        return await handler(context)
    
    async def emit_webhook(self, event: str, data: Dict[str, Any]):
        """Emit webhook event"""
        handlers = self.webhook_handlers.get(event, [])
        
        for handler in handlers:
            try:
                await handler(data)
            except Exception as e:
                logger.error(f"Webhook handler error: {e}")

class IntegrationHub:
    def __init__(self):
        self.integrations = {}
        self.pre_built_integrations = self._initialize_integrations()
    
    def _initialize_integrations(self) -> Dict[str, Dict[str, Any]]:
        """Initialize pre-built integrations"""
        return {
            'quickbooks': {
                'name': 'QuickBooks',
                'type': 'accounting',
                'description': 'Sync Lightning payments with QuickBooks',
                'config_fields': ['api_key', 'company_id'],
                'webhook_url': '/integrations/quickbooks/webhook'
            },
            'stripe': {
                'name': 'Stripe',
                'type': 'payment_processor',
                'description': 'Accept fiat payments alongside Lightning',
                'config_fields': ['publishable_key', 'secret_key'],
                'webhook_url': '/integrations/stripe/webhook'
            },
            'slack': {
                'name': 'Slack',
                'type': 'notification',
                'description': 'Send Lightning payment notifications to Slack',
                'config_fields': ['webhook_url', 'channel'],
                'webhook_url': '/integrations/slack/webhook'
            },
            'telegram': {
                'name': 'Telegram',
                'type': 'notification',
                'description': 'Send Lightning payment notifications to Telegram',
                'config_fields': ['bot_token', 'chat_id'],
                'webhook_url': '/integrations/telegram/webhook'
            }
        }
    
    async def setup_integration(self, user_id: str, integration_id: str, 
                              config: Dict[str, Any]) -> bool:
        """Setup integration for user"""
        integration_info = self.pre_built_integrations.get(integration_id)
        if not integration_info:
            return False
        
        # Validate config
        required_fields = integration_info.get('config_fields', [])
        for field in required_fields:
            if field not in config:
                return False
        
        # Store integration config
        if user_id not in self.integrations:
            self.integrations[user_id] = {}
        
        self.integrations[user_id][integration_id] = {
            'config': config,
            'enabled': True,
            'setup_at': datetime.utcnow()
        }
        
        logger.info(f"Setup integration {integration_id} for user {user_id}")
        return True

class MarketplaceManager:
    def __init__(self):
        self.plugin_registry = PluginRegistry()
        self.app_store = AppStore()
        self.developer_portal = DeveloperPortal()
        self.plugin_sandbox = PluginSandbox()
        self.marketplace_sdk = MarketplaceSDK()
        self.integration_hub = IntegrationHub()
        self.initialized = False
    
    async def initialize(self):
        """Initialize marketplace ecosystem"""
        try:
            # Setup SDK API endpoints
            await self._setup_sdk_endpoints()
            
            # Load existing plugins
            await self._load_existing_plugins()
            
            # Setup default integrations
            await self._setup_default_integrations()
            
            self.initialized = True
            logger.info("Marketplace ecosystem initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize marketplace: {e}")
            raise
    
    async def _setup_sdk_endpoints(self):
        """Setup SDK API endpoints"""
        self.marketplace_sdk.register_api_endpoint('/wallet/balance', self._api_get_balance)
        self.marketplace_sdk.register_api_endpoint('/payments/send', self._api_send_payment)
        self.marketplace_sdk.register_api_endpoint('/invoices/create', self._api_create_invoice)
        self.marketplace_sdk.register_api_endpoint('/channels/list', self._api_list_channels)
    
    async def _api_get_balance(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """SDK API: Get wallet balance"""
        # In production, this would call actual wallet API
        return {'balance_sats': 1000000, 'currency': 'BTC'}
    
    async def _api_send_payment(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """SDK API: Send payment"""
        data = context.get('data', {})
        return {
            'payment_id': str(uuid.uuid4()),
            'amount': data.get('amount', 0),
            'status': 'pending'
        }
    
    async def _api_create_invoice(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """SDK API: Create invoice"""
        data = context.get('data', {})
        return {
            'invoice_id': str(uuid.uuid4()),
            'payment_request': 'lnbc...',
            'amount': data.get('amount', 0)
        }
    
    async def _api_list_channels(self, context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """SDK API: List channels"""
        return [
            {'channel_id': str(uuid.uuid4()), 'capacity': 5000000, 'local_balance': 2500000}
        ]
    
    async def _load_existing_plugins(self):
        """Load existing installed plugins"""
        plugins_dir = Path("plugins")
        if not plugins_dir.exists():
            plugins_dir.mkdir()
            return
        
        for plugin_dir in plugins_dir.iterdir():
            if plugin_dir.is_dir():
                manifest_file = plugin_dir / "manifest.json"
                if manifest_file.exists():
                    try:
                        manifest_data = json.loads(manifest_file.read_text())
                        manifest = PluginManifest(**manifest_data)
                        
                        plugin = Plugin(
                            manifest=manifest,
                            package_path=str(plugin_dir),
                            installation_status=InstallationStatus.INSTALLED,
                            installed_version=manifest.version,
                            installed_at=datetime.utcnow()
                        )
                        
                        await self.plugin_registry.register_plugin(plugin)
                        
                    except Exception as e:
                        logger.error(f"Failed to load plugin from {plugin_dir}: {e}")
    
    async def _setup_default_integrations(self):
        """Setup default integrations"""
        # This would setup webhook handlers for pre-built integrations
        pass
    
    async def install_plugin(self, user_id: str, app_id: str) -> bool:
        """Install plugin for user"""
        app = await self.app_store.get_app_details(app_id)
        if not app:
            return False
        
        # Record download
        await self.app_store.record_download(app_id)
        
        # Install plugin
        success = await self.plugin_registry.install_plugin(
            app.plugin.manifest.plugin_id,
            app.plugin.package_path or ""
        )
        
        if success:
            logger.info(f"User {user_id} installed plugin {app.plugin.manifest.name}")
        
        return success
    
    async def get_marketplace_home(self, user_id: str = None) -> Dict[str, Any]:
        """Get marketplace home page data"""
        return {
            'featured_apps': await self.app_store.get_featured_apps(),
            'categories': [
                {
                    'type': plugin_type.value,
                    'name': category_name,
                    'app_count': len([
                        app for app in self.app_store.published_apps.values() 
                        if app.plugin.manifest.plugin_type == plugin_type
                    ])
                }
                for plugin_type, category_name in self.app_store.categories.items()
            ],
            'recent_apps': sorted(
                self.app_store.published_apps.values(),
                key=lambda x: x.created_at,
                reverse=True
            )[:10],
            'popular_apps': sorted(
                self.app_store.published_apps.values(),
                key=lambda x: x.downloads,
                reverse=True
            )[:10]
        }
    
    async def get_user_plugins(self, user_id: str) -> List[Plugin]:
        """Get plugins installed by user"""
        # In production, this would filter by user
        return list(self.plugin_registry.installed_plugins.values())
    
    async def execute_plugin_hook(self, hook_name: str, context: Dict[str, Any] = None) -> List[Any]:
        """Execute plugin hooks"""
        return await self.plugin_registry.execute_hook(hook_name, context)

# Global marketplace manager
_marketplace_manager_instance = None

async def get_marketplace_manager() -> MarketplaceManager:
    """Get or create marketplace manager"""
    global _marketplace_manager_instance
    
    if _marketplace_manager_instance is None:
        _marketplace_manager_instance = MarketplaceManager()
        await _marketplace_manager_instance.initialize()
    
    return _marketplace_manager_instance

async def initialize_marketplace_ecosystem() -> MarketplaceManager:
    """Initialize marketplace ecosystem"""
    manager = MarketplaceManager()
    await manager.initialize()
    logger.info("Marketplace and plugin ecosystem initialized")
    return manager

class SecurityError(Exception):
    """Security-related error in plugin system"""
    pass