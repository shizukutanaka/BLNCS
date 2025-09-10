"""
Universal User Tier System
Comprehensive tier management supporting personal users to enterprise organizations.
"""

import asyncio
import json
import logging
import time
import uuid
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Callable
from enum import Enum
from dataclasses import dataclass, field, asdict
from collections import defaultdict
import structlog

logger = structlog.get_logger(__name__)

class UserTier(Enum):
    FREE = "free"
    PERSONAL = "personal"
    PROFESSIONAL = "professional"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"
    CUSTOM = "custom"

class BillingPeriod(Enum):
    MONTHLY = "monthly"
    YEARLY = "yearly"
    USAGE_BASED = "usage_based"
    CUSTOM = "custom"

class FeatureType(Enum):
    # Core Lightning Features
    CHANNELS_MAX = "channels_max"
    PAYMENT_VOLUME_MONTHLY = "payment_volume_monthly"
    TRANSACTION_LIMIT_DAILY = "transaction_limit_daily"
    CHANNEL_SIZE_MAX = "channel_size_max"
    
    # Business Features
    MULTI_USER_ACCOUNTS = "multi_user_accounts"
    API_CALLS_MONTHLY = "api_calls_monthly"
    WEBHOOK_ENDPOINTS = "webhook_endpoints"
    CUSTOM_BRANDING = "custom_branding"
    
    # Technical Features
    BACKUP_RETENTION_DAYS = "backup_retention_days"
    ANALYTICS_HISTORY_MONTHS = "analytics_history_months"
    PRIORITY_SUPPORT = "priority_support"
    SLA_GUARANTEE = "sla_guarantee"
    
    # Enterprise Features
    DEDICATED_INFRASTRUCTURE = "dedicated_infrastructure"
    CUSTOM_INTEGRATIONS = "custom_integrations"
    COMPLIANCE_REPORTING = "compliance_reporting"
    ADVANCED_SECURITY = "advanced_security"

@dataclass
class FeatureLimits:
    # Core Lightning Network limits
    max_channels: int = 5
    monthly_payment_volume_sats: int = 1_000_000  # 1M sats
    daily_transaction_limit: int = 100
    max_channel_size_sats: int = 5_000_000  # 5M sats
    
    # Business features
    max_users: int = 1
    monthly_api_calls: int = 1_000
    webhook_endpoints: int = 1
    custom_branding: bool = False
    
    # Technical features  
    backup_retention_days: int = 7
    analytics_history_months: int = 1
    priority_support: bool = False
    sla_percentage: float = 99.0
    
    # Enterprise features
    dedicated_infrastructure: bool = False
    custom_integrations: bool = False
    compliance_reporting: bool = False
    advanced_security: bool = False
    
    # Additional features
    white_label: bool = False
    custom_domain: bool = False
    advanced_analytics: bool = False
    multi_signature_wallets: bool = False
    hardware_wallet_support: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class TierConfiguration:
    tier: UserTier
    name: str
    description: str
    monthly_price_usd: float
    yearly_price_usd: float
    features: FeatureLimits
    billing_period: BillingPeriod = BillingPeriod.MONTHLY
    trial_days: int = 0
    popular: bool = False
    custom_features: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def monthly_price_cents(self) -> int:
        return int(self.monthly_price_usd * 100)
    
    @property
    def yearly_price_cents(self) -> int:
        return int(self.yearly_price_usd * 100)

@dataclass
class UserAccount:
    user_id: str
    email: str
    tier: UserTier
    organization_name: Optional[str] = None
    billing_email: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    subscription_id: Optional[str] = None
    trial_ends_at: Optional[datetime] = None
    billing_cycle_ends_at: Optional[datetime] = None
    usage_limits: FeatureLimits = field(default_factory=FeatureLimits)
    current_usage: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    status: str = "active"

class UsageTracker:
    def __init__(self):
        self.usage_data = defaultdict(lambda: defaultdict(int))
        self.daily_usage = defaultdict(lambda: defaultdict(int))
        self.monthly_usage = defaultdict(lambda: defaultdict(int))
        
    async def track_usage(self, user_id: str, feature_type: FeatureType, amount: int = 1):
        """Track feature usage for user"""
        current_date = datetime.utcnow().date()
        current_month = current_date.replace(day=1)
        
        # Track overall usage
        self.usage_data[user_id][feature_type.value] += amount
        
        # Track daily usage
        self.daily_usage[f"{user_id}_{current_date}"][feature_type.value] += amount
        
        # Track monthly usage
        self.monthly_usage[f"{user_id}_{current_month}"][feature_type.value] += amount
        
        logger.debug(f"Usage tracked: {user_id} - {feature_type.value}: +{amount}")
    
    async def get_current_usage(self, user_id: str) -> Dict[str, int]:
        """Get current usage for user"""
        current_month = datetime.utcnow().date().replace(day=1)
        monthly_key = f"{user_id}_{current_month}"
        
        return dict(self.monthly_usage.get(monthly_key, {}))
    
    async def check_usage_limit(self, user_id: str, feature_type: FeatureType, 
                               limits: FeatureLimits, requested_amount: int = 1) -> bool:
        """Check if usage would exceed limits"""
        current_usage = await self.get_current_usage(user_id)
        current_value = current_usage.get(feature_type.value, 0)
        
        # Map feature types to limit attributes
        limit_mapping = {
            FeatureType.CHANNELS_MAX.value: limits.max_channels,
            FeatureType.PAYMENT_VOLUME_MONTHLY.value: limits.monthly_payment_volume_sats,
            FeatureType.TRANSACTION_LIMIT_DAILY.value: limits.daily_transaction_limit,
            FeatureType.API_CALLS_MONTHLY.value: limits.monthly_api_calls,
            FeatureType.WEBHOOK_ENDPOINTS.value: limits.webhook_endpoints,
        }
        
        limit_value = limit_mapping.get(feature_type.value)
        if limit_value is None:
            return True  # No limit defined, allow usage
        
        return (current_value + requested_amount) <= limit_value
    
    async def reset_monthly_usage(self, user_id: str):
        """Reset monthly usage counters"""
        current_month = datetime.utcnow().date().replace(day=1)
        monthly_key = f"{user_id}_{current_month}"
        
        if monthly_key in self.monthly_usage:
            del self.monthly_usage[monthly_key]

class BillingManager:
    def __init__(self):
        self.invoices = {}
        self.payment_methods = {}
        self.billing_cycles = {}
    
    async def create_subscription(self, user_id: str, tier_config: TierConfiguration) -> str:
        """Create subscription for user"""
        subscription_id = str(uuid.uuid4())
        
        subscription = {
            'subscription_id': subscription_id,
            'user_id': user_id,
            'tier': tier_config.tier,
            'monthly_price_cents': tier_config.monthly_price_cents,
            'yearly_price_cents': tier_config.yearly_price_cents,
            'billing_period': tier_config.billing_period,
            'created_at': datetime.utcnow(),
            'status': 'active',
            'current_period_start': datetime.utcnow(),
            'current_period_end': self._calculate_period_end(tier_config.billing_period),
            'trial_end': datetime.utcnow() + timedelta(days=tier_config.trial_days) if tier_config.trial_days > 0 else None
        }
        
        self.billing_cycles[subscription_id] = subscription
        
        logger.info(f"Subscription created: {subscription_id} for user {user_id} on tier {tier_config.tier.value}")
        return subscription_id
    
    def _calculate_period_end(self, billing_period: BillingPeriod) -> datetime:
        """Calculate billing period end date"""
        now = datetime.utcnow()
        
        if billing_period == BillingPeriod.MONTHLY:
            if now.month == 12:
                return now.replace(year=now.year + 1, month=1)
            else:
                return now.replace(month=now.month + 1)
        elif billing_period == BillingPeriod.YEARLY:
            return now.replace(year=now.year + 1)
        else:
            return now + timedelta(days=30)  # Default fallback
    
    async def generate_invoice(self, subscription_id: str) -> Dict[str, Any]:
        """Generate invoice for subscription"""
        subscription = self.billing_cycles.get(subscription_id)
        if not subscription:
            raise ValueError(f"Subscription not found: {subscription_id}")
        
        invoice_id = str(uuid.uuid4())
        
        if subscription['billing_period'] == BillingPeriod.MONTHLY:
            amount_cents = subscription['monthly_price_cents']
        else:
            amount_cents = subscription['yearly_price_cents']
        
        invoice = {
            'invoice_id': invoice_id,
            'subscription_id': subscription_id,
            'user_id': subscription['user_id'],
            'amount_cents': amount_cents,
            'currency': 'USD',
            'status': 'pending',
            'created_at': datetime.utcnow(),
            'due_date': datetime.utcnow() + timedelta(days=30),
            'description': f"BLNCS {subscription['tier'].value.title()} Plan"
        }
        
        self.invoices[invoice_id] = invoice
        return invoice
    
    async def process_payment(self, invoice_id: str, payment_method: str) -> bool:
        """Process payment for invoice"""
        invoice = self.invoices.get(invoice_id)
        if not invoice:
            return False
        
        try:
            # Mock payment processing
            # In production, integrate with Stripe, PayPal, or other payment processors
            
            invoice['status'] = 'paid'
            invoice['paid_at'] = datetime.utcnow()
            invoice['payment_method'] = payment_method
            
            logger.info(f"Payment processed successfully for invoice {invoice_id}")
            return True
            
        except Exception as e:
            logger.error(f"Payment processing failed for invoice {invoice_id}: {e}")
            invoice['status'] = 'failed'
            invoice['error'] = str(e)
            return False
    
    async def handle_failed_payment(self, subscription_id: str):
        """Handle failed payment"""
        subscription = self.billing_cycles.get(subscription_id)
        if subscription:
            subscription['status'] = 'past_due'
            subscription['grace_period_end'] = datetime.utcnow() + timedelta(days=7)
            
            # In production, send notification emails, retry payment, etc.
            logger.warning(f"Payment failed for subscription {subscription_id}")

class UserOnboardingManager:
    def __init__(self):
        self.onboarding_flows = {
            UserTier.FREE: self._free_tier_onboarding,
            UserTier.PERSONAL: self._personal_tier_onboarding,
            UserTier.PROFESSIONAL: self._professional_tier_onboarding,
            UserTier.BUSINESS: self._business_tier_onboarding,
            UserTier.ENTERPRISE: self._enterprise_tier_onboarding
        }
    
    async def start_onboarding(self, user_account: UserAccount) -> Dict[str, Any]:
        """Start onboarding process for user tier"""
        onboarding_flow = self.onboarding_flows.get(user_account.tier)
        
        if onboarding_flow:
            return await onboarding_flow(user_account)
        else:
            return await self._default_onboarding(user_account)
    
    async def _free_tier_onboarding(self, user_account: UserAccount) -> Dict[str, Any]:
        """Onboarding flow for free tier users"""
        return {
            'flow_type': 'free_tier',
            'steps': [
                {
                    'step': 'welcome',
                    'title': 'Welcome to BLNCS',
                    'description': 'Start your Lightning Network journey',
                    'action': 'show_introduction'
                },
                {
                    'step': 'quick_setup',
                    'title': 'Quick Setup',
                    'description': 'Create your first Lightning wallet',
                    'action': 'create_wallet_wizard'
                },
                {
                    'step': 'first_channel',
                    'title': 'Open Your First Channel',
                    'description': 'Connect to the Lightning Network',
                    'action': 'channel_creation_wizard'
                },
                {
                    'step': 'first_payment',
                    'title': 'Make Your First Payment',
                    'description': 'Send or receive Lightning payments',
                    'action': 'payment_tutorial'
                }
            ],
            'estimated_time_minutes': 15
        }
    
    async def _personal_tier_onboarding(self, user_account: UserAccount) -> Dict[str, Any]:
        """Onboarding flow for personal tier users"""
        return {
            'flow_type': 'personal_tier',
            'steps': [
                {
                    'step': 'welcome',
                    'title': 'Welcome to BLNCS Personal',
                    'description': 'Enhanced Lightning Network experience',
                    'action': 'show_personal_features'
                },
                {
                    'step': 'wallet_setup',
                    'title': 'Advanced Wallet Setup',
                    'description': 'Configure backup and security',
                    'action': 'advanced_wallet_wizard'
                },
                {
                    'step': 'channel_management',
                    'title': 'Channel Management',
                    'description': 'Optimize your channels',
                    'action': 'channel_optimization_tutorial'
                },
                {
                    'step': 'automation_setup',
                    'title': 'Automation Setup',
                    'description': 'Configure automatic rebalancing',
                    'action': 'automation_wizard'
                }
            ],
            'estimated_time_minutes': 25
        }
    
    async def _professional_tier_onboarding(self, user_account: UserAccount) -> Dict[str, Any]:
        """Onboarding flow for professional tier users"""
        return {
            'flow_type': 'professional_tier',
            'steps': [
                {
                    'step': 'welcome',
                    'title': 'Welcome to BLNCS Professional',
                    'description': 'Professional Lightning Network tools',
                    'action': 'show_professional_features'
                },
                {
                    'step': 'business_profile',
                    'title': 'Business Profile Setup',
                    'description': 'Configure your business information',
                    'action': 'business_profile_wizard'
                },
                {
                    'step': 'api_setup',
                    'title': 'API Integration',
                    'description': 'Set up API keys and webhooks',
                    'action': 'api_integration_wizard'
                },
                {
                    'step': 'analytics_dashboard',
                    'title': 'Analytics Dashboard',
                    'description': 'Monitor your Lightning operations',
                    'action': 'analytics_tour'
                }
            ],
            'estimated_time_minutes': 35
        }
    
    async def _business_tier_onboarding(self, user_account: UserAccount) -> Dict[str, Any]:
        """Onboarding flow for business tier users"""
        return {
            'flow_type': 'business_tier',
            'steps': [
                {
                    'step': 'welcome',
                    'title': 'Welcome to BLNCS Business',
                    'description': 'Enterprise-grade Lightning solutions',
                    'action': 'show_business_features'
                },
                {
                    'step': 'team_setup',
                    'title': 'Team Management',
                    'description': 'Add team members and set permissions',
                    'action': 'team_management_wizard'
                },
                {
                    'step': 'integration_setup',
                    'title': 'System Integration',
                    'description': 'Connect with your existing systems',
                    'action': 'integration_wizard'
                },
                {
                    'step': 'compliance_setup',
                    'title': 'Compliance Configuration',
                    'description': 'Configure reporting and compliance',
                    'action': 'compliance_wizard'
                }
            ],
            'estimated_time_minutes': 45
        }
    
    async def _enterprise_tier_onboarding(self, user_account: UserAccount) -> Dict[str, Any]:
        """Onboarding flow for enterprise tier users"""
        return {
            'flow_type': 'enterprise_tier',
            'steps': [
                {
                    'step': 'welcome',
                    'title': 'Welcome to BLNCS Enterprise',
                    'description': 'White-glove enterprise setup',
                    'action': 'schedule_onboarding_call'
                },
                {
                    'step': 'requirements_analysis',
                    'title': 'Requirements Analysis',
                    'description': 'Detailed analysis of your needs',
                    'action': 'requirements_questionnaire'
                },
                {
                    'step': 'infrastructure_planning',
                    'title': 'Infrastructure Planning',
                    'description': 'Design your deployment architecture',
                    'action': 'infrastructure_planning_session'
                },
                {
                    'step': 'deployment_coordination',
                    'title': 'Deployment Coordination',
                    'description': 'Coordinate with your technical team',
                    'action': 'deployment_planning'
                }
            ],
            'estimated_time_minutes': 120,
            'requires_human_assistance': True
        }
    
    async def _default_onboarding(self, user_account: UserAccount) -> Dict[str, Any]:
        """Default onboarding flow"""
        return {
            'flow_type': 'default',
            'steps': [
                {
                    'step': 'welcome',
                    'title': 'Welcome to BLNCS',
                    'description': 'Get started with Lightning Network',
                    'action': 'basic_setup'
                }
            ],
            'estimated_time_minutes': 10
        }

class TierMigrationManager:
    def __init__(self, usage_tracker: UsageTracker, billing_manager: BillingManager):
        self.usage_tracker = usage_tracker
        self.billing_manager = billing_manager
    
    async def migrate_user_tier(self, user_account: UserAccount, 
                               new_tier: UserTier, tier_configs: Dict[UserTier, TierConfiguration]) -> bool:
        """Migrate user to new tier"""
        old_tier = user_account.tier
        
        try:
            # Check if migration is valid
            if not await self._validate_migration(user_account, new_tier):
                return False
            
            # Handle billing changes
            if new_tier != UserTier.FREE:
                new_config = tier_configs[new_tier]
                
                # Cancel old subscription if exists
                if user_account.subscription_id:
                    await self._cancel_subscription(user_account.subscription_id)
                
                # Create new subscription
                new_subscription_id = await self.billing_manager.create_subscription(
                    user_account.user_id, new_config
                )
                user_account.subscription_id = new_subscription_id
            
            # Update user account
            user_account.tier = new_tier
            user_account.usage_limits = tier_configs[new_tier].features
            
            # Reset usage if upgrading
            if self._is_upgrade(old_tier, new_tier):
                await self.usage_tracker.reset_monthly_usage(user_account.user_id)
            
            logger.info(f"User {user_account.user_id} migrated from {old_tier.value} to {new_tier.value}")
            return True
            
        except Exception as e:
            logger.error(f"Tier migration failed for user {user_account.user_id}: {e}")
            return False
    
    async def _validate_migration(self, user_account: UserAccount, new_tier: UserTier) -> bool:
        """Validate if migration is allowed"""
        # Check if user has outstanding invoices
        # Check if current usage is compatible with new tier limits
        # Add custom validation logic here
        
        return True
    
    def _is_upgrade(self, old_tier: UserTier, new_tier: UserTier) -> bool:
        """Check if tier change is an upgrade"""
        tier_hierarchy = {
            UserTier.FREE: 0,
            UserTier.PERSONAL: 1,
            UserTier.PROFESSIONAL: 2,
            UserTier.BUSINESS: 3,
            UserTier.ENTERPRISE: 4,
            UserTier.CUSTOM: 5
        }
        
        return tier_hierarchy.get(new_tier, 0) > tier_hierarchy.get(old_tier, 0)
    
    async def _cancel_subscription(self, subscription_id: str):
        """Cancel existing subscription"""
        if subscription_id in self.billing_manager.billing_cycles:
            subscription = self.billing_manager.billing_cycles[subscription_id]
            subscription['status'] = 'cancelled'
            subscription['cancelled_at'] = datetime.utcnow()

class UserTierManager:
    def __init__(self):
        self.tier_configurations = self._initialize_default_tiers()
        self.user_accounts = {}
        self.usage_tracker = UsageTracker()
        self.billing_manager = BillingManager()
        self.onboarding_manager = UserOnboardingManager()
        self.migration_manager = TierMigrationManager(self.usage_tracker, self.billing_manager)
    
    def _initialize_default_tiers(self) -> Dict[UserTier, TierConfiguration]:
        """Initialize default tier configurations"""
        return {
            UserTier.FREE: TierConfiguration(
                tier=UserTier.FREE,
                name="Free",
                description="Perfect for getting started with Lightning Network",
                monthly_price_usd=0.0,
                yearly_price_usd=0.0,
                features=FeatureLimits(
                    max_channels=3,
                    monthly_payment_volume_sats=500_000,
                    daily_transaction_limit=50,
                    max_channel_size_sats=1_000_000,
                    max_users=1,
                    monthly_api_calls=100,
                    webhook_endpoints=1,
                    backup_retention_days=7,
                    analytics_history_months=1
                ),
                trial_days=0
            ),
            
            UserTier.PERSONAL: TierConfiguration(
                tier=UserTier.PERSONAL,
                name="Personal",
                description="Enhanced features for personal Lightning usage",
                monthly_price_usd=9.99,
                yearly_price_usd=99.99,
                features=FeatureLimits(
                    max_channels=10,
                    monthly_payment_volume_sats=5_000_000,
                    daily_transaction_limit=200,
                    max_channel_size_sats=10_000_000,
                    max_users=1,
                    monthly_api_calls=1_000,
                    webhook_endpoints=3,
                    backup_retention_days=30,
                    analytics_history_months=3,
                    hardware_wallet_support=True
                ),
                trial_days=7,
                popular=True
            ),
            
            UserTier.PROFESSIONAL: TierConfiguration(
                tier=UserTier.PROFESSIONAL,
                name="Professional",
                description="Professional tools for Lightning Network businesses",
                monthly_price_usd=49.99,
                yearly_price_usd=499.99,
                features=FeatureLimits(
                    max_channels=50,
                    monthly_payment_volume_sats=50_000_000,
                    daily_transaction_limit=1_000,
                    max_channel_size_sats=50_000_000,
                    max_users=5,
                    monthly_api_calls=10_000,
                    webhook_endpoints=10,
                    custom_branding=True,
                    backup_retention_days=90,
                    analytics_history_months=12,
                    priority_support=True,
                    advanced_analytics=True,
                    multi_signature_wallets=True,
                    hardware_wallet_support=True
                ),
                trial_days=14
            ),
            
            UserTier.BUSINESS: TierConfiguration(
                tier=UserTier.BUSINESS,
                name="Business",
                description="Complete solution for Lightning Network businesses",
                monthly_price_usd=199.99,
                yearly_price_usd=1999.99,
                features=FeatureLimits(
                    max_channels=200,
                    monthly_payment_volume_sats=500_000_000,
                    daily_transaction_limit=10_000,
                    max_channel_size_sats=100_000_000,
                    max_users=25,
                    monthly_api_calls=100_000,
                    webhook_endpoints=50,
                    custom_branding=True,
                    backup_retention_days=365,
                    analytics_history_months=24,
                    priority_support=True,
                    sla_percentage=99.5,
                    advanced_analytics=True,
                    multi_signature_wallets=True,
                    hardware_wallet_support=True,
                    custom_domain=True,
                    compliance_reporting=True
                ),
                trial_days=30
            ),
            
            UserTier.ENTERPRISE: TierConfiguration(
                tier=UserTier.ENTERPRISE,
                name="Enterprise",
                description="Enterprise-grade Lightning Network infrastructure",
                monthly_price_usd=999.99,
                yearly_price_usd=9999.99,
                features=FeatureLimits(
                    max_channels=-1,  # Unlimited
                    monthly_payment_volume_sats=-1,  # Unlimited
                    daily_transaction_limit=-1,  # Unlimited
                    max_channel_size_sats=-1,  # Unlimited
                    max_users=-1,  # Unlimited
                    monthly_api_calls=-1,  # Unlimited
                    webhook_endpoints=-1,  # Unlimited
                    custom_branding=True,
                    backup_retention_days=-1,  # Unlimited
                    analytics_history_months=-1,  # Unlimited
                    priority_support=True,
                    sla_percentage=99.9,
                    dedicated_infrastructure=True,
                    custom_integrations=True,
                    compliance_reporting=True,
                    advanced_security=True,
                    white_label=True,
                    custom_domain=True,
                    advanced_analytics=True,
                    multi_signature_wallets=True,
                    hardware_wallet_support=True
                ),
                trial_days=30
            )
        }
    
    async def create_user_account(self, email: str, tier: UserTier = UserTier.FREE,
                                 organization_name: Optional[str] = None) -> UserAccount:
        """Create new user account"""
        user_id = str(uuid.uuid4())
        tier_config = self.tier_configurations[tier]
        
        user_account = UserAccount(
            user_id=user_id,
            email=email,
            tier=tier,
            organization_name=organization_name,
            usage_limits=tier_config.features,
            trial_ends_at=datetime.utcnow() + timedelta(days=tier_config.trial_days) if tier_config.trial_days > 0 else None
        )
        
        # Create subscription if paid tier
        if tier != UserTier.FREE:
            subscription_id = await self.billing_manager.create_subscription(user_id, tier_config)
            user_account.subscription_id = subscription_id
        
        self.user_accounts[user_id] = user_account
        
        logger.info(f"User account created: {email} on {tier.value} tier")
        return user_account
    
    async def get_user_account(self, user_id: str) -> Optional[UserAccount]:
        """Get user account by ID"""
        return self.user_accounts.get(user_id)
    
    async def check_feature_access(self, user_id: str, feature_type: FeatureType, 
                                  requested_amount: int = 1) -> bool:
        """Check if user has access to feature"""
        user_account = await self.get_user_account(user_id)
        if not user_account:
            return False
        
        # Check if user is in trial or paid
        if not await self._is_user_active(user_account):
            return False
        
        # Check usage limits
        return await self.usage_tracker.check_usage_limit(
            user_id, feature_type, user_account.usage_limits, requested_amount
        )
    
    async def track_feature_usage(self, user_id: str, feature_type: FeatureType, amount: int = 1):
        """Track feature usage"""
        await self.usage_tracker.track_usage(user_id, feature_type, amount)
    
    async def get_usage_summary(self, user_id: str) -> Dict[str, Any]:
        """Get usage summary for user"""
        user_account = await self.get_user_account(user_id)
        if not user_account:
            return {}
        
        current_usage = await self.usage_tracker.get_current_usage(user_id)
        
        return {
            'user_id': user_id,
            'tier': user_account.tier.value,
            'limits': user_account.usage_limits.to_dict(),
            'current_usage': current_usage,
            'usage_percentage': self._calculate_usage_percentages(current_usage, user_account.usage_limits)
        }
    
    def _calculate_usage_percentages(self, current_usage: Dict[str, int], 
                                   limits: FeatureLimits) -> Dict[str, float]:
        """Calculate usage percentages"""
        percentages = {}
        
        limit_mapping = {
            'channels_max': limits.max_channels,
            'payment_volume_monthly': limits.monthly_payment_volume_sats,
            'transaction_limit_daily': limits.daily_transaction_limit,
            'api_calls_monthly': limits.monthly_api_calls,
        }
        
        for usage_key, usage_value in current_usage.items():
            limit_value = limit_mapping.get(usage_key)
            if limit_value and limit_value > 0:
                percentage = (usage_value / limit_value) * 100
                percentages[usage_key] = min(percentage, 100.0)
        
        return percentages
    
    async def _is_user_active(self, user_account: UserAccount) -> bool:
        """Check if user account is active"""
        now = datetime.utcnow()
        
        # Check trial status
        if user_account.trial_ends_at and now < user_account.trial_ends_at:
            return True
        
        # Check paid subscription
        if user_account.subscription_id:
            subscription = self.billing_manager.billing_cycles.get(user_account.subscription_id)
            if subscription and subscription['status'] == 'active':
                return now < subscription.get('current_period_end', now)
        
        # Free tier is always active
        return user_account.tier == UserTier.FREE
    
    async def get_tier_comparison(self) -> Dict[str, Any]:
        """Get tier comparison data for pricing page"""
        comparison = {
            'tiers': [],
            'features': []
        }
        
        # Get all features
        all_features = set()
        for config in self.tier_configurations.values():
            features_dict = config.features.to_dict()
            all_features.update(features_dict.keys())
        
        # Build comparison data
        for tier, config in self.tier_configurations.items():
            tier_data = {
                'tier': tier.value,
                'name': config.name,
                'description': config.description,
                'monthly_price': config.monthly_price_usd,
                'yearly_price': config.yearly_price_usd,
                'popular': config.popular,
                'trial_days': config.trial_days,
                'features': config.features.to_dict()
            }
            comparison['tiers'].append(tier_data)
        
        comparison['features'] = list(all_features)
        return comparison
    
    async def upgrade_user_tier(self, user_id: str, new_tier: UserTier) -> bool:
        """Upgrade user to new tier"""
        user_account = await self.get_user_account(user_id)
        if not user_account:
            return False
        
        return await self.migration_manager.migrate_user_tier(
            user_account, new_tier, self.tier_configurations
        )
    
    async def start_user_onboarding(self, user_id: str) -> Dict[str, Any]:
        """Start onboarding process for user"""
        user_account = await self.get_user_account(user_id)
        if not user_account:
            return {}
        
        return await self.onboarding_manager.start_onboarding(user_account)

# Global tier manager instance
_tier_manager_instance = None

async def get_tier_manager() -> UserTierManager:
    """Get or create tier manager"""
    global _tier_manager_instance
    
    if _tier_manager_instance is None:
        _tier_manager_instance = UserTierManager()
    
    return _tier_manager_instance

async def initialize_tier_system() -> UserTierManager:
    """Initialize tier system"""
    manager = UserTierManager()
    logger.info("User tier system initialized")
    return manager