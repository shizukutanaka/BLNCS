"""
Freemium and Usage-Based Pricing Engine
Sophisticated pricing system with multiple models and flexible billing options.
"""

import asyncio
import json
import logging
import uuid
import decimal
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple
from enum import Enum
from dataclasses import dataclass, field, asdict
from collections import defaultdict
import structlog

logger = structlog.get_logger(__name__)

class PricingModel(Enum):
    FREEMIUM = "freemium"
    SUBSCRIPTION = "subscription"
    USAGE_BASED = "usage_based"
    HYBRID = "hybrid"
    CUSTOM = "custom"

class BillingFrequency(Enum):
    MONTHLY = "monthly"
    YEARLY = "yearly"
    USAGE_BASED = "usage_based"
    WEEKLY = "weekly"
    DAILY = "daily"

class UsageMetric(Enum):
    API_CALLS = "api_calls"
    PAYMENT_VOLUME = "payment_volume"
    CHANNELS_COUNT = "channels_count"
    TRANSACTIONS_COUNT = "transactions_count"
    STORAGE_GB = "storage_gb"
    BANDWIDTH_GB = "bandwidth_gb"
    USERS_COUNT = "users_count"
    COMPUTE_HOURS = "compute_hours"

class DiscountType(Enum):
    PERCENTAGE = "percentage"
    FIXED_AMOUNT = "fixed_amount"
    FREE_TIER = "free_tier"
    VOLUME_DISCOUNT = "volume_discount"

@dataclass
class PricingTier:
    tier_id: str
    name: str
    base_price_cents: int = 0  # Base monthly price in cents
    included_usage: Dict[UsageMetric, int] = field(default_factory=dict)
    overage_rates: Dict[UsageMetric, decimal.Decimal] = field(default_factory=dict)
    features: List[str] = field(default_factory=list)
    limits: Dict[str, Any] = field(default_factory=dict)
    billing_frequency: BillingFrequency = BillingFrequency.MONTHLY

@dataclass
class UsageRecord:
    user_id: str
    metric: UsageMetric
    quantity: decimal.Decimal
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    billing_period: str = ""
    
    def __post_init__(self):
        if not self.billing_period:
            self.billing_period = self.timestamp.strftime("%Y-%m")

@dataclass
class BillingLineItem:
    description: str
    quantity: decimal.Decimal
    unit_price_cents: int
    total_cents: int
    usage_metric: Optional[UsageMetric] = None
    billing_period: str = ""

@dataclass
class Invoice:
    invoice_id: str
    user_id: str
    billing_period: str
    line_items: List[BillingLineItem] = field(default_factory=list)
    subtotal_cents: int = 0
    tax_cents: int = 0
    discount_cents: int = 0
    total_cents: int = 0
    created_at: datetime = field(default_factory=datetime.utcnow)
    due_date: datetime = field(default_factory=lambda: datetime.utcnow() + timedelta(days=30))
    status: str = "pending"

class UsageMetering:
    def __init__(self):
        self.usage_records = defaultdict(list)
        self.aggregated_usage = defaultdict(lambda: defaultdict(decimal.Decimal))
    
    async def record_usage(self, user_id: str, metric: UsageMetric, 
                          quantity: decimal.Decimal, metadata: Dict[str, Any] = None):
        """Record usage for billing"""
        usage_record = UsageRecord(
            user_id=user_id,
            metric=metric,
            quantity=quantity,
            timestamp=datetime.utcnow(),
            metadata=metadata or {}
        )
        
        self.usage_records[user_id].append(usage_record)
        
        # Update aggregated usage for current billing period
        billing_period = usage_record.billing_period
        self.aggregated_usage[user_id][f"{metric.value}_{billing_period}"] += quantity
        
        logger.debug(f"Usage recorded: {user_id} - {metric.value}: {quantity}")
    
    async def get_usage_for_period(self, user_id: str, billing_period: str) -> Dict[UsageMetric, decimal.Decimal]:
        """Get aggregated usage for billing period"""
        usage_summary = {}
        
        for key, quantity in self.aggregated_usage[user_id].items():
            if key.endswith(billing_period):
                metric_name = key.replace(f"_{billing_period}", "")
                try:
                    metric = UsageMetric(metric_name)
                    usage_summary[metric] = quantity
                except ValueError:
                    continue
        
        return usage_summary
    
    async def get_current_usage(self, user_id: str) -> Dict[UsageMetric, decimal.Decimal]:
        """Get current month usage"""
        current_period = datetime.utcnow().strftime("%Y-%m")
        return await self.get_usage_for_period(user_id, current_period)
    
    async def reset_usage_for_period(self, user_id: str, billing_period: str):
        """Reset usage counters for billing period"""
        keys_to_remove = [
            key for key in self.aggregated_usage[user_id].keys() 
            if key.endswith(billing_period)
        ]
        
        for key in keys_to_remove:
            del self.aggregated_usage[user_id][key]

class BillingCalculator:
    def __init__(self):
        self.tax_rates = {
            'US': decimal.Decimal('0.08'),  # 8% average US sales tax
            'EU': decimal.Decimal('0.20'),  # 20% VAT
            'default': decimal.Decimal('0.00')
        }
        self.discount_rules = {}
    
    async def calculate_subscription_billing(self, pricing_tier: PricingTier, 
                                           billing_frequency: BillingFrequency) -> int:
        """Calculate subscription billing amount"""
        base_price = pricing_tier.base_price_cents
        
        if billing_frequency == BillingFrequency.YEARLY:
            # Apply annual discount (typically 10-20%)
            annual_price = base_price * 12
            discount = int(annual_price * decimal.Decimal('0.15'))  # 15% annual discount
            return annual_price - discount
        elif billing_frequency == BillingFrequency.MONTHLY:
            return base_price
        else:
            return base_price
    
    async def calculate_usage_billing(self, user_id: str, pricing_tier: PricingTier,
                                    usage_data: Dict[UsageMetric, decimal.Decimal],
                                    billing_period: str) -> List[BillingLineItem]:
        """Calculate usage-based billing"""
        line_items = []
        
        for metric, usage_quantity in usage_data.items():
            # Get included usage and overage rate
            included = decimal.Decimal(pricing_tier.included_usage.get(metric, 0))
            overage_rate = pricing_tier.overage_rates.get(metric, decimal.Decimal('0'))
            
            if usage_quantity > included and overage_rate > 0:
                # Calculate overage
                overage_quantity = usage_quantity - included
                overage_price_cents = int(overage_quantity * overage_rate * 100)  # Convert to cents
                
                line_item = BillingLineItem(
                    description=f"{metric.value.replace('_', ' ').title()} Overage",
                    quantity=overage_quantity,
                    unit_price_cents=int(overage_rate * 100),
                    total_cents=overage_price_cents,
                    usage_metric=metric,
                    billing_period=billing_period
                )
                
                line_items.append(line_item)
        
        return line_items
    
    async def calculate_total_bill(self, user_id: str, pricing_tier: PricingTier,
                                 usage_data: Dict[UsageMetric, decimal.Decimal],
                                 billing_period: str, country_code: str = 'US') -> Invoice:
        """Calculate complete bill including taxes and discounts"""
        invoice = Invoice(
            invoice_id=str(uuid.uuid4()),
            user_id=user_id,
            billing_period=billing_period
        )
        
        # Add subscription base cost
        if pricing_tier.base_price_cents > 0:
            subscription_cost = await self.calculate_subscription_billing(
                pricing_tier, pricing_tier.billing_frequency
            )
            
            base_line_item = BillingLineItem(
                description=f"{pricing_tier.name} Plan",
                quantity=decimal.Decimal('1'),
                unit_price_cents=subscription_cost,
                total_cents=subscription_cost,
                billing_period=billing_period
            )
            invoice.line_items.append(base_line_item)
        
        # Add usage-based charges
        usage_line_items = await self.calculate_usage_billing(
            user_id, pricing_tier, usage_data, billing_period
        )
        invoice.line_items.extend(usage_line_items)
        
        # Calculate subtotal
        invoice.subtotal_cents = sum(item.total_cents for item in invoice.line_items)
        
        # Apply discounts
        invoice.discount_cents = await self._calculate_discounts(user_id, invoice.subtotal_cents)
        
        # Calculate tax
        tax_rate = self.tax_rates.get(country_code, self.tax_rates['default'])
        taxable_amount = invoice.subtotal_cents - invoice.discount_cents
        invoice.tax_cents = int(decimal.Decimal(taxable_amount) * tax_rate)
        
        # Calculate total
        invoice.total_cents = invoice.subtotal_cents - invoice.discount_cents + invoice.tax_cents
        
        return invoice
    
    async def _calculate_discounts(self, user_id: str, subtotal_cents: int) -> int:
        """Calculate applicable discounts"""
        discount_amount = 0
        
        # Apply volume discounts
        if subtotal_cents > 10000:  # $100+
            discount_amount = int(subtotal_cents * decimal.Decimal('0.05'))  # 5% volume discount
        elif subtotal_cents > 5000:  # $50+
            discount_amount = int(subtotal_cents * decimal.Decimal('0.02'))  # 2% volume discount
        
        return discount_amount
    
    def add_discount_rule(self, rule_id: str, rule: Dict[str, Any]):
        """Add custom discount rule"""
        self.discount_rules[rule_id] = rule

class SubscriptionPricing:
    def __init__(self):
        self.pricing_tiers = self._initialize_default_tiers()
    
    def _initialize_default_tiers(self) -> Dict[str, PricingTier]:
        """Initialize default subscription tiers"""
        return {
            'free': PricingTier(
                tier_id='free',
                name='Free',
                base_price_cents=0,
                included_usage={
                    UsageMetric.API_CALLS: 1000,
                    UsageMetric.PAYMENT_VOLUME: 1000000,  # 1M sats
                    UsageMetric.CHANNELS_COUNT: 3,
                    UsageMetric.TRANSACTIONS_COUNT: 100
                },
                overage_rates={},  # No overage for free tier
                features=['Basic Lightning wallet', 'Mobile app', 'Basic support'],
                limits={'max_channels': 3, 'max_users': 1}
            ),
            
            'personal': PricingTier(
                tier_id='personal',
                name='Personal',
                base_price_cents=999,  # $9.99/month
                included_usage={
                    UsageMetric.API_CALLS: 10000,
                    UsageMetric.PAYMENT_VOLUME: 10000000,  # 10M sats
                    UsageMetric.CHANNELS_COUNT: 10,
                    UsageMetric.TRANSACTIONS_COUNT: 1000
                },
                overage_rates={
                    UsageMetric.API_CALLS: decimal.Decimal('0.001'),  # $0.001 per call
                    UsageMetric.PAYMENT_VOLUME: decimal.Decimal('0.00000001'),  # per sat
                },
                features=['Advanced wallet', 'Analytics', 'Priority support', 'Hardware wallet support'],
                limits={'max_channels': 10, 'max_users': 1}
            ),
            
            'business': PricingTier(
                tier_id='business',
                name='Business',
                base_price_cents=4999,  # $49.99/month
                included_usage={
                    UsageMetric.API_CALLS: 100000,
                    UsageMetric.PAYMENT_VOLUME: 100000000,  # 100M sats
                    UsageMetric.CHANNELS_COUNT: 50,
                    UsageMetric.TRANSACTIONS_COUNT: 10000,
                    UsageMetric.USERS_COUNT: 10
                },
                overage_rates={
                    UsageMetric.API_CALLS: decimal.Decimal('0.0005'),
                    UsageMetric.PAYMENT_VOLUME: decimal.Decimal('0.000000005'),
                    UsageMetric.USERS_COUNT: decimal.Decimal('5.00'),  # $5 per additional user
                },
                features=['Multi-user', 'Advanced analytics', 'API access', 'Custom branding'],
                limits={'max_channels': 50, 'max_users': 10}
            ),
            
            'enterprise': PricingTier(
                tier_id='enterprise',
                name='Enterprise',
                base_price_cents=19999,  # $199.99/month
                included_usage={
                    UsageMetric.API_CALLS: 1000000,
                    UsageMetric.PAYMENT_VOLUME: 1000000000,  # 1B sats
                    UsageMetric.CHANNELS_COUNT: 200,
                    UsageMetric.TRANSACTIONS_COUNT: 100000,
                    UsageMetric.USERS_COUNT: 50
                },
                overage_rates={
                    UsageMetric.API_CALLS: decimal.Decimal('0.0001'),
                    UsageMetric.PAYMENT_VOLUME: decimal.Decimal('0.000000001'),
                    UsageMetric.USERS_COUNT: decimal.Decimal('3.00'),
                },
                features=['Unlimited channels', 'White-label', 'SLA', 'Dedicated support'],
                limits={'max_channels': -1, 'max_users': 50}
            )
        }
    
    def get_tier(self, tier_id: str) -> Optional[PricingTier]:
        """Get pricing tier by ID"""
        return self.pricing_tiers.get(tier_id)
    
    def get_all_tiers(self) -> Dict[str, PricingTier]:
        """Get all pricing tiers"""
        return self.pricing_tiers
    
    def create_custom_tier(self, tier_data: Dict[str, Any]) -> PricingTier:
        """Create custom pricing tier"""
        tier = PricingTier(
            tier_id=tier_data['tier_id'],
            name=tier_data['name'],
            base_price_cents=tier_data.get('base_price_cents', 0),
            included_usage=tier_data.get('included_usage', {}),
            overage_rates=tier_data.get('overage_rates', {}),
            features=tier_data.get('features', []),
            limits=tier_data.get('limits', {})
        )
        
        self.pricing_tiers[tier.tier_id] = tier
        return tier

class UsageBasedPricing:
    def __init__(self):
        self.usage_rates = self._initialize_usage_rates()
        self.volume_discounts = self._initialize_volume_discounts()
    
    def _initialize_usage_rates(self) -> Dict[UsageMetric, decimal.Decimal]:
        """Initialize pay-as-you-go rates"""
        return {
            UsageMetric.API_CALLS: decimal.Decimal('0.001'),  # $0.001 per call
            UsageMetric.PAYMENT_VOLUME: decimal.Decimal('0.00000001'),  # per sat
            UsageMetric.CHANNELS_COUNT: decimal.Decimal('1.00'),  # $1 per channel per month
            UsageMetric.TRANSACTIONS_COUNT: decimal.Decimal('0.01'),  # $0.01 per transaction
            UsageMetric.STORAGE_GB: decimal.Decimal('0.10'),  # $0.10 per GB per month
            UsageMetric.BANDWIDTH_GB: decimal.Decimal('0.05'),  # $0.05 per GB
            UsageMetric.USERS_COUNT: decimal.Decimal('5.00'),  # $5 per user per month
            UsageMetric.COMPUTE_HOURS: decimal.Decimal('0.50'),  # $0.50 per compute hour
        }
    
    def _initialize_volume_discounts(self) -> Dict[UsageMetric, List[Dict[str, Any]]]:
        """Initialize volume discount tiers"""
        return {
            UsageMetric.API_CALLS: [
                {'min_quantity': 100000, 'discount_percentage': 10},
                {'min_quantity': 1000000, 'discount_percentage': 20},
                {'min_quantity': 10000000, 'discount_percentage': 30}
            ],
            UsageMetric.PAYMENT_VOLUME: [
                {'min_quantity': 100000000, 'discount_percentage': 5},  # 100M sats
                {'min_quantity': 1000000000, 'discount_percentage': 10},  # 1B sats
                {'min_quantity': 10000000000, 'discount_percentage': 15}  # 10B sats
            ]
        }
    
    def calculate_usage_cost(self, metric: UsageMetric, quantity: decimal.Decimal) -> int:
        """Calculate cost for usage-based pricing"""
        base_rate = self.usage_rates.get(metric, decimal.Decimal('0'))
        base_cost = quantity * base_rate
        
        # Apply volume discounts
        discounts = self.volume_discounts.get(metric, [])
        discount_percentage = decimal.Decimal('0')
        
        for discount_tier in discounts:
            if quantity >= discount_tier['min_quantity']:
                discount_percentage = decimal.Decimal(str(discount_tier['discount_percentage'])) / 100
        
        discounted_cost = base_cost * (decimal.Decimal('1') - discount_percentage)
        return int(discounted_cost * 100)  # Convert to cents

class FreemiumManager:
    def __init__(self, usage_metering: UsageMetering, subscription_pricing: SubscriptionPricing):
        self.usage_metering = usage_metering
        self.subscription_pricing = subscription_pricing
        self.free_tier_limits = {}
        self.upgrade_triggers = {}
    
    async def check_free_tier_limits(self, user_id: str) -> Dict[str, Any]:
        """Check if user is approaching or exceeding free tier limits"""
        free_tier = self.subscription_pricing.get_tier('free')
        if not free_tier:
            return {'status': 'error', 'message': 'Free tier not found'}
        
        current_usage = await self.usage_metering.get_current_usage(user_id)
        limit_status = {}
        
        for metric, limit in free_tier.included_usage.items():
            usage = current_usage.get(metric, decimal.Decimal('0'))
            usage_percentage = (float(usage) / limit * 100) if limit > 0 else 0
            
            limit_status[metric.value] = {
                'current': float(usage),
                'limit': limit,
                'percentage': usage_percentage,
                'exceeded': usage > limit,
                'approaching_limit': usage_percentage > 80
            }
        
        return {
            'status': 'success',
            'user_id': user_id,
            'limits': limit_status,
            'should_upgrade': any(status['exceeded'] for status in limit_status.values()),
            'approaching_limits': [metric for metric, status in limit_status.items() if status['approaching_limit']]
        }
    
    async def suggest_upgrade_tier(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Suggest appropriate upgrade tier based on usage"""
        current_usage = await self.usage_metering.get_current_usage(user_id)
        
        # Find best tier based on usage
        all_tiers = self.subscription_pricing.get_all_tiers()
        suitable_tiers = []
        
        for tier_id, tier in all_tiers.items():
            if tier_id == 'free':
                continue
            
            is_suitable = True
            estimated_cost = tier.base_price_cents
            
            for metric, usage in current_usage.items():
                included = tier.included_usage.get(metric, 0)
                if usage > included:
                    overage_rate = tier.overage_rates.get(metric, decimal.Decimal('0'))
                    if overage_rate > 0:
                        overage_cost = int((usage - included) * overage_rate * 100)
                        estimated_cost += overage_cost
                    else:
                        # Hard limit exceeded
                        is_suitable = False
                        break
            
            if is_suitable:
                suitable_tiers.append({
                    'tier_id': tier_id,
                    'tier_name': tier.name,
                    'estimated_monthly_cost_cents': estimated_cost,
                    'estimated_monthly_cost_dollars': estimated_cost / 100,
                    'savings_compared_to_payg': 0  # Calculate PAYG cost comparison
                })
        
        if suitable_tiers:
            # Sort by cost
            suitable_tiers.sort(key=lambda x: x['estimated_monthly_cost_cents'])
            recommended_tier = suitable_tiers[0]
            
            return {
                'recommended_tier': recommended_tier,
                'all_suitable_tiers': suitable_tiers,
                'current_usage': {metric.value: float(usage) for metric, usage in current_usage.items()}
            }
        
        return None
    
    def add_upgrade_trigger(self, trigger_id: str, condition: Dict[str, Any]):
        """Add automatic upgrade trigger"""
        self.upgrade_triggers[trigger_id] = condition
    
    async def check_upgrade_triggers(self, user_id: str) -> List[str]:
        """Check if any upgrade triggers are activated"""
        activated_triggers = []
        current_usage = await self.usage_metering.get_current_usage(user_id)
        
        for trigger_id, condition in self.upgrade_triggers.items():
            if await self._evaluate_trigger_condition(condition, current_usage):
                activated_triggers.append(trigger_id)
        
        return activated_triggers
    
    async def _evaluate_trigger_condition(self, condition: Dict[str, Any], 
                                        usage: Dict[UsageMetric, decimal.Decimal]) -> bool:
        """Evaluate trigger condition"""
        condition_type = condition.get('type')
        
        if condition_type == 'usage_threshold':
            metric = UsageMetric(condition['metric'])
            threshold = decimal.Decimal(str(condition['threshold']))
            return usage.get(metric, decimal.Decimal('0')) >= threshold
        
        elif condition_type == 'multiple_limits_exceeded':
            exceeded_count = 0
            free_tier = self.subscription_pricing.get_tier('free')
            
            for metric, usage_amount in usage.items():
                limit = free_tier.included_usage.get(metric, 0)
                if usage_amount > limit:
                    exceeded_count += 1
            
            return exceeded_count >= condition.get('min_exceeded', 2)
        
        return False

class PricingEngine:
    def __init__(self):
        self.usage_metering = UsageMetering()
        self.billing_calculator = BillingCalculator()
        self.subscription_pricing = SubscriptionPricing()
        self.usage_based_pricing = UsageBasedPricing()
        self.freemium_manager = FreemiumManager(self.usage_metering, self.subscription_pricing)
        self.user_tiers = {}  # user_id -> tier_id mapping
        self.generated_invoices = {}
    
    async def initialize(self):
        """Initialize pricing engine"""
        # Setup default upgrade triggers
        self.freemium_manager.add_upgrade_trigger('high_api_usage', {
            'type': 'usage_threshold',
            'metric': 'api_calls',
            'threshold': 5000
        })
        
        self.freemium_manager.add_upgrade_trigger('multiple_limits', {
            'type': 'multiple_limits_exceeded',
            'min_exceeded': 2
        })
        
        logger.info("Pricing engine initialized successfully")
    
    async def record_user_usage(self, user_id: str, metric: UsageMetric, 
                               quantity: decimal.Decimal, metadata: Dict[str, Any] = None):
        """Record usage for user"""
        await self.usage_metering.record_usage(user_id, metric, quantity, metadata)
    
    async def get_user_tier(self, user_id: str) -> str:
        """Get user's current pricing tier"""
        return self.user_tiers.get(user_id, 'free')
    
    async def set_user_tier(self, user_id: str, tier_id: str):
        """Set user's pricing tier"""
        if tier_id in self.subscription_pricing.get_all_tiers():
            self.user_tiers[user_id] = tier_id
            logger.info(f"User {user_id} tier set to {tier_id}")
        else:
            raise ValueError(f"Invalid tier: {tier_id}")
    
    async def generate_monthly_invoice(self, user_id: str, 
                                     billing_period: Optional[str] = None) -> Invoice:
        """Generate monthly invoice for user"""
        if billing_period is None:
            billing_period = datetime.utcnow().strftime("%Y-%m")
        
        # Get user's pricing tier
        tier_id = await self.get_user_tier(user_id)
        pricing_tier = self.subscription_pricing.get_tier(tier_id)
        
        if not pricing_tier:
            raise ValueError(f"Pricing tier not found: {tier_id}")
        
        # Get usage data for billing period
        usage_data = await self.usage_metering.get_usage_for_period(user_id, billing_period)
        
        # Calculate bill
        invoice = await self.billing_calculator.calculate_total_bill(
            user_id, pricing_tier, usage_data, billing_period
        )
        
        # Store generated invoice
        self.generated_invoices[invoice.invoice_id] = invoice
        
        return invoice
    
    async def get_pricing_comparison(self) -> Dict[str, Any]:
        """Get pricing comparison for all tiers"""
        all_tiers = self.subscription_pricing.get_all_tiers()
        comparison = {
            'tiers': [],
            'features_comparison': {},
            'usage_based_rates': {}
        }
        
        for tier_id, tier in all_tiers.items():
            tier_info = {
                'tier_id': tier_id,
                'name': tier.name,
                'monthly_price_dollars': tier.base_price_cents / 100,
                'annual_price_dollars': (tier.base_price_cents * 12 * 0.85) / 100,  # 15% annual discount
                'included_usage': {metric.value: limit for metric, limit in tier.included_usage.items()},
                'overage_rates': {metric.value: float(rate) for metric, rate in tier.overage_rates.items()},
                'features': tier.features,
                'popular': tier_id == 'personal'  # Mark personal as popular
            }
            comparison['tiers'].append(tier_info)
        
        # Add usage-based rates
        comparison['usage_based_rates'] = {
            metric.value: float(rate) for metric, rate in self.usage_based_pricing.usage_rates.items()
        }
        
        return comparison
    
    async def check_user_limits(self, user_id: str) -> Dict[str, Any]:
        """Check user's current usage against limits"""
        if await self.get_user_tier(user_id) == 'free':
            return await self.freemium_manager.check_free_tier_limits(user_id)
        else:
            # For paid tiers, check overage
            tier_id = await self.get_user_tier(user_id)
            pricing_tier = self.subscription_pricing.get_tier(tier_id)
            current_usage = await self.usage_metering.get_current_usage(user_id)
            
            usage_status = {}
            for metric, usage in current_usage.items():
                included = pricing_tier.included_usage.get(metric, 0)
                overage = max(0, float(usage) - included)
                
                usage_status[metric.value] = {
                    'current': float(usage),
                    'included': included,
                    'overage': overage,
                    'will_incur_charges': overage > 0 and metric in pricing_tier.overage_rates
                }
            
            return {
                'status': 'success',
                'tier': tier_id,
                'usage_status': usage_status
            }
    
    async def get_upgrade_recommendations(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get upgrade recommendations for user"""
        return await self.freemium_manager.suggest_upgrade_tier(user_id)
    
    async def estimate_monthly_cost(self, user_id: str, tier_id: str) -> Dict[str, Any]:
        """Estimate monthly cost for user on specific tier"""
        pricing_tier = self.subscription_pricing.get_tier(tier_id)
        if not pricing_tier:
            return {'error': f'Tier not found: {tier_id}'}
        
        current_usage = await self.usage_metering.get_current_usage(user_id)
        
        base_cost = pricing_tier.base_price_cents
        overage_cost = 0
        
        overage_breakdown = {}
        for metric, usage in current_usage.items():
            included = pricing_tier.included_usage.get(metric, 0)
            if usage > included:
                overage_rate = pricing_tier.overage_rates.get(metric, decimal.Decimal('0'))
                if overage_rate > 0:
                    overage_amount = usage - included
                    cost = int(overage_amount * overage_rate * 100)
                    overage_cost += cost
                    overage_breakdown[metric.value] = {
                        'overage_quantity': float(overage_amount),
                        'rate_dollars': float(overage_rate),
                        'cost_cents': cost
                    }
        
        total_cost = base_cost + overage_cost
        
        return {
            'tier_id': tier_id,
            'tier_name': pricing_tier.name,
            'base_cost_cents': base_cost,
            'overage_cost_cents': overage_cost,
            'total_cost_cents': total_cost,
            'total_cost_dollars': total_cost / 100,
            'overage_breakdown': overage_breakdown
        }

# Global pricing engine instance
_pricing_engine_instance = None

async def get_pricing_engine() -> PricingEngine:
    """Get or create pricing engine"""
    global _pricing_engine_instance
    
    if _pricing_engine_instance is None:
        _pricing_engine_instance = PricingEngine()
        await _pricing_engine_instance.initialize()
    
    return _pricing_engine_instance

async def initialize_pricing_system() -> PricingEngine:
    """Initialize pricing system"""
    engine = PricingEngine()
    await engine.initialize()
    logger.info("Freemium and usage-based pricing system initialized")
    return engine