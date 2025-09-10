"""
Simplified Setup Wizard and Onboarding System
Comprehensive guided setup experience for users of all technical levels.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Callable
from enum import Enum
from dataclasses import dataclass, field, asdict
from collections import defaultdict
import structlog

logger = structlog.get_logger(__name__)

class WizardType(Enum):
    QUICK_START = "quick_start"
    FULL_SETUP = "full_setup"
    WALLET_SETUP = "wallet_setup"
    CHANNEL_SETUP = "channel_setup"
    BUSINESS_SETUP = "business_setup"
    DEVELOPER_SETUP = "developer_setup"
    MIGRATION_WIZARD = "migration_wizard"

class StepType(Enum):
    WELCOME = "welcome"
    USER_INFO = "user_info"
    PREFERENCES = "preferences"
    WALLET_CREATE = "wallet_create"
    WALLET_RESTORE = "wallet_restore"
    SECURITY_SETUP = "security_setup"
    CHANNEL_CREATE = "channel_create"
    PAYMENT_TEST = "payment_test"
    BUSINESS_INFO = "business_info"
    API_SETUP = "api_setup"
    INTEGRATION = "integration"
    COMPLETION = "completion"

class ValidationResult(Enum):
    VALID = "valid"
    INVALID = "invalid"
    WARNING = "warning"
    REQUIRES_CONFIRMATION = "requires_confirmation"

@dataclass
class WizardStep:
    step_id: str
    step_type: StepType
    title: str
    description: str
    component: str  # Frontend component to render
    required: bool = True
    skippable: bool = False
    estimated_time_minutes: int = 2
    help_text: Optional[str] = None
    validation_rules: List[str] = field(default_factory=list)
    next_step_conditions: Dict[str, str] = field(default_factory=dict)  # condition -> next_step_id
    data_requirements: List[str] = field(default_factory=list)
    api_calls: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class SetupFlow:
    flow_id: str
    wizard_type: WizardType
    name: str
    description: str
    target_audience: str
    estimated_time_minutes: int
    steps: List[WizardStep] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    completion_rewards: List[str] = field(default_factory=list)
    
    def add_step(self, step: WizardStep):
        """Add step to flow"""
        self.steps.append(step)
    
    def get_step(self, step_id: str) -> Optional[WizardStep]:
        """Get step by ID"""
        return next((step for step in self.steps if step.step_id == step_id), None)
    
    def get_next_step(self, current_step_id: str, user_data: Dict[str, Any] = None) -> Optional[WizardStep]:
        """Get next step based on current step and user data"""
        current_step = self.get_step(current_step_id)
        if not current_step:
            return None
        
        current_index = self.steps.index(current_step)
        
        # Check conditional next steps
        if user_data and current_step.next_step_conditions:
            for condition, next_step_id in current_step.next_step_conditions.items():
                if self._evaluate_condition(condition, user_data):
                    return self.get_step(next_step_id)
        
        # Return next step in sequence
        if current_index < len(self.steps) - 1:
            return self.steps[current_index + 1]
        
        return None
    
    def _evaluate_condition(self, condition: str, user_data: Dict[str, Any]) -> bool:
        """Evaluate step condition"""
        # Simple condition evaluation - in production, use more sophisticated logic
        if '=' in condition:
            key, value = condition.split('=', 1)
            return user_data.get(key.strip()) == value.strip()
        
        return user_data.get(condition, False)

@dataclass
class OnboardingProgress:
    user_id: str
    flow_id: str
    current_step_id: str
    completed_steps: List[str] = field(default_factory=list)
    step_data: Dict[str, Any] = field(default_factory=dict)
    started_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    completion_percentage: float = 0.0
    estimated_time_remaining: int = 0
    status: str = "in_progress"
    notes: List[str] = field(default_factory=list)

class QuickStartWizard:
    def __init__(self):
        self.flow = self._create_quick_start_flow()
    
    def _create_quick_start_flow(self) -> SetupFlow:
        """Create quick start setup flow"""
        flow = SetupFlow(
            flow_id="quick_start",
            wizard_type=WizardType.QUICK_START,
            name="Quick Start",
            description="Get up and running with Lightning Network in 10 minutes",
            target_audience="New users who want to start quickly",
            estimated_time_minutes=10
        )
        
        # Welcome step
        flow.add_step(WizardStep(
            step_id="welcome",
            step_type=StepType.WELCOME,
            title="Welcome to BLNCS",
            description="Let's get you started with the Lightning Network in just a few steps",
            component="WelcomeComponent",
            skippable=False,
            estimated_time_minutes=1,
            help_text="The Lightning Network enables instant, low-cost Bitcoin payments."
        ))
        
        # Basic user info
        flow.add_step(WizardStep(
            step_id="user_info",
            step_type=StepType.USER_INFO,
            title="Tell us about yourself",
            description="Help us customize your experience",
            component="UserInfoComponent",
            estimated_time_minutes=2,
            data_requirements=["user_type", "experience_level", "primary_use_case"],
            validation_rules=["required:user_type", "required:experience_level"],
            next_step_conditions={
                "user_type=business": "business_info",
                "experience_level=beginner": "guided_wallet_setup"
            }
        ))
        
        # Quick wallet setup
        flow.add_step(WizardStep(
            step_id="quick_wallet_setup",
            step_type=StepType.WALLET_CREATE,
            title="Create Your Lightning Wallet",
            description="We'll create a secure wallet for you",
            component="QuickWalletComponent",
            estimated_time_minutes=3,
            api_calls=["create_wallet", "generate_seed"],
            help_text="Your seed phrase is your wallet backup - keep it safe!"
        ))
        
        # First channel
        flow.add_step(WizardStep(
            step_id="first_channel",
            step_type=StepType.CHANNEL_CREATE,
            title="Open Your First Channel",
            description="Connect to the Lightning Network",
            component="FirstChannelComponent",
            estimated_time_minutes=2,
            api_calls=["suggest_nodes", "open_channel"],
            help_text="Channels allow you to send and receive Lightning payments"
        ))
        
        # Test payment
        flow.add_step(WizardStep(
            step_id="test_payment",
            step_type=StepType.PAYMENT_TEST,
            title="Make Your First Payment",
            description="Try sending a small test payment",
            component="TestPaymentComponent",
            estimated_time_minutes=2,
            api_calls=["create_invoice", "send_payment"],
            skippable=True
        ))
        
        # Completion
        flow.add_step(WizardStep(
            step_id="completion",
            step_type=StepType.COMPLETION,
            title="You're All Set!",
            description="Welcome to the Lightning Network",
            component="CompletionComponent",
            estimated_time_minutes=1,
            completion_rewards=["First Channel Badge", "Quick Start Achievement"]
        ))
        
        return flow

class WalletSetupWizard:
    def __init__(self):
        self.flow = self._create_wallet_setup_flow()
    
    def _create_wallet_setup_flow(self) -> SetupFlow:
        """Create comprehensive wallet setup flow"""
        flow = SetupFlow(
            flow_id="wallet_setup",
            wizard_type=WizardType.WALLET_SETUP,
            name="Wallet Setup",
            description="Complete wallet setup with advanced security options",
            target_audience="Users who want full control over their wallet setup",
            estimated_time_minutes=20
        )
        
        # Wallet type selection
        flow.add_step(WizardStep(
            step_id="wallet_type",
            step_type=StepType.PREFERENCES,
            title="Choose Wallet Type",
            description="Select how you want to manage your wallet",
            component="WalletTypeSelector",
            estimated_time_minutes=2,
            data_requirements=["wallet_type", "custody_preference"],
            next_step_conditions={
                "wallet_type=new": "create_wallet",
                "wallet_type=restore": "restore_wallet",
                "wallet_type=hardware": "hardware_setup"
            }
        ))
        
        # Create new wallet
        flow.add_step(WizardStep(
            step_id="create_wallet",
            step_type=StepType.WALLET_CREATE,
            title="Create New Wallet",
            description="Generate a new Lightning wallet",
            component="CreateWalletComponent",
            estimated_time_minutes=5,
            api_calls=["generate_mnemonic", "create_wallet"],
            data_requirements=["wallet_password", "confirm_seed_backup"]
        ))
        
        # Restore wallet
        flow.add_step(WizardStep(
            step_id="restore_wallet",
            step_type=StepType.WALLET_RESTORE,
            title="Restore Wallet",
            description="Restore wallet from seed phrase",
            component="RestoreWalletComponent",
            estimated_time_minutes=3,
            api_calls=["restore_from_seed"],
            data_requirements=["seed_phrase", "wallet_password"],
            validation_rules=["validate_seed_phrase"]
        ))
        
        # Security setup
        flow.add_step(WizardStep(
            step_id="security_setup",
            step_type=StepType.SECURITY_SETUP,
            title="Enhanced Security",
            description="Set up additional security measures",
            component="SecuritySetupComponent",
            estimated_time_minutes=5,
            data_requirements=["two_factor_auth", "backup_location", "auto_backup"],
            skippable=True
        ))
        
        # Wallet testing
        flow.add_step(WizardStep(
            step_id="wallet_test",
            step_type=StepType.PAYMENT_TEST,
            title="Test Your Wallet",
            description="Verify wallet functionality",
            component="WalletTestComponent",
            estimated_time_minutes=3,
            api_calls=["test_wallet_functions"]
        ))
        
        # Completion
        flow.add_step(WizardStep(
            step_id="completion",
            step_type=StepType.COMPLETION,
            title="Wallet Setup Complete",
            description="Your secure Lightning wallet is ready",
            component="WalletCompletionComponent",
            estimated_time_minutes=2,
            completion_rewards=["Secure Wallet Badge", "Advanced User Status"]
        ))
        
        return flow

class BusinessSetupWizard:
    def __init__(self):
        self.flow = self._create_business_setup_flow()
    
    def _create_business_setup_flow(self) -> SetupFlow:
        """Create business-focused setup flow"""
        flow = SetupFlow(
            flow_id="business_setup",
            wizard_type=WizardType.BUSINESS_SETUP,
            name="Business Setup",
            description="Complete business integration setup",
            target_audience="Business users and merchants",
            estimated_time_minutes=30
        )
        
        # Business information
        flow.add_step(WizardStep(
            step_id="business_info",
            step_type=StepType.BUSINESS_INFO,
            title="Business Information",
            description="Tell us about your business",
            component="BusinessInfoComponent",
            estimated_time_minutes=5,
            data_requirements=[
                "company_name", "business_type", "industry", 
                "expected_volume", "team_size", "compliance_requirements"
            ],
            validation_rules=["required:company_name", "required:business_type"]
        ))
        
        # Team setup
        flow.add_step(WizardStep(
            step_id="team_setup",
            step_type=StepType.USER_INFO,
            title="Team Setup",
            description="Add team members and set permissions",
            component="TeamSetupComponent",
            estimated_time_minutes=8,
            data_requirements=["team_members", "role_assignments"],
            api_calls=["invite_users", "set_permissions"],
            skippable=True
        ))
        
        # API and integration setup
        flow.add_step(WizardStep(
            step_id="api_setup",
            step_type=StepType.API_SETUP,
            title="API Integration",
            description="Configure API access and webhooks",
            component="APISetupComponent",
            estimated_time_minutes=10,
            data_requirements=["api_scopes", "webhook_urls", "rate_limits"],
            api_calls=["generate_api_keys", "setup_webhooks"]
        ))
        
        # Payment integration
        flow.add_step(WizardStep(
            step_id="payment_integration",
            step_type=StepType.INTEGRATION,
            title="Payment Integration",
            description="Integrate Lightning payments into your system",
            component="PaymentIntegrationComponent",
            estimated_time_minutes=5,
            data_requirements=["integration_type", "callback_urls"],
            help_text="Choose how customers will pay with Lightning"
        ))
        
        # Testing and validation
        flow.add_step(WizardStep(
            step_id="business_testing",
            step_type=StepType.PAYMENT_TEST,
            title="Test Your Integration",
            description="Verify your business setup works correctly",
            component="BusinessTestingComponent",
            estimated_time_minutes=5,
            api_calls=["test_business_flows"]
        ))
        
        # Completion
        flow.add_step(WizardStep(
            step_id="completion",
            step_type=StepType.COMPLETION,
            title="Business Setup Complete",
            description="Your Lightning business integration is ready",
            component="BusinessCompletionComponent",
            estimated_time_minutes=2,
            completion_rewards=["Business Account Badge", "API Access Enabled"]
        ))
        
        return flow

class OnboardingProgressTracker:
    def __init__(self):
        self.progress_data = {}
        self.completion_stats = defaultdict(int)
    
    async def start_onboarding(self, user_id: str, flow_id: str) -> OnboardingProgress:
        """Start onboarding process"""
        progress = OnboardingProgress(
            user_id=user_id,
            flow_id=flow_id,
            current_step_id="",  # Will be set when first step is accessed
            status="started"
        )
        
        self.progress_data[f"{user_id}_{flow_id}"] = progress
        logger.info(f"Started onboarding for user {user_id} with flow {flow_id}")
        
        return progress
    
    async def update_step_progress(self, user_id: str, flow_id: str, 
                                  step_id: str, step_data: Dict[str, Any]) -> bool:
        """Update progress for specific step"""
        key = f"{user_id}_{flow_id}"
        progress = self.progress_data.get(key)
        
        if not progress:
            return False
        
        # Update step data
        progress.step_data[step_id] = step_data
        progress.current_step_id = step_id
        progress.updated_at = datetime.utcnow()
        
        # Mark step as completed if it has required data
        if step_id not in progress.completed_steps:
            progress.completed_steps.append(step_id)
        
        logger.debug(f"Updated step progress: {user_id} - {step_id}")
        return True
    
    async def complete_step(self, user_id: str, flow_id: str, step_id: str) -> bool:
        """Mark step as completed"""
        key = f"{user_id}_{flow_id}"
        progress = self.progress_data.get(key)
        
        if not progress:
            return False
        
        if step_id not in progress.completed_steps:
            progress.completed_steps.append(step_id)
        
        progress.updated_at = datetime.utcnow()
        return True
    
    async def get_progress(self, user_id: str, flow_id: str) -> Optional[OnboardingProgress]:
        """Get current progress"""
        key = f"{user_id}_{flow_id}"
        return self.progress_data.get(key)
    
    async def calculate_completion_percentage(self, user_id: str, flow_id: str, 
                                            total_steps: int) -> float:
        """Calculate completion percentage"""
        progress = await self.get_progress(user_id, flow_id)
        
        if not progress:
            return 0.0
        
        if total_steps == 0:
            return 100.0
        
        completion_percent = (len(progress.completed_steps) / total_steps) * 100
        progress.completion_percentage = completion_percent
        
        return completion_percent
    
    async def complete_onboarding(self, user_id: str, flow_id: str):
        """Mark onboarding as completed"""
        key = f"{user_id}_{flow_id}"
        progress = self.progress_data.get(key)
        
        if progress:
            progress.status = "completed"
            progress.completion_percentage = 100.0
            progress.updated_at = datetime.utcnow()
            
            # Track completion stats
            self.completion_stats[flow_id] += 1
            
            logger.info(f"Onboarding completed: {user_id} - {flow_id}")

class SetupWizardManager:
    def __init__(self):
        self.wizards = {
            WizardType.QUICK_START: QuickStartWizard(),
            WizardType.WALLET_SETUP: WalletSetupWizard(),
            WizardType.BUSINESS_SETUP: BusinessSetupWizard()
        }
        self.progress_tracker = OnboardingProgressTracker()
        self.validation_handlers = {}
    
    async def get_available_wizards(self, user_type: str = None) -> List[Dict[str, Any]]:
        """Get list of available setup wizards"""
        wizards = []
        
        for wizard_type, wizard in self.wizards.items():
            wizard_info = {
                'type': wizard_type.value,
                'name': wizard.flow.name,
                'description': wizard.flow.description,
                'target_audience': wizard.flow.target_audience,
                'estimated_time': wizard.flow.estimated_time_minutes,
                'step_count': len(wizard.flow.steps)
            }
            
            # Filter by user type if specified
            if user_type:
                if user_type == 'business' and wizard_type == WizardType.BUSINESS_SETUP:
                    wizard_info['recommended'] = True
                elif user_type == 'individual' and wizard_type == WizardType.QUICK_START:
                    wizard_info['recommended'] = True
            
            wizards.append(wizard_info)
        
        return wizards
    
    async def start_wizard(self, user_id: str, wizard_type: WizardType) -> Dict[str, Any]:
        """Start setup wizard for user"""
        wizard = self.wizards.get(wizard_type)
        if not wizard:
            raise ValueError(f"Unknown wizard type: {wizard_type}")
        
        # Start progress tracking
        progress = await self.progress_tracker.start_onboarding(user_id, wizard.flow.flow_id)
        
        # Get first step
        first_step = wizard.flow.steps[0] if wizard.flow.steps else None
        if first_step:
            progress.current_step_id = first_step.step_id
        
        return {
            'wizard_id': wizard.flow.flow_id,
            'name': wizard.flow.name,
            'description': wizard.flow.description,
            'total_steps': len(wizard.flow.steps),
            'estimated_time': wizard.flow.estimated_time_minutes,
            'current_step': first_step.to_dict() if first_step else None,
            'progress': {
                'completed_steps': 0,
                'completion_percentage': 0.0,
                'current_step_index': 0
            }
        }
    
    async def get_current_step(self, user_id: str, wizard_type: WizardType) -> Optional[Dict[str, Any]]:
        """Get current step for user's wizard"""
        wizard = self.wizards.get(wizard_type)
        if not wizard:
            return None
        
        progress = await self.progress_tracker.get_progress(user_id, wizard.flow.flow_id)
        if not progress:
            return None
        
        current_step = wizard.flow.get_step(progress.current_step_id)
        if not current_step:
            return None
        
        return {
            'step': current_step.to_dict(),
            'progress': {
                'completed_steps': len(progress.completed_steps),
                'total_steps': len(wizard.flow.steps),
                'completion_percentage': progress.completion_percentage,
                'step_data': progress.step_data.get(current_step.step_id, {})
            }
        }
    
    async def submit_step_data(self, user_id: str, wizard_type: WizardType, 
                              step_id: str, step_data: Dict[str, Any]) -> Dict[str, Any]:
        """Submit data for current step"""
        wizard = self.wizards.get(wizard_type)
        if not wizard:
            raise ValueError(f"Unknown wizard type: {wizard_type}")
        
        current_step = wizard.flow.get_step(step_id)
        if not current_step:
            raise ValueError(f"Unknown step: {step_id}")
        
        # Validate step data
        validation_result = await self._validate_step_data(current_step, step_data)
        
        if validation_result['valid']:
            # Update progress
            await self.progress_tracker.update_step_progress(
                user_id, wizard.flow.flow_id, step_id, step_data
            )
            
            # Mark step as completed
            await self.progress_tracker.complete_step(user_id, wizard.flow.flow_id, step_id)
            
            # Get next step
            next_step = wizard.flow.get_next_step(step_id, step_data)
            
            # Update completion percentage
            completion_percentage = await self.progress_tracker.calculate_completion_percentage(
                user_id, wizard.flow.flow_id, len(wizard.flow.steps)
            )
            
            # Check if wizard is complete
            if not next_step:
                await self.progress_tracker.complete_onboarding(user_id, wizard.flow.flow_id)
                
                return {
                    'success': True,
                    'completed': True,
                    'completion_percentage': 100.0,
                    'rewards': wizard.flow.completion_rewards
                }
            
            # Update current step
            progress = await self.progress_tracker.get_progress(user_id, wizard.flow.flow_id)
            if progress:
                progress.current_step_id = next_step.step_id
            
            return {
                'success': True,
                'next_step': next_step.to_dict(),
                'completion_percentage': completion_percentage,
                'completed': False
            }
        else:
            return {
                'success': False,
                'validation_errors': validation_result['errors'],
                'warnings': validation_result.get('warnings', [])
            }
    
    async def _validate_step_data(self, step: WizardStep, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate step data against rules"""
        validation_result = {
            'valid': True,
            'errors': [],
            'warnings': []
        }
        
        # Check required fields
        for requirement in step.data_requirements:
            if requirement not in data or not data[requirement]:
                validation_result['valid'] = False
                validation_result['errors'].append(f"Required field missing: {requirement}")
        
        # Apply validation rules
        for rule in step.validation_rules:
            if ':' in rule:
                rule_type, rule_param = rule.split(':', 1)
                
                if rule_type == 'required' and (rule_param not in data or not data[rule_param]):
                    validation_result['valid'] = False
                    validation_result['errors'].append(f"Required field: {rule_param}")
                
                elif rule_type == 'min_length':
                    field, min_len = rule_param.split(':', 1)
                    if field in data and len(str(data[field])) < int(min_len):
                        validation_result['valid'] = False
                        validation_result['errors'].append(f"{field} must be at least {min_len} characters")
                
                elif rule_type == 'validate_seed_phrase':
                    if 'seed_phrase' in data:
                        # Mock seed phrase validation
                        words = data['seed_phrase'].split()
                        if len(words) not in [12, 24]:
                            validation_result['valid'] = False
                            validation_result['errors'].append("Seed phrase must be 12 or 24 words")
        
        return validation_result
    
    async def skip_step(self, user_id: str, wizard_type: WizardType, step_id: str) -> Dict[str, Any]:
        """Skip current step if allowed"""
        wizard = self.wizards.get(wizard_type)
        if not wizard:
            raise ValueError(f"Unknown wizard type: {wizard_type}")
        
        current_step = wizard.flow.get_step(step_id)
        if not current_step or not current_step.skippable:
            return {'success': False, 'error': 'Step cannot be skipped'}
        
        # Mark step as completed (but skipped)
        await self.progress_tracker.update_step_progress(
            user_id, wizard.flow.flow_id, step_id, {'skipped': True}
        )
        
        # Get next step
        next_step = wizard.flow.get_next_step(step_id)
        
        # Update progress
        progress = await self.progress_tracker.get_progress(user_id, wizard.flow.flow_id)
        if progress and next_step:
            progress.current_step_id = next_step.step_id
        
        return {
            'success': True,
            'next_step': next_step.to_dict() if next_step else None,
            'skipped': True
        }
    
    async def get_wizard_progress(self, user_id: str, wizard_type: WizardType) -> Dict[str, Any]:
        """Get detailed progress information"""
        wizard = self.wizards.get(wizard_type)
        if not wizard:
            return {}
        
        progress = await self.progress_tracker.get_progress(user_id, wizard.flow.flow_id)
        if not progress:
            return {}
        
        return {
            'flow_id': wizard.flow.flow_id,
            'flow_name': wizard.flow.name,
            'total_steps': len(wizard.flow.steps),
            'completed_steps': len(progress.completed_steps),
            'current_step_id': progress.current_step_id,
            'completion_percentage': progress.completion_percentage,
            'estimated_time_remaining': progress.estimated_time_remaining,
            'status': progress.status,
            'started_at': progress.started_at,
            'updated_at': progress.updated_at
        }
    
    async def restart_wizard(self, user_id: str, wizard_type: WizardType) -> Dict[str, Any]:
        """Restart wizard from beginning"""
        wizard = self.wizards.get(wizard_type)
        if not wizard:
            raise ValueError(f"Unknown wizard type: {wizard_type}")
        
        # Clear existing progress
        key = f"{user_id}_{wizard.flow.flow_id}"
        if key in self.progress_tracker.progress_data:
            del self.progress_tracker.progress_data[key]
        
        # Start fresh
        return await self.start_wizard(user_id, wizard_type)

# Global setup wizard manager instance
_setup_wizard_manager = None

async def get_setup_wizard_manager() -> SetupWizardManager:
    """Get or create setup wizard manager"""
    global _setup_wizard_manager
    
    if _setup_wizard_manager is None:
        _setup_wizard_manager = SetupWizardManager()
    
    return _setup_wizard_manager

async def initialize_onboarding_system() -> SetupWizardManager:
    """Initialize onboarding system"""
    manager = SetupWizardManager()
    logger.info("Onboarding system initialized with setup wizards")
    return manager