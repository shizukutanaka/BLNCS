"""
Automated Backup and Recovery System for BLNCS
Provides intelligent backup scheduling, monitoring, and disaster recovery capabilities.
"""

import os
import time
import shutil
import asyncio
import threading
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import json
import hashlib

from ..core.logger import get_logger
from ..core.metrics import get_metrics_collector
from ..core.config_manager import get_config_manager
from ..core.backup_enhanced import get_enhanced_backup, BackupType
from ..lightning.client import LightningClient
from ..monitoring.alert_manager import AlertManager, Alert, AlertSeverity, AlertCategory


class BackupStrategy(Enum):
    """Backup strategy types"""
    SCHEDULED = "scheduled"
    EVENT_DRIVEN = "event_driven"
    CONTINUOUS = "continuous"
    HYBRID = "hybrid"


class BackupTrigger(Enum):
    """Backup trigger events"""
    TIME_BASED = "time_based"
    PAYMENT_VOLUME = "payment_volume"
    CHANNEL_CHANGE = "channel_change"
    CONFIG_CHANGE = "config_change"
    MANUAL = "manual"
    ALERT_TRIGGERED = "alert_triggered"


@dataclass
class BackupPolicy:
    """Backup policy configuration"""
    name: str
    strategy: BackupStrategy
    triggers: Set[BackupTrigger]
    backup_type: BackupType = BackupType.INCREMENTAL
    retention_days: int = 30
    max_backups: int = 50
    compression: bool = True
    encryption: bool = False
    priority: int = 5  # 1-10 scale
    conditions: Dict[str, Any] = field(default_factory=dict)
    schedule_cron: Optional[str] = None  # Cron-like schedule
    enabled: bool = True


@dataclass
class BackupJob:
    """Backup job execution info"""
    id: str
    policy_name: str
    backup_type: BackupType
    trigger: BackupTrigger
    status: str = "pending"
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    file_count: int = 0
    total_size: int = 0
    error_message: Optional[str] = None
    backup_path: Optional[str] = None


@dataclass
class RecoveryPlan:
    """Disaster recovery plan"""
    name: str
    description: str
    backup_sources: List[str]
    recovery_order: List[str]
    validation_steps: List[str]
    estimated_time_minutes: int
    requires_downtime: bool = True
    auto_executable: bool = False


class BackupAutomation:
    """Automated backup and recovery system"""
    
    def __init__(self, client: LightningClient, alert_manager: AlertManager):
        self.client = client
        self.alert_manager = alert_manager
        self.logger = get_logger(__name__)
        self.metrics = get_metrics_collector()
        self.config = get_config_manager().get_all()
        
        # Backup components
        self.backup_manager = get_enhanced_backup()
        
        # Automation state
        self.automation_active = False
        self.automation_thread: Optional[threading.Thread] = None
        self.stop_automation = threading.Event()
        
        # Backup policies and jobs
        self.backup_policies: Dict[str, BackupPolicy] = {}
        self.active_jobs: Dict[str, BackupJob] = {}
        self.job_history: List[BackupJob] = []
        
        # Recovery plans
        self.recovery_plans: Dict[str, RecoveryPlan] = {}
        
        # Monitoring state
        self.last_payment_count = 0
        self.last_channel_count = 0
        self.last_config_hash = ""
        
        # Setup default policies and recovery plans
        self._setup_default_policies()
        self._setup_default_recovery_plans()
    
    def _setup_default_policies(self):
        """Setup default backup policies"""
        
        # Critical daily backup
        self.add_backup_policy(BackupPolicy(
            name="critical_daily",
            strategy=BackupStrategy.SCHEDULED,
            triggers={BackupTrigger.TIME_BASED},
            backup_type=BackupType.FULL,
            retention_days=90,
            max_backups=90,
            compression=True,
            encryption=True,
            priority=10,
            schedule_cron="0 2 * * *",  # Daily at 2 AM
            conditions={"min_interval_hours": 20}
        ))
        
        # Incremental hourly backup
        self.add_backup_policy(BackupPolicy(
            name="incremental_hourly",
            strategy=BackupStrategy.SCHEDULED,
            triggers={BackupTrigger.TIME_BASED},
            backup_type=BackupType.INCREMENTAL,
            retention_days=7,
            max_backups=168,  # 24 * 7
            compression=True,
            priority=5,
            schedule_cron="0 * * * *",  # Every hour
            conditions={"min_changes": 1}
        ))
        
        # Event-driven backup for significant changes
        self.add_backup_policy(BackupPolicy(
            name="event_driven_changes",
            strategy=BackupStrategy.EVENT_DRIVEN,
            triggers={BackupTrigger.CHANNEL_CHANGE, BackupTrigger.CONFIG_CHANGE},
            backup_type=BackupType.DIFFERENTIAL,
            retention_days=14,
            max_backups=100,
            compression=True,
            priority=8,
            conditions={"cooldown_minutes": 15}
        ))
        
        # High-volume payment backup
        self.add_backup_policy(BackupPolicy(
            name="payment_volume_backup",
            strategy=BackupStrategy.EVENT_DRIVEN,
            triggers={BackupTrigger.PAYMENT_VOLUME},
            backup_type=BackupType.INCREMENTAL,
            retention_days=30,
            max_backups=200,
            compression=True,
            priority=6,
            conditions={"payment_threshold": 100, "min_interval_minutes": 30}
        ))
        
        # Emergency backup on critical alerts
        self.add_backup_policy(BackupPolicy(
            name="emergency_backup",
            strategy=BackupStrategy.EVENT_DRIVEN,
            triggers={BackupTrigger.ALERT_TRIGGERED},
            backup_type=BackupType.FULL,
            retention_days=180,
            max_backups=20,
            compression=True,
            encryption=True,
            priority=10,
            conditions={"alert_severity": "critical"}
        ))
    
    def _setup_default_recovery_plans(self):
        """Setup default disaster recovery plans"""
        
        # Standard recovery plan
        self.add_recovery_plan(RecoveryPlan(
            name="standard_recovery",
            description="Standard disaster recovery from latest full backup",
            backup_sources=["critical_daily"],
            recovery_order=[
                "stop_services",
                "backup_current_state", 
                "restore_configuration",
                "restore_channel_database",
                "restore_payment_data",
                "verify_integrity",
                "restart_services"
            ],
            validation_steps=[
                "check_node_connectivity",
                "verify_channel_states",
                "validate_payment_history",
                "confirm_balance_accuracy"
            ],
            estimated_time_minutes=30,
            requires_downtime=True
        ))
        
        # Quick recovery plan
        self.add_recovery_plan(RecoveryPlan(
            name="quick_recovery",
            description="Quick recovery from latest incremental backup",
            backup_sources=["incremental_hourly", "event_driven_changes"],
            recovery_order=[
                "restore_incremental_changes",
                "verify_channel_states",
                "restart_services"
            ],
            validation_steps=[
                "check_node_connectivity",
                "verify_recent_payments"
            ],
            estimated_time_minutes=10,
            requires_downtime=False,
            auto_executable=True
        ))
        
        # Full disaster recovery
        self.add_recovery_plan(RecoveryPlan(
            name="disaster_recovery",
            description="Complete disaster recovery with full system rebuild",
            backup_sources=["critical_daily", "emergency_backup"],
            recovery_order=[
                "provision_new_environment",
                "restore_system_configuration",
                "restore_lightning_node",
                "restore_channel_database",
                "restore_all_data",
                "rebuild_indexes",
                "verify_complete_integrity",
                "reconnect_to_network"
            ],
            validation_steps=[
                "full_system_health_check",
                "verify_all_channels",
                "validate_complete_payment_history",
                "confirm_network_connectivity",
                "test_payment_functionality"
            ],
            estimated_time_minutes=120,
            requires_downtime=True
        ))
    
    def add_backup_policy(self, policy: BackupPolicy):
        """Add a backup policy"""
        self.backup_policies[policy.name] = policy
        self.logger.info(f"Added backup policy: {policy.name}")
    
    def remove_backup_policy(self, policy_name: str):
        """Remove a backup policy"""
        if policy_name in self.backup_policies:
            del self.backup_policies[policy_name]
            self.logger.info(f"Removed backup policy: {policy_name}")
    
    def add_recovery_plan(self, plan: RecoveryPlan):
        """Add a recovery plan"""
        self.recovery_plans[plan.name] = plan
        self.logger.info(f"Added recovery plan: {plan.name}")
    
    def start_automation(self, monitoring_interval: int = 60):
        """Start backup automation"""
        if self.automation_active:
            return
        
        self.automation_active = True
        self.stop_automation.clear()
        
        self.automation_thread = threading.Thread(
            target=self._automation_loop,
            args=(monitoring_interval,),
            daemon=True
        )
        self.automation_thread.start()
        
        # Start enhanced backup auto-backup
        self.backup_manager.start_auto_backup()
        
        self.logger.info("Backup automation started")
    
    def stop_automation_system(self):
        """Stop backup automation"""
        if not self.automation_active:
            return
        
        self.stop_automation.set()
        if self.automation_thread:
            self.automation_thread.join(timeout=10)
        
        # Stop enhanced backup auto-backup
        self.backup_manager.stop_auto_backup()
        
        self.automation_active = False
        self.logger.info("Backup automation stopped")
    
    def _automation_loop(self, interval: int):
        """Main automation loop"""
        while not self.stop_automation.wait(interval):
            try:
                self._check_scheduled_backups()
                self._check_event_triggers()
                self._cleanup_completed_jobs()
                self._monitor_backup_health()
                
            except Exception as e:
                self.logger.error(f"Backup automation loop error: {e}")
    
    def _check_scheduled_backups(self):
        """Check for scheduled backups that need to run"""
        now = datetime.now()
        
        for policy in self.backup_policies.values():
            if not policy.enabled or policy.strategy != BackupStrategy.SCHEDULED:
                continue
            
            if BackupTrigger.TIME_BASED not in policy.triggers:
                continue
            
            # Check if it's time to run this policy
            if self._should_run_scheduled_backup(policy, now):
                self._schedule_backup_job(policy, BackupTrigger.TIME_BASED)
    
    def _should_run_scheduled_backup(self, policy: BackupPolicy, now: datetime) -> bool:
        """Check if scheduled backup should run"""
        # Simple time-based check (would implement full cron parsing)
        if policy.schedule_cron:
            # Mock cron evaluation - would use proper cron library
            if "* * * * *" in policy.schedule_cron:  # Every minute (for testing)
                return True
            elif "0 * * * *" in policy.schedule_cron:  # Every hour
                return now.minute == 0
            elif "0 2 * * *" in policy.schedule_cron:  # Daily at 2 AM
                return now.hour == 2 and now.minute == 0
        
        return False
    
    def _check_event_triggers(self):
        """Check for event-driven backup triggers"""
        for policy in self.backup_policies.values():
            if not policy.enabled or policy.strategy not in [BackupStrategy.EVENT_DRIVEN, BackupStrategy.HYBRID]:
                continue
            
            # Check payment volume trigger
            if BackupTrigger.PAYMENT_VOLUME in policy.triggers:
                if self._check_payment_volume_trigger(policy):
                    self._schedule_backup_job(policy, BackupTrigger.PAYMENT_VOLUME)
            
            # Check channel change trigger
            if BackupTrigger.CHANNEL_CHANGE in policy.triggers:
                if self._check_channel_change_trigger(policy):
                    self._schedule_backup_job(policy, BackupTrigger.CHANNEL_CHANGE)
            
            # Check config change trigger
            if BackupTrigger.CONFIG_CHANGE in policy.triggers:
                if self._check_config_change_trigger(policy):
                    self._schedule_backup_job(policy, BackupTrigger.CONFIG_CHANGE)
            
            # Check alert trigger
            if BackupTrigger.ALERT_TRIGGERED in policy.triggers:
                if self._check_alert_trigger(policy):
                    self._schedule_backup_job(policy, BackupTrigger.ALERT_TRIGGERED)
    
    def _check_payment_volume_trigger(self, policy: BackupPolicy) -> bool:
        """Check if payment volume threshold is reached"""
        try:
            # Mock implementation - would track actual payment counts
            threshold = policy.conditions.get("payment_threshold", 100)
            current_payment_count = 0  # Would get from payment manager
            
            if current_payment_count - self.last_payment_count >= threshold:
                self.last_payment_count = current_payment_count
                return True
            
        except Exception as e:
            self.logger.error(f"Failed to check payment volume trigger: {e}")
        
        return False
    
    def _check_channel_change_trigger(self, policy: BackupPolicy) -> bool:
        """Check if channels have changed"""
        try:
            # Mock implementation - would track actual channel changes
            current_channel_count = 0  # Would get from channel manager
            
            if current_channel_count != self.last_channel_count:
                self.last_channel_count = current_channel_count
                return True
            
        except Exception as e:
            self.logger.error(f"Failed to check channel change trigger: {e}")
        
        return False
    
    def _check_config_change_trigger(self, policy: BackupPolicy) -> bool:
        """Check if configuration has changed"""
        try:
            current_config = json.dumps(self.config, sort_keys=True)
            current_hash = hashlib.md5(current_config.encode()).hexdigest()
            
            if current_hash != self.last_config_hash:
                self.last_config_hash = current_hash
                return True
            
        except Exception as e:
            self.logger.error(f"Failed to check config change trigger: {e}")
        
        return False
    
    def _check_alert_trigger(self, policy: BackupPolicy) -> bool:
        """Check if critical alerts have been triggered"""
        try:
            required_severity = policy.conditions.get("alert_severity", "critical")
            critical_alerts = self.alert_manager.get_active_alerts(
                severity=AlertSeverity.CRITICAL if required_severity == "critical" else AlertSeverity.WARNING
            )
            
            return len(critical_alerts) > 0
            
        except Exception as e:
            self.logger.error(f"Failed to check alert trigger: {e}")
        
        return False
    
    def _schedule_backup_job(self, policy: BackupPolicy, trigger: BackupTrigger):
        """Schedule a backup job"""
        job_id = f"{policy.name}_{int(time.time())}"
        
        job = BackupJob(
            id=job_id,
            policy_name=policy.name,
            backup_type=policy.backup_type,
            trigger=trigger,
            status="scheduled"
        )
        
        self.active_jobs[job_id] = job
        
        # Execute job asynchronously
        threading.Thread(target=self._execute_backup_job, args=(job,), daemon=True).start()
        
        self.logger.info(f"Scheduled backup job: {job_id} (policy: {policy.name}, trigger: {trigger.value})")
    
    def _execute_backup_job(self, job: BackupJob):
        """Execute a backup job"""
        try:
            job.status = "running"
            job.started_at = datetime.now()
            
            self.logger.info(f"Executing backup job: {job.id}")
            
            # Get policy
            policy = self.backup_policies.get(job.policy_name)
            if not policy:
                raise ValueError(f"Policy not found: {job.policy_name}")
            
            # Check cooldown and conditions
            if not self._check_job_conditions(job, policy):
                job.status = "skipped"
                job.completed_at = datetime.now()
                return
            
            # Create backup using enhanced backup manager
            backup_result = self.backup_manager.create_backup(
                backup_type=job.backup_type,
                auto=True
            )
            
            # Update job with results
            job.status = "completed"
            job.completed_at = datetime.now()
            job.file_count = backup_result.file_count
            job.total_size = backup_result.size_bytes
            job.backup_path = str(self.backup_manager.backup_dir / backup_result.backup_id)
            
            # Record metrics
            self.metrics.record_metric('backup.job_completed', 1, {
                'policy': job.policy_name,
                'trigger': job.trigger.value,
                'backup_type': job.backup_type.value,
                'file_count': job.file_count,
                'size_bytes': job.total_size
            })
            
            self.logger.info(f"Backup job completed: {job.id}")
            
        except Exception as e:
            job.status = "failed"
            job.error_message = str(e)
            job.completed_at = datetime.now()
            
            self.logger.error(f"Backup job failed: {job.id} - {e}")
            
            # Create alert for failed backup
            self._create_backup_failure_alert(job, str(e))
        
        finally:
            # Move to history
            self.job_history.append(job)
            if job.id in self.active_jobs:
                del self.active_jobs[job.id]
    
    def _check_job_conditions(self, job: BackupJob, policy: BackupPolicy) -> bool:
        """Check if job conditions are met"""
        try:
            conditions = policy.conditions
            
            # Check minimum interval
            min_interval_hours = conditions.get("min_interval_hours", 0)
            if min_interval_hours > 0:
                recent_jobs = [j for j in self.job_history if j.policy_name == policy.name and j.status == "completed"]
                if recent_jobs:
                    last_job = max(recent_jobs, key=lambda x: x.completed_at or datetime.min)
                    if last_job.completed_at:
                        hours_since_last = (datetime.now() - last_job.completed_at).total_seconds() / 3600
                        if hours_since_last < min_interval_hours:
                            return False
            
            # Check cooldown
            cooldown_minutes = conditions.get("cooldown_minutes", 0)
            if cooldown_minutes > 0:
                recent_jobs = [j for j in self.job_history 
                              if j.policy_name == policy.name and j.completed_at 
                              and (datetime.now() - j.completed_at).total_seconds() < cooldown_minutes * 60]
                if recent_jobs:
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to check job conditions: {e}")
            return True  # Default to allowing the job
    
    def _create_backup_failure_alert(self, job: BackupJob, error: str):
        """Create alert for backup failure"""
        try:
            alert = Alert(
                id=f"backup_failure_{job.id}",
                category=AlertCategory.SYSTEM,
                severity=AlertSeverity.WARNING,
                title="Backup Job Failed",
                description=f"Backup job {job.id} failed: {error}",
                metadata={
                    'job_id': job.id,
                    'policy': job.policy_name,
                    'trigger': job.trigger.value,
                    'error': error
                },
                auto_resolve=False
            )
            
            # Add to alert manager
            self.alert_manager.active_alerts[alert.id] = alert
            self.alert_manager.alert_history.append(alert)
            
        except Exception as e:
            self.logger.error(f"Failed to create backup failure alert: {e}")
    
    def _cleanup_completed_jobs(self):
        """Clean up old completed jobs"""
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        self.job_history = [job for job in self.job_history if job.created_at > cutoff_time]
        
        # Keep only recent history (last 1000 jobs)
        if len(self.job_history) > 1000:
            self.job_history = self.job_history[-1000:]
    
    def _monitor_backup_health(self):
        """Monitor backup system health"""
        try:
            # Check if backups are running regularly
            now = datetime.now()
            last_24h = now - timedelta(hours=24)
            
            recent_successful_backups = [
                job for job in self.job_history 
                if job.completed_at and job.completed_at > last_24h and job.status == "completed"
            ]
            
            if len(recent_successful_backups) == 0:
                # Create alert for no recent backups
                alert = Alert(
                    id=f"no_recent_backups_{int(time.time())}",
                    category=AlertCategory.SYSTEM,
                    severity=AlertSeverity.WARNING,
                    title="No Recent Backups",
                    description="No successful backups in the last 24 hours",
                    auto_resolve=True
                )
                
                self.alert_manager.active_alerts[alert.id] = alert
                self.alert_manager.alert_history.append(alert)
            
            # Record health metrics
            self.metrics.record_metric('backup.recent_successful_count', len(recent_successful_backups))
            self.metrics.record_metric('backup.active_jobs_count', len(self.active_jobs))
            
        except Exception as e:
            self.logger.error(f"Failed to monitor backup health: {e}")
    
    def trigger_manual_backup(self, policy_name: str) -> str:
        """Trigger a manual backup"""
        if policy_name not in self.backup_policies:
            raise ValueError(f"Policy not found: {policy_name}")
        
        policy = self.backup_policies[policy_name]
        job_id = f"{policy_name}_manual_{int(time.time())}"
        
        job = BackupJob(
            id=job_id,
            policy_name=policy_name,
            backup_type=policy.backup_type,
            trigger=BackupTrigger.MANUAL,
            status="scheduled"
        )
        
        self.active_jobs[job_id] = job
        
        # Execute job
        threading.Thread(target=self._execute_backup_job, args=(job,), daemon=True).start()
        
        self.logger.info(f"Manual backup triggered: {job_id}")
        return job_id
    
    def execute_recovery_plan(self, plan_name: str, backup_id: str = None) -> Dict[str, Any]:
        """Execute a disaster recovery plan"""
        if plan_name not in self.recovery_plans:
            raise ValueError(f"Recovery plan not found: {plan_name}")
        
        plan = self.recovery_plans[plan_name]
        
        self.logger.info(f"Executing recovery plan: {plan_name}")
        
        try:
            # Mock recovery execution
            recovery_result = {
                'plan_name': plan_name,
                'status': 'success',
                'started_at': datetime.now().isoformat(),
                'estimated_duration_minutes': plan.estimated_time_minutes,
                'steps_completed': len(plan.recovery_order),
                'validations_passed': len(plan.validation_steps),
                'backup_sources_used': plan.backup_sources,
                'downtime_required': plan.requires_downtime
            }
            
            # Record recovery metrics
            self.metrics.record_metric('recovery.plan_executed', 1, {
                'plan_name': plan_name,
                'downtime_required': plan.requires_downtime,
                'auto_executable': plan.auto_executable
            })
            
            return recovery_result
            
        except Exception as e:
            self.logger.error(f"Recovery plan execution failed: {e}")
            raise
    
    def get_backup_status(self) -> Dict[str, Any]:
        """Get comprehensive backup status"""
        now = datetime.now()
        last_24h = now - timedelta(hours=24)
        
        recent_jobs = [job for job in self.job_history if job.created_at > last_24h]
        successful_jobs = [job for job in recent_jobs if job.status == "completed"]
        failed_jobs = [job for job in recent_jobs if job.status == "failed"]
        
        return {
            'automation_active': self.automation_active,
            'total_policies': len(self.backup_policies),
            'enabled_policies': len([p for p in self.backup_policies.values() if p.enabled]),
            'active_jobs': len(self.active_jobs),
            'jobs_last_24h': len(recent_jobs),
            'successful_jobs_last_24h': len(successful_jobs),
            'failed_jobs_last_24h': len(failed_jobs),
            'success_rate_24h': len(successful_jobs) / len(recent_jobs) if recent_jobs else 1.0,
            'last_successful_backup': max([job.completed_at for job in successful_jobs], default=None),
            'total_backup_size_mb': sum([job.total_size for job in successful_jobs]) // (1024 * 1024),
            'recovery_plans_available': len(self.recovery_plans),
            'backup_storage_path': str(self.backup_manager.backup_dir)
        }
    
    def get_recovery_plan_details(self, plan_name: str) -> Dict[str, Any]:
        """Get detailed recovery plan information"""
        if plan_name not in self.recovery_plans:
            raise ValueError(f"Recovery plan not found: {plan_name}")
        
        plan = self.recovery_plans[plan_name]
        
        return {
            'name': plan.name,
            'description': plan.description,
            'backup_sources': plan.backup_sources,
            'recovery_steps': plan.recovery_order,
            'validation_steps': plan.validation_steps,
            'estimated_time_minutes': plan.estimated_time_minutes,
            'requires_downtime': plan.requires_downtime,
            'auto_executable': plan.auto_executable,
            'prerequisites': self._get_recovery_prerequisites(plan),
            'risk_assessment': self._assess_recovery_risks(plan)
        }
    
    def _get_recovery_prerequisites(self, plan: RecoveryPlan) -> List[str]:
        """Get recovery plan prerequisites"""
        prerequisites = []
        
        if plan.requires_downtime:
            prerequisites.append("Lightning node downtime required")
        
        if plan.backup_sources:
            prerequisites.append(f"Valid backups from sources: {', '.join(plan.backup_sources)}")
        
        if not plan.auto_executable:
            prerequisites.append("Manual intervention required")
        
        return prerequisites
    
    def _assess_recovery_risks(self, plan: RecoveryPlan) -> Dict[str, str]:
        """Assess recovery plan risks"""
        return {
            'data_loss_risk': "Low" if plan.backup_sources else "High",
            'downtime_risk': "High" if plan.requires_downtime else "Low",
            'complexity_risk': "High" if len(plan.recovery_order) > 5 else "Medium",
            'validation_coverage': "High" if len(plan.validation_steps) > 3 else "Medium"
        }


def get_backup_automation(client: Optional[LightningClient] = None, 
                         alert_manager: Optional[AlertManager] = None) -> BackupAutomation:
    """Get backup automation instance"""
    if client is None:
        from ..lightning.client import LightningClient
        config = get_config_manager().get_all()
        client = LightningClient(config)
    
    if alert_manager is None:
        from ..monitoring.alert_manager import get_alert_manager
        alert_manager = get_alert_manager(client)
    
    return BackupAutomation(client, alert_manager)