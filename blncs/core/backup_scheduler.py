"""
Automated Backup Scheduler
Scheduled backup system for Lightning Node data and configuration.
"""

import os
import time
import gzip
import json
import shutil
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import hashlib

from .logger import get_logger
from .config_manager import get_config_manager
from .database import get_database_manager
from .metrics import get_metrics_collector, increment_counter, set_gauge


class BackupType(Enum):
    """Types of backup operations"""
    FULL = "full"
    INCREMENTAL = "incremental"
    CONFIG_ONLY = "config_only"
    DATA_ONLY = "data_only"


@dataclass
class BackupJob:
    """Backup job configuration"""
    name: str
    backup_type: BackupType
    schedule_interval: int  # seconds
    retention_days: int
    enabled: bool = True
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    failure_count: int = 0
    max_failures: int = 3
    
    def should_run(self) -> bool:
        """Check if backup job should run"""
        if not self.enabled or self.failure_count >= self.max_failures:
            return False
        
        if not self.next_run:
            return True
        
        return datetime.now() >= self.next_run
    
    def update_schedule(self):
        """Update next run time"""
        self.last_run = datetime.now()
        self.next_run = self.last_run + timedelta(seconds=self.schedule_interval)


@dataclass
class BackupResult:
    """Result of backup operation"""
    success: bool
    backup_path: Optional[str] = None
    file_size: int = 0
    duration: float = 0
    items_backed_up: int = 0
    error_message: Optional[str] = None
    backup_hash: Optional[str] = None


class AutomatedBackupScheduler:
    """Automated backup scheduler with intelligent retention"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config_manager = get_config_manager()
        self.db = get_database_manager()
        self.metrics = get_metrics_collector()
        
        # Configuration
        self.backup_config = self.config_manager.get('backup', {})
        self.backup_dir = Path(self.backup_config.get('directory', 'backups'))
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Backup jobs
        self.backup_jobs: Dict[str, BackupJob] = {}
        self._initialize_default_jobs()
        
        # Threading
        self.scheduler_thread: Optional[threading.Thread] = None
        self.running = False
        self.lock = threading.RLock()
        
        # Callbacks for custom backup sources
        self.backup_sources: Dict[str, Callable] = {}
        
        # Statistics
        self.total_backups = 0
        self.successful_backups = 0
        self.failed_backups = 0
        self.total_backup_size = 0
        
        self.logger.info(f"Backup scheduler initialized with directory: {self.backup_dir}")
    
    def _initialize_default_jobs(self):
        """Initialize default backup jobs"""
        default_jobs = {
            'daily_full': BackupJob(
                name='daily_full',
                backup_type=BackupType.FULL,
                schedule_interval=24 * 3600,  # Daily
                retention_days=7
            ),
            'hourly_config': BackupJob(
                name='hourly_config',
                backup_type=BackupType.CONFIG_ONLY,
                schedule_interval=3600,  # Hourly
                retention_days=3
            ),
            'weekly_archive': BackupJob(
                name='weekly_archive',
                backup_type=BackupType.FULL,
                schedule_interval=7 * 24 * 3600,  # Weekly
                retention_days=30
            )
        }
        
        # Override with user configuration
        user_jobs = self.backup_config.get('jobs', {})
        for job_name, job_config in user_jobs.items():
            if job_name in default_jobs:
                # Update existing job
                job = default_jobs[job_name]
                job.schedule_interval = job_config.get('interval_hours', job.schedule_interval // 3600) * 3600
                job.retention_days = job_config.get('retention_days', job.retention_days)
                job.enabled = job_config.get('enabled', job.enabled)
            else:
                # Create new job
                default_jobs[job_name] = BackupJob(
                    name=job_name,
                    backup_type=BackupType(job_config.get('type', 'full')),
                    schedule_interval=job_config.get('interval_hours', 24) * 3600,
                    retention_days=job_config.get('retention_days', 7),
                    enabled=job_config.get('enabled', True)
                )
        
        self.backup_jobs = default_jobs
    
    def start(self) -> bool:
        """Start the backup scheduler"""
        if self.running:
            return True
        
        self.running = True
        self.scheduler_thread = threading.Thread(
            target=self._scheduler_loop,
            daemon=True,
            name="BackupScheduler"
        )
        self.scheduler_thread.start()
        
        self.logger.info("Backup scheduler started")
        return True
    
    def stop(self):
        """Stop the backup scheduler"""
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        self.logger.info("Backup scheduler stopped")
    
    def _scheduler_loop(self):
        """Main scheduler loop"""
        while self.running:
            try:
                self._check_and_run_backups()
                self._cleanup_old_backups()
                time.sleep(60)  # Check every minute
            except Exception as e:
                self.logger.error(f"Backup scheduler loop error: {e}")
                time.sleep(60)
    
    def _check_and_run_backups(self):
        """Check and run due backup jobs"""
        with self.lock:
            for job in self.backup_jobs.values():
                if job.should_run():
                    try:
                        self.logger.info(f"Running backup job: {job.name}")
                        result = self._execute_backup_job(job)
                        
                        if result.success:
                            job.failure_count = 0
                            job.update_schedule()
                            self.successful_backups += 1
                            
                            self.logger.info(f"Backup {job.name} completed successfully: {result.backup_path}")
                        else:
                            job.failure_count += 1
                            self.failed_backups += 1
                            
                            self.logger.error(f"Backup {job.name} failed: {result.error_message}")
                        
                        self.total_backups += 1
                        
                        # Record metrics
                        increment_counter('backups_total', {'job': job.name, 'status': 'success' if result.success else 'failed'})
                        if result.file_size > 0:
                            self.total_backup_size += result.file_size
                            set_gauge('backup_total_size_bytes', self.total_backup_size)
                        
                        # Record in database
                        self.db.record_event(
                            event_type='backup_completed',
                            severity='info' if result.success else 'error',
                            message=f"Backup job {job.name} {'completed' if result.success else 'failed'}",
                            details={
                                'job_name': job.name,
                                'backup_type': job.backup_type.value,
                                'file_size': result.file_size,
                                'duration': result.duration,
                                'items_backed_up': result.items_backed_up,
                                'backup_hash': result.backup_hash,
                                'error': result.error_message
                            }
                        )
                        
                    except Exception as e:
                        job.failure_count += 1
                        self.failed_backups += 1
                        self.logger.error(f"Failed to execute backup job {job.name}: {e}")
    
    def _execute_backup_job(self, job: BackupJob) -> BackupResult:
        """Execute a specific backup job"""
        start_time = time.time()
        
        try:
            # Generate backup filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_filename = f"blncs_{job.name}_{timestamp}.json.gz"
            backup_path = self.backup_dir / backup_filename
            
            # Collect data based on backup type
            backup_data = self._collect_backup_data(job.backup_type)
            
            # Compress and save
            with gzip.open(backup_path, 'wt', encoding='utf-8') as f:
                json.dump(backup_data, f, indent=2, default=str)
            
            # Calculate file hash for integrity
            backup_hash = self._calculate_file_hash(backup_path)
            
            # Get file size
            file_size = backup_path.stat().st_size
            duration = time.time() - start_time
            
            return BackupResult(
                success=True,
                backup_path=str(backup_path),
                file_size=file_size,
                duration=duration,
                items_backed_up=self._count_backup_items(backup_data),
                backup_hash=backup_hash
            )
            
        except Exception as e:
            return BackupResult(
                success=False,
                error_message=str(e),
                duration=time.time() - start_time
            )
    
    def _collect_backup_data(self, backup_type: BackupType) -> Dict[str, Any]:
        """Collect data for backup based on type"""
        backup_data = {
            'backup_info': {
                'timestamp': datetime.now().isoformat(),
                'backup_type': backup_type.value,
                'blncs_version': '1.0.0',  # Would come from version file
                'system_info': {
                    'hostname': os.uname().nodename if hasattr(os, 'uname') else 'unknown',
                    'platform': os.name
                }
            }
        }
        
        try:
            if backup_type in [BackupType.FULL, BackupType.CONFIG_ONLY]:
                # Configuration data
                backup_data['configuration'] = self.config_manager.get_all()
            
            if backup_type in [BackupType.FULL, BackupType.DATA_ONLY]:
                # Database data
                backup_data['database_stats'] = self.db.get_database_stats()
                
                # Recent events (last 30 days)
                backup_data['recent_events'] = self.db.get_recent_events(limit=1000)
                
                # Metrics data (last 7 days)
                end_time = int(time.time())
                start_time = end_time - (7 * 24 * 3600)
                backup_data['metrics_sample'] = self.db.get_metrics('system_health', start_time, end_time, limit=100)
            
            if backup_type == BackupType.FULL:
                # Add Lightning node data if available
                try:
                    for source_name, source_func in self.backup_sources.items():
                        backup_data[source_name] = source_func()
                except Exception as e:
                    self.logger.warning(f"Failed to collect custom backup data: {e}")
            
        except Exception as e:
            self.logger.error(f"Error collecting backup data: {e}")
            backup_data['collection_error'] = str(e)
        
        return backup_data
    
    def _count_backup_items(self, backup_data: Dict[str, Any]) -> int:
        """Count items in backup data"""
        count = 0
        for key, value in backup_data.items():
            if key == 'backup_info':
                count += 1
            elif isinstance(value, list):
                count += len(value)
            elif isinstance(value, dict):
                count += len(value)
            else:
                count += 1
        return count
    
    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of backup file"""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def _cleanup_old_backups(self):
        """Clean up old backup files based on retention policies"""
        try:
            for job in self.backup_jobs.values():
                if not job.enabled:
                    continue
                
                cutoff_date = datetime.now() - timedelta(days=job.retention_days)
                pattern = f"blncs_{job.name}_*.json.gz"
                
                old_files = []
                for backup_file in self.backup_dir.glob(pattern):
                    try:
                        # Extract timestamp from filename
                        timestamp_str = backup_file.stem.split('_')[-2:]  # date_time
                        timestamp_str = '_'.join(timestamp_str).replace('.json', '')
                        file_date = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                        
                        if file_date < cutoff_date:
                            old_files.append(backup_file)
                    except (ValueError, IndexError):
                        # Skip files with unexpected naming
                        continue
                
                # Remove old files
                for old_file in old_files:
                    try:
                        old_file.unlink()
                        self.logger.debug(f"Deleted old backup: {old_file.name}")
                    except Exception as e:
                        self.logger.error(f"Failed to delete {old_file}: {e}")
        
        except Exception as e:
            self.logger.error(f"Backup cleanup error: {e}")
    
    def register_backup_source(self, name: str, source_func: Callable) -> bool:
        """Register a custom backup data source"""
        try:
            self.backup_sources[name] = source_func
            self.logger.info(f"Registered backup source: {name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to register backup source {name}: {e}")
            return False
    
    def run_backup_now(self, job_name: str) -> BackupResult:
        """Run a backup job immediately"""
        if job_name not in self.backup_jobs:
            return BackupResult(
                success=False,
                error_message=f"Backup job '{job_name}' not found"
            )
        
        job = self.backup_jobs[job_name]
        self.logger.info(f"Running backup job on demand: {job_name}")
        
        result = self._execute_backup_job(job)
        
        if result.success:
            job.update_schedule()
        
        return result
    
    def create_manual_backup(self, backup_type: BackupType = BackupType.FULL) -> BackupResult:
        """Create a manual backup immediately"""
        manual_job = BackupJob(
            name='manual',
            backup_type=backup_type,
            schedule_interval=0,  # Not scheduled
            retention_days=30,
            enabled=True
        )
        
        self.logger.info(f"Creating manual backup: {backup_type.value}")
        return self._execute_backup_job(manual_job)
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """List available backup files"""
        backups = []
        
        for backup_file in self.backup_dir.glob("blncs_*.json.gz"):
            try:
                file_stat = backup_file.stat()
                
                # Extract job name and timestamp
                parts = backup_file.stem.split('_')
                job_name = parts[1] if len(parts) > 1 else 'unknown'
                timestamp_str = '_'.join(parts[2:]).replace('.json', '')
                
                try:
                    file_date = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                except ValueError:
                    file_date = datetime.fromtimestamp(file_stat.st_mtime)
                
                backups.append({
                    'filename': backup_file.name,
                    'job_name': job_name,
                    'created': file_date.isoformat(),
                    'size_bytes': file_stat.st_size,
                    'size_mb': round(file_stat.st_size / (1024 * 1024), 2),
                    'path': str(backup_file)
                })
            except Exception as e:
                self.logger.warning(f"Error processing backup file {backup_file}: {e}")
        
        # Sort by creation date, newest first
        backups.sort(key=lambda x: x['created'], reverse=True)
        return backups
    
    def restore_backup(self, backup_path: str) -> Dict[str, Any]:
        """Restore from a backup file (returns data, doesn't actually restore)"""
        try:
            backup_file = Path(backup_path)
            
            if not backup_file.exists():
                return {'success': False, 'error': 'Backup file not found'}
            
            # Read and decompress backup
            with gzip.open(backup_file, 'rt', encoding='utf-8') as f:
                backup_data = json.load(f)
            
            return {
                'success': True,
                'backup_data': backup_data,
                'backup_info': backup_data.get('backup_info', {}),
                'items_count': self._count_backup_items(backup_data)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to restore backup {backup_path}: {e}")
            return {'success': False, 'error': str(e)}
    
    def get_backup_stats(self) -> Dict[str, Any]:
        """Get backup scheduler statistics"""
        with self.lock:
            return {
                'total_backups': self.total_backups,
                'successful_backups': self.successful_backups,
                'failed_backups': self.failed_backups,
                'success_rate': (self.successful_backups / self.total_backups) * 100 if self.total_backups > 0 else 0,
                'total_backup_size_mb': round(self.total_backup_size / (1024 * 1024), 2),
                'active_jobs': len([j for j in self.backup_jobs.values() if j.enabled]),
                'failed_jobs': len([j for j in self.backup_jobs.values() if j.failure_count >= j.max_failures]),
                'backup_directory': str(self.backup_dir),
                'next_backup_times': {
                    job.name: job.next_run.isoformat() if job.next_run else None
                    for job in self.backup_jobs.values() if job.enabled
                }
            }
    
    def update_job_schedule(self, job_name: str, interval_hours: int, retention_days: int = None) -> bool:
        """Update backup job schedule"""
        if job_name not in self.backup_jobs:
            return False
        
        job = self.backup_jobs[job_name]
        job.schedule_interval = interval_hours * 3600
        
        if retention_days is not None:
            job.retention_days = retention_days
        
        # Reset next run time
        job.next_run = datetime.now() + timedelta(seconds=job.schedule_interval)
        
        self.logger.info(f"Updated backup job {job_name}: interval={interval_hours}h, retention={job.retention_days}d")
        return True


# Global instance
_backup_scheduler = None

def get_backup_scheduler() -> AutomatedBackupScheduler:
    """Get global backup scheduler instance"""
    global _backup_scheduler
    if _backup_scheduler is None:
        _backup_scheduler = AutomatedBackupScheduler()
    return _backup_scheduler