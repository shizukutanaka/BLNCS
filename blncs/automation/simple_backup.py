"""
Simple Backup Automation
Lightweight backup system for critical BLNCS data.
"""

import os
import shutil
import time
import gzip
import json
import threading
from typing import Dict, List, Any, Optional, Callable
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass, field

from ..core.logger import get_logger
from ..core.config_manager import get_config_manager

logger = get_logger(__name__)

@dataclass
class BackupJob:
    """Backup job configuration."""
    name: str
    source_paths: List[str]
    destination: str
    schedule_hours: int = 24  # Every 24 hours
    compress: bool = True
    max_backups: int = 7  # Keep 7 backups
    enabled: bool = True
    exclude_patterns: List[str] = field(default_factory=list)

@dataclass
class BackupResult:
    """Backup operation result."""
    job_name: str
    success: bool
    start_time: datetime
    end_time: datetime
    files_backed_up: int = 0
    total_size_bytes: int = 0
    error_message: Optional[str] = None
    backup_path: Optional[str] = None

class SimpleBackupManager:
    """Simple backup manager for automated backups."""
    
    def __init__(self, backup_dir: str = "backups"):
        """Initialize backup manager."""
        self.logger = get_logger(__name__)
        self.config_manager = get_config_manager()
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(exist_ok=True, parents=True)
        
        self.jobs: Dict[str, BackupJob] = {}
        self.last_run: Dict[str, datetime] = {}
        self.running = False
        self.scheduler_thread: Optional[threading.Thread] = None
        
        # Default backup jobs
        self._setup_default_jobs()
    
    def _setup_default_jobs(self):
        """Setup default backup jobs."""
        
        # Configuration backup
        self.add_job(BackupJob(
            name="config_backup",
            source_paths=["config/", ".env"],
            destination="config_backups",
            schedule_hours=12,  # Every 12 hours
            max_backups=14  # Keep 2 weeks
        ))
        
        # Data backup  
        self.add_job(BackupJob(
            name="data_backup",
            source_paths=["data/", "logs/"],
            destination="data_backups",
            schedule_hours=6,  # Every 6 hours
            max_backups=28,  # Keep 1 week (4 per day)
            exclude_patterns=["*.tmp", "*.lock", "__pycache__"]
        ))
        
        # Lightning node backup (if exists)
        lightning_paths = [
            "~/.lnd/data/chain/bitcoin/mainnet/channel.backup",
            "~/.lightning/bitcoin/channels_backup"
        ]
        existing_paths = [p for p in lightning_paths if Path(p).expanduser().exists()]
        
        if existing_paths:
            self.add_job(BackupJob(
                name="lightning_backup", 
                source_paths=existing_paths,
                destination="lightning_backups",
                schedule_hours=1,  # Every hour for critical data
                max_backups=168,  # Keep 1 week (24*7)
                compress=True
            ))
    
    def add_job(self, job: BackupJob):
        """Add a backup job."""
        self.jobs[job.name] = job
        self.logger.info(f"Added backup job: {job.name}")
    
    def remove_job(self, job_name: str):
        """Remove a backup job."""
        if job_name in self.jobs:
            del self.jobs[job_name]
            if job_name in self.last_run:
                del self.last_run[job_name]
            self.logger.info(f"Removed backup job: {job_name}")
    
    def _should_run_job(self, job: BackupJob) -> bool:
        """Check if job should run."""
        if not job.enabled:
            return False
        
        if job.name not in self.last_run:
            return True
        
        time_since_last = datetime.now() - self.last_run[job.name]
        return time_since_last.total_seconds() >= job.schedule_hours * 3600
    
    def _get_backup_filename(self, job_name: str) -> str:
        """Generate backup filename."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        extension = ".tar.gz" if self.jobs[job_name].compress else ".tar"
        return f"{job_name}_{timestamp}{extension}"
    
    def _cleanup_old_backups(self, job: BackupJob):
        """Remove old backups to maintain max_backups limit."""
        job_backup_dir = self.backup_dir / job.destination
        if not job_backup_dir.exists():
            return
        
        # Get all backup files for this job
        pattern = f"{job.name}_*.tar*"
        backup_files = list(job_backup_dir.glob(pattern))
        
        # Sort by modification time (newest first)
        backup_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        
        # Remove excess backups
        if len(backup_files) > job.max_backups:
            for old_backup in backup_files[job.max_backups:]:
                try:
                    old_backup.unlink()
                    self.logger.info(f"Removed old backup: {old_backup}")
                except Exception as e:
                    self.logger.error(f"Failed to remove old backup {old_backup}: {e}")
    
    def _create_backup_archive(self, job: BackupJob, backup_path: Path) -> BackupResult:
        """Create backup archive for a job."""
        start_time = datetime.now()
        files_backed_up = 0
        total_size = 0
        
        try:
            import tarfile
            
            mode = "w:gz" if job.compress else "w"
            with tarfile.open(backup_path, mode) as tar:
                for source_path in job.source_paths:
                    source = Path(source_path).expanduser()
                    
                    if not source.exists():
                        self.logger.warning(f"Source path does not exist: {source}")
                        continue
                    
                    if source.is_file():
                        # Backup single file
                        if not self._should_exclude_file(source, job.exclude_patterns):
                            tar.add(source, arcname=source.name)
                            files_backed_up += 1
                            total_size += source.stat().st_size
                            
                    elif source.is_dir():
                        # Backup directory recursively
                        for file_path in source.rglob("*"):
                            if file_path.is_file() and not self._should_exclude_file(file_path, job.exclude_patterns):
                                # Calculate relative path to preserve directory structure
                                rel_path = file_path.relative_to(source.parent)
                                tar.add(file_path, arcname=rel_path)
                                files_backed_up += 1
                                total_size += file_path.stat().st_size
            
            end_time = datetime.now()
            
            return BackupResult(
                job_name=job.name,
                success=True,
                start_time=start_time,
                end_time=end_time,
                files_backed_up=files_backed_up,
                total_size_bytes=total_size,
                backup_path=str(backup_path)
            )
            
        except Exception as e:
            end_time = datetime.now()
            self.logger.error(f"Backup failed for job {job.name}: {e}")
            
            # Clean up failed backup file
            if backup_path.exists():
                try:
                    backup_path.unlink()
                except:
                    pass
            
            return BackupResult(
                job_name=job.name,
                success=False,
                start_time=start_time,
                end_time=end_time,
                error_message=str(e)
            )
    
    def _should_exclude_file(self, file_path: Path, exclude_patterns: List[str]) -> bool:
        """Check if file should be excluded based on patterns."""
        import fnmatch
        
        filename = file_path.name
        file_str = str(file_path)
        
        for pattern in exclude_patterns:
            if fnmatch.fnmatch(filename, pattern) or fnmatch.fnmatch(file_str, pattern):
                return True
        
        return False
    
    def run_backup(self, job_name: str) -> BackupResult:
        """Run a specific backup job."""
        if job_name not in self.jobs:
            raise ValueError(f"Backup job not found: {job_name}")
        
        job = self.jobs[job_name]
        self.logger.info(f"Starting backup job: {job_name}")
        
        # Create destination directory
        job_backup_dir = self.backup_dir / job.destination
        job_backup_dir.mkdir(exist_ok=True, parents=True)
        
        # Create backup
        backup_filename = self._get_backup_filename(job_name)
        backup_path = job_backup_dir / backup_filename
        
        result = self._create_backup_archive(job, backup_path)
        
        if result.success:
            self.last_run[job_name] = datetime.now()
            self.logger.info(
                f"Backup completed for {job_name}: "
                f"{result.files_backed_up} files, "
                f"{result.total_size_bytes / (1024*1024):.2f} MB"
            )
            
            # Cleanup old backups
            self._cleanup_old_backups(job)
        else:
            self.logger.error(f"Backup failed for {job_name}: {result.error_message}")
        
        return result
    
    def run_all_backups(self) -> Dict[str, BackupResult]:
        """Run all enabled backup jobs."""
        results = {}
        
        for job_name, job in self.jobs.items():
            if job.enabled:
                try:
                    results[job_name] = self.run_backup(job_name)
                except Exception as e:
                    self.logger.error(f"Failed to run backup job {job_name}: {e}")
                    results[job_name] = BackupResult(
                        job_name=job_name,
                        success=False,
                        start_time=datetime.now(),
                        end_time=datetime.now(),
                        error_message=str(e)
                    )
        
        return results
    
    def run_scheduled_backups(self) -> Dict[str, BackupResult]:
        """Run backup jobs that are scheduled to run."""
        results = {}
        
        for job_name, job in self.jobs.items():
            if self._should_run_job(job):
                try:
                    results[job_name] = self.run_backup(job_name)
                except Exception as e:
                    self.logger.error(f"Scheduled backup failed for {job_name}: {e}")
                    results[job_name] = BackupResult(
                        job_name=job_name,
                        success=False,
                        start_time=datetime.now(),
                        end_time=datetime.now(),
                        error_message=str(e)
                    )
        
        return results
    
    def start_scheduler(self, check_interval: int = 3600):
        """Start the backup scheduler."""
        if self.running:
            self.logger.warning("Backup scheduler is already running")
            return
        
        self.running = True
        
        def scheduler_loop():
            self.logger.info("Backup scheduler started")
            
            while self.running:
                try:
                    results = self.run_scheduled_backups()
                    if results:
                        success_count = sum(1 for r in results.values() if r.success)
                        total_count = len(results)
                        self.logger.info(
                            f"Scheduled backups completed: "
                            f"{success_count}/{total_count} successful"
                        )
                except Exception as e:
                    self.logger.error(f"Error in backup scheduler: {e}")
                
                # Wait for next check
                time.sleep(check_interval)
            
            self.logger.info("Backup scheduler stopped")
        
        self.scheduler_thread = threading.Thread(target=scheduler_loop, daemon=True)
        self.scheduler_thread.start()
    
    def stop_scheduler(self):
        """Stop the backup scheduler."""
        if not self.running:
            return
        
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        
        self.logger.info("Backup scheduler stopped")
    
    def get_backup_status(self) -> Dict[str, Any]:
        """Get status of all backup jobs."""
        status = {
            "total_jobs": len(self.jobs),
            "enabled_jobs": sum(1 for job in self.jobs.values() if job.enabled),
            "jobs": {}
        }
        
        for job_name, job in self.jobs.items():
            last_run = self.last_run.get(job_name)
            next_run = None
            
            if last_run:
                next_run = last_run + timedelta(hours=job.schedule_hours)
            
            status["jobs"][job_name] = {
                "enabled": job.enabled,
                "schedule_hours": job.schedule_hours,
                "max_backups": job.max_backups,
                "last_run": last_run.isoformat() if last_run else None,
                "next_run": next_run.isoformat() if next_run else "overdue",
                "should_run": self._should_run_job(job)
            }
        
        return status
    
    def restore_backup(self, backup_path: str, restore_to: str) -> bool:
        """Restore from a backup file."""
        try:
            import tarfile
            
            backup_file = Path(backup_path)
            if not backup_file.exists():
                raise FileNotFoundError(f"Backup file not found: {backup_path}")
            
            restore_dir = Path(restore_to)
            restore_dir.mkdir(exist_ok=True, parents=True)
            
            with tarfile.open(backup_file, "r:*") as tar:
                tar.extractall(path=restore_dir)
            
            self.logger.info(f"Backup restored from {backup_path} to {restore_to}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to restore backup {backup_path}: {e}")
            return False

# Global backup manager instance
_backup_manager: Optional[SimpleBackupManager] = None

def get_backup_manager() -> SimpleBackupManager:
    """Get global backup manager instance."""
    global _backup_manager
    if _backup_manager is None:
        _backup_manager = SimpleBackupManager()
    return _backup_manager

if __name__ == "__main__":
    # Test the backup system
    backup_manager = SimpleBackupManager("test_backups")
    
    # Run a test backup
    if backup_manager.jobs:
        first_job = next(iter(backup_manager.jobs.keys()))
        result = backup_manager.run_backup(first_job)
        print(f"Backup result: {result.success}")
        
        # Print status
        status = backup_manager.get_backup_status()
        print(f"Backup status: {json.dumps(status, indent=2, default=str)}")