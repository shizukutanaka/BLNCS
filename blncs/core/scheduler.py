#!/usr/bin/env python3
"""
BLNCS Automation Scheduler
Lightweight background task scheduler for automated operations
"""

import time
import threading
import schedule
from typing import Dict, List, Any, Callable, Optional
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class AutomationScheduler:
    """
    Lightweight automation scheduler for BLNCS operations
    """

    def __init__(self):
        self.jobs: Dict[str, schedule.Job] = {}
        self.running = False
        self.thread = None
        self._lock = threading.RLock()

    def start(self):
        """Start the automation scheduler"""
        if self.running:
            return

        self.running = True
        self.thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.thread.start()
        logger.info("Automation scheduler started")

    def stop(self):
        """Stop the automation scheduler"""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
        logger.info("Automation scheduler stopped")

    def _run_scheduler(self):
        """Main scheduler loop"""
        while self.running:
            try:
                schedule.run_pending()
                time.sleep(60)  # Check every minute
            except Exception as e:
                logger.error(f"Scheduler error: {e}")
                time.sleep(300)  # Wait 5 minutes on error

    def add_health_check(self, interval_hours: int = 1):
        """Add automated health check"""
        def health_check_job():
            try:
                logger.info("Running automated health check")

                # Import here to avoid circular imports
                from blncs.core.config import get_config
                from blncs.core.lightweight_metrics import get_metrics_collector

                config = get_config()
                collector = get_metrics_collector()

                # Run health checks
                issues = []
                warnings = []

                # Check system resources
                current = collector.get_current_metrics()
                if current:
                    cpu_percent = current.get('cpu', {}).get('percent', 0)
                    memory_percent = current.get('memory', {}).get('percent', 0)
                    disk_percent = current.get('disk', {}).get('percent', 0)

                    if cpu_percent > 85:
                        issues.append(f"High CPU usage: {cpu_percent:.1f}%")
                    elif cpu_percent > 70:
                        warnings.append(f"Elevated CPU usage: {cpu_percent:.1f}%")

                    if memory_percent > 90:
                        issues.append(f"Critical memory usage: {memory_percent:.1f}%")
                    elif memory_percent > 80:
                        warnings.append(f"High memory usage: {memory_percent:.1f}%")

                    if disk_percent > 95:
                        issues.append(f"Critical disk usage: {disk_percent:.1f}%")
                    elif disk_percent > 85:
                        warnings.append(f"High disk usage: {disk_percent:.1f}%")

                # Check Lightning connection
                try:
                    from blncs.lightning.simple_client import get_lightning_client
                    lightning = get_lightning_client()
                    if not lightning.connect():
                        warnings.append("Lightning Network connection failed")
                    lightning.disconnect()
                except Exception as e:
                    warnings.append(f"Lightning check failed: {e}")

                # Log results
                if issues:
                    logger.warning(f"Health check found {len(issues)} issues: {', '.join(issues)}")
                if warnings:
                    logger.info(f"Health check found {len(warnings)} warnings: {', '.join(warnings)}")

                if not issues and not warnings:
                    logger.info("Health check passed - all systems normal")

            except Exception as e:
                logger.error(f"Automated health check failed: {e}")

        job_id = f"health_check_{interval_hours}h"
        self.jobs[job_id] = schedule.every(interval_hours).hours.do(health_check_job)
        logger.info(f"Added automated health check every {interval_hours} hours")

    def add_metrics_collection(self, interval_minutes: int = 30):
        """Add automated metrics collection"""
        def metrics_job():
            try:
                logger.info("Running automated metrics collection")

                from blncs.core.lightweight_metrics import get_metrics_collector
                collector = get_metrics_collector()

                # Ensure collection is running
                if not collector._running:
                    collector.start_collection()

                # Export metrics summary
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"metrics_auto_{timestamp}.json"

                collector.export_metrics(filename)
                logger.info(f"Metrics exported to {filename}")

            except Exception as e:
                logger.error(f"Automated metrics collection failed: {e}")

        job_id = f"metrics_{interval_minutes}min"
        self.jobs[job_id] = schedule.every(interval_minutes).minutes.do(metrics_job)
        logger.info(f"Added automated metrics collection every {interval_minutes} minutes")

    def add_backup_task(self, interval_hours: int = 24):
        """Add automated backup task"""
        def backup_job():
            try:
                logger.info("Running automated backup")

                from blncs.core.config import get_config
                config = get_config()

                # Create backup
                from blncs.utils.simple_backup_recovery import auto_backup
                import os
                from pathlib import Path

                # Get backup paths from config
                db_path = config.get('database.path', 'data/blncs.db')
                backup_root = config.get('backup.destination', 'backups')

                # Ensure backup directory exists
                Path(backup_root).mkdir(exist_ok=True)

                if Path(db_path).exists():
                    backups = auto_backup(
                        include_paths=[db_path],
                        backup_root=backup_root,
                        backup_type='auto'
                    )

                    if backups:
                        logger.info(f"Automated backup created: {backups[0].path}")
                    else:
                        logger.warning("Automated backup failed - no backups created")
                else:
                    logger.warning(f"Database not found for backup: {db_path}")

            except Exception as e:
                logger.error(f"Automated backup failed: {e}")

        job_id = f"backup_{interval_hours}h"
        self.jobs[job_id] = schedule.every(interval_hours).hours.do(backup_job)
        logger.info(f"Added automated backup every {interval_hours} hours")

    def add_log_rotation(self, interval_hours: int = 24):
        """Add automated log rotation"""
        def rotation_job():
            try:
                logger.info("Running automated log rotation")

                from blncs.core.unified_logging import get_log_manager
                log_manager = get_log_manager()

                # Rotate main log
                if hasattr(log_manager, 'rotate_log'):
                    log_manager.rotate_log()
                    logger.info("Log rotation completed")
                else:
                    logger.info("Log rotation not available")

            except Exception as e:
                logger.error(f"Automated log rotation failed: {e}")

        job_id = f"log_rotation_{interval_hours}h"
        self.jobs[job_id] = schedule.every(interval_hours).hours.do(rotation_job)
        logger.info(f"Added automated log rotation every {interval_hours} hours")

    def add_config_backup(self, interval_hours: int = 24):
        """Add automated configuration backup"""
        def config_backup_job():
            try:
                logger.info("Running automated config backup")

                from blncs.core.config import get_config
                config = get_config()

                # Create config backup
                backup_path = config.create_backup()
                logger.info(f"Configuration backup created: {backup_path}")

            except Exception as e:
                logger.error(f"Automated config backup failed: {e}")

        job_id = f"config_backup_{interval_hours}h"
        self.jobs[job_id] = schedule.every(interval_hours).hours.do(config_backup_job)
        logger.info(f"Added automated config backup every {interval_hours} hours")

    def remove_job(self, job_id: str):
        """Remove a scheduled job"""
        if job_id in self.jobs:
            schedule.cancel_job(self.jobs[job_id])
            del self.jobs[job_id]
            logger.info(f"Removed automated job: {job_id}")
            return True
        return False

    def list_jobs(self) -> List[Dict[str, Any]]:
        """List all scheduled jobs"""
        jobs_info = []

        for job_id, job in self.jobs.items():
            job_info = {
                'id': job_id,
                'next_run': str(job.next_run) if job.next_run else None,
                'enabled': True
            }
            jobs_info.append(job_info)

        return jobs_info

    def enable_default_schedule(self):
        """Enable default automation schedule"""
        # Health checks every hour
        self.add_health_check(interval_hours=1)

        # Metrics collection every 30 minutes
        self.add_metrics_collection(interval_minutes=30)

        # Database backup daily
        self.add_backup_task(interval_hours=24)

        # Log rotation daily
        self.add_log_rotation(interval_hours=24)

        # Config backup daily
        self.add_config_backup(interval_hours=24)

        logger.info("Default automation schedule enabled")

    def __repr__(self) -> str:
        return f"AutomationScheduler(jobs={len(self.jobs)}, running={self.running})"


# Global scheduler instance
_scheduler = None

def get_scheduler() -> AutomationScheduler:
    """Get global automation scheduler instance"""
    global _scheduler
    if _scheduler is None:
        _scheduler = AutomationScheduler()
    return _scheduler

def start_automation():
    """Start the automation system"""
    scheduler = get_scheduler()
    scheduler.enable_default_schedule()
    scheduler.start()

def stop_automation():
    """Stop the automation system"""
    scheduler = get_scheduler()
    scheduler.stop()

__all__ = [
    'AutomationScheduler',
    'get_scheduler',
    'start_automation',
    'stop_automation'
]
