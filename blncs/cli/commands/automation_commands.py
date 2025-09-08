"""
Automation and Scheduling Commands
Practical automation tools for maintenance and monitoring.
"""

import click
import json
import time
import schedule
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional

from ...lightning.client import LightningClient
from ...core.exceptions import format_error_for_cli
from ...core.health import get_health_checker
from ...core.performance_manager import get_performance_manager
from ...core.security_enhanced import get_enhanced_security_manager
from ...core.liquidity_optimizer import get_liquidity_optimizer
from ...core.backup_enhanced import get_enhanced_backup_manager


class AutomationScheduler:
    """Handles scheduled automation tasks"""
    
    def __init__(self):
        self.running = False
        self.thread = None
        self.tasks_file = Path('./automation/scheduled_tasks.json')
        self.tasks_file.parent.mkdir(exist_ok=True)
        
        # Initialize tasks file if not exists
        if not self.tasks_file.exists():
            self._save_tasks({})
    
    def _load_tasks(self) -> Dict[str, Any]:
        """Load scheduled tasks from file"""
        try:
            with open(self.tasks_file, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    
    def _save_tasks(self, tasks: Dict[str, Any]):
        """Save scheduled tasks to file"""
        try:
            with open(self.tasks_file, 'w') as f:
                json.dump(tasks, f, indent=2)
        except Exception as e:
            click.echo(f"Failed to save tasks: {e}")
    
    def start(self):
        """Start the scheduler thread"""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self.thread.start()
        click.echo("🕐 Automation scheduler started")
    
    def stop(self):
        """Stop the scheduler"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        click.echo("🛑 Automation scheduler stopped")
    
    def _run_scheduler(self):
        """Main scheduler loop"""
        while self.running:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
    
    def add_task(self, task_id: str, task_type: str, schedule_spec: str, params: Dict[str, Any]):
        """Add a scheduled task"""
        tasks = self._load_tasks()
        
        tasks[task_id] = {
            'type': task_type,
            'schedule': schedule_spec,
            'params': params,
            'created': datetime.now().isoformat(),
            'last_run': None,
            'run_count': 0,
            'enabled': True
        }
        
        self._save_tasks(tasks)
        self._schedule_task(task_id, task_type, schedule_spec, params)
    
    def _schedule_task(self, task_id: str, task_type: str, schedule_spec: str, params: Dict[str, Any]):
        """Schedule a task with the schedule library"""
        def task_wrapper():
            self._execute_task(task_id, task_type, params)
        
        # Parse schedule specification and create schedule
        if schedule_spec.startswith('every'):
            # Examples: "every 1 hour", "every 30 minutes", "every 1 day"
            parts = schedule_spec.split()
            if len(parts) >= 3:
                interval = int(parts[1])
                unit = parts[2].rstrip('s')  # Remove plural 's'
                
                if unit == 'minute':
                    schedule.every(interval).minutes.do(task_wrapper)
                elif unit == 'hour':
                    schedule.every(interval).hours.do(task_wrapper)
                elif unit == 'day':
                    schedule.every(interval).days.do(task_wrapper)
                elif unit == 'week':
                    schedule.every(interval).weeks.do(task_wrapper)
    
    def _execute_task(self, task_id: str, task_type: str, params: Dict[str, Any]):
        """Execute a scheduled task"""
        try:
            click.echo(f"🔧 Executing task: {task_id} ({task_type})")
            
            if task_type == 'health_check':
                self._run_health_check(params)
            elif task_type == 'backup':
                self._run_backup(params)
            elif task_type == 'cleanup':
                self._run_cleanup(params)
            elif task_type == 'liquidity_check':
                self._run_liquidity_check(params)
            elif task_type == 'security_audit':
                self._run_security_audit(params)
            elif task_type == 'performance_report':
                self._run_performance_report(params)
            
            # Update task statistics
            tasks = self._load_tasks()
            if task_id in tasks:
                tasks[task_id]['last_run'] = datetime.now().isoformat()
                tasks[task_id]['run_count'] += 1
                self._save_tasks(tasks)
            
            click.echo(f"✅ Task completed: {task_id}")
            
        except Exception as e:
            click.echo(f"❌ Task failed: {task_id} - {e}")
    
    def _run_health_check(self, params: Dict[str, Any]):
        """Run automated health check"""
        from .dashboard_commands import health
        
        # This is a simplified version - in practice you'd want to capture results
        try:
            client = LightningClient()
            # Run health check logic here
            health_score = 85  # Placeholder
            
            if health_score < params.get('alert_threshold', 75):
                self._send_alert(f"Health check alert: Score {health_score}/100")
                
        except Exception as e:
            self._send_alert(f"Health check failed: {e}")
    
    def _run_backup(self, params: Dict[str, Any]):
        """Run automated backup"""
        try:
            backup_manager = get_enhanced_backup_manager()
            backup_type = params.get('backup_type', 'incremental')
            
            # Determine backup sources
            sources = params.get('sources', ['./blncs.db', './security/', './config/'])
            
            result = backup_manager.create_backup(backup_type, sources)
            
            if result.get('success'):
                click.echo(f"📦 Backup created: {result.get('backup_file')}")
            else:
                self._send_alert(f"Backup failed: {result.get('error')}")
                
        except Exception as e:
            self._send_alert(f"Backup process failed: {e}")
    
    def _run_cleanup(self, params: Dict[str, Any]):
        """Run automated cleanup"""
        try:
            # Clean old logs
            max_age_days = params.get('log_retention_days', 30)
            cutoff_date = datetime.now() - timedelta(days=max_age_days)
            
            log_files_cleaned = 0
            log_dir = Path('./logs')
            if log_dir.exists():
                for log_file in log_dir.glob('*.log'):
                    if datetime.fromtimestamp(log_file.stat().st_mtime) < cutoff_date:
                        log_file.unlink()
                        log_files_cleaned += 1
            
            # Clean cache
            cache_cleaned = False
            try:
                from ...core.fast_cache import get_fast_cache
                cache = get_fast_cache()
                expired_count = cache.cleanup_expired()
                cache_cleaned = expired_count > 0
            except Exception:
                pass
            
            # Clean database
            db_optimized = False
            try:
                from ...core.storage_optimizer import get_optimized_storage
                storage = get_optimized_storage()
                storage.optimize_database()
                db_optimized = True
            except Exception:
                pass
            
            click.echo(f"🧹 Cleanup completed: {log_files_cleaned} old logs removed, "
                      f"Cache: {'✓' if cache_cleaned else '✗'}, "
                      f"DB optimized: {'✓' if db_optimized else '✗'}")
                      
        except Exception as e:
            self._send_alert(f"Cleanup failed: {e}")
    
    def _run_liquidity_check(self, params: Dict[str, Any]):
        """Run automated liquidity check"""
        try:
            client = LightningClient()
            optimizer = get_liquidity_optimizer(client)
            summary = optimizer.get_liquidity_summary()
            
            if summary.get('status') != 'no_data':
                health_score = summary.get('average_liquidity_score', 0)
                imbalanced = summary.get('imbalanced_channels', 0)
                
                alert_threshold = params.get('health_threshold', 60)
                max_imbalanced = params.get('max_imbalanced_channels', 3)
                
                if health_score < alert_threshold:
                    self._send_alert(f"Liquidity health alert: Score {health_score:.1f}/100")
                
                if imbalanced > max_imbalanced:
                    self._send_alert(f"Too many imbalanced channels: {imbalanced}")
                    
                click.echo(f"💧 Liquidity check: Health {health_score:.1f}/100, "
                          f"Imbalanced: {imbalanced}")
        
        except Exception as e:
            self._send_alert(f"Liquidity check failed: {e}")
    
    def _run_security_audit(self, params: Dict[str, Any]):
        """Run automated security audit"""
        try:
            sm = get_enhanced_security_manager()
            
            # Check for security events
            security_status = sm.get_security_status()
            recent_events = security_status.get('recent_events', 0)
            blocked_ips = security_status.get('temp_blocked_ips', 0)
            
            event_threshold = params.get('event_threshold', 10)
            
            if recent_events > event_threshold:
                self._send_alert(f"High security activity: {recent_events} events in 24h")
            
            if blocked_ips > 0:
                self._send_alert(f"Security notice: {blocked_ips} IPs currently blocked")
            
            click.echo(f"🔒 Security audit: {recent_events} events, {blocked_ips} blocked IPs")
            
        except Exception as e:
            self._send_alert(f"Security audit failed: {e}")
    
    def _run_performance_report(self, params: Dict[str, Any]):
        """Generate automated performance report"""
        try:
            pm = get_performance_manager()
            report = pm.get_performance_report(hours=24)
            
            # Check for performance issues
            system_perf = report.get('system_performance', {})
            cpu_avg = system_perf.get('cpu_usage', {}).get('avg', 0)
            memory_avg = system_perf.get('memory_usage', {}).get('avg', 0)
            
            cpu_threshold = params.get('cpu_alert_threshold', 80)
            memory_threshold = params.get('memory_alert_threshold', 85)
            
            if cpu_avg > cpu_threshold:
                self._send_alert(f"High average CPU usage: {cpu_avg:.1f}%")
            
            if memory_avg > memory_threshold:
                self._send_alert(f"High average memory usage: {memory_avg:.1f}%")
            
            click.echo(f"📊 Performance report: CPU {cpu_avg:.1f}%, Memory {memory_avg:.1f}%")
            
        except Exception as e:
            self._send_alert(f"Performance report failed: {e}")
    
    def _send_alert(self, message: str):
        """Send alert (placeholder for notification system)"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        alert_msg = f"[{timestamp}] ALERT: {message}"
        
        # Write to alert log
        alert_file = Path('./automation/alerts.log')
        try:
            with open(alert_file, 'a') as f:
                f.write(alert_msg + '\n')
        except Exception:
            pass
        
        # Print alert
        click.echo(f"🚨 {alert_msg}")
        
        # Future: Send email, SMS, webhook, etc.
    
    def list_tasks(self) -> Dict[str, Any]:
        """List all scheduled tasks"""
        return self._load_tasks()
    
    def remove_task(self, task_id: str) -> bool:
        """Remove a scheduled task"""
        tasks = self._load_tasks()
        if task_id in tasks:
            del tasks[task_id]
            self._save_tasks(tasks)
            return True
        return False


# Global scheduler instance
_scheduler = None

def get_scheduler() -> AutomationScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = AutomationScheduler()
    return _scheduler


@click.group()
def automation():
    """Automation and scheduling commands"""
    pass


@automation.command()
@click.option('--task-type', type=click.Choice(['health_check', 'backup', 'cleanup', 'liquidity_check', 'security_audit', 'performance_report']),
              required=True, help='Type of task to schedule')
@click.option('--schedule', required=True, help='Schedule specification (e.g., "every 1 hour", "every 30 minutes")')
@click.option('--name', required=True, help='Unique name for the task')
@click.option('--params', help='JSON parameters for the task')
def schedule_task(task_type: str, schedule: str, name: str, params: Optional[str]):
    """Schedule an automated task"""
    
    try:
        # Parse parameters
        task_params = {}
        if params:
            task_params = json.loads(params)
        
        # Add default parameters based on task type
        if task_type == 'health_check':
            task_params.setdefault('alert_threshold', 75)
        elif task_type == 'backup':
            task_params.setdefault('backup_type', 'incremental')
            task_params.setdefault('sources', ['./blncs.db', './security/', './config/'])
        elif task_type == 'cleanup':
            task_params.setdefault('log_retention_days', 30)
        elif task_type == 'liquidity_check':
            task_params.setdefault('health_threshold', 60)
            task_params.setdefault('max_imbalanced_channels', 3)
        elif task_type == 'security_audit':
            task_params.setdefault('event_threshold', 10)
        elif task_type == 'performance_report':
            task_params.setdefault('cpu_alert_threshold', 80)
            task_params.setdefault('memory_alert_threshold', 85)
        
        scheduler = get_scheduler()
        scheduler.add_task(name, task_type, schedule, task_params)
        
        click.echo(f"✅ Scheduled task '{name}' ({task_type}) to run {schedule}")
        
        # Start scheduler if not running
        if not scheduler.running:
            scheduler.start()
    
    except json.JSONDecodeError:
        click.echo("❌ Invalid JSON in parameters", err=True)
    except Exception as e:
        click.echo(format_error_for_cli(e), err=True)


@automation.command()
def list_tasks():
    """List all scheduled tasks"""
    
    scheduler = get_scheduler()
    tasks = scheduler.list_tasks()
    
    if not tasks:
        click.echo("No scheduled tasks found")
        return
    
    click.echo("📅 Scheduled Tasks")
    click.echo("=" * 60)
    
    for task_id, task_info in tasks.items():
        status = "🟢 Enabled" if task_info.get('enabled', True) else "🔴 Disabled"
        last_run = task_info.get('last_run', 'Never')
        if last_run != 'Never':
            last_run = datetime.fromisoformat(last_run).strftime('%Y-%m-%d %H:%M')
        
        click.echo(f"\n📋 Task: {task_id}")
        click.echo(f"   Type: {task_info['type']}")
        click.echo(f"   Schedule: {task_info['schedule']}")
        click.echo(f"   Status: {status}")
        click.echo(f"   Last Run: {last_run}")
        click.echo(f"   Run Count: {task_info.get('run_count', 0)}")


@automation.command()
@click.argument('task_name')
def remove_task(task_name: str):
    """Remove a scheduled task"""
    
    scheduler = get_scheduler()
    
    if scheduler.remove_task(task_name):
        click.echo(f"✅ Removed task '{task_name}'")
    else:
        click.echo(f"❌ Task '{task_name}' not found", err=True)


@automation.command()
def start():
    """Start the automation scheduler"""
    
    scheduler = get_scheduler()
    
    if scheduler.running:
        click.echo("⚠️  Scheduler is already running")
        return
    
    scheduler.start()
    click.echo("🚀 Automation scheduler started")
    
    # Show active tasks
    tasks = scheduler.list_tasks()
    active_tasks = len([t for t in tasks.values() if t.get('enabled', True)])
    click.echo(f"📋 {active_tasks} active tasks scheduled")


@automation.command()
def stop():
    """Stop the automation scheduler"""
    
    scheduler = get_scheduler()
    
    if not scheduler.running:
        click.echo("⚠️  Scheduler is not running")
        return
    
    scheduler.stop()


@automation.command()
def status():
    """Show automation scheduler status"""
    
    scheduler = get_scheduler()
    tasks = scheduler.list_tasks()
    
    click.echo("🤖 Automation Status")
    click.echo("=" * 40)
    
    status_text = "🟢 Running" if scheduler.running else "🔴 Stopped"
    click.echo(f"Scheduler: {status_text}")
    
    total_tasks = len(tasks)
    enabled_tasks = len([t for t in tasks.values() if t.get('enabled', True)])
    
    click.echo(f"Total Tasks: {total_tasks}")
    click.echo(f"Enabled Tasks: {enabled_tasks}")
    
    if tasks:
        # Show next run times (simplified)
        recent_tasks = sorted(tasks.items(), 
                            key=lambda x: x[1].get('last_run', ''), 
                            reverse=True)[:3]
        
        click.echo(f"\n📋 Recent Tasks:")
        for task_id, task_info in recent_tasks:
            last_run = task_info.get('last_run', 'Never')
            if last_run != 'Never':
                last_run = datetime.fromisoformat(last_run).strftime('%m-%d %H:%M')
            
            click.echo(f"  • {task_id}: {task_info['type']} (Last: {last_run})")


@automation.command()
@click.option('--quick', is_flag=True, help='Quick maintenance (essential tasks only)')
def maintenance(quick: bool):
    """Run system maintenance tasks"""
    
    click.echo("🔧 Running System Maintenance")
    click.echo("=" * 50)
    
    maintenance_tasks = []
    
    if not quick:
        maintenance_tasks = [
            ("Database Optimization", "_optimize_database"),
            ("Cache Cleanup", "_cleanup_cache"),
            ("Log Rotation", "_rotate_logs"),
            ("Security Audit", "_security_check"),
            ("Performance Check", "_performance_check"),
            ("Health Check", "_health_check"),
            ("Backup Verification", "_verify_backups")
        ]
    else:
        maintenance_tasks = [
            ("Cache Cleanup", "_cleanup_cache"),
            ("Health Check", "_health_check"),
            ("Security Check", "_security_check")
        ]
    
    results = []
    
    for task_name, task_func in maintenance_tasks:
        click.echo(f"\n🔄 {task_name}...")
        
        try:
            if task_func == "_optimize_database":
                from ...core.storage_optimizer import get_optimized_storage
                storage = get_optimized_storage()
                result = storage.optimize_database()
                success = result.get('optimization_completed', False)
                
            elif task_func == "_cleanup_cache":
                from ...core.fast_cache import get_fast_cache
                cache = get_fast_cache()
                expired_count = cache.cleanup_expired()
                success = True
                
            elif task_func == "_rotate_logs":
                # Simple log rotation
                log_dir = Path('./logs')
                rotated = 0
                if log_dir.exists():
                    for log_file in log_dir.glob('*.log'):
                        if log_file.stat().st_size > 10 * 1024 * 1024:  # 10MB
                            backup_name = f"{log_file.stem}_{int(time.time())}.log"
                            log_file.rename(log_dir / backup_name)
                            rotated += 1
                success = True
                
            elif task_func == "_security_check":
                sm = get_enhanced_security_manager()
                status = sm.get_security_status()
                success = status.get('encryption_available', False)
                
            elif task_func == "_performance_check":
                pm = get_performance_manager()
                current = pm.get_current_performance()
                success = current.get('status') != 'no_data'
                
            elif task_func == "_health_check":
                # Simplified health check
                try:
                    client = LightningClient()
                    client.connect()
                    success = True
                except Exception:
                    success = False
                    
            elif task_func == "_verify_backups":
                backup_dir = Path('./backups')
                recent_backups = 0
                if backup_dir.exists():
                    cutoff = time.time() - (7 * 24 * 3600)  # 7 days
                    recent_backups = len([f for f in backup_dir.iterdir() 
                                        if f.stat().st_mtime > cutoff])
                success = recent_backups > 0
                
            else:
                success = True
            
            if success:
                click.echo(f"   ✅ {task_name} completed")
                results.append((task_name, True, None))
            else:
                click.echo(f"   ⚠️  {task_name} completed with warnings")
                results.append((task_name, False, "Completed with warnings"))
                
        except Exception as e:
            click.echo(f"   ❌ {task_name} failed: {str(e)[:50]}")
            results.append((task_name, False, str(e)))
    
    # Summary
    click.echo(f"\n📊 Maintenance Summary")
    click.echo("-" * 30)
    
    successful = len([r for r in results if r[1]])
    total = len(results)
    
    click.echo(f"Tasks completed: {successful}/{total}")
    
    if successful == total:
        click.echo("🎉 All maintenance tasks completed successfully!")
    else:
        click.echo("⚠️  Some tasks completed with issues:")
        for task_name, success, error in results:
            if not success:
                click.echo(f"  • {task_name}: {error or 'Failed'}")


# Add commands to the main CLI
__all__ = ['automation']