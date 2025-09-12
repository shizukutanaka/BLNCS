"""
Maintenance Commands for BLNCS
Control automatic maintenance and cleanup tasks.
"""

import click
import time
import json
from typing import Dict, Any

@click.group(name='maintenance')
def maintenance_commands():
    """System maintenance and cleanup"""
    pass

@maintenance_commands.command()
@click.option('--format', '-f', default='table', type=click.Choice(['table', 'json']), help='Output format')
def status(format):
    """Show maintenance task status"""
    try:
        from blncs.core.maintenance import get_maintenance_manager
        
        manager = get_maintenance_manager()
        task_status = manager.get_task_status()
        
        if format == 'json':
            click.echo(json.dumps(task_status, indent=2))
        else:
            click.echo("=== Maintenance Task Status ===")
            click.echo(f"{'Task':<20} {'Status':<8} {'Last Run':<16} {'Runs':<6} {'Errors':<6} {'Next Run':<16}")
            click.echo("-" * 90)
            
            for name, info in task_status.items():
                status_text = "Enabled" if info['enabled'] else "Disabled"
                last_run = info['last_run'][:16] if info['last_run'] else "Never"
                next_run = info['next_run'][:16] if info['next_run'] else "N/A"
                
                click.echo(f"{name:<20} {status_text:<8} {last_run:<16} {info['run_count']:<6} {info['error_count']:<6} {next_run:<16}")
        
    except Exception as e:
        click.echo(f"Error getting maintenance status: {e}")

@maintenance_commands.command()
def start():
    """Start maintenance scheduler"""
    try:
        from blncs.core.maintenance import get_maintenance_manager
        
        manager = get_maintenance_manager()
        manager.start()
        click.echo("✓ Maintenance scheduler started")
        
    except Exception as e:
        click.echo(f"Error starting maintenance: {e}")

@maintenance_commands.command()
def stop():
    """Stop maintenance scheduler"""
    try:
        from blncs.core.maintenance import get_maintenance_manager
        
        manager = get_maintenance_manager()
        manager.stop()
        click.echo("✓ Maintenance scheduler stopped")
        
    except Exception as e:
        click.echo(f"Error stopping maintenance: {e}")

@maintenance_commands.command()
@click.argument('task_name')
def run(task_name):
    """Run a specific maintenance task now"""
    try:
        from blncs.core.maintenance import get_maintenance_manager
        
        manager = get_maintenance_manager()
        
        click.echo(f"Running maintenance task: {task_name}")
        success = manager.run_task_now(task_name)
        
        if success:
            click.echo(f"✓ Task '{task_name}' completed successfully")
        else:
            click.echo(f"✗ Task '{task_name}' failed or not found")
        
    except Exception as e:
        click.echo(f"Error running maintenance task: {e}")

@maintenance_commands.command()
@click.argument('task_name')
def enable(task_name):
    """Enable a maintenance task"""
    try:
        from blncs.core.maintenance import get_maintenance_manager
        
        manager = get_maintenance_manager()
        
        if manager.enable_task(task_name):
            click.echo(f"✓ Task '{task_name}' enabled")
        else:
            click.echo(f"✗ Task '{task_name}' not found")
        
    except Exception as e:
        click.echo(f"Error enabling task: {e}")

@maintenance_commands.command()
@click.argument('task_name')
def disable(task_name):
    """Disable a maintenance task"""
    try:
        from blncs.core.maintenance import get_maintenance_manager
        
        manager = get_maintenance_manager()
        
        if manager.disable_task(task_name):
            click.echo(f"✓ Task '{task_name}' disabled")
        else:
            click.echo(f"✗ Task '{task_name}' not found")
        
    except Exception as e:
        click.echo(f"Error disabling task: {e}")

@maintenance_commands.command()
def cleanup():
    """Run all cleanup tasks manually"""
    try:
        from blncs.core.maintenance import get_maintenance_manager
        
        manager = get_maintenance_manager()
        
        cleanup_tasks = ['cache_cleanup', 'temp_cleanup', 'log_rotation']
        successful_tasks = []
        failed_tasks = []
        
        for task in cleanup_tasks:
            click.echo(f"Running {task}...")
            if manager.run_task_now(task):
                successful_tasks.append(task)
                click.echo(f"  ✓ {task} completed")
            else:
                failed_tasks.append(task)
                click.echo(f"  ✗ {task} failed")
        
        click.echo(f"\nCleanup summary:")
        click.echo(f"  Successful: {len(successful_tasks)}")
        click.echo(f"  Failed: {len(failed_tasks)}")
        
        if failed_tasks:
            click.echo(f"  Failed tasks: {', '.join(failed_tasks)}")
        
    except Exception as e:
        click.echo(f"Error running cleanup: {e}")

@maintenance_commands.command()
@click.option('--force', is_flag=True, help='Force optimization even if recently done')
def optimize():
    """Optimize system performance"""
    try:
        from blncs.core.maintenance import get_maintenance_manager
        
        manager = get_maintenance_manager()
        
        optimization_tasks = ['database_vacuum', 'cache_cleanup']
        click.echo("Running system optimization...")
        
        for task in optimization_tasks:
            click.echo(f"  Running {task}...")
            if manager.run_task_now(task):
                click.echo(f"    ✓ {task} completed")
            else:
                click.echo(f"    ✗ {task} failed")
        
        # Additional optimization steps
        try:
            import gc
            gc.collect()
            click.echo("  ✓ Memory garbage collection completed")
        except Exception:
            pass
        
        click.echo("System optimization completed")
        
    except Exception as e:
        click.echo(f"Error running optimization: {e}")

@maintenance_commands.command()
@click.option('--days', default=7, help='Number of days to keep')
def purge_old(days):
    """Purge old data and files"""
    try:
        from blncs.core.maintenance import get_maintenance_manager
        from pathlib import Path
        import time
        
        manager = get_maintenance_manager()
        cutoff_time = time.time() - (days * 24 * 3600)
        
        click.echo(f"Purging data older than {days} days...")
        
        # Clean old log files
        purged_count = 0
        try:
            logs_dir = Path("logs")
            if logs_dir.exists():
                for log_file in logs_dir.glob("*.log*"):
                    if log_file.stat().st_mtime < cutoff_time:
                        log_file.unlink()
                        purged_count += 1
            click.echo(f"  ✓ Removed {purged_count} old log files")
        except Exception as e:
            click.echo(f"  ✗ Log file cleanup failed: {e}")
        
        # Clean old backup files if they exist
        try:
            backups_dir = Path("backups")
            if backups_dir.exists():
                backup_count = 0
                for backup_file in backups_dir.glob("*.zip"):
                    if backup_file.stat().st_mtime < cutoff_time:
                        backup_file.unlink()
                        backup_count += 1
                click.echo(f"  ✓ Removed {backup_count} old backup files")
        except Exception as e:
            click.echo(f"  ✗ Backup cleanup failed: {e}")
        
        click.echo("Purge operation completed")
        
    except Exception as e:
        click.echo(f"Error purging old data: {e}")

@maintenance_commands.command()
@click.option('--interval', default=60, help='Check interval in seconds')
@click.option('--duration', default=300, help='Monitor duration in seconds')
def monitor(interval, duration):
    """Monitor system maintenance status"""
    try:
        from blncs.core.maintenance import get_maintenance_manager
        import time
        
        manager = get_maintenance_manager()
        
        start_time = time.time()
        click.echo(f"Monitoring maintenance for {duration} seconds (checking every {interval}s)")
        click.echo("Press Ctrl+C to stop early")
        
        try:
            while time.time() - start_time < duration:
                task_status = manager.get_task_status()
                
                click.clear()
                click.echo(f"=== Maintenance Monitor ({time.strftime('%H:%M:%S')}) ===")
                
                active_tasks = sum(1 for info in task_status.values() if info['enabled'])
                total_runs = sum(info['run_count'] for info in task_status.values())
                total_errors = sum(info['error_count'] for info in task_status.values())
                
                click.echo(f"Active Tasks: {active_tasks}/{len(task_status)}")
                click.echo(f"Total Runs: {total_runs}")
                click.echo(f"Total Errors: {total_errors}")
                
                if total_errors > 0:
                    click.echo("\nTasks with Errors:")
                    for name, info in task_status.items():
                        if info['error_count'] > 0:
                            click.echo(f"  {name}: {info['error_count']} errors")
                
                time.sleep(interval)
        
        except KeyboardInterrupt:
            click.echo("\nMonitoring stopped by user")
        
    except Exception as e:
        click.echo(f"Error monitoring maintenance: {e}")

if __name__ == '__main__':
    maintenance_commands()