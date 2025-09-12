"""
System Commands for BLNCS
Essential system status, health checks, and diagnostics.
"""

import click
import time
import psutil
import sys
import os
from pathlib import Path
from typing import Dict, Any

@click.group(name='system')
def system_commands():
    """System management and diagnostics"""
    pass

@system_commands.command()
@click.option('--detailed', '-d', is_flag=True, help='Show detailed information')
def status(detailed):
    """Show system status and health"""
    click.echo("=== BLNCS System Status ===")
    
    # Basic system info
    click.echo(f"Platform: {sys.platform}")
    click.echo(f"Python: {sys.version.split()[0]}")
    click.echo(f"Working Directory: {os.getcwd()}")
    
    # Memory usage
    memory = psutil.virtual_memory()
    click.echo(f"Memory: {memory.percent}% used ({memory.available // 1024 // 1024} MB available)")
    
    # CPU usage
    cpu_percent = psutil.cpu_percent(interval=1)
    click.echo(f"CPU: {cpu_percent}% usage")
    
    # Disk usage
    disk = psutil.disk_usage('.')
    disk_percent = (disk.used / disk.total) * 100
    click.echo(f"Disk: {disk_percent:.1f}% used ({disk.free // 1024 // 1024 // 1024} GB free)")
    
    if detailed:
        click.echo("\n=== Detailed System Information ===")
        
        # Process info
        process = psutil.Process()
        click.echo(f"Process ID: {process.pid}")
        click.echo(f"Process Memory: {process.memory_info().rss // 1024 // 1024} MB")
        click.echo(f"Process CPU: {process.cpu_percent()}%")
        
        # Module count
        click.echo(f"Loaded Modules: {len(sys.modules)}")
        
        # Data directory
        try:
            from blncs.core.config_manager import get_config_manager
            config = get_config_manager()
            data_dir = config.get_data_dir()
            click.echo(f"Data Directory: {data_dir}")
            if data_dir.exists():
                click.echo(f"Data Directory Size: {sum(f.stat().st_size for f in data_dir.rglob('*') if f.is_file()) // 1024 // 1024} MB")
        except Exception as e:
            click.echo(f"Config Error: {e}")

@system_commands.command()
@click.option('--fix', is_flag=True, help='Attempt to fix issues automatically')
def health(fix):
    """Run system health checks"""
    click.echo("=== System Health Check ===")
    
    issues_found = 0
    
    # Check configuration
    click.echo("Checking configuration...")
    try:
        from blncs.core.config_manager import get_config_manager
        config = get_config_manager()
        config_data = config.get_all()
        if config_data:
            click.echo("✓ Configuration loaded successfully")
        else:
            click.echo("✗ Configuration is empty")
            issues_found += 1
    except Exception as e:
        click.echo(f"✗ Configuration error: {e}")
        issues_found += 1
    
    # Check database
    click.echo("Checking database...")
    try:
        from blncs.core.database import get_database
        db = get_database()
        db.execute("SELECT 1")
        click.echo("✓ Database connection working")
    except Exception as e:
        click.echo(f"✗ Database error: {e}")
        issues_found += 1
        if fix:
            click.echo("Attempting database repair...")
            try:
                db = get_database()
                db.execute("PRAGMA integrity_check")
                click.echo("✓ Database repair attempted")
            except Exception as repair_error:
                click.echo(f"✗ Database repair failed: {repair_error}")
    
    # Check cache
    click.echo("Checking cache system...")
    try:
        from blncs.core.cache_unified import get_cache
        cache = get_cache()
        cache.set("health_check", "test", 5)
        if cache.get("health_check") == "test":
            click.echo("✓ Cache system working")
        else:
            click.echo("✗ Cache system not working")
            issues_found += 1
    except Exception as e:
        click.echo(f"✗ Cache error: {e}")
        issues_found += 1
    
    # Check file permissions
    click.echo("Checking file permissions...")
    try:
        test_file = Path("test_permissions.tmp")
        test_file.write_text("test")
        test_file.unlink()
        click.echo("✓ File system permissions OK")
    except Exception as e:
        click.echo(f"✗ File permission error: {e}")
        issues_found += 1
    
    # Summary
    click.echo(f"\nHealth check completed: {issues_found} issues found")
    if issues_found == 0:
        click.echo("✓ System is healthy")
    else:
        click.echo(f"✗ System has {issues_found} issues that need attention")

@system_commands.command()
@click.option('--component', help='Clean specific component (cache, logs, temp)')
@click.option('--dry-run', is_flag=True, help='Show what would be cleaned without doing it')
def cleanup(component, dry_run):
    """Clean up system files and caches"""
    click.echo("=== System Cleanup ===")
    
    cleaned_items = []
    
    if not component or component == 'cache':
        click.echo("Cleaning cache...")
        try:
            from blncs.core.cache_unified import get_cache
            cache = get_cache()
            if not dry_run:
                cache.clear()
                click.echo("✓ Cache cleared")
            else:
                click.echo("Would clear cache")
            cleaned_items.append("cache")
        except Exception as e:
            click.echo(f"✗ Cache cleanup error: {e}")
    
    if not component or component == 'logs':
        click.echo("Cleaning old logs...")
        log_files_cleaned = 0
        try:
            from blncs.core.config_manager import get_config_manager
            config = get_config_manager()
            data_dir = config.get_data_dir()
            logs_dir = data_dir / "logs"
            
            if logs_dir.exists():
                for log_file in logs_dir.glob("*.log*"):
                    if log_file.stat().st_size > 100 * 1024 * 1024:  # Files > 100MB
                        if not dry_run:
                            log_file.unlink()
                        log_files_cleaned += 1
                        
            if log_files_cleaned > 0:
                click.echo(f"{'Would clean' if dry_run else 'Cleaned'} {log_files_cleaned} large log files")
            else:
                click.echo("No large log files to clean")
            cleaned_items.append("logs")
        except Exception as e:
            click.echo(f"✗ Log cleanup error: {e}")
    
    if not component or component == 'temp':
        click.echo("Cleaning temporary files...")
        temp_files_cleaned = 0
        try:
            temp_patterns = ["*.tmp", "*.temp", "*~", ".#*"]
            for pattern in temp_patterns:
                for temp_file in Path(".").glob(pattern):
                    if not dry_run:
                        temp_file.unlink()
                    temp_files_cleaned += 1
            
            if temp_files_cleaned > 0:
                click.echo(f"{'Would clean' if dry_run else 'Cleaned'} {temp_files_cleaned} temporary files")
            else:
                click.echo("No temporary files to clean")
            cleaned_items.append("temp")
        except Exception as e:
            click.echo(f"✗ Temp cleanup error: {e}")
    
    click.echo(f"Cleanup completed for: {', '.join(cleaned_items)}")

@system_commands.command()
def benchmark():
    """Run basic performance benchmarks"""
    click.echo("=== Performance Benchmark ===")
    
    results = {}
    
    # Database performance
    click.echo("Testing database performance...")
    try:
        from blncs.core.database import get_database
        db = get_database()
        
        start_time = time.time()
        for i in range(100):
            db.execute("SELECT ?", (i,))
        db_time = time.time() - start_time
        results['database'] = f"{db_time:.3f}s for 100 queries"
        click.echo(f"Database: {results['database']}")
    except Exception as e:
        click.echo(f"Database benchmark failed: {e}")
    
    # Cache performance
    click.echo("Testing cache performance...")
    try:
        from blncs.core.cache_unified import get_cache
        cache = get_cache()
        
        start_time = time.time()
        for i in range(1000):
            cache.set(f"bench_{i}", f"value_{i}")
        cache_write_time = time.time() - start_time
        
        start_time = time.time()
        for i in range(1000):
            cache.get(f"bench_{i}")
        cache_read_time = time.time() - start_time
        
        results['cache_write'] = f"{cache_write_time:.3f}s for 1000 writes"
        results['cache_read'] = f"{cache_read_time:.3f}s for 1000 reads"
        click.echo(f"Cache Write: {results['cache_write']}")
        click.echo(f"Cache Read: {results['cache_read']}")
    except Exception as e:
        click.echo(f"Cache benchmark failed: {e}")
    
    # Config performance
    click.echo("Testing config performance...")
    try:
        from blncs.core.config_manager import get_config_manager
        
        start_time = time.time()
        for i in range(100):
            config = get_config_manager()
            config.get('lightning.host', 'localhost')
        config_time = time.time() - start_time
        results['config'] = f"{config_time:.3f}s for 100 reads"
        click.echo(f"Config: {results['config']}")
    except Exception as e:
        click.echo(f"Config benchmark failed: {e}")
    
    click.echo("\nBenchmark completed!")

if __name__ == '__main__':
    system_commands()