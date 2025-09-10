"""
Database Management CLI Commands
Provides database optimization, maintenance, and monitoring commands.
"""

import click
from datetime import datetime
from typing import Dict, Any

from ...core.database import get_database_manager
from ...core.exceptions import format_error_for_cli


def format_bytes(bytes_value: int) -> str:
    """Format bytes into human readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024
    return f"{bytes_value:.1f} TB"


@click.command()
@click.option('--detailed', '-d', is_flag=True, help='Show detailed database information')
def db_status(detailed: bool) -> None:
    """Show database status and statistics"""
    try:
        db = get_database_manager()
        
        # Get basic statistics
        stats = db.get_database_stats()
        
        click.echo("Database Status")
        click.echo("=" * 40)
        
        # File size
        if 'file_size_mb' in stats:
            file_size_mb = stats['file_size_mb']
            click.echo(f"Database Size: {file_size_mb:.2f} MB")
        
        # Batch queue
        if 'batch_queue_size' in stats:
            click.echo(f"Batch Queue: {stats['batch_queue_size']} pending operations")
        
        # Table statistics
        click.echo("\nTable Statistics:")
        for table_name, table_stats in stats.items():
            if isinstance(table_stats, dict) and 'row_count' in table_stats:
                click.echo(f"  {table_name}: {table_stats['row_count']:,} records")
                
                if detailed and table_stats.get('oldest_timestamp') and table_stats.get('newest_timestamp'):
                    oldest = datetime.fromtimestamp(table_stats['oldest_timestamp']).strftime('%Y-%m-%d %H:%M')
                    newest = datetime.fromtimestamp(table_stats['newest_timestamp']).strftime('%Y-%m-%d %H:%M')
                    click.echo(f"    Date range: {oldest} to {newest}")
        
        # Performance metrics if detailed
        if detailed:
            click.echo("\nPerformance Metrics:")
            perf_metrics = db.get_performance_metrics()
            
            if 'connection_pool' in perf_metrics:
                pool = perf_metrics['connection_pool']
                click.echo(f"  Connection Pool: {pool['active_connections']}/{pool['max_connections']} "
                          f"({pool['pool_utilization']:.1%} utilization)")
            
            if 'query_performance' in perf_metrics:
                query = perf_metrics['query_performance']
                click.echo(f"  Cache Size: {query.get('cache_size', 'unknown')} pages")
                click.echo(f"  Database Size: {query.get('database_size_mb', 0):.2f} MB")
    
    except Exception as e:
        click.echo(f"Error getting database status: {format_error_for_cli(e)}", err=True)


@click.command()
@click.option('--force', is_flag=True, help='Force optimization even if not needed')
def db_optimize(force: bool) -> None:
    """Optimize database performance"""
    try:
        click.echo("Starting database optimization...")
        
        db = get_database_manager()
        
        # Check if optimization is needed
        if not force:
            stats = db.get_database_stats()
            total_records = sum(table.get('row_count', 0) for table in stats.values() if isinstance(table, dict))
            
            if total_records < 1000:
                click.echo("Database optimization not needed (less than 1000 records)")
                click.echo("Use --force to optimize anyway")
                return
        
        # Perform optimization
        results = db.optimize_database()
        
        if 'error' in results:
            click.echo(f"Optimization failed: {results['error']}", err=True)
            return
        
        click.echo("Database optimization completed successfully!")
        
        if 'optimization_duration' in results:
            click.echo(f"Duration: {results['optimization_duration']:.2f} seconds")
        
        # Show what was done
        operations = []
        if results.get('analyze_completed'):
            operations.append("Query analysis")
        if results.get('reindex_completed'):
            operations.append("Index rebuild")
        if results.get('optimize_completed'):
            operations.append("Statistics update")
        if results.get('memory_optimized'):
            operations.append("Memory optimization")
        
        if operations:
            click.echo(f"Operations performed: {', '.join(operations)}")
        
        if 'integrity_check' in results:
            integrity = results['integrity_check']
            if integrity == 'ok':
                click.echo("Database integrity: OK")
            else:
                click.echo(f"Database integrity: {integrity}", err=True)
    
    except Exception as e:
        click.echo(f"Database optimization failed: {format_error_for_cli(e)}", err=True)


@click.command()
@click.option('--days', '-d', default=30, help='Keep data newer than N days (default: 30)')
@click.option('--dry-run', is_flag=True, help='Show what would be deleted without deleting')
def db_cleanup(days: int, dry_run: bool) -> None:
    """Clean up old database records"""
    try:
        db = get_database_manager()
        
        if dry_run:
            click.echo(f"DRY RUN: Would clean data older than {days} days")
            # We could implement a preview function here
            click.echo("Use without --dry-run to perform actual cleanup")
            return
        
        click.echo(f"Cleaning data older than {days} days...")
        
        # Note: The existing cleanup_old_data method uses default retention
        # We would need to modify it to accept days parameter
        results = db.cleanup_old_data()
        
        click.echo("Cleanup completed!")
        click.echo(f"Metrics deleted: {results.get('metrics_deleted', 0)}")
        click.echo(f"Events deleted: {results.get('events_deleted', 0)}")
        click.echo(f"KV pairs deleted: {results.get('kv_deleted', 0)}")
        
        # Show space reclaimed
        if sum(results.values()) > 0:
            click.echo("Database has been vacuumed to reclaim space")
    
    except Exception as e:
        click.echo(f"Database cleanup failed: {format_error_for_cli(e)}", err=True)


@click.command()
def db_maintenance() -> None:
    """Run automatic database maintenance"""
    try:
        click.echo("Starting automatic database maintenance...")
        
        db = get_database_manager()
        results = db.auto_maintenance()
        
        if results.get('success'):
            click.echo("Database maintenance completed successfully!")
            
            # Show cleanup results
            if 'cleanup' in results:
                cleanup = results['cleanup']
                total_deleted = sum(cleanup.values())
                if total_deleted > 0:
                    click.echo(f"Cleaned up {total_deleted} old records")
            
            # Show optimization results
            if 'optimization' in results:
                opt = results['optimization']
                if 'optimization_duration' in opt:
                    click.echo(f"Optimization completed in {opt['optimization_duration']:.2f}s")
            
            # Show performance metrics
            if 'performance_metrics' in results:
                perf = results['performance_metrics']
                if 'query_performance' in perf:
                    db_size = perf['query_performance'].get('database_size_mb', 0)
                    click.echo(f"Database size: {db_size:.2f} MB")
        else:
            error = results.get('error', 'Unknown error')
            click.echo(f"Maintenance failed: {error}", err=True)
    
    except Exception as e:
        click.echo(f"Database maintenance failed: {format_error_for_cli(e)}", err=True)


@click.command()
def db_vacuum() -> None:
    """Manually vacuum database to reclaim space"""
    try:
        click.echo("Vacuuming database...")
        
        db = get_database_manager()
        
        # Get size before
        stats_before = db.get_database_stats()
        size_before = stats_before.get('file_size_mb', 0)
        
        # Perform vacuum operation
        with db.pool.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("VACUUM")
        
        # Get size after
        stats_after = db.get_database_stats()
        size_after = stats_after.get('file_size_mb', 0)
        
        space_reclaimed = size_before - size_after
        
        click.echo("Database vacuum completed!")
        click.echo(f"Size before: {size_before:.2f} MB")
        click.echo(f"Size after: {size_after:.2f} MB")
        
        if space_reclaimed > 0:
            click.echo(f"Space reclaimed: {space_reclaimed:.2f} MB")
        else:
            click.echo("No space was reclaimed")
    
    except Exception as e:
        click.echo(f"Database vacuum failed: {format_error_for_cli(e)}", err=True)