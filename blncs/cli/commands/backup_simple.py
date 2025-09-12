"""
Simple Backup Commands
Basic backup operations without complex dependencies.
"""

import click
import json
import os
import shutil
from datetime import datetime
from pathlib import Path

def get_default_backup_dir():
    """Get default backup directory"""
    home = Path.home()
    backup_dir = home / '.blncs' / 'backups'
    backup_dir.mkdir(parents=True, exist_ok=True)
    return backup_dir

@click.command()
@click.option('--path', help='Backup file path (optional)')
@click.option('--compress', is_flag=True, help='Compress backup')
def create_backup(path, compress):
    """Create a backup of node data"""
    try:
        from ...lightning.client_simple import get_lightning_client
        client = get_lightning_client()
        client.connect()
        
        # Generate backup filename if not provided
        if not path:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_dir = get_default_backup_dir()
            filename = f"blncs_backup_{timestamp}.json"
            if compress:
                filename += '.gz'
            backup_path = backup_dir / filename
        else:
            backup_path = Path(path)
            backup_path.parent.mkdir(parents=True, exist_ok=True)
        
        click.echo(f"💾 Creating backup...")
        click.echo(f"Path: {backup_path}")
        
        # Collect data to backup
        backup_data = {
            'timestamp': datetime.now().isoformat(),
            'version': '1.0.0',
            'node_info': client.get_info(),
            'balance': client.get_balance(),
            'channels': client.list_channels(),
            'network_info': client.get_network_info()
        }
        
        # Add system configuration
        try:
            from ...core.config_manager import get_config_manager
            config = get_config_manager()
            backup_data['config'] = config.get_all()
        except:
            backup_data['config'] = {}
        
        # Write backup file
        if compress and str(backup_path).endswith('.gz'):
            import gzip
            with gzip.open(backup_path, 'wt') as f:
                json.dump(backup_data, f, indent=2)
        else:
            with open(backup_path, 'w') as f:
                json.dump(backup_data, f, indent=2)
        
        # Get file size
        file_size = backup_path.stat().st_size
        size_str = f"{file_size} bytes" if file_size < 1024 else f"{file_size/1024:.1f} KB"
        
        click.echo("✅ Backup created successfully!")
        click.echo(f"Size: {size_str}")
        click.echo(f"Channels: {len(backup_data['channels'])}")
        click.echo(f"Compressed: {'Yes' if compress else 'No'}")
        
    except Exception as e:
        click.echo(f"❌ Backup failed: {e}", err=True)

@click.command()
@click.argument('path')
@click.option('--dry-run', is_flag=True, help='Show what would be restored without doing it')
def restore_backup(path, dry_run):
    """Restore from backup"""
    try:
        backup_path = Path(path)
        
        if not backup_path.exists():
            click.echo(f"❌ Backup file not found: {backup_path}", err=True)
            return
        
        click.echo(f"📂 Reading backup from: {backup_path}")
        
        # Read backup file
        try:
            if str(backup_path).endswith('.gz'):
                import gzip
                with gzip.open(backup_path, 'rt') as f:
                    backup_data = json.load(f)
            else:
                with open(backup_path, 'r') as f:
                    backup_data = json.load(f)
        except Exception as e:
            click.echo(f"❌ Failed to read backup: {e}", err=True)
            return
        
        # Validate backup format
        required_keys = ['timestamp', 'version', 'node_info']
        for key in required_keys:
            if key not in backup_data:
                click.echo(f"❌ Invalid backup format: missing {key}", err=True)
                return
        
        click.echo("📋 Backup Information:")
        click.echo(f"Created: {backup_data['timestamp']}")
        click.echo(f"Version: {backup_data['version']}")
        click.echo(f"Node: {backup_data['node_info'].get('alias', 'Unknown')}")
        click.echo(f"Channels: {len(backup_data.get('channels', []))}")
        
        if dry_run:
            click.echo("\n🔍 DRY RUN - No changes will be made")
            click.echo("Would restore:")
            if 'config' in backup_data:
                click.echo("- Configuration settings")
            if 'channels' in backup_data:
                click.echo(f"- {len(backup_data['channels'])} channel configurations")
            click.echo("\n💡 Remove --dry-run to perform actual restore")
            return
        
        # Confirm restore
        click.echo(f"\n⚠️  This will restore node configuration from backup.")
        if not click.confirm("Continue with restore?"):
            click.echo("Restore cancelled")
            return
        
        # Restore configuration
        restored_items = 0
        
        if 'config' in backup_data and backup_data['config']:
            try:
                from ...core.config_manager import get_config_manager
                config = get_config_manager()
                
                # Restore configuration (be careful with sensitive data)
                safe_config_keys = ['lightning.network', 'system.data_dir', 'logging.level']
                for key in safe_config_keys:
                    if key in backup_data['config']:
                        config.set(key, backup_data['config'][key])
                
                config.save()
                click.echo("✅ Configuration restored")
                restored_items += 1
            except Exception as e:
                click.echo(f"⚠️  Configuration restore failed: {e}")
        
        click.echo(f"\n✅ Restore completed!")
        click.echo(f"Items restored: {restored_items}")
        click.echo("⚠️  Note: Channel states and funds cannot be restored from backup")
        click.echo("    Only configuration and metadata have been restored")
        
    except Exception as e:
        click.echo(f"❌ Restore failed: {e}", err=True)

@click.command()
@click.option('--path', help='Backup directory path')
def list_backups(path):
    """List available backups"""
    try:
        if path:
            backup_dir = Path(path)
        else:
            backup_dir = get_default_backup_dir()
        
        if not backup_dir.exists():
            click.echo("No backup directory found")
            return
        
        click.echo(f"📂 Backups in: {backup_dir}")
        click.echo("=" * 50)
        
        # Find backup files
        backup_files = []
        for ext in ['*.json', '*.json.gz']:
            backup_files.extend(backup_dir.glob(ext))
        
        backup_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        
        if not backup_files:
            click.echo("No backup files found")
            return
        
        for i, backup_file in enumerate(backup_files, 1):
            try:
                # Get file info
                stat = backup_file.stat()
                size = stat.st_size
                size_str = f"{size} bytes" if size < 1024 else f"{size/1024:.1f} KB"
                modified = datetime.fromtimestamp(stat.st_mtime)
                
                # Try to read backup metadata
                try:
                    if str(backup_file).endswith('.gz'):
                        import gzip
                        with gzip.open(backup_file, 'rt') as f:
                            data = json.load(f)
                    else:
                        with open(backup_file, 'r') as f:
                            data = json.load(f)
                    
                    node_alias = data.get('node_info', {}).get('alias', 'Unknown')
                    num_channels = len(data.get('channels', []))
                    backup_time = data.get('timestamp', 'Unknown')
                    
                    click.echo(f"\n{i}. {backup_file.name}")
                    click.echo(f"   Node: {node_alias}")
                    click.echo(f"   Channels: {num_channels}")
                    click.echo(f"   Created: {backup_time}")
                    click.echo(f"   Size: {size_str}")
                    click.echo(f"   Modified: {modified.strftime('%Y-%m-%d %H:%M:%S')}")
                    
                except:
                    click.echo(f"\n{i}. {backup_file.name}")
                    click.echo(f"   Size: {size_str}")
                    click.echo(f"   Modified: {modified.strftime('%Y-%m-%d %H:%M:%S')}")
                    click.echo(f"   Status: ⚠️  Cannot read backup metadata")
                    
            except Exception as e:
                click.echo(f"\n{i}. {backup_file.name} - Error: {e}")
        
        click.echo(f"\nTotal: {len(backup_files)} backup(s)")
        
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)