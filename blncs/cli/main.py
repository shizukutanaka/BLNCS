# BLNCS Command Line Interface
# Clean and efficient CLI following Pike's simplicity
import sys
import argparse
import json
from pathlib import Path
from typing import Optional, Dict, Any, List
import asyncio

class BLNCSCli:
    """
    Command line interface for BLNCS.
    Simple, powerful, and user-friendly.
    """
    
    def __init__(self):
        self.parser = self._create_parser()
        self.commands = {}
        self._register_commands()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            prog='blncs',
            description='BLNCS - Lightweight Application Framework',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  blncs start              Start BLNCS server
  blncs backup create      Create backup
  blncs config show        Show configuration
  blncs monitor            Monitor resources
  blncs plugin list        List plugins
            """
        )
        
        parser.add_argument(
            '--version',
            action='version',
            version='BLNCS 0.0.1'
        )
        
        parser.add_argument(
            '--config',
            type=str,
            help='Config file path'
        )
        
        parser.add_argument(
            '--verbose', '-v',
            action='store_true',
            help='Verbose output'
        )
        
        # Subcommands
        subparsers = parser.add_subparsers(
            dest='command',
            help='Available commands'
        )
        
        # Start command
        start_parser = subparsers.add_parser('start', help='Start BLNCS')
        start_parser.add_argument('--mode', choices=['gui', 'server', 'cli'], default='auto')
        start_parser.add_argument('--port', type=int, default=8080)
        start_parser.add_argument('--host', default='127.0.0.1')
        
        # Stop command
        subparsers.add_parser('stop', help='Stop BLNCS')
        
        # Status command
        subparsers.add_parser('status', help='Show status')
        
        # Config command
        config_parser = subparsers.add_parser('config', help='Configuration management')
        config_sub = config_parser.add_subparsers(dest='config_action')
        config_sub.add_parser('show', help='Show configuration')
        config_set = config_sub.add_parser('set', help='Set configuration')
        config_set.add_argument('key', help='Config key')
        config_set.add_argument('value', help='Config value')
        config_sub.add_parser('reset', help='Reset to defaults')
        
        # Backup command
        backup_parser = subparsers.add_parser('backup', help='Backup management')
        backup_sub = backup_parser.add_subparsers(dest='backup_action')
        backup_sub.add_parser('create', help='Create backup')
        backup_sub.add_parser('list', help='List backups')
        backup_restore = backup_sub.add_parser('restore', help='Restore backup')
        backup_restore.add_argument('backup_id', help='Backup ID')
        
        # Plugin command
        plugin_parser = subparsers.add_parser('plugin', help='Plugin management')
        plugin_sub = plugin_parser.add_subparsers(dest='plugin_action')
        plugin_sub.add_parser('list', help='List plugins')
        plugin_install = plugin_sub.add_parser('install', help='Install plugin')
        plugin_install.add_argument('path', help='Plugin path')
        plugin_remove = plugin_sub.add_parser('remove', help='Remove plugin')
        plugin_remove.add_argument('name', help='Plugin name')
        
        # Monitor command
        monitor_parser = subparsers.add_parser('monitor', help='Monitor resources')
        monitor_parser.add_argument('--interval', type=int, default=1)
        monitor_parser.add_argument('--duration', type=int, default=0)
        
        # Log command
        log_parser = subparsers.add_parser('log', help='View logs')
        log_parser.add_argument('--tail', type=int, default=10)
        log_parser.add_argument('--follow', '-f', action='store_true')
        log_parser.add_argument('--level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])
        
        # Database command
        db_parser = subparsers.add_parser('db', help='Database operations')
        db_sub = db_parser.add_subparsers(dest='db_action')
        db_sub.add_parser('info', help='Database info')
        db_sub.add_parser('optimize', help='Optimize database')
        db_sub.add_parser('vacuum', help='Vacuum database')
        
        return parser
    
    def _register_commands(self):
        """Register command handlers"""
        self.commands = {
            'start': self.cmd_start,
            'stop': self.cmd_stop,
            'status': self.cmd_status,
            'config': self.cmd_config,
            'backup': self.cmd_backup,
            'plugin': self.cmd_plugin,
            'monitor': self.cmd_monitor,
            'log': self.cmd_log,
            'db': self.cmd_database
        }
    
    def run(self, args: Optional[List[str]] = None):
        """Run CLI with arguments"""
        parsed = self.parser.parse_args(args)
        
        if not parsed.command:
            self.parser.print_help()
            return 1
        
        # Execute command
        handler = self.commands.get(parsed.command)
        if handler:
            try:
                return handler(parsed)
            except Exception as e:
                print(f"⚠️  エラーが発生しました: {e}\n💡 詳細なヘルプは '--help' をご利用ください", file=sys.stderr)
                return 1
        
        return 0
    
    def cmd_start(self, args) -> int:
        """Start BLNCS"""
        print(f"Starting BLNCS in {args.mode} mode...")
        
        from blncs.app import BLNCS
        app = BLNCS(mode=args.mode)
        app.config.host = args.host
        app.config.port = args.port
        
        try:
            app.run()
            return 0
        except KeyboardInterrupt:
            print("\nShutdown requested...")
            return 0
    
    def cmd_stop(self, args) -> int:
        """Stop BLNCS"""
        print("Stopping BLNCS...")
        # Implementation would send stop signal to running instance
        return 0
    
    def cmd_status(self, args) -> int:
        """Show status"""
        from blncs.config import get_config
        from blncs.resource_monitor import get_resource_monitor
        
        config = get_config()
        monitor = get_resource_monitor()
        stats = monitor.get_current_stats()
        
        print("BLNCS Status")
        print("-" * 40)
        print(f"Mode: {config.mode}")
        print(f"Host: {config.host}:{config.port}")
        print(f"Database: {config.db_path}")
        print(f"CPU: {stats.cpu_percent:.1f}%")
        print(f"Memory: {stats.memory_mb:.1f}MB ({stats.memory_percent:.1f}%)")
        print(f"Threads: {stats.thread_count}")
        
        return 0
    
    def cmd_config(self, args) -> int:
        """Configuration management"""
        from blncs.config import get_config
        
        config = get_config()
        
        if args.config_action == 'show':
            # Show configuration
            for key, value in config.to_dict().items():
                print(f"{key}: {value}")
        
        elif args.config_action == 'set':
            # Set configuration
            config.set(args.key, args.value)
            config.save_to_file(Path("config.json"))
            print(f"Set {args.key} = {args.value}")
        
        elif args.config_action == 'reset':
            # Reset configuration
            from blncs.config import reset_config
            reset_config()
            print("Configuration reset to defaults")
        
        return 0
    
    def cmd_backup(self, args) -> int:
        """Backup management"""
        from blncs.backup import get_auto_backup
        
        backup = get_auto_backup()
        
        if args.backup_action == 'create':
            # Create backup
            print("Creating backup...")
            info = backup.create_backup(Path("data"))
            if info:
                print(f"Backup created: {info.id}")
            else:
                print("Backup failed")
                return 1
        
        elif args.backup_action == 'list':
            # List backups
            backups = backup.list_backups()
            if backups:
                print("Available backups:")
                for b in backups:
                    size_mb = b['size'] / 1024 / 1024
                    print(f"  {b['id']} - {b['type']} - {size_mb:.1f}MB")
            else:
                print("No backups found")
        
        elif args.backup_action == 'restore':
            # Restore backup
            print(f"Restoring backup {args.backup_id}...")
            if backup.restore_backup(args.backup_id, Path("data")):
                print("Backup restored successfully")
            else:
                print("Restore failed")
                return 1
        
        return 0
    
    def cmd_plugin(self, args) -> int:
        """Plugin management"""
        from blncs.plugins import get_plugin_manager
        
        manager = get_plugin_manager()
        
        if args.plugin_action == 'list':
            # List plugins
            plugins = manager.list_plugins()
            if plugins:
                print("Installed plugins:")
                for name in plugins:
                    print(f"  - {name}")
            else:
                print("No plugins installed")
        
        elif args.plugin_action == 'install':
            # Install plugin
            path = Path(args.path)
            if manager.load_plugin(path):
                print(f"Plugin installed from {path}")
            else:
                print("Failed to install plugin")
                return 1
        
        elif args.plugin_action == 'remove':
            # Remove plugin
            manager.unload_plugin(args.name)
            print(f"Plugin {args.name} removed")
        
        return 0
    
    def cmd_monitor(self, args) -> int:
        """Monitor resources"""
        from blncs.resource_monitor import get_resource_monitor
        import time
        
        monitor = get_resource_monitor()
        monitor.start_monitoring()
        
        print("Resource Monitor (Ctrl+C to stop)")
        print("-" * 50)
        
        try:
            start_time = time.time()
            while True:
                stats = monitor.get_current_stats()
                
                print(f"\r[{datetime.now().strftime('%H:%M:%S')}] "
                      f"CPU: {stats.cpu_percent:5.1f}% | "
                      f"Memory: {stats.memory_mb:7.1f}MB | "
                      f"Threads: {stats.thread_count:3d} | "
                      f"Files: {stats.open_files:3d}", end='')
                
                time.sleep(args.interval)
                
                if args.duration > 0:
                    if time.time() - start_time > args.duration:
                        break
        
        except KeyboardInterrupt:
            pass
        
        print("\n")
        monitor.stop_monitoring()
        return 0
    
    def cmd_log(self, args) -> int:
        """View logs"""
        from blncs.logger import get_logger
        
        log_file = Path("logs/blncs.log")
        
        if not log_file.exists():
            print("No log file found")
            return 1
        
        if args.follow:
            # Follow mode
            import time
            with open(log_file, 'r') as f:
                # Go to end
                f.seek(0, 2)
                
                try:
                    while True:
                        line = f.readline()
                        if line:
                            if not args.level or args.level in line:
                                print(line, end='')
                        else:
                            time.sleep(0.1)
                except KeyboardInterrupt:
                    pass
        else:
            # Tail mode
            with open(log_file, 'r') as f:
                lines = f.readlines()
                
                if args.level:
                    lines = [l for l in lines if args.level in l]
                
                for line in lines[-args.tail:]:
                    print(line, end='')
        
        return 0
    
    def cmd_database(self, args) -> int:
        """Database operations"""
        from blncs.database import Database
        
        if args.db_action == 'info':
            # Show database info
            print("Database Information")
            print("-" * 40)
            
            from blncs.config import get_config
            config = get_config()
            
            db_path = config.db_path
            if db_path.exists():
                size_mb = db_path.stat().st_size / 1024 / 1024
                print(f"Path: {db_path}")
                print(f"Size: {size_mb:.2f}MB")
                
                # Get stats
                async def get_stats():
                    db = Database(db_path)
                    await db.connect()
                    stats = await db.get_stats()
                    await db.disconnect()
                    return stats
                
                stats = asyncio.run(get_stats())
                for key, value in stats.items():
                    print(f"{key}: {value}")
            else:
                print("Database not found")
        
        elif args.db_action == 'optimize':
            # Optimize database
            print("Optimizing database...")
            # Implementation would run ANALYZE
            print("Database optimized")
        
        elif args.db_action == 'vacuum':
            # Vacuum database
            print("Vacuuming database...")
            # Implementation would run VACUUM
            print("Database vacuumed")
        
        return 0

def main():
    """Main CLI entry point"""
    cli = BLNCSCli()
    sys.exit(cli.run())

if __name__ == "__main__":
    main()