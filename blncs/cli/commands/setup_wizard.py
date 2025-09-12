"""
BLNCS Setup Wizard
Interactive setup for first-time users.
"""

import click
import os
from pathlib import Path
import json

def create_config_dir():
    """Create BLNCS configuration directory"""
    config_dir = Path.home() / '.blncs'
    config_dir.mkdir(exist_ok=True)
    
    # Create subdirectories
    (config_dir / 'backups').mkdir(exist_ok=True)
    (config_dir / 'logs').mkdir(exist_ok=True)
    (config_dir / 'data').mkdir(exist_ok=True)
    
    return config_dir

def get_default_config():
    """Get default configuration"""
    return {
        "system": {
            "name": "BLNCS",
            "environment": "development",
            "data_dir": str(Path.home() / '.blncs' / 'data'),
            "backup_dir": str(Path.home() / '.blncs' / 'backups'),
            "log_dir": str(Path.home() / '.blncs' / 'logs')
        },
        "lightning": {
            "host": "localhost",
            "port": 8080,
            "network": "testnet",
            "timeout": 10,
            "mock_mode": True
        },
        "security": {
            "verify_ssl": False
        },
        "logging": {
            "level": "INFO",
            "console_enabled": True
        }
    }

@click.command()
@click.option('--force', is_flag=True, help='Force overwrite existing configuration')
def setup(force):
    """Interactive setup wizard for BLNCS"""
    try:
        click.echo("🚀 BLNCS Setup Wizard")
        click.echo("=" * 50)
        
        # Check if already configured
        config_dir = Path.home() / '.blncs'
        config_file = config_dir / 'config.yaml'
        
        if config_file.exists() and not force:
            click.echo("⚠️  BLNCS is already configured.")
            click.echo(f"Config location: {config_file}")
            if not click.confirm("Do you want to reconfigure?"):
                click.echo("Setup cancelled.")
                return
        
        click.echo("📁 Setting up directories...")
        config_dir = create_config_dir()
        click.echo(f"✅ Created config directory: {config_dir}")
        
        # Interactive configuration
        click.echo("\n⚙️  Configuration Setup")
        click.echo("-" * 30)
        
        config = get_default_config()
        
        # Lightning network selection
        click.echo("🌐 Lightning Network Configuration:")
        network = click.prompt(
            "Network", 
            default="testnet",
            type=click.Choice(['mainnet', 'testnet', 'regtest'])
        )
        config['lightning']['network'] = network
        
        # Mode selection
        mock_mode = click.confirm("Use mock mode (for testing without real Lightning node)?", default=True)
        config['lightning']['mock_mode'] = mock_mode
        
        if not mock_mode:
            click.echo("\n⚡ Lightning Node Connection:")
            host = click.prompt("Lightning node host", default="localhost")
            port = click.prompt("Lightning node port", default=8080, type=int)
            config['lightning']['host'] = host
            config['lightning']['port'] = port
        
        # Logging level
        click.echo("\n📝 Logging Configuration:")
        log_level = click.prompt(
            "Log level",
            default="INFO",
            type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR'])
        )
        config['logging']['level'] = log_level
        
        # Environment
        click.echo("\n🏗️  Environment Configuration:")
        environment = click.prompt(
            "Environment",
            default="development",
            type=click.Choice(['development', 'production', 'testing'])
        )
        config['system']['environment'] = environment
        
        # Save configuration
        click.echo(f"\n💾 Saving configuration to: {config_file}")
        
        # Convert to YAML-like format manually (to avoid yaml dependency)
        config_content = []
        for section, values in config.items():
            config_content.append(f"{section}:")
            for key, value in values.items():
                if isinstance(value, str):
                    config_content.append(f"  {key}: \"{value}\"")
                else:
                    config_content.append(f"  {key}: {value}")
            config_content.append("")
        
        with open(config_file, 'w') as f:
            f.write('\n'.join(config_content))
        
        # Success message
        click.echo("✅ Configuration saved successfully!")
        
        # Show next steps
        click.echo("\n🎉 Setup Complete!")
        click.echo("=" * 50)
        click.echo("Next steps:")
        click.echo("1. Test your setup:")
        click.echo("   python3 -m blncs version")
        click.echo("   python3 -m blncs info")
        click.echo("   python3 -m blncs dashboard")
        click.echo("")
        click.echo("2. Explore available commands:")
        click.echo("   python3 -m blncs --help")
        click.echo("")
        click.echo("3. Monitor your Lightning node:")
        click.echo("   python3 -m blncs health")
        click.echo("   python3 -m blncs balance")
        click.echo("")
        
        if config['lightning']['mock_mode']:
            click.echo("💡 Note: You're in mock mode.")
            click.echo("   To connect to a real Lightning node:")
            click.echo("   1. Update config: python3 -m blncs config set lightning.mock_mode false")
            click.echo("   2. Set node details: python3 -m blncs config set lightning.host <your-host>")
            click.echo("")
        
        click.echo("📖 For help: python3 -m blncs --help")
        click.echo("🐛 Issues: Check logs in " + str(config_dir / 'logs'))
        
    except Exception as e:
        click.echo(f"❌ Setup failed: {e}", err=True)

@click.command()
def verify():
    """Verify BLNCS installation and configuration"""
    try:
        click.echo("🔍 BLNCS Installation Verification")
        click.echo("=" * 50)
        
        checks = []
        
        # Check config directory
        config_dir = Path.home() / '.blncs'
        if config_dir.exists():
            checks.append(("Configuration directory", True, str(config_dir)))
        else:
            checks.append(("Configuration directory", False, "Not found"))
        
        # Check config file
        config_file = config_dir / 'config.yaml'
        if config_file.exists():
            checks.append(("Configuration file", True, str(config_file)))
        else:
            checks.append(("Configuration file", False, "Not found"))
        
        # Check directories
        for subdir in ['backups', 'logs', 'data']:
            path = config_dir / subdir
            if path.exists():
                checks.append((f"{subdir.title()} directory", True, str(path)))
            else:
                checks.append((f"{subdir.title()} directory", False, "Not found"))
        
        # Test imports
        try:
            from ...lightning.client_simple import get_lightning_client
            checks.append(("Lightning client import", True, "OK"))
        except Exception as e:
            checks.append(("Lightning client import", False, str(e)))
        
        try:
            from ...core.config_manager import get_config_manager
            config = get_config_manager()
            checks.append(("Configuration manager", True, "OK"))
        except Exception as e:
            checks.append(("Configuration manager", False, str(e)))
        
        # Display results
        passed = 0
        failed = 0
        
        for name, status, details in checks:
            icon = "✅" if status else "❌"
            click.echo(f"{icon} {name}: {details}")
            if status:
                passed += 1
            else:
                failed += 1
        
        click.echo("\n" + "=" * 50)
        click.echo(f"📊 Results: {passed} passed, {failed} failed")
        
        if failed == 0:
            click.echo("🎉 All checks passed! BLNCS is ready to use.")
        else:
            click.echo("⚠️  Some checks failed. Run setup to fix issues:")
            click.echo("   python3 -m blncs setup")
        
    except Exception as e:
        click.echo(f"❌ Verification failed: {e}", err=True)