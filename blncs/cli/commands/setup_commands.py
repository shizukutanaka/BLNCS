"""
Interactive Setup and Configuration Wizard
User-friendly setup process with best practices and validation.
"""

import click
import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

from ...core.exceptions import format_error_for_cli
from ...core.config_manager import get_config_manager
from ...core.enhanced_validator import get_enhanced_validator
from ...core.security_enhanced import get_enhanced_security_manager
from ...lightning.client import LightningClient


def validate_path(path: str, must_exist: bool = True) -> bool:
    """Validate file/directory path"""
    try:
        p = Path(path).expanduser()
        if must_exist:
            return p.exists()
        else:
            # Check if parent directory exists for new files
            return p.parent.exists()
    except Exception:
        return False


def prompt_with_validation(prompt: str, validator=None, default=None, required=True) -> str:
    """Prompt user with validation"""
    while True:
        if default:
            value = click.prompt(prompt, default=default, show_default=True)
        elif not required:
            value = click.prompt(prompt, default='', show_default=False)
            if not value:
                return ''
        else:
            value = click.prompt(prompt)
        
        if validator:
            if validator(value):
                return value
            else:
                click.echo("❌ Invalid input, please try again")
        else:
            return value


def test_lightning_connection(host: str, port: int, cert_path: str, macaroon_path: str) -> Tuple[bool, str]:
    """Test Lightning Network connection"""
    try:
        config = {
            'lightning': {
                'host': host,
                'port': port,
                'cert_path': cert_path,
                'macaroon_path': macaroon_path
            }
        }
        
        client = LightningClient(config)
        node_info = client.get_info()
        
        alias = node_info.get('alias', 'Unknown')
        network = node_info.get('network', 'Unknown')
        
        return True, f"Connected to '{alias}' on {network}"
        
    except Exception as e:
        return False, str(e)


@click.group()
def setup():
    """Setup and configuration wizard"""
    pass


@setup.command()
def wizard():
    """Interactive setup wizard for first-time configuration"""
    
    click.echo("Welcome to BLNCS Setup Wizard!")
    click.echo("=" * 50)
    click.echo("This wizard will help you configure BLNCS for first-time use.")
    click.echo("You can skip any optional steps by pressing Enter.\n")
    
    config_manager = get_config_manager()
    config = {}
    
    # Step 1: Lightning Network Configuration
    click.echo("Step 1: Lightning Network Configuration")
    click.echo("-" * 40)
    
    ln_host = prompt_with_validation(
        "Lightning node host", 
        default="localhost"
    )
    
    ln_port = click.prompt("Lightning node port (gRPC)", type=int, default=10009)
    
    # Certificate path
    cert_path = prompt_with_validation(
        "TLS certificate path",
        validator=lambda p: validate_path(p, must_exist=True),
        default="~/.lnd/tls.cert"
    )
    
    if not validate_path(cert_path):
        click.echo(f"Warning: Certificate file not found at {cert_path}")
        if click.confirm("Continue anyway?"):
            cert_path = cert_path
        else:
            cert_path = prompt_with_validation(
                "Alternative certificate path",
                validator=lambda p: validate_path(p, must_exist=True)
            )
    
    # Macaroon path
    macaroon_path = prompt_with_validation(
        "Admin macaroon path",
        validator=lambda p: validate_path(p, must_exist=True),
        default="~/.lnd/data/chain/bitcoin/testnet/admin.macaroon"
    )
    
    if not validate_path(macaroon_path):
        click.echo(f"Warning: Macaroon file not found at {macaroon_path}")
        if click.confirm("Continue anyway?"):
            macaroon_path = macaroon_path
        else:
            macaroon_path = prompt_with_validation(
                "Alternative macaroon path",
                validator=lambda p: validate_path(p, must_exist=True)
            )
    
    # Network selection
    network = click.prompt(
        "Bitcoin network", 
        type=click.Choice(['mainnet', 'testnet', 'regtest']), 
        default='testnet'
    )
    
    # Test connection
    click.echo("\nTesting Lightning connection...")
    
    connection_success, connection_msg = test_lightning_connection(
        ln_host, ln_port, cert_path, macaroon_path
    )
    
    if connection_success:
        click.echo(f"Connection successful: {connection_msg}")
    else:
        click.echo(f"Connection failed: {connection_msg}")
        if not click.confirm("Continue with setup anyway?"):
            click.echo("Setup cancelled")
            return
    
    # Save Lightning config
    config['lightning'] = {
        'host': ln_host,
        'port': ln_port,
        'grpc_port': ln_port,
        'rest_port': ln_port + 1,  # Common convention
        'cert_path': cert_path,
        'macaroon_path': macaroon_path,
        'network': network
    }
    
    # Step 2: System Configuration
    click.echo("\nStep 2: System Configuration")
    click.echo("-" * 40)
    
    # Logging level
    log_level = click.prompt(
        "Logging level",
        type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']),
        default='INFO'
    )
    
    # Data directory
    data_dir = prompt_with_validation(
        "Data directory",
        default="./data",
        validator=lambda p: True  # We'll create it if needed
    )
    
    # Create data directory if it doesn't exist
    data_path = Path(data_dir)
    if not data_path.exists():
        if click.confirm(f"Create data directory {data_dir}?"):
            data_path.mkdir(parents=True, exist_ok=True)
            click.echo(f"Created data directory: {data_dir}")
    
    config['system'] = {
        'log_level': log_level,
        'log_file': f"{data_dir}/blncs.log",
        'data_dir': data_dir
    }
    
    # Step 3: Performance Configuration
    click.echo("\nStep 3: Performance Configuration")
    click.echo("-" * 40)
    
    if click.confirm("Enable performance monitoring?", default=True):
        config['performance'] = {
            'monitoring_enabled': True,
            'auto_optimization': click.confirm("Enable automatic optimization?", default=True),
            'snapshot_interval': click.prompt("Monitoring interval (seconds)", type=int, default=60),
            'cache_ttl': click.prompt("Cache TTL (seconds)", type=int, default=300),
            'max_workers': click.prompt("Max parallel workers", type=int, default=8)
        }
    
    # Step 4: Security Configuration
    click.echo("\nStep 4: Security Configuration")
    click.echo("-" * 40)
    
    enable_security = click.confirm("Enable enhanced security features?", default=True)
    
    if enable_security:
        config['security'] = {
            'monitoring_enabled': True,
            'level': 2,  # Medium security level
            'auto_block_threats': click.confirm("Auto-block security threats?", default=True),
            'session_timeout': click.prompt("Session timeout (seconds)", type=int, default=3600),
            'max_failed_attempts': click.prompt("Max failed login attempts", type=int, default=5)
        }
        
        # Initialize security system
        if click.confirm("Initialize encryption keys?", default=True):
            try:
                sm = get_enhanced_security_manager()
                if sm.key_manager.encryption_enabled:
                    click.echo("Encryption system initialized")
                else:
                    click.echo("Warning: Encryption not available (install 'cryptography' package)")
            except Exception as e:
                click.echo(f"Warning: Encryption initialization failed: {e}")
    
    # Step 5: Automation Setup
    click.echo("\nStep 5: Automation Setup")
    click.echo("-" * 40)
    
    if click.confirm("Setup automated maintenance tasks?", default=True):
        config['automation'] = {
            'enabled': True,
            'health_check_interval': 'every 1 hour',
            'backup_interval': 'every 6 hours',
            'cleanup_interval': 'every 1 day'
        }
        
        # Backup configuration
        backup_dir = prompt_with_validation(
            "Backup directory",
            default="./backups",
            validator=lambda p: True
        )
        
        backup_path = Path(backup_dir)
        if not backup_path.exists():
            if click.confirm(f"Create backup directory {backup_dir}?"):
                backup_path.mkdir(parents=True, exist_ok=True)
                click.echo(f"Created backup directory: {backup_dir}")
        
        config['backup'] = {
            'enabled': True,
            'backup_dir': backup_dir,
            'retention_days': click.prompt("Backup retention (days)", type=int, default=30),
            'compress': click.confirm("Compress backups?", default=True)
        }
    
    # Step 6: Save Configuration
    click.echo("\nStep 6: Save Configuration")
    click.echo("-" * 40)
    
    # Display configuration summary
    click.echo("Configuration Summary:")
    click.echo(f"  Lightning Node: {ln_host}:{ln_port} ({network})")
    click.echo(f"  Data Directory: {data_dir}")
    click.echo(f"  Logging Level: {log_level}")
    
    if config.get('performance'):
        click.echo(f"  Performance Monitoring: Enabled")
    
    if config.get('security'):
        click.echo(f"  Security Level: {config['security']['level']}")
    
    if config.get('automation'):
        click.echo(f"  Automation: Enabled")
    
    if click.confirm("\nSave this configuration?", default=True):
        try:
            # Save to config manager
            for section, values in config.items():
                for key, value in values.items():
                    config_manager.set(f"{section}.{key}", value)
            
            click.echo("Configuration saved successfully!")
            
            # Create essential directories
            essential_dirs = ['security', 'logs', 'automation']
            if config.get('backup'):
                essential_dirs.append('backups')
            
            for dir_name in essential_dirs:
                dir_path = Path(dir_name)
                if not dir_path.exists():
                    dir_path.mkdir(parents=True, exist_ok=True)
            
            # Setup automation if enabled
            if config.get('automation', {}).get('enabled'):
                if click.confirm("Setup default automated tasks now?"):
                    setup_default_automation()
            
            click.echo("\nBLNCS setup completed successfully!")
            click.echo("\nNext steps:")
            click.echo("  1. Run 'blncs status' to check system status")
            click.echo("  2. Run 'blncs health' for a comprehensive health check")
            click.echo("  3. Run 'blncs dashboard' for real-time monitoring")
            click.echo("  4. Check out 'blncs --help' for all available commands")
            
        except Exception as e:
            click.echo(f"Failed to save configuration: {e}")
            return
    else:
        click.echo("Setup cancelled")


def setup_default_automation() -> None:
    """Setup default automation tasks"""
    try:
        from .automation_commands import get_scheduler
        
        scheduler = get_scheduler()
        
        # Default tasks
        default_tasks = [
            {
                'name': 'health_check_hourly',
                'type': 'health_check',
                'schedule': 'every 1 hour',
                'params': {'alert_threshold': 75}
            },
            {
                'name': 'backup_daily',
                'type': 'backup', 
                'schedule': 'every 6 hours',
                'params': {
                    'backup_type': 'incremental',
                    'sources': ['./blncs.db', './security/', './config/']
                }
            },
            {
                'name': 'cleanup_daily',
                'type': 'cleanup',
                'schedule': 'every 1 day',
                'params': {'log_retention_days': 30}
            },
            {
                'name': 'security_audit',
                'type': 'security_audit',
                'schedule': 'every 4 hours',
                'params': {'event_threshold': 10}
            }
        ]
        
        for task in default_tasks:
            scheduler.add_task(
                task['name'],
                task['type'],
                task['schedule'],
                task['params']
            )
        
        scheduler.start()
        click.echo(f"Setup {len(default_tasks)} automated tasks")
        
    except Exception as e:
        click.echo(f"Warning: Failed to setup automation: {e}")


@setup.command()
def verify():
    """Verify current system configuration"""
    
    click.echo("BLNCS Configuration Verification")
    click.echo("=" * 50)
    
    config_manager = get_config_manager()
    validator = get_enhanced_validator()
    
    issues = []
    warnings = []
    score = 0
    total_checks = 0
    
    # Check Lightning configuration
    click.echo("\nLightning Network Configuration")
    click.echo("-" * 40)
    
    ln_host = config_manager.get('lightning.host', 'localhost')
    ln_port = config_manager.get('lightning.port', 8080)
    cert_path = config_manager.get('lightning.cert_path', '')
    macaroon_path = config_manager.get('lightning.macaroon_path', '')
    network = config_manager.get('lightning.network', 'testnet')
    
    click.echo(f"Host: {ln_host}:{ln_port}")
    click.echo(f"Network: {network}")
    
    # Test certificate
    if cert_path:
        if validate_path(cert_path):
            click.echo(f"✅ TLS Certificate: {cert_path}")
            score += 10
        else:
            click.echo(f"❌ TLS Certificate: {cert_path} (not found)")
            issues.append(f"TLS certificate not found: {cert_path}")
    else:
        click.echo("⚠️  TLS Certificate: Not configured")
        warnings.append("TLS certificate path not set")
    
    # Test macaroon
    if macaroon_path:
        if validate_path(macaroon_path):
            click.echo(f"✅ Macaroon: {macaroon_path}")
            score += 10
        else:
            click.echo(f"❌ Macaroon: {macaroon_path} (not found)")
            issues.append(f"Macaroon file not found: {macaroon_path}")
    else:
        click.echo("⚠️  Macaroon: Not configured")
        warnings.append("Macaroon path not set")
    
    # Test connection
    if cert_path and macaroon_path:
        click.echo("\n🔌 Testing connection...")
        success, msg = test_lightning_connection(ln_host, ln_port, cert_path, macaroon_path)
        if success:
            click.echo(f"✅ Connection: {msg}")
            score += 20
        else:
            click.echo(f"❌ Connection: {msg}")
            issues.append(f"Lightning connection failed: {msg}")
    
    total_checks += 4
    
    # Check system configuration
    click.echo("\n🔧 System Configuration")
    click.echo("-" * 40)
    
    data_dir = config_manager.get('system.data_dir', './data')
    log_level = config_manager.get('system.log_level', 'INFO')
    log_file = config_manager.get('system.log_file', './blncs.log')
    
    # Check data directory
    if validate_path(data_dir, must_exist=False):
        if Path(data_dir).exists():
            click.echo(f"✅ Data Directory: {data_dir}")
            score += 5
        else:
            click.echo(f"⚠️  Data Directory: {data_dir} (will be created)")
            warnings.append(f"Data directory doesn't exist: {data_dir}")
    else:
        click.echo(f"❌ Data Directory: Invalid path {data_dir}")
        issues.append(f"Invalid data directory path: {data_dir}")
    
    # Check log configuration
    valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR']
    if log_level in valid_levels:
        click.echo(f"✅ Log Level: {log_level}")
        score += 5
    else:
        click.echo(f"❌ Log Level: Invalid level {log_level}")
        issues.append(f"Invalid log level: {log_level}")
    
    total_checks += 2
    
    # Check security configuration
    click.echo("\n🔒 Security Configuration")
    click.echo("-" * 40)
    
    try:
        sm = get_enhanced_security_manager()
        security_status = sm.get_security_status()
        
        if security_status.get('encryption_available'):
            click.echo("✅ Encryption: Available")
            score += 10
        else:
            click.echo("❌ Encryption: Not available")
            issues.append("Encryption not available - install 'cryptography' package")
        
        if security_status.get('monitoring_enabled'):
            click.echo("✅ Security Monitoring: Enabled")
            score += 5
        else:
            click.echo("⚠️  Security Monitoring: Disabled")
            warnings.append("Security monitoring is disabled")
        
        total_checks += 2
        
    except Exception as e:
        click.echo(f"❌ Security System: {e}")
        issues.append(f"Security system error: {e}")
    
    # Check performance configuration
    click.echo("\n⚡ Performance Configuration")
    click.echo("-" * 40)
    
    try:
        from ...core.performance_manager import get_performance_manager
        pm = get_performance_manager()
        
        perf_status = pm.get_current_performance()
        if perf_status.get('status') != 'no_data':
            click.echo("✅ Performance Monitoring: Active")
            score += 10
        else:
            click.echo("⚠️  Performance Monitoring: No data available")
            warnings.append("Performance monitoring has no data")
        
        total_checks += 1
        
    except Exception as e:
        click.echo(f"❌ Performance System: {e}")
        issues.append(f"Performance system error: {e}")
    
    # Check essential directories
    click.echo("\n📁 Directory Structure")
    click.echo("-" * 40)
    
    essential_dirs = ['security', 'logs', 'config', 'data']
    for dir_name in essential_dirs:
        dir_path = Path(dir_name)
        if dir_path.exists():
            click.echo(f"✅ {dir_name.title()}: {dir_path}")
        else:
            click.echo(f"⚠️  {dir_name.title()}: Missing (will be created)")
            warnings.append(f"Missing directory: {dir_name}")
    
    # Calculate final score
    max_score = total_checks * 10
    final_score = (score / max_score * 100) if max_score > 0 else 0
    
    # Summary
    click.echo(f"\n📊 Configuration Score: {final_score:.1f}/100")
    
    if final_score >= 90:
        click.secho("🟢 EXCELLENT - Configuration is optimal", fg='green', bold=True)
    elif final_score >= 75:
        click.secho("🟢 GOOD - Configuration is solid with minor issues", fg='green')
    elif final_score >= 60:
        click.secho("🟡 FAIR - Configuration needs some attention", fg='yellow')
    else:
        click.secho("🔴 POOR - Configuration has significant issues", fg='red', bold=True)
    
    # Show issues and warnings
    if issues:
        click.echo(f"\n❌ Critical Issues ({len(issues)}):")
        for i, issue in enumerate(issues, 1):
            click.echo(f"  {i}. {issue}")
    
    if warnings:
        click.echo(f"\n⚠️  Warnings ({len(warnings)}):")
        for i, warning in enumerate(warnings, 1):
            click.echo(f"  {i}. {warning}")
    
    if not issues and not warnings:
        click.echo("\n🎉 No issues found - configuration looks great!")
    
    # Recommendations
    if issues or warnings:
        click.echo(f"\n💡 Recommendations:")
        
        if any("not found" in issue for issue in issues):
            click.echo("  • Verify Lightning node is running and paths are correct")
            click.echo("  • Check file permissions on certificate and macaroon files")
        
        if any("connection failed" in issue for issue in issues):
            click.echo("  • Ensure Lightning node is accessible from this machine")
            click.echo("  • Check firewall settings and network connectivity")
        
        if any("Encryption not available" in issue for issue in issues):
            click.echo("  • Install cryptography: pip install cryptography")
        
        if any("directory" in warning.lower() for warning in warnings):
            click.echo("  • Run 'blncs setup init' to create missing directories")
    
    return final_score >= 75


@setup.command()
def init():
    """Initialize BLNCS directory structure and files"""
    
    click.echo("🏗️  Initializing BLNCS directory structure...")
    
    # Essential directories
    directories = [
        'config',
        'data', 
        'logs',
        'security',
        'backups',
        'automation'
    ]
    
    created_dirs = []
    
    for dir_name in directories:
        dir_path = Path(dir_name)
        if not dir_path.exists():
            try:
                dir_path.mkdir(parents=True, exist_ok=True)
                # Set appropriate permissions
                if dir_name in ['security', 'backups']:
                    os.chmod(dir_path, 0o700)  # Owner only
                else:
                    os.chmod(dir_path, 0o755)  # Standard permissions
                
                created_dirs.append(dir_name)
                click.echo(f"✅ Created directory: {dir_name}")
            except Exception as e:
                click.echo(f"❌ Failed to create {dir_name}: {e}")
        else:
            click.echo(f"📁 Directory exists: {dir_name}")
    
    # Create default config file if doesn't exist
    config_file = Path('config/blncs.yaml')
    if not config_file.exists():
        try:
            default_config = {
                'lightning': {
                    'host': 'localhost',
                    'port': 10009,
                    'network': 'testnet',
                    'cert_path': '~/.lnd/tls.cert',
                    'macaroon_path': '~/.lnd/data/chain/bitcoin/testnet/admin.macaroon'
                },
                'system': {
                    'log_level': 'INFO',
                    'log_file': 'logs/blncs.log',
                    'data_dir': 'data'
                },
                'performance': {
                    'monitoring_enabled': True,
                    'cache_ttl': 300
                },
                'security': {
                    'monitoring_enabled': True,
                    'level': 2
                }
            }
            
            import yaml
            with open(config_file, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False, indent=2)
            
            click.echo(f"✅ Created default config: {config_file}")
            
        except Exception as e:
            click.echo(f"❌ Failed to create config file: {e}")
    
    # Create .gitignore if doesn't exist
    gitignore_file = Path('.gitignore')
    if not gitignore_file.exists():
        gitignore_content = """# BLNCS files
logs/
security/
data/
backups/
automation/

# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
share/python-wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# Environment
.env
.venv
env/
venv/
ENV/
env.bak/
venv.bak/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db
"""
        try:
            with open(gitignore_file, 'w') as f:
                f.write(gitignore_content)
            click.echo(f"✅ Created .gitignore file")
        except Exception as e:
            click.echo(f"⚠️  Failed to create .gitignore: {e}")
    
    click.echo(f"\n🎉 Initialization completed!")
    
    if created_dirs:
        click.echo(f"Created {len(created_dirs)} directories: {', '.join(created_dirs)}")
    
    click.echo("\nNext steps:")
    click.echo("  1. Run 'blncs setup wizard' for interactive configuration")
    click.echo("  2. Or manually edit config/blncs.yaml")
    click.echo("  3. Run 'blncs setup verify' to check your configuration")


# Add commands to main CLI
__all__ = ['setup']