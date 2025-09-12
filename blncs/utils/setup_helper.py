#!/usr/bin/env python3
"""
Setup helper utility
Creates basic BLNCS configuration structure.
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime


def create_directory(dir_path: str) -> Dict[str, Any]:
    """Create directory if it doesn't exist"""
    try:
        path = Path(dir_path).expanduser()
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
            return {"status": "created", "message": f"Created directory: {path}"}
        else:
            return {"status": "exists", "message": f"Directory already exists: {path}"}
    except Exception as e:
        return {"status": "error", "message": f"Failed to create directory: {e}"}


def create_basic_config_file(config_path: str) -> Dict[str, Any]:
    """Create a basic BLNCS configuration file"""
    try:
        path = Path(config_path).expanduser()
        
        # Don't overwrite existing config
        if path.exists():
            return {"status": "exists", "message": f"Config file already exists: {path}"}
        
        # Basic configuration template
        config = {
            "created": datetime.now().isoformat(),
            "lightning": {
                "host": "localhost",
                "port": 8080,
                "network": "testnet",
                "timeout": 30,
                "connect_timeout": 10,
                "macaroon_path": "~/.lnd/data/chain/bitcoin/testnet/readonly.macaroon",
                "tls_cert_path": "~/.lnd/tls.cert"
            },
            "bitcoin": {
                "host": "localhost",
                "port": 8332,
                "network": "testnet"
            },
            "blncs": {
                "data_dir": "~/.blncs",
                "log_level": "INFO",
                "cache_ttl": 300,
                "backup_enabled": True
            }
        }
        
        # Create parent directory if needed
        path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write config file
        with open(path, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, default_flow_style=False, indent=2)
        
        return {"status": "created", "message": f"Created config file: {path}"}
        
    except Exception as e:
        return {"status": "error", "message": f"Failed to create config file: {e}"}


def create_env_template(env_path: str = ".env.example") -> Dict[str, Any]:
    """Create environment variables template"""
    try:
        path = Path(env_path)
        
        if path.exists():
            return {"status": "exists", "message": f"Environment template already exists: {path}"}
        
        env_template = """# BLNCS Environment Variables
# Copy this file to .env and customize for your setup

# Network configuration
NETWORK=testnet

# Lightning Network configuration
LND_HOST=localhost
LND_PORT=8080
LND_MACAROON_PATH=~/.lnd/data/chain/bitcoin/testnet/readonly.macaroon
LND_TLS_CERT_PATH=~/.lnd/tls.cert

# Bitcoin Core configuration
BITCOIN_HOST=localhost
BITCOIN_RPC_PORT=8332
BITCOIN_DATADIR=~/.bitcoin

# BLNCS configuration
BLNCS_CONFIG=~/.blncs/config.yml
BLNCS_DATA_DIR=~/.blncs
BLNCS_LOG_LEVEL=INFO

# Optional: Custom paths
# BLNCS_LOG_FILE=~/.blncs/blncs.log
# BLNCS_BACKUP_DIR=~/.blncs/backups
"""
        
        with open(path, 'w', encoding='utf-8') as f:
            f.write(env_template)
        
        return {"status": "created", "message": f"Created environment template: {path}"}
        
    except Exception as e:
        return {"status": "error", "message": f"Failed to create environment template: {e}"}


def run_basic_setup() -> Dict[str, Any]:
    """Run basic BLNCS setup"""
    results = {
        "timestamp": datetime.now().isoformat(),
        "setup_steps": {}
    }
    
    print("Running BLNCS basic setup...")
    
    # Create main configuration directory
    print("- Creating configuration directory...")
    results["setup_steps"]["config_dir"] = create_directory("~/.blncs")
    
    # Create subdirectories
    subdirs = ["logs", "backups", "cache"]
    for subdir in subdirs:
        print(f"- Creating {subdir} directory...")
        results["setup_steps"][f"{subdir}_dir"] = create_directory(f"~/.blncs/{subdir}")
    
    # Create basic configuration file
    print("- Creating basic configuration...")
    results["setup_steps"]["config_file"] = create_basic_config_file("~/.blncs/config.yml")
    
    # Create environment template
    print("- Creating environment template...")
    results["setup_steps"]["env_template"] = create_env_template()
    
    return results


def format_setup_results(results: Dict[str, Any]) -> str:
    """Format setup results for display"""
    output = []
    output.append("BLNCS Setup Results")
    output.append("=" * 30)
    output.append(f"Timestamp: {results['timestamp']}")
    output.append("")
    
    steps = results.get("setup_steps", {})
    
    for step_name, result in steps.items():
        status_icon = {"created": "[CREATED]", "exists": "[EXISTS]", "error": "[ERROR]"}.get(result["status"], "[?]")
        step_display = step_name.replace("_", " ").title()
        output.append(f"{status_icon} {step_display}")
        output.append(f"    {result['message']}")
        output.append("")
    
    # Add next steps
    output.append("Next Steps:")
    output.append("1. Review and customize ~/.blncs/config.yml")
    output.append("2. Copy .env.example to .env and customize")
    output.append("3. Ensure Lightning Network node is running")
    output.append("4. Test connectivity with: blncs nettest")
    
    return "\n".join(output)


if __name__ == "__main__":
    # Run setup when executed directly
    results = run_basic_setup()
    print("\n" + format_setup_results(results))