#!/usr/bin/env python3
"""
BLNCS Configuration Migrator
Handles migration of configuration files between versions.
"""

import json
import os
import configparser
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class ConfigMigrator:
    """Migrate configuration files between BLNCS versions"""
    
    def __init__(self, config_dir: str = None):
        self.config_dir = Path(config_dir or os.path.expanduser("~/.blncs"))
        self.backup_dir = self.config_dir / "migration_backups"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    def migrate_1_0_to_1_1(self) -> Dict[str, Any]:
        """Migrate configuration from v1.0 to v1.1"""
        logger.info("Migrating configuration from v1.0 to v1.1")
        
        result = {
            "success": True,
            "changes": [],
            "errors": [],
            "warnings": []
        }
        
        try:
            # Backup existing configuration
            self._backup_config_files("1.0_to_1.1")
            
            # Migrate backup configuration
            old_backup_config = self.config_dir / "backup_config.json"
            new_backup_config = self.config_dir / "backup_items.json"
            
            if old_backup_config.exists():
                with open(old_backup_config, 'r') as f:
                    old_config = json.load(f)
                
                # Convert old format to new format
                new_config = {
                    "version": "1.1.0",
                    "backup_items": [],
                    "global_settings": {
                        "default_compression": old_config.get("compression", True),
                        "default_encryption": old_config.get("encryption", False),
                        "default_backup_type": old_config.get("backup_type", "incremental")
                    }
                }
                
                # Convert backup items
                for item_name, item_config in old_config.get("items", {}).items():
                    new_item = {
                        "id": item_name.lower().replace(" ", "_"),
                        "name": item_name,
                        "source_path": item_config["path"],
                        "backup_type": item_config.get("type", "incremental"),
                        "enabled": item_config.get("enabled", True),
                        "priority": item_config.get("priority", 5),
                        "encryption": item_config.get("encryption", False),
                        "compression": item_config.get("compression", True)
                    }
                    new_config["backup_items"].append(new_item)
                
                # Save new configuration
                with open(new_backup_config, 'w') as f:
                    json.dump(new_config, f, indent=2)
                
                result["changes"].append(f"Migrated backup configuration: {len(new_config['backup_items'])} items")
            
            # Create initial scheduler configuration
            scheduler_config = {
                "version": "1.1.0",
                "scheduler_enabled": False,
                "schedules": [],
                "global_settings": {
                    "max_concurrent_backups": 2,
                    "retry_failed_backups": True,
                    "retention_policy": "30_days"
                }
            }
            
            scheduler_file = self.config_dir / "scheduler.json"
            with open(scheduler_file, 'w') as f:
                json.dump(scheduler_config, f, indent=2)
            
            result["changes"].append("Created scheduler configuration")
            
        except Exception as e:
            result["success"] = False
            result["errors"].append(f"Migration failed: {str(e)}")
            logger.error(f"Migration 1.0->1.1 failed: {e}")
        
        return result
    
    def migrate_1_1_to_1_2(self) -> Dict[str, Any]:
        """Migrate configuration from v1.1 to v1.2"""
        logger.info("Migrating configuration from v1.1 to v1.2")
        
        result = {
            "success": True,
            "changes": [],
            "errors": [],
            "warnings": []
        }
        
        try:
            # Backup existing configuration
            self._backup_config_files("1.1_to_1.2")
            
            # Migrate scheduler configuration with enhanced features
            scheduler_file = self.config_dir / "scheduler.json"
            if scheduler_file.exists():
                with open(scheduler_file, 'r') as f:
                    scheduler_config = json.load(f)
                
                # Add new scheduler features
                scheduler_config["version"] = "1.2.0"
                if "advanced_scheduling" not in scheduler_config:
                    scheduler_config["advanced_scheduling"] = {
                        "dependency_chains": [],
                        "conditional_schedules": [],
                        "resource_limits": {
                            "max_cpu_percent": 80,
                            "max_memory_mb": 1024,
                            "max_network_mbps": 100
                        }
                    }
                
                # Enhance existing schedules with new options
                for schedule in scheduler_config.get("schedules", []):
                    if "notification_settings" not in schedule:
                        schedule["notification_settings"] = {
                            "on_success": False,
                            "on_failure": True,
                            "on_warning": False
                        }
                    if "recovery_options" not in schedule:
                        schedule["recovery_options"] = {
                            "auto_verify": True,
                            "create_recovery_info": True
                        }
                
                with open(scheduler_file, 'w') as f:
                    json.dump(scheduler_config, f, indent=2)
                
                result["changes"].append("Enhanced scheduler configuration with v1.2 features")
            
            # Create storage backends configuration
            storage_config = {
                "version": "1.2.0",
                "storage_backends": [
                    {
                        "id": "local_primary",
                        "name": "Local Storage",
                        "type": "local",
                        "config": {
                            "path": str(self.config_dir / "backups")
                        },
                        "enabled": True,
                        "priority": 1,
                        "encryption_enabled": False
                    }
                ],
                "global_settings": {
                    "redundancy_level": 1,
                    "verify_on_write": True,
                    "compression_algorithm": "gzip",
                    "encryption_algorithm": "AES256"
                }
            }
            
            storage_file = self.config_dir / "storage_backends.json"
            with open(storage_file, 'w') as f:
                json.dump(storage_config, f, indent=2)
            
            result["changes"].append("Created storage backends configuration")
            
            # Enhance backup items with recovery metadata
            backup_items_file = self.config_dir / "backup_items.json"
            if backup_items_file.exists():
                with open(backup_items_file, 'r') as f:
                    backup_config = json.load(f)
                
                backup_config["version"] = "1.2.0"
                
                # Add recovery features to each backup item
                for item in backup_config.get("backup_items", []):
                    if "recovery_metadata" not in item:
                        item["recovery_metadata"] = {
                            "include_permissions": True,
                            "include_ownership": True,
                            "include_timestamps": True,
                            "create_recovery_script": True
                        }
                    if "validation_rules" not in item:
                        item["validation_rules"] = {
                            "check_integrity": True,
                            "verify_restore": False,
                            "hash_algorithm": "sha256"
                        }
                
                with open(backup_items_file, 'w') as f:
                    json.dump(backup_config, f, indent=2)
                
                result["changes"].append("Enhanced backup items with recovery metadata")
            
        except Exception as e:
            result["success"] = False
            result["errors"].append(f"Migration failed: {str(e)}")
            logger.error(f"Migration 1.1->1.2 failed: {e}")
        
        return result
    
    def migrate_1_2_to_2_0(self) -> Dict[str, Any]:
        """Migrate configuration from v1.2 to v2.0"""
        logger.info("Migrating configuration from v1.2 to v2.0")
        
        result = {
            "success": True,
            "changes": [],
            "errors": [],
            "warnings": []
        }
        
        try:
            # Backup existing configuration
            self._backup_config_files("1.2_to_2.0")
            
            # Create unified configuration structure for v2.0
            unified_config = {
                "version": "2.0.0",
                "system": {
                    "installation_id": self._generate_installation_id(),
                    "api_enabled": True,
                    "api_port": 8080,
                    "api_host": "localhost",
                    "log_level": "INFO",
                    "max_workers": 4
                },
                "security": {
                    "api_authentication": True,
                    "default_permissions": ["read", "write"],
                    "rate_limiting": {
                        "enabled": True,
                        "requests_per_minute": 100
                    },
                    "encryption": {
                        "algorithm": "AES-256-GCM",
                        "key_derivation": "PBKDF2"
                    }
                },
                "backup": {},
                "scheduler": {},
                "storage": {},
                "monitoring": {
                    "enabled": True,
                    "metrics_retention_days": 30,
                    "health_check_interval": 300,
                    "alert_thresholds": {
                        "disk_usage_percent": 90,
                        "memory_usage_percent": 85,
                        "failed_backups_count": 3
                    }
                }
            }
            
            # Migrate backup items configuration
            backup_items_file = self.config_dir / "backup_items.json"
            if backup_items_file.exists():
                with open(backup_items_file, 'r') as f:
                    backup_config = json.load(f)
                
                unified_config["backup"] = {
                    "items": backup_config.get("backup_items", []),
                    "global_settings": backup_config.get("global_settings", {}),
                    "default_storage_backend": "local_primary",
                    "backup_retention": {
                        "keep_daily": 7,
                        "keep_weekly": 4,
                        "keep_monthly": 12,
                        "keep_yearly": 5
                    }
                }
                
                result["changes"].append(f"Migrated {len(unified_config['backup']['items'])} backup items")
            
            # Migrate scheduler configuration
            scheduler_file = self.config_dir / "scheduler.json"
            if scheduler_file.exists():
                with open(scheduler_file, 'r') as f:
                    scheduler_config = json.load(f)
                
                unified_config["scheduler"] = {
                    "enabled": scheduler_config.get("scheduler_enabled", False),
                    "schedules": scheduler_config.get("schedules", []),
                    "global_settings": scheduler_config.get("global_settings", {}),
                    "advanced_scheduling": scheduler_config.get("advanced_scheduling", {}),
                    "notification_channels": []
                }
                
                result["changes"].append(f"Migrated {len(unified_config['scheduler']['schedules'])} schedules")
            
            # Migrate storage backends configuration  
            storage_file = self.config_dir / "storage_backends.json"
            if storage_file.exists():
                with open(storage_file, 'r') as f:
                    storage_config = json.load(f)
                
                unified_config["storage"] = {
                    "backends": storage_config.get("storage_backends", []),
                    "global_settings": storage_config.get("global_settings", {}),
                    "replication": {
                        "enabled": False,
                        "min_replicas": 1,
                        "preferred_backends": []
                    }
                }
                
                result["changes"].append(f"Migrated {len(unified_config['storage']['backends'])} storage backends")
            
            # Save unified configuration
            unified_config_file = self.config_dir / "blncs_config.json"
            with open(unified_config_file, 'w') as f:
                json.dump(unified_config, f, indent=2)
            
            result["changes"].append("Created unified v2.0 configuration")
            
            # Create API configuration
            api_config = {
                "version": "2.0.0",
                "authentication": {
                    "default_api_key": self._generate_api_key(),
                    "key_expiry_days": 365,
                    "require_https": False
                },
                "cors": {
                    "enabled": True,
                    "allowed_origins": ["http://localhost:3000", "http://localhost:8080"],
                    "allowed_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                    "allowed_headers": ["Content-Type", "Authorization", "X-API-Key"]
                },
                "rate_limiting": {
                    "requests_per_minute": 100,
                    "burst_limit": 20
                }
            }
            
            api_config_file = self.config_dir / "api_config.json"
            with open(api_config_file, 'w') as f:
                json.dump(api_config, f, indent=2)
            
            result["changes"].append("Created API configuration")
            
            # Migration completion marker
            result["warnings"].append("Please update any custom scripts to use the new unified configuration format")
            result["warnings"].append("API endpoints have changed - see API_DOCUMENTATION.md for details")
            
        except Exception as e:
            result["success"] = False
            result["errors"].append(f"Migration failed: {str(e)}")
            logger.error(f"Migration 1.2->2.0 failed: {e}")
        
        return result
    
    def _backup_config_files(self, migration_name: str):
        """Backup existing configuration files before migration"""
        backup_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_subdir = self.backup_dir / f"{migration_name}_{backup_timestamp}"
        backup_subdir.mkdir(parents=True, exist_ok=True)
        
        # Backup all JSON configuration files
        for config_file in self.config_dir.glob("*.json"):
            if config_file.is_file():
                shutil.copy2(config_file, backup_subdir)
        
        # Backup any INI configuration files
        for config_file in self.config_dir.glob("*.conf"):
            if config_file.is_file():
                shutil.copy2(config_file, backup_subdir)
        
        logger.info(f"Configuration backed up to {backup_subdir}")
    
    def _generate_installation_id(self) -> str:
        """Generate unique installation ID"""
        import uuid
        return str(uuid.uuid4())
    
    def _generate_api_key(self) -> str:
        """Generate default API key"""
        import secrets
        return secrets.token_urlsafe(32)
    
    def migrate_ini_to_json(self, ini_file: Path, json_file: Path) -> bool:
        """Convert INI configuration to JSON format"""
        try:
            config = configparser.ConfigParser()
            config.read(ini_file)
            
            json_config = {}
            for section_name in config.sections():
                section = config[section_name]
                json_config[section_name] = dict(section)
            
            with open(json_file, 'w') as f:
                json.dump(json_config, f, indent=2)
            
            logger.info(f"Converted {ini_file} to {json_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to convert {ini_file} to JSON: {e}")
            return False
    
    def validate_configuration(self, config_file: Path) -> Dict[str, Any]:
        """Validate configuration file structure"""
        validation = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "version": None
        }
        
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            # Check version
            validation["version"] = config.get("version", "unknown")
            
            # Validate required sections for v2.0
            if validation["version"] == "2.0.0":
                required_sections = ["system", "backup", "scheduler", "storage"]
                for section in required_sections:
                    if section not in config:
                        validation["errors"].append(f"Missing required section: {section}")
                        validation["valid"] = False
            
            # Validate backup items
            if "backup" in config and "items" in config["backup"]:
                for i, item in enumerate(config["backup"]["items"]):
                    if "name" not in item or "source_path" not in item:
                        validation["errors"].append(f"Backup item {i} missing required fields")
                        validation["valid"] = False
            
            # Validate storage backends
            if "storage" in config and "backends" in config["storage"]:
                for i, backend in enumerate(config["storage"]["backends"]):
                    if "name" not in backend or "type" not in backend:
                        validation["errors"].append(f"Storage backend {i} missing required fields")
                        validation["valid"] = False
            
        except json.JSONDecodeError as e:
            validation["valid"] = False
            validation["errors"].append(f"Invalid JSON: {e}")
        except Exception as e:
            validation["valid"] = False
            validation["errors"].append(f"Configuration validation error: {e}")
        
        return validation
    
    def get_configuration_diff(self, old_config: Path, new_config: Path) -> Dict[str, Any]:
        """Compare two configuration files and show differences"""
        diff = {
            "changes": [],
            "additions": [],
            "removals": [],
            "modifications": []
        }
        
        try:
            with open(old_config, 'r') as f:
                old = json.load(f)
            with open(new_config, 'r') as f:
                new = json.load(f)
            
            # Simple diff implementation - could be enhanced
            old_keys = set(self._flatten_dict(old).keys())
            new_keys = set(self._flatten_dict(new).keys())
            
            diff["additions"] = list(new_keys - old_keys)
            diff["removals"] = list(old_keys - new_keys)
            
            common_keys = old_keys & new_keys
            old_flat = self._flatten_dict(old)
            new_flat = self._flatten_dict(new)
            
            for key in common_keys:
                if old_flat[key] != new_flat[key]:
                    diff["modifications"].append({
                        "key": key,
                        "old_value": old_flat[key],
                        "new_value": new_flat[key]
                    })
            
        except Exception as e:
            logger.error(f"Failed to generate configuration diff: {e}")
        
        return diff
    
    def _flatten_dict(self, d: Dict, parent_key: str = '', sep: str = '.') -> Dict:
        """Flatten nested dictionary for comparison"""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)