#!/usr/bin/env python3
"""
BLNCS Version Manager
Handles version detection, compatibility checking, and upgrade paths.
"""

import json
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

@dataclass
class Version:
    """Version representation with semantic versioning"""
    major: int
    minor: int
    patch: int
    pre_release: Optional[str] = None
    
    @classmethod
    def from_string(cls, version_str: str) -> 'Version':
        """Parse version string into Version object"""
        # Handle semantic versioning (1.2.3-alpha.1)
        pattern = r'^(\d+)\.(\d+)\.(\d+)(?:-([a-zA-Z0-9.-]+))?$'
        match = re.match(pattern, version_str.strip())
        
        if not match:
            raise ValueError(f"Invalid version format: {version_str}")
        
        major, minor, patch, pre_release = match.groups()
        return cls(
            major=int(major),
            minor=int(minor), 
            patch=int(patch),
            pre_release=pre_release
        )
    
    def __str__(self) -> str:
        version_str = f"{self.major}.{self.minor}.{self.patch}"
        if self.pre_release:
            version_str += f"-{self.pre_release}"
        return version_str
    
    def __lt__(self, other: 'Version') -> bool:
        if (self.major, self.minor, self.patch) != (other.major, other.minor, other.patch):
            return (self.major, self.minor, self.patch) < (other.major, other.minor, other.patch)
        
        # Handle pre-release versions
        if self.pre_release is None and other.pre_release is not None:
            return False  # 1.0.0 > 1.0.0-alpha
        if self.pre_release is not None and other.pre_release is None:
            return True   # 1.0.0-alpha < 1.0.0
        if self.pre_release is not None and other.pre_release is not None:
            return self.pre_release < other.pre_release
        
        return False
    
    def __eq__(self, other: 'Version') -> bool:
        return (self.major, self.minor, self.patch, self.pre_release) == \
               (other.major, other.minor, other.patch, other.pre_release)
    
    def __le__(self, other: 'Version') -> bool:
        return self < other or self == other
    
    def is_compatible(self, other: 'Version') -> bool:
        """Check if versions are compatible (same major version)"""
        return self.major == other.major

class VersionManager:
    """Manage version detection and upgrade paths"""
    
    def __init__(self, config_dir: str = None):
        self.config_dir = Path(config_dir or os.path.expanduser("~/.blncs"))
        self.version_file = self.config_dir / "version.json"
        self.current_version = Version.from_string("2.0.0")
        
        # Version compatibility matrix
        self.compatibility_matrix = {
            "1.0.0": ["1.0.x", "1.1.x"],
            "1.1.0": ["1.0.x", "1.1.x", "1.2.x"],
            "1.2.0": ["1.1.x", "1.2.x", "2.0.x"],
            "2.0.0": ["1.2.x", "2.0.x", "2.1.x"]
        }
        
        # Migration paths between versions
        self.migration_paths = {
            ("1.0.0", "1.1.0"): "migrate_1_0_to_1_1",
            ("1.1.0", "1.2.0"): "migrate_1_1_to_1_2",
            ("1.2.0", "2.0.0"): "migrate_1_2_to_2_0",
            ("2.0.0", "2.1.0"): "migrate_2_0_to_2_1"
        }
    
    def detect_installed_version(self) -> Optional[Version]:
        """Detect currently installed BLNCS version"""
        
        # Check version file first
        if self.version_file.exists():
            try:
                with open(self.version_file, 'r') as f:
                    version_data = json.load(f)
                    return Version.from_string(version_data.get('version', '1.0.0'))
            except Exception as e:
                logger.warning(f"Could not read version file: {e}")
        
        # Check legacy config files for version hints
        legacy_paths = [
            self.config_dir / "blncs.conf",
            self.config_dir / "config.json",
            Path("/etc/blncs/blncs.conf")
        ]
        
        for path in legacy_paths:
            if path.exists():
                version = self._detect_version_from_config(path)
                if version:
                    return version
        
        # Check for specific file patterns that indicate versions
        version_indicators = {
            "1.0.0": ["backup_config.json", "simple_backup.py"],
            "1.1.0": ["scheduler.json", "automated_backup.py"],
            "1.2.0": ["storage_backends.json", "recovery_enhanced.py"],
            "2.0.0": ["api/endpoints.py", "core/service_container.py"]
        }
        
        for version_str, indicators in version_indicators.items():
            if all((self.config_dir.parent / "blncs" / indicator).exists() for indicator in indicators):
                return Version.from_string(version_str)
        
        # Default to oldest version if nothing detected
        return Version.from_string("1.0.0")
    
    def _detect_version_from_config(self, config_path: Path) -> Optional[Version]:
        """Try to detect version from config file contents"""
        try:
            content = config_path.read_text()
            
            # Look for version indicators in config
            if 'api_endpoints' in content and 'service_container' in content:
                return Version.from_string("2.0.0")
            elif 'storage_backends' in content and 'recovery_enhanced' in content:
                return Version.from_string("1.2.0")
            elif 'scheduler' in content and 'automated_backup' in content:
                return Version.from_string("1.1.0")
            elif 'backup_config' in content:
                return Version.from_string("1.0.0")
                
        except Exception as e:
            logger.debug(f"Could not read config file {config_path}: {e}")
        
        return None
    
    def save_version_info(self, version: Version, installation_info: Dict = None):
        """Save version information to version file"""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        version_data = {
            'version': str(version),
            'installed_at': installation_info.get('timestamp') if installation_info else None,
            'installation_type': installation_info.get('type') if installation_info else 'standard',
            'previous_version': installation_info.get('previous_version') if installation_info else None,
            'migration_applied': installation_info.get('migration_applied') if installation_info else False
        }
        
        try:
            with open(self.version_file, 'w') as f:
                json.dump(version_data, f, indent=2)
            logger.info(f"Saved version info: {version}")
        except Exception as e:
            logger.error(f"Failed to save version info: {e}")
    
    def check_upgrade_needed(self) -> Tuple[bool, Optional[Version], List[str]]:
        """Check if upgrade is needed and return upgrade path"""
        installed_version = self.detect_installed_version()
        
        if not installed_version:
            return True, None, ["fresh_install"]
        
        if installed_version == self.current_version:
            return False, installed_version, []
        
        if installed_version > self.current_version:
            logger.warning(f"Installed version {installed_version} is newer than current {self.current_version}")
            return False, installed_version, []
        
        # Find upgrade path
        upgrade_path = self._find_upgrade_path(installed_version, self.current_version)
        return True, installed_version, upgrade_path
    
    def _find_upgrade_path(self, from_version: Version, to_version: Version) -> List[str]:
        """Find the migration path between versions"""
        path = []
        current = from_version
        
        # Direct path available
        if (str(from_version), str(to_version)) in self.migration_paths:
            return [self.migration_paths[(str(from_version), str(to_version))]]
        
        # Find intermediate steps
        intermediate_versions = [
            Version.from_string("1.1.0"),
            Version.from_string("1.2.0"),
            Version.from_string("2.0.0")
        ]
        
        for intermediate in intermediate_versions:
            if current < intermediate <= to_version:
                if (str(current), str(intermediate)) in self.migration_paths:
                    path.append(self.migration_paths[(str(current), str(intermediate))])
                    current = intermediate
        
        # Final step to target version
        if current < to_version and (str(current), str(to_version)) in self.migration_paths:
            path.append(self.migration_paths[(str(current), str(to_version))])
        
        return path
    
    def is_version_compatible(self, version: Version) -> bool:
        """Check if a version is compatible with current version"""
        return version.is_compatible(self.current_version)
    
    def get_breaking_changes(self, from_version: Version, to_version: Version) -> List[Dict]:
        """Get list of breaking changes between versions"""
        breaking_changes = []
        
        # Define breaking changes by version
        version_changes = {
            "2.0.0": [
                {
                    "type": "config_format",
                    "description": "Configuration format changed from INI to JSON",
                    "action_required": "Configuration will be automatically migrated"
                },
                {
                    "type": "api_endpoints", 
                    "description": "REST API endpoints restructured",
                    "action_required": "Update any custom scripts using the API"
                },
                {
                    "type": "backup_format",
                    "description": "Backup metadata format updated",
                    "action_required": "Existing backups remain compatible"
                },
                {
                    "type": "python_version",
                    "description": "Minimum Python version increased to 3.8",
                    "action_required": "Upgrade Python if using older version"
                }
            ],
            "1.2.0": [
                {
                    "type": "storage_backends",
                    "description": "Storage backend configuration restructured", 
                    "action_required": "Storage backends will be automatically migrated"
                }
            ],
            "1.1.0": [
                {
                    "type": "scheduler_format",
                    "description": "Backup scheduler configuration format changed",
                    "action_required": "Existing schedules will be automatically migrated"
                }
            ]
        }
        
        # Collect breaking changes for version range
        for version_str, changes in version_changes.items():
            version = Version.from_string(version_str)
            if from_version < version <= to_version:
                breaking_changes.extend(changes)
        
        return breaking_changes
    
    def validate_upgrade_requirements(self, target_version: Version = None) -> Dict:
        """Validate system requirements for upgrade"""
        target = target_version or self.current_version
        
        requirements = {
            "python_version": True,
            "disk_space": True,
            "permissions": True,
            "dependencies": True,
            "backup_space": True,
            "errors": [],
            "warnings": []
        }
        
        # Check Python version
        import sys
        if sys.version_info < (3, 8):
            requirements["python_version"] = False
            requirements["errors"].append("Python 3.8+ required for BLNCS 2.0+")
        
        # Check disk space (simplified)
        try:
            import shutil
            total, used, free = shutil.disk_usage(self.config_dir.parent)
            if free < 100 * 1024 * 1024:  # 100MB minimum
                requirements["disk_space"] = False
                requirements["errors"].append("Insufficient disk space for upgrade")
        except Exception:
            requirements["warnings"].append("Could not check disk space")
        
        # Check write permissions
        if not os.access(self.config_dir.parent, os.W_OK):
            requirements["permissions"] = False
            requirements["errors"].append("No write permission to BLNCS directory")
        
        return requirements