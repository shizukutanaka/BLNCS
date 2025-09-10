"""
Auto-Update System
Lightweight automatic update mechanism for BLNCS.
"""

import os
import json
import hashlib
import tempfile
import subprocess
import time
from pathlib import Path
from typing import Dict, Optional, Tuple, Any, List
from dataclasses import dataclass
from urllib.parse import urlparse
import requests
import shutil

from .logger import get_logger
from .config_manager import get_config_manager
from .database import get_database_manager


@dataclass
class UpdateInfo:
    """Information about an available update"""
    current_version: str
    latest_version: str
    update_available: bool
    download_url: str
    changelog: str
    size_mb: float
    is_critical: bool = False
    
    @property
    def version_newer(self) -> bool:
        """Check if latest version is newer than current"""
        return self._compare_versions(self.latest_version, self.current_version) > 0
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings. Returns 1 if v1 > v2, -1 if v1 < v2, 0 if equal"""
        try:
            # Simple version comparison (e.g., "1.2.3" vs "1.2.4")
            v1_parts = [int(x) for x in v1.split('.')]
            v2_parts = [int(x) for x in v2.split('.')]
            
            # Pad shorter version with zeros
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            for i in range(max_len):
                if v1_parts[i] > v2_parts[i]:
                    return 1
                elif v1_parts[i] < v2_parts[i]:
                    return -1
            return 0
        except:
            # Fallback to string comparison
            return 1 if v1 > v2 else -1 if v1 < v2 else 0


@dataclass
class UpdateResult:
    """Result of an update operation"""
    success: bool
    version: str = ""
    error: str = ""
    backup_path: str = ""
    requires_restart: bool = False


class AutoUpdater:
    """Automatic update system for BLNCS"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config_manager = get_config_manager()
        self.db = get_database_manager()
        
        # Update configuration
        self.current_version = self._get_current_version()
        self.update_check_interval = 3600  # 1 hour
        self.update_server_url = "https://api.github.com/repos/example/blncs"  # Replace with actual URL
        self.auto_update_enabled = self._get_auto_update_setting()
        
        # Update cache
        self.last_check_time = 0
        self.cached_update_info: Optional[UpdateInfo] = None
        
        # Paths
        self.install_dir = Path(__file__).parent.parent.parent  # BLNCS root directory
        self.backup_dir = self.install_dir / "backups" / "updates"
        self.temp_dir = Path(tempfile.gettempdir()) / "blncs_updates"
        
        # Create directories
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
    
    def _get_current_version(self) -> str:
        """Get current BLNCS version"""
        try:
            # Try to read from version file
            version_file = self.install_dir / "VERSION"
            if version_file.exists():
                return version_file.read_text().strip()
            
            # Try to read from setup.py or similar
            setup_file = self.install_dir / "setup.py" 
            if setup_file.exists():
                setup_content = setup_file.read_text()
                # Extract version from setup.py (simple regex)
                import re
                match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', setup_content)
                if match:
                    return match.group(1)
            
            # Fallback version
            return "0.1.0"
            
        except Exception as e:
            self.logger.warning(f"Could not determine current version: {e}")
            return "unknown"
    
    def _get_auto_update_setting(self) -> bool:
        """Get auto-update setting from config"""
        return self.config_manager.get('system.auto_update_enabled', False)
    
    def check_for_updates(self, force: bool = False) -> Optional[UpdateInfo]:
        """
        Check for available updates
        
        Args:
            force: Force check even if recently checked
            
        Returns:
            UpdateInfo if update available, None otherwise
        """
        current_time = time.time()
        
        # Use cached result if recent and not forced
        if (not force and 
            self.cached_update_info and 
            current_time - self.last_check_time < self.update_check_interval):
            return self.cached_update_info if self.cached_update_info.update_available else None
        
        self.logger.info("Checking for updates...")
        
        try:
            # Check for updates from server
            update_info = self._fetch_update_info()
            
            self.last_check_time = current_time
            self.cached_update_info = update_info
            
            if update_info and update_info.update_available:
                self.logger.info(f"Update available: {update_info.current_version} -> {update_info.latest_version}")
                return update_info
            else:
                self.logger.info("No updates available")
                return None
                
        except Exception as e:
            self.logger.error(f"Update check failed: {e}")
            return None
    
    def _fetch_update_info(self) -> Optional[UpdateInfo]:
        """Fetch update information from server"""
        try:
            # Simulate update server response
            # In a real implementation, this would contact an actual update server
            
            # For demonstration, we'll simulate a newer version occasionally
            import random
            
            latest_version = "0.2.0"  # Simulated latest version
            download_url = f"{self.update_server_url}/releases/download/v{latest_version}/blncs-{latest_version}.zip"
            changelog = "Bug fixes and performance improvements"
            
            update_info = UpdateInfo(
                current_version=self.current_version,
                latest_version=latest_version,
                update_available=latest_version != self.current_version,
                download_url=download_url,
                changelog=changelog,
                size_mb=2.5,
                is_critical=False
            )
            
            return update_info
            
        except requests.RequestException as e:
            self.logger.error(f"Failed to fetch update info: {e}")
            return None
    
    def download_update(self, update_info: UpdateInfo) -> Optional[Path]:
        """
        Download update package
        
        Args:
            update_info: Update information
            
        Returns:
            Path to downloaded file or None if failed
        """
        try:
            self.logger.info(f"Downloading update {update_info.latest_version}...")
            
            # Create download path
            filename = f"blncs-{update_info.latest_version}.zip"
            download_path = self.temp_dir / filename
            
            # For demonstration, create a dummy update file
            # In a real implementation, this would download from update_info.download_url
            dummy_content = json.dumps({
                "version": update_info.latest_version,
                "changelog": update_info.changelog,
                "files": ["blncs/", "config/", "tests/"]
            }, indent=2).encode()
            
            download_path.write_bytes(dummy_content)
            
            self.logger.info(f"Update downloaded: {download_path}")
            return download_path
            
        except Exception as e:
            self.logger.error(f"Update download failed: {e}")
            return None
    
    def backup_current_installation(self) -> Optional[Path]:
        """
        Create backup of current installation
        
        Returns:
            Path to backup or None if failed
        """
        try:
            timestamp = int(time.time())
            backup_name = f"blncs-backup-{self.current_version}-{timestamp}"
            backup_path = self.backup_dir / backup_name
            
            self.logger.info(f"Creating backup: {backup_path}")
            
            # Create backup directory
            backup_path.mkdir(exist_ok=True)
            
            # Copy essential files
            essential_dirs = ["blncs", "config"]
            essential_files = ["requirements.txt", "VERSION"]
            
            for dir_name in essential_dirs:
                src_dir = self.install_dir / dir_name
                if src_dir.exists():
                    dst_dir = backup_path / dir_name
                    shutil.copytree(src_dir, dst_dir, dirs_exist_ok=True)
            
            for file_name in essential_files:
                src_file = self.install_dir / file_name
                if src_file.exists():
                    dst_file = backup_path / file_name
                    shutil.copy2(src_file, dst_file)
            
            # Create backup metadata
            metadata = {
                "version": self.current_version,
                "backup_time": timestamp,
                "backup_type": "auto_update"
            }
            
            metadata_file = backup_path / "backup_metadata.json"
            metadata_file.write_text(json.dumps(metadata, indent=2))
            
            self.logger.info(f"Backup created successfully: {backup_path}")
            return backup_path
            
        except Exception as e:
            self.logger.error(f"Backup creation failed: {e}")
            return None
    
    def apply_update(self, update_path: Path, backup_path: Optional[Path] = None) -> UpdateResult:
        """
        Apply downloaded update
        
        Args:
            update_path: Path to update package
            backup_path: Path to backup (for rollback)
            
        Returns:
            UpdateResult with operation status
        """
        try:
            self.logger.info("Applying update...")
            
            # For demonstration, simulate update application
            # In a real implementation, this would extract and copy files
            
            # Update version file
            version_file = self.install_dir / "VERSION"
            
            # Read update info from downloaded file
            update_content = json.loads(update_path.read_text())
            new_version = update_content["version"]
            
            # Write new version
            version_file.write_text(new_version)
            
            # Update configuration if needed
            self._update_configuration(new_version)
            
            # Log successful update
            self._log_update(new_version, True)
            
            self.logger.info(f"Update applied successfully: {new_version}")
            
            return UpdateResult(
                success=True,
                version=new_version,
                backup_path=str(backup_path) if backup_path else "",
                requires_restart=True
            )
            
        except Exception as e:
            self.logger.error(f"Update application failed: {e}")
            return UpdateResult(
                success=False,
                error=str(e)
            )
    
    def rollback_update(self, backup_path: Path) -> bool:
        """
        Rollback to previous version using backup
        
        Args:
            backup_path: Path to backup directory
            
        Returns:
            True if rollback successful
        """
        try:
            self.logger.info(f"Rolling back update from: {backup_path}")
            
            # Read backup metadata
            metadata_file = backup_path / "backup_metadata.json"
            if metadata_file.exists():
                metadata = json.loads(metadata_file.read_text())
                old_version = metadata["version"]
            else:
                old_version = "unknown"
            
            # Restore files from backup
            for item in backup_path.iterdir():
                if item.name == "backup_metadata.json":
                    continue
                
                dst_path = self.install_dir / item.name
                
                if item.is_dir():
                    if dst_path.exists():
                        shutil.rmtree(dst_path)
                    shutil.copytree(item, dst_path)
                else:
                    shutil.copy2(item, dst_path)
            
            # Log rollback
            self._log_update(old_version, False, rollback=True)
            
            self.logger.info(f"Rollback completed: restored version {old_version}")
            return True
            
        except Exception as e:
            self.logger.error(f"Rollback failed: {e}")
            return False
    
    def auto_update(self) -> Optional[UpdateResult]:
        """
        Perform automatic update if enabled and update available
        
        Returns:
            UpdateResult if update was attempted, None if no action taken
        """
        if not self.auto_update_enabled:
            return None
        
        # Check for updates
        update_info = self.check_for_updates()
        if not update_info:
            return None
        
        self.logger.info("Starting automatic update process...")
        
        try:
            # Create backup first
            backup_path = self.backup_current_installation()
            if not backup_path:
                return UpdateResult(success=False, error="Backup creation failed")
            
            # Download update
            update_path = self.download_update(update_info)
            if not update_path:
                return UpdateResult(success=False, error="Update download failed")
            
            # Apply update
            result = self.apply_update(update_path, backup_path)
            
            # Cleanup temp files
            try:
                if update_path.exists():
                    update_path.unlink()
            except:
                pass
            
            return result
            
        except Exception as e:
            self.logger.error(f"Auto update failed: {e}")
            return UpdateResult(success=False, error=str(e))
    
    def _update_configuration(self, new_version: str):
        """Update configuration for new version if needed"""
        try:
            # Check if configuration updates are needed
            config_updates = self._get_config_updates(new_version)
            
            if config_updates:
                self.logger.info("Applying configuration updates...")
                for key, value in config_updates.items():
                    self.config_manager.set(key, value)
                    
        except Exception as e:
            self.logger.warning(f"Configuration update failed: {e}")
    
    def _get_config_updates(self, version: str) -> Dict[str, Any]:
        """Get configuration updates needed for version"""
        # Define version-specific configuration updates
        version_configs = {
            "0.2.0": {
                "system.new_feature_enabled": True,
                "performance.optimization_level": 2
            }
        }
        
        return version_configs.get(version, {})
    
    def _log_update(self, version: str, success: bool, rollback: bool = False):
        """Log update operation to database"""
        try:
            event_type = "rollback" if rollback else "update"
            status = "success" if success else "failed"
            
            self.db.record_event(
                event_type=f"auto_{event_type}",
                severity="info" if success else "error",
                message=f"Auto {event_type} to version {version}: {status}",
                details={
                    "version": version,
                    "success": success,
                    "rollback": rollback,
                    "timestamp": int(time.time())
                }
            )
        except Exception as e:
            self.logger.error(f"Failed to log update: {e}")
    
    def get_update_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get history of update operations"""
        try:
            events = self.db.get_events(
                event_types=["auto_update", "auto_rollback"],
                limit=limit
            )
            
            history = []
            for event in events:
                history.append({
                    "timestamp": event["timestamp"],
                    "type": event["event_type"],
                    "version": event["details"].get("version", "unknown"),
                    "success": event["details"].get("success", False),
                    "message": event["message"]
                })
            
            return history
            
        except Exception as e:
            self.logger.error(f"Failed to get update history: {e}")
            return []
    
    def cleanup_old_backups(self, keep_count: int = 5):
        """Clean up old backup directories"""
        try:
            if not self.backup_dir.exists():
                return
            
            # Get all backup directories
            backups = []
            for item in self.backup_dir.iterdir():
                if item.is_dir() and item.name.startswith("blncs-backup-"):
                    backups.append(item)
            
            # Sort by modification time (newest first)
            backups.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            
            # Remove old backups
            for backup in backups[keep_count:]:
                self.logger.info(f"Removing old backup: {backup.name}")
                shutil.rmtree(backup)
                
        except Exception as e:
            self.logger.error(f"Backup cleanup failed: {e}")
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get system information for update purposes"""
        return {
            "current_version": self.current_version,
            "auto_update_enabled": self.auto_update_enabled,
            "last_check_time": self.last_check_time,
            "install_directory": str(self.install_dir),
            "update_available": self.cached_update_info.update_available if self.cached_update_info else False
        }


def get_auto_updater() -> AutoUpdater:
    """Get singleton AutoUpdater instance"""
    return AutoUpdater()