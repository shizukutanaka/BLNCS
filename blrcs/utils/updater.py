# BLRCS Auto-Update Module
# Self-updating mechanism with rollback support
import os
import sys
import json
import shutil
import hashlib
import tempfile
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from datetime import datetime
import requests
import zipfile
import tarfile
from packaging import version

class AutoUpdater:
    """
    Automatic update system with safety checks.
    Supports incremental updates and rollback.
    """
    
    def __init__(self, app_path: Path = None, 
                 update_url: str = None,
                 current_version: str = "0.0.1"):
        """
        Initialize auto-updater.
        
        Args:
            app_path: Application installation path
            update_url: URL to check for updates
            current_version: Current application version
        """
        self.app_path = app_path or Path(sys.argv[0]).parent
        self.update_url = update_url or os.environ.get('BLRCS_UPDATE_URL', '')
        self.current_version = current_version
        
        # Paths
        self.backup_dir = self.app_path / '.backup'
        self.temp_dir = Path(tempfile.gettempdir()) / 'blrcs_update'
        self.update_log = self.app_path / 'update.log'
        
        # Create directories
        self.backup_dir.mkdir(exist_ok=True)
        self.temp_dir.mkdir(exist_ok=True)
    
    def check_for_updates(self) -> Optional[Dict[str, Any]]:
        """
        Check if updates are available.
        
        Returns:
            Update information if available, None otherwise
        """
        if not self.update_url:
            return None
        
        try:
            # Fetch update manifest
            response = requests.get(
                f"{self.update_url}/manifest.json",
                timeout=10
            )
            response.raise_for_status()
            
            manifest = response.json()
            latest_version = manifest.get('version')
            
            # Compare versions
            if version.parse(latest_version) > version.parse(self.current_version):
                return {
                    'version': latest_version,
                    'download_url': manifest.get('download_url'),
                    'changelog': manifest.get('changelog', ''),
                    'size': manifest.get('size', 0),
                    'checksum': manifest.get('checksum'),
                    'release_date': manifest.get('release_date')
                }
            
            return None
        
        except Exception as e:
            self._log(f"Failed to check for updates: {e}")
            return None
    
    def download_update(self, update_info: Dict[str, Any]) -> Optional[Path]:
        """
        Download update package.
        
        Args:
            update_info: Update information from check_for_updates
            
        Returns:
            Path to downloaded update package
        """
        download_url = update_info.get('download_url')
        
        if not download_url:
            return None
        
        try:
            # Download file
            update_file = self.temp_dir / f"update_{update_info['version']}.zip"
            
            response = requests.get(download_url, stream=True)
            response.raise_for_status()
            
            # Save with progress
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            with open(update_file, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        
                        # Progress callback
                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            self._log(f"Download progress: {progress:.1f}%")
            
            # Verify checksum
            if update_info.get('checksum'):
                if not self._verify_checksum(update_file, update_info['checksum']):
                    update_file.unlink()
                    self._log("Checksum verification failed")
                    return None
            
            return update_file
        
        except Exception as e:
            self._log(f"Failed to download update: {e}")
            return None
    
    def create_backup(self) -> bool:
        """
        Create backup of current installation.
        
        Returns:
            True if backup successful
        """
        try:
            # Create timestamped backup
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = self.backup_dir / f"backup_{timestamp}"
            
            # Copy current installation
            if self.app_path.is_dir():
                shutil.copytree(
                    self.app_path,
                    backup_path,
                    ignore=shutil.ignore_patterns(
                        '*.pyc', '__pycache__', '.backup', '*.log'
                    )
                )
            
            # Keep only last 3 backups
            self._cleanup_old_backups()
            
            self._log(f"Backup created: {backup_path}")
            return True
        
        except Exception as e:
            self._log(f"Failed to create backup: {e}")
            return False
    
    def apply_update(self, update_file: Path) -> bool:
        """
        Apply update from downloaded package.
        
        Args:
            update_file: Path to update package
            
        Returns:
            True if update successful
        """
        try:
            # Create backup first
            if not self.create_backup():
                return False
            
            # Extract update
            extract_dir = self.temp_dir / 'extract'
            extract_dir.mkdir(exist_ok=True)
            
            if update_file.suffix == '.zip':
                with zipfile.ZipFile(update_file, 'r') as zf:
                    zf.extractall(extract_dir)
            
            elif update_file.suffix in ['.tar', '.gz', '.bz2']:
                with tarfile.open(update_file, 'r:*') as tf:
                    tf.extractall(extract_dir)
            
            else:
                self._log(f"Unsupported update format: {update_file.suffix}")
                return False
            
            # Apply update files
            self._apply_files(extract_dir)
            
            # Run post-update scripts if any
            self._run_post_update_scripts(extract_dir)
            
            # Cleanup
            shutil.rmtree(extract_dir, ignore_errors=True)
            update_file.unlink()
            
            self._log("Update applied successfully")
            return True
        
        except Exception as e:
            self._log(f"Failed to apply update: {e}")
            
            # Attempt rollback
            self.rollback()
            return False
    
    def _apply_files(self, source_dir: Path):
        """Apply update files to installation"""
        # Update manifest if exists
        manifest_file = source_dir / 'update_manifest.json'
        
        if manifest_file.exists():
            with open(manifest_file, 'r') as f:
                manifest = json.load(f)
            
            # Process file operations
            for operation in manifest.get('operations', []):
                op_type = operation['type']
                
                if op_type == 'add' or op_type == 'update':
                    src = source_dir / operation['source']
                    dst = self.app_path / operation['destination']
                    
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(src, dst)
                
                elif op_type == 'delete':
                    target = self.app_path / operation['target']
                    if target.exists():
                        if target.is_dir():
                            shutil.rmtree(target)
                        else:
                            target.unlink()
        
        else:
            # Simple copy all files
            for item in source_dir.iterdir():
                if item.name not in ['update_manifest.json', 'post_update.py']:
                    dst = self.app_path / item.name
                    
                    if item.is_dir():
                        if dst.exists():
                            shutil.rmtree(dst)
                        shutil.copytree(item, dst)
                    else:
                        shutil.copy2(item, dst)
    
    def _run_post_update_scripts(self, extract_dir: Path):
        """Run post-update scripts if present"""
        script_file = extract_dir / 'post_update.py'
        
        if script_file.exists():
            try:
                subprocess.run(
                    [sys.executable, str(script_file)],
                    cwd=self.app_path,
                    check=True,
                    capture_output=True,
                    text=True
                )
                self._log("Post-update script executed")
            except subprocess.CalledProcessError as e:
                self._log(f"Post-update script failed: {e.stderr}")
    
    def rollback(self) -> bool:
        """
        Rollback to previous version from backup.
        
        Returns:
            True if rollback successful
        """
        try:
            # Find latest backup
            backups = sorted(self.backup_dir.glob("backup_*"))
            
            if not backups:
                self._log("No backup available for rollback")
                return False
            
            latest_backup = backups[-1]
            
            # Restore from backup
            for item in latest_backup.iterdir():
                dst = self.app_path / item.name
                
                if dst.exists():
                    if dst.is_dir():
                        shutil.rmtree(dst)
                    else:
                        dst.unlink()
                
                if item.is_dir():
                    shutil.copytree(item, dst)
                else:
                    shutil.copy2(item, dst)
            
            self._log(f"Rolled back to: {latest_backup.name}")
            return True
        
        except Exception as e:
            self._log(f"Rollback failed: {e}")
            return False
    
    def _verify_checksum(self, file_path: Path, expected_checksum: str) -> bool:
        """Verify file checksum"""
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        
        return sha256.hexdigest() == expected_checksum
    
    def _cleanup_old_backups(self, keep: int = 3):
        """Keep only recent backups"""
        backups = sorted(self.backup_dir.glob("backup_*"))
        
        if len(backups) > keep:
            for backup in backups[:-keep]:
                shutil.rmtree(backup)
    
    def _log(self, message: str):
        """Log update events"""
        timestamp = datetime.now().isoformat()
        log_entry = f"[{timestamp}] {message}\n"
        
        with open(self.update_log, 'a') as f:
            f.write(log_entry)
        
        print(message)
    
    def auto_update(self) -> bool:
        """
        Perform automatic update if available.
        
        Returns:
            True if update performed successfully
        """
        # Check for updates
        update_info = self.check_for_updates()
        
        if not update_info:
            self._log("No updates available")
            return False
        
        self._log(f"Update available: {update_info['version']}")
        
        # Download update
        update_file = self.download_update(update_info)
        
        if not update_file:
            return False
        
        # Apply update
        if self.apply_update(update_file):
            self._log(f"Successfully updated to version {update_info['version']}")
            
            # Update version
            self.current_version = update_info['version']
            
            # Restart application if needed
            if self._should_restart():
                self.restart_application()
            
            return True
        
        return False
    
    def _should_restart(self) -> bool:
        """Check if application should restart after update"""
        # Can be customized based on update type
        return os.environ.get('BLRCS_AUTO_RESTART', 'false').lower() == 'true'
    
    def restart_application(self):
        """Restart the application"""
        self._log("Restarting application...")
        
        # Launch new instance - 安全な引数検証
        safe_args = [arg for arg in sys.argv if not arg.startswith('../') and not arg.startswith('..\\')]
        subprocess.Popen([sys.executable] + safe_args)
        
        # Exit current instance
        sys.exit(0)

class UpdateScheduler:
    """
    Schedule automatic update checks.
    Runs in background without blocking.
    """
    
    def __init__(self, updater: AutoUpdater, 
                 check_interval: int = 86400):  # Daily by default
        self.updater = updater
        self.check_interval = check_interval
        self.running = False
    
    async def start(self):
        """Start scheduled update checks"""
        import asyncio
        
        self.running = True
        
        while self.running:
            try:
                # Check for updates
                update_info = self.updater.check_for_updates()
                
                if update_info:
                    # Notify about available update
                    print(f"Update available: {update_info['version']}")
                    
                    # Auto-update if configured
                    if os.environ.get('BLRCS_AUTO_UPDATE', 'false').lower() == 'true':
                        self.updater.auto_update()
            
            except Exception:
                pass
            
            # Wait for next check
            await asyncio.sleep(self.check_interval)
    
    def stop(self):
        """Stop scheduled checks"""
        self.running = False

# Global updater instance
_updater: Optional[AutoUpdater] = None

def get_updater(current_version: str = "0.0.1") -> AutoUpdater:
    """Get global updater instance"""
    global _updater
    
    if _updater is None:
        _updater = AutoUpdater(current_version=current_version)
    
    return _updater

def check_and_update(current_version: str = "0.0.1") -> bool:
    """
    Quick function to check and apply updates.
    
    Returns:
        True if update was applied
    """
    updater = get_updater(current_version)
    return updater.auto_update()