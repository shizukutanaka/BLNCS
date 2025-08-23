# BLNCS Backup Module
# Automatic backup and restore functionality
import os
import json
import shutil
import asyncio
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import hashlib
from dataclasses import dataclass
import time

from .compression import Compressor, CompressionType
from .database import Database
from .logger import get_logger

logger = get_logger(__name__)

@dataclass
class BackupInfo:
    """Backup information"""
    id: str
    path: str
    source: str
    type: str  # full, incremental
    size: int
    hash: str
    timestamp: float
    duration: float

class BackupManager:
    """
    Automatic backup and restore manager.
    Implements incremental and full backups with compression.
    """
    
    def __init__(self, backup_dir: Path = Path("backups"), 
                 max_backups: int = 10,
                 compress: bool = True):
        self.backup_dir = Path(backup_dir)
        self.max_backups = max_backups
        self.compress = compress
        self.compressor = Compressor(CompressionType.GZIP) if compress else None
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Backup metadata
        self.metadata_file = self.backup_dir / "backup_metadata.json"
        self.metadata = self._load_metadata()
    
    def _load_metadata(self) -> Dict[str, Any]:
        """Load backup metadata"""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        
        return {
            "backups": [],
            "last_full": None,
            "last_incremental": None,
            "total_backups": 0
        }
    
    def _save_metadata(self):
        """Save backup metadata"""
        with open(self.metadata_file, 'w') as f:
            json.dump(self.metadata, f, indent=2, default=str)
    
    async def backup(self, source_path: Path, backup_type: str = "full") -> Dict[str, Any]:
        """
        Create a backup of the specified path.
        
        Args:
            source_path: Path to backup
            backup_type: "full" or "incremental"
            
        Returns:
            Backup information dictionary
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{source_path.name}_{backup_type}_{timestamp}"
        
        if self.compress:
            backup_name += ".tar.gz"
        
        backup_path = self.backup_dir / backup_name
        
        # Create backup
        if backup_type == "full":
            result = await self._create_full_backup(source_path, backup_path)
        else:
            result = await self._create_incremental_backup(source_path, backup_path)
        
        # Update metadata
        backup_info = {
            "name": backup_name,
            "path": str(backup_path),
            "source": str(source_path),
            "type": backup_type,
            "timestamp": timestamp,
            "size": backup_path.stat().st_size if backup_path.exists() else 0,
            "compressed": self.compress,
            "checksum": self._calculate_checksum(backup_path) if backup_path.exists() else None
        }
        
        self.metadata["backups"].append(backup_info)
        self.metadata["total_backups"] += 1
        
        if backup_type == "full":
            self.metadata["last_full"] = timestamp
        else:
            self.metadata["last_incremental"] = timestamp
        
        # Cleanup old backups
        await self._cleanup_old_backups()
        
        self._save_metadata()
        
        logger.info(f"Backup created: {backup_name}")
        return backup_info
    
    async def _create_full_backup(self, source: Path, destination: Path) -> bool:
        """Create a full backup"""
        try:
            if self.compress:
                # Create tar.gz archive
                import tarfile
                with tarfile.open(destination, "w:gz") as tar:
                    tar.add(source, arcname=source.name)
            else:
                # Copy directory
                if source.is_dir():
                    shutil.copytree(source, destination, dirs_exist_ok=True)
                else:
                    shutil.copy2(source, destination)
            
            return True
        except Exception as e:
            logger.error(f"Full backup failed: {e}")
            return False
    
    async def _create_incremental_backup(self, source: Path, destination: Path) -> bool:
        """Create an incremental backup (only changed files)"""
        try:
            # Get last full backup timestamp
            last_full = self.metadata.get("last_full")
            if not last_full:
                # No full backup exists, create one instead
                return await self._create_full_backup(source, destination)
            
            # Parse timestamp
            last_full_time = datetime.strptime(last_full, "%Y%m%d_%H%M%S")
            
            # Find changed files
            changed_files = []
            for file_path in source.rglob("*"):
                if file_path.is_file():
                    mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
                    if mtime > last_full_time:
                        changed_files.append(file_path)
            
            if not changed_files:
                logger.info("No changes detected for incremental backup")
                return False
            
            # Create incremental backup
            if self.compress:
                import tarfile
                with tarfile.open(destination, "w:gz") as tar:
                    for file_path in changed_files:
                        arcname = file_path.relative_to(source.parent)
                        tar.add(file_path, arcname=str(arcname))
            else:
                # Create directory structure
                destination.mkdir(parents=True, exist_ok=True)
                for file_path in changed_files:
                    rel_path = file_path.relative_to(source)
                    dest_file = destination / rel_path
                    dest_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(file_path, dest_file)
            
            logger.info(f"Incremental backup created with {len(changed_files)} changed files")
            return True
            
        except Exception as e:
            logger.error(f"Incremental backup failed: {e}")
            return False
    
    async def restore(self, backup_name: str, destination: Path) -> bool:
        """
        Restore from a backup.
        
        Args:
            backup_name: Name of the backup to restore
            destination: Where to restore the backup
            
        Returns:
            True if successful
        """
        # Find backup in metadata
        backup_info = None
        for backup in self.metadata["backups"]:
            if backup["name"] == backup_name:
                backup_info = backup
                break
        
        if not backup_info:
            logger.error(f"Backup not found: {backup_name}")
            return False
        
        backup_path = Path(backup_info["path"])
        if not backup_path.exists():
            logger.error(f"Backup file not found: {backup_path}")
            return False
        
        # Verify checksum
        if backup_info.get("checksum"):
            current_checksum = self._calculate_checksum(backup_path)
            if current_checksum != backup_info["checksum"]:
                logger.error("Backup checksum mismatch - file may be corrupted")
                return False
        
        try:
            if backup_info.get("compressed"):
                # Extract compressed backup
                import tarfile
                with tarfile.open(backup_path, "r:gz") as tar:
                    tar.extractall(destination)
            else:
                # Copy backup
                if backup_path.is_dir():
                    shutil.copytree(backup_path, destination, dirs_exist_ok=True)
                else:
                    shutil.copy2(backup_path, destination)
            
            logger.info(f"Backup restored: {backup_name} to {destination}")
            return True
            
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            return False
    
    async def _cleanup_old_backups(self):
        """Remove old backups exceeding max_backups limit"""
        if len(self.metadata["backups"]) <= self.max_backups:
            return
        
        # Sort by timestamp (oldest first)
        backups = sorted(self.metadata["backups"], 
                        key=lambda x: x["timestamp"])
        
        # Remove oldest backups
        to_remove = len(backups) - self.max_backups
        for i in range(to_remove):
            backup = backups[i]
            backup_path = Path(backup["path"])
            
            try:
                if backup_path.exists():
                    if backup_path.is_dir():
                        shutil.rmtree(backup_path)
                    else:
                        backup_path.unlink()
                
                logger.info(f"Removed old backup: {backup['name']}")
            except Exception as e:
                logger.error(f"Failed to remove backup: {e}")
        
        # Update metadata
        self.metadata["backups"] = backups[to_remove:]
    
    def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate SHA256 checksum of a file"""
        sha256 = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except:
            return ""
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """List all available backups"""
        return self.metadata["backups"].copy()
    
    def get_backup_info(self, backup_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific backup"""
        for backup in self.metadata["backups"]:
            if backup["name"] == backup_name:
                return backup.copy()
        return None
    
    async def verify_backup(self, backup_name: str) -> bool:
        """Verify backup integrity"""
        backup_info = self.get_backup_info(backup_name)
        if not backup_info:
            return False
        
        backup_path = Path(backup_info["path"])
        if not backup_path.exists():
            return False
        
        if backup_info.get("checksum"):
            current_checksum = self._calculate_checksum(backup_path)
            return current_checksum == backup_info["checksum"]
        
        return True

class AutoBackupScheduler:
    """
    Automatic backup scheduler.
    Runs backups at specified intervals.
    """
    
    def __init__(self, backup_manager: BackupManager):
        self.backup_manager = backup_manager
        self.running = False
        self.tasks = []
    
    async def start(self, source_path: Path, 
                   full_interval: timedelta = timedelta(days=7),
                   incremental_interval: timedelta = timedelta(days=1)):
        """
        Start automatic backup schedule.
        
        Args:
            source_path: Path to backup
            full_interval: Time between full backups
            incremental_interval: Time between incremental backups
        """
        self.running = True
        
        # Schedule full backups
        full_task = asyncio.create_task(
            self._schedule_backups(source_path, "full", full_interval)
        )
        self.tasks.append(full_task)
        
        # Schedule incremental backups
        incremental_task = asyncio.create_task(
            self._schedule_backups(source_path, "incremental", incremental_interval)
        )
        self.tasks.append(incremental_task)
        
        logger.info("Automatic backup scheduler started")
    
    async def _schedule_backups(self, source_path: Path, 
                               backup_type: str, 
                               interval: timedelta):
        """Schedule periodic backups"""
        while self.running:
            try:
                # Perform backup
                await self.backup_manager.backup(source_path, backup_type)
                
                # Wait for next interval
                await asyncio.sleep(interval.total_seconds())
                
            except Exception as e:
                logger.error(f"Scheduled backup failed: {e}")
                # Wait before retry
                await asyncio.sleep(60)
    
    async def stop(self):
        """Stop automatic backups"""
        self.running = False
        
        # Cancel all tasks
        for task in self.tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self.tasks, return_exceptions=True)
        
        self.tasks.clear()
        logger.info("Automatic backup scheduler stopped")

# Compatibility layer for auto_backup.py migration
class AutoBackup:
    """Compatibility wrapper for auto_backup.py interface"""
    
    def __init__(self, backup_dir: Path = Path("backups")):
        self.manager = BackupManager(backup_dir)
        self.loop = None
    
    def _get_loop(self):
        """Get or create event loop"""
        try:
            return asyncio.get_running_loop()
        except RuntimeError:
            if self.loop is None:
                self.loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self.loop)
            return self.loop
    
    def create_backup(self, source: Path, backup_type: str = "full") -> Optional[BackupInfo]:
        """Create backup (sync wrapper)"""
        loop = self._get_loop()
        result = loop.run_until_complete(
            self.manager.backup(source, backup_type)
        )
        
        if result:
            return BackupInfo(
                id=result['name'],
                path=result['path'],
                source=result['source'],
                type=result['type'],
                size=result['size'],
                hash=result.get('checksum', ''),
                timestamp=time.time(),
                duration=0
            )
        return None
    
    def restore_backup(self, backup_id: str, destination: Path) -> bool:
        """Restore backup (sync wrapper)"""
        loop = self._get_loop()
        
        # Find backup by name/id
        backup_info = None
        for backup in self.manager.metadata.get('backups', []):
            if backup['name'] == backup_id or backup_id in backup['name']:
                backup_info = backup
                break
        
        if not backup_info:
            return False
        
        result = loop.run_until_complete(
            self.manager.restore(Path(backup_info['path']), destination)
        )
        return result
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """List all backups"""
        return self.manager.list_backups()

# Global auto backup instance
_auto_backup: Optional[AutoBackup] = None

def get_auto_backup() -> AutoBackup:
    """Get global AutoBackup instance (for compatibility)"""
    global _auto_backup
    if _auto_backup is None:
        _auto_backup = AutoBackup()
    return _auto_backup
