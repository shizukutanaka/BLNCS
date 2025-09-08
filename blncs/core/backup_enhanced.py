"""
Enhanced backup system for BLNCS
Automatic, incremental, and reliable backup functionality.
"""

import os
import shutil
import json
import gzip
import hashlib
import threading
import time
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum

from .logger import get_logger
from .config import get_config
from .exceptions import BLNCSError


class BackupType(Enum):
    """Types of backups"""
    FULL = "full"
    INCREMENTAL = "incremental"
    DIFFERENTIAL = "differential"


@dataclass
class BackupInfo:
    """Information about a backup"""
    backup_id: str
    backup_type: BackupType
    timestamp: datetime
    size_bytes: int
    file_count: int
    checksum: str
    compressed: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


class EnhancedBackupManager:
    """Enhanced backup system with automatic, incremental backups"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config()
        
        # Backup configuration
        self.enabled = self.config.get('backup.enabled', True)
        self.backup_dir = Path(self.config.get('backup.directory', './backups'))
        self.max_backups = self.config.get('backup.max_backups', 30)
        self.compression_enabled = self.config.get('backup.compression', True)
        self.auto_interval_hours = self.config.get('backup.auto_interval_hours', 6)
        
        # Backup sources
        self.backup_sources = {
            'config': self.config.get('backup.config_files', ['config/']),
            'data': self.config.get('backup.data_files', ['data/']),
            'logs': self.config.get('backup.log_files', ['logs/']),
            'cache': self.config.get('backup.cache_files', [])  # Usually excluded
        }
        
        # State tracking
        self.backup_history: List[BackupInfo] = []
        self.last_full_backup: Optional[datetime] = None
        self.last_backup: Optional[datetime] = None
        self.backup_lock = threading.Lock()
        
        # Auto backup thread
        self._auto_backup_thread = None
        self._stop_auto_backup = threading.Event()
        
        self._initialize_backup_system()
    
    def _initialize_backup_system(self) -> None:
        """Initialize the backup system"""
        # Create backup directory
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Load existing backup history
        self._load_backup_history()
        
        self.logger.info(f"Backup system initialized: {self.backup_dir}")
    
    def _load_backup_history(self) -> None:
        """Load backup history from disk"""
        history_file = self.backup_dir / 'backup_history.json'
        if history_file.exists():
            try:
                with open(history_file, 'r') as f:
                    history_data = json.load(f)
                
                self.backup_history = []
                for item in history_data:
                    backup_info = BackupInfo(
                        backup_id=item['backup_id'],
                        backup_type=BackupType(item['backup_type']),
                        timestamp=datetime.fromisoformat(item['timestamp']),
                        size_bytes=item['size_bytes'],
                        file_count=item['file_count'],
                        checksum=item['checksum'],
                        compressed=item.get('compressed', True),
                        metadata=item.get('metadata', {})
                    )
                    self.backup_history.append(backup_info)
                
                # Find last full backup
                for backup in reversed(self.backup_history):
                    if backup.backup_type == BackupType.FULL:
                        self.last_full_backup = backup.timestamp
                        break
                
                # Find last backup
                if self.backup_history:
                    self.last_backup = self.backup_history[-1].timestamp
                
                self.logger.info(f"Loaded {len(self.backup_history)} backup records")
                
            except Exception as e:
                self.logger.error(f"Failed to load backup history: {e}")
    
    def _save_backup_history(self) -> None:
        """Save backup history to disk"""
        history_file = self.backup_dir / 'backup_history.json'
        try:
            history_data = []
            for backup in self.backup_history:
                history_data.append({
                    'backup_id': backup.backup_id,
                    'backup_type': backup.backup_type.value,
                    'timestamp': backup.timestamp.isoformat(),
                    'size_bytes': backup.size_bytes,
                    'file_count': backup.file_count,
                    'checksum': backup.checksum,
                    'compressed': backup.compressed,
                    'metadata': backup.metadata
                })
            
            with open(history_file, 'w') as f:
                json.dump(history_data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to save backup history: {e}")
    
    def start_auto_backup(self) -> None:
        """Start automatic backup"""
        if not self.enabled:
            self.logger.info("Backup system disabled")
            return
        
        if self._auto_backup_thread and self._auto_backup_thread.is_alive():
            return
        
        self._stop_auto_backup.clear()
        self._auto_backup_thread = threading.Thread(target=self._auto_backup_loop, daemon=True)
        self._auto_backup_thread.start()
        self.logger.info("Auto-backup started")
    
    def stop_auto_backup(self) -> None:
        """Stop automatic backup"""
        self._stop_auto_backup.set()
        if self._auto_backup_thread:
            self._auto_backup_thread.join(timeout=5)
        self.logger.info("Auto-backup stopped")
    
    def _auto_backup_loop(self) -> None:
        """Auto backup loop"""
        while not self._stop_auto_backup.is_set():
            try:
                # Check if backup is needed
                if self._should_perform_backup():
                    backup_type = self._determine_backup_type()
                    self.create_backup(backup_type=backup_type, auto=True)
                
                # Wait for next check (check every hour)
                self._stop_auto_backup.wait(3600)
                
            except Exception as e:
                self.logger.error(f"Auto-backup error: {e}")
                self._stop_auto_backup.wait(300)  # Wait 5 minutes on error
    
    def _should_perform_backup(self) -> bool:
        """Check if a backup should be performed"""
        if not self.last_backup:
            return True  # No backup exists
        
        time_since_last = datetime.now() - self.last_backup
        return time_since_last >= timedelta(hours=self.auto_interval_hours)
    
    def _determine_backup_type(self) -> BackupType:
        """Determine what type of backup to perform"""
        # Full backup if no full backup exists or it's been a week
        if not self.last_full_backup:
            return BackupType.FULL
        
        days_since_full = (datetime.now() - self.last_full_backup).days
        if days_since_full >= 7:
            return BackupType.FULL
        
        # Otherwise incremental
        return BackupType.INCREMENTAL
    
    def create_backup(self, backup_type: BackupType = BackupType.INCREMENTAL,
                     sources: Optional[List[str]] = None, auto: bool = False) -> BackupInfo:
        """Create a backup"""
        if not self.enabled:
            raise BLNCSError("Backup system is disabled")
        
        with self.backup_lock:
            self.logger.info(f"Starting {backup_type.value} backup")
            
            # Generate backup ID
            backup_id = f"{backup_type.value}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            backup_path = self.backup_dir / backup_id
            backup_path.mkdir(exist_ok=True)
            
            # Determine what to backup
            if sources is None:
                sources = self._get_backup_sources(backup_type)
            
            # Collect files to backup
            files_to_backup = self._collect_files(sources, backup_type)
            
            if not files_to_backup:
                self.logger.warning("No files to backup")
                backup_path.rmdir()
                raise BLNCSError("No files to backup")
            
            # Create backup
            total_size = 0
            file_count = 0
            
            for source_path in files_to_backup:
                try:
                    if source_path.is_file():
                        dest_path = backup_path / source_path.name
                        
                        if self.compression_enabled:
                            self._compress_file(source_path, dest_path.with_suffix('.gz'))
                        else:
                            shutil.copy2(source_path, dest_path)
                        
                        total_size += source_path.stat().st_size
                        file_count += 1
                        
                except Exception as e:
                    self.logger.error(f"Failed to backup {source_path}: {e}")
            
            # Calculate checksum
            checksum = self._calculate_backup_checksum(backup_path)
            
            # Create backup info
            backup_info = BackupInfo(
                backup_id=backup_id,
                backup_type=backup_type,
                timestamp=datetime.now(),
                size_bytes=total_size,
                file_count=file_count,
                checksum=checksum,
                compressed=self.compression_enabled,
                metadata={
                    'auto_backup': auto,
                    'sources': [str(p) for p in sources]
                }
            )
            
            # Save backup metadata
            metadata_file = backup_path / 'backup_info.json'
            with open(metadata_file, 'w') as f:
                json.dump({
                    'backup_id': backup_info.backup_id,
                    'backup_type': backup_info.backup_type.value,
                    'timestamp': backup_info.timestamp.isoformat(),
                    'size_bytes': backup_info.size_bytes,
                    'file_count': backup_info.file_count,
                    'checksum': backup_info.checksum,
                    'compressed': backup_info.compressed,
                    'metadata': backup_info.metadata
                }, f, indent=2)
            
            # Update history
            self.backup_history.append(backup_info)
            self.last_backup = backup_info.timestamp
            if backup_type == BackupType.FULL:
                self.last_full_backup = backup_info.timestamp
            
            # Clean old backups
            self._cleanup_old_backups()
            
            # Save history
            self._save_backup_history()
            
            self.logger.info(f"Backup completed: {backup_id} ({file_count} files, {total_size} bytes)")
            return backup_info
    
    def _get_backup_sources(self, backup_type: BackupType) -> List[str]:
        """Get list of sources to backup"""
        sources = []
        
        # Always include critical sources
        sources.extend(self.backup_sources['config'])
        sources.extend(self.backup_sources['data'])
        
        # Include logs for full backups
        if backup_type == BackupType.FULL:
            sources.extend(self.backup_sources['logs'])
        
        return sources
    
    def _collect_files(self, sources: List[str], backup_type: BackupType) -> List[Path]:
        """Collect files to backup based on sources and type"""
        files_to_backup = []
        
        for source in sources:
            source_path = Path(source)
            if not source_path.exists():
                self.logger.warning(f"Backup source not found: {source}")
                continue
            
            if source_path.is_file():
                if self._should_backup_file(source_path, backup_type):
                    files_to_backup.append(source_path)
            else:
                # Directory - recursively collect files
                for file_path in source_path.rglob('*'):
                    if file_path.is_file() and self._should_backup_file(file_path, backup_type):
                        files_to_backup.append(file_path)
        
        return files_to_backup
    
    def _should_backup_file(self, file_path: Path, backup_type: BackupType) -> bool:
        """Check if a file should be backed up"""
        # Skip temporary files
        if file_path.name.startswith('.') or file_path.name.startswith('~'):
            return False
        
        # Skip cache files unless explicitly included
        if 'cache' in str(file_path).lower() and 'cache' not in self.backup_sources:
            return False
        
        # For incremental backups, only backup modified files
        if backup_type == BackupType.INCREMENTAL and self.last_backup:
            file_mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
            if file_mtime <= self.last_backup:
                return False
        
        return True
    
    def _compress_file(self, source_path: Path, dest_path: Path) -> None:
        """Compress a file using gzip"""
        with open(source_path, 'rb') as f_in:
            with gzip.open(dest_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
    
    def _calculate_backup_checksum(self, backup_path: Path) -> str:
        """Calculate checksum for backup verification"""
        hasher = hashlib.sha256()
        
        for file_path in sorted(backup_path.rglob('*')):
            if file_path.is_file() and file_path.name != 'backup_info.json':
                with open(file_path, 'rb') as f:
                    hasher.update(f.read())
        
        return hasher.hexdigest()
    
    def _cleanup_old_backups(self) -> None:
        """Clean up old backups to maintain max_backups limit"""
        if len(self.backup_history) <= self.max_backups:
            return
        
        # Sort by timestamp (oldest first)
        sorted_backups = sorted(self.backup_history, key=lambda x: x.timestamp)
        
        # Keep the most recent backups
        backups_to_remove = sorted_backups[:-self.max_backups]
        
        for backup in backups_to_remove:
            backup_path = self.backup_dir / backup.backup_id
            if backup_path.exists():
                try:
                    shutil.rmtree(backup_path)
                    self.logger.info(f"Removed old backup: {backup.backup_id}")
                except Exception as e:
                    self.logger.error(f"Failed to remove backup {backup.backup_id}: {e}")
            
            self.backup_history.remove(backup)
    
    def restore_backup(self, backup_id: str, restore_path: Optional[str] = None) -> bool:
        """Restore from a backup"""
        backup_info = next((b for b in self.backup_history if b.backup_id == backup_id), None)
        if not backup_info:
            raise BLNCSError(f"Backup not found: {backup_id}")
        
        backup_path = self.backup_dir / backup_id
        if not backup_path.exists():
            raise BLNCSError(f"Backup files not found: {backup_path}")
        
        if restore_path is None:
            restore_path = "."
        
        restore_dir = Path(restore_path)
        restore_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            files_restored = 0
            for backup_file in backup_path.glob('*'):
                if backup_file.name == 'backup_info.json':
                    continue
                
                if backup_file.suffix == '.gz' and backup_info.compressed:
                    # Decompress file
                    dest_file = restore_dir / backup_file.stem
                    with gzip.open(backup_file, 'rb') as f_in:
                        with open(dest_file, 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                else:
                    # Copy file as-is
                    dest_file = restore_dir / backup_file.name
                    shutil.copy2(backup_file, dest_file)
                
                files_restored += 1
            
            self.logger.info(f"Restored {files_restored} files from backup {backup_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to restore backup {backup_id}: {e}")
            return False
    
    def verify_backup(self, backup_id: str) -> bool:
        """Verify backup integrity"""
        backup_info = next((b for b in self.backup_history if b.backup_id == backup_id), None)
        if not backup_info:
            raise BLNCSError(f"Backup not found: {backup_id}")
        
        backup_path = self.backup_dir / backup_id
        if not backup_path.exists():
            raise BLNCSError(f"Backup files not found: {backup_path}")
        
        # Recalculate checksum
        current_checksum = self._calculate_backup_checksum(backup_path)
        
        if current_checksum == backup_info.checksum:
            self.logger.info(f"Backup {backup_id} verification successful")
            return True
        else:
            self.logger.error(f"Backup {backup_id} verification failed")
            return False
    
    def get_backup_status(self) -> Dict[str, Any]:
        """Get backup system status"""
        return {
            'enabled': self.enabled,
            'backup_directory': str(self.backup_dir),
            'total_backups': len(self.backup_history),
            'last_backup': self.last_backup.isoformat() if self.last_backup else None,
            'last_full_backup': self.last_full_backup.isoformat() if self.last_full_backup else None,
            'auto_backup_active': self._auto_backup_thread.is_alive() if self._auto_backup_thread else False,
            'next_backup_due': self._get_next_backup_time(),
            'backup_sources': self.backup_sources
        }
    
    def _get_next_backup_time(self) -> Optional[str]:
        """Calculate when next backup is due"""
        if not self.last_backup:
            return "Now (no previous backup)"
        
        next_backup = self.last_backup + timedelta(hours=self.auto_interval_hours)
        if next_backup <= datetime.now():
            return "Now (overdue)"
        
        return next_backup.isoformat()


# Global instance
_enhanced_backup = None

def get_enhanced_backup() -> EnhancedBackupManager:
    """Get global enhanced backup manager"""
    global _enhanced_backup
    if _enhanced_backup is None:
        _enhanced_backup = EnhancedBackupManager()
    return _enhanced_backup

# Backward compatibility for simple_backup.py
class SimpleBackup:
    """Backward compatibility wrapper for SimpleBackup"""
    
    def __init__(self):
        self._backup = get_enhanced_backup()
    
    def create_backup(self, backup_name: Optional[str] = None) -> str:
        """Create backup (compatibility method)"""
        backup_info = self._backup.create_backup(
            backup_type=BackupType.FULL if backup_name else BackupType.INCREMENTAL,
            auto=False
        )
        return str(self._backup.backup_dir / backup_info.backup_id)
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """List backups (compatibility method)"""
        backups = []
        for backup in self._backup.backup_history:
            backup_path = self._backup.backup_dir / backup.backup_id
            if backup_path.exists():
                backups.append({
                    'name': backup.backup_id,
                    'path': str(backup_path),
                    'size_mb': round(backup.size_bytes / (1024 * 1024), 2),
                    'created': backup.timestamp.isoformat(),
                    'age_days': (datetime.now() - backup.timestamp).days
                })
        return backups
    
    def restore_backup(self, backup_path: str, restore_dir: Optional[str] = None) -> bool:
        """Restore backup (compatibility method)"""
        backup_id = Path(backup_path).name
        return self._backup.restore_backup(backup_id, restore_dir)
    
    def delete_backup(self, backup_name: str) -> bool:
        """Delete backup (compatibility method)"""
        if backup_name.endswith('.tar.gz'):
            backup_name = backup_name[:-7]  # Remove .tar.gz
        
        # Find and remove from history
        for backup in self._backup.backup_history[:]:
            if backup.backup_id == backup_name:
                backup_path = self._backup.backup_dir / backup.backup_id
                if backup_path.exists():
                    import shutil
                    shutil.rmtree(backup_path)
                self._backup.backup_history.remove(backup)
                self._backup._save_backup_history()
                return True
        return False
    
    def get_backup_status(self) -> Dict[str, Any]:
        """Get backup status (compatibility method)"""
        status = self._backup.get_backup_status()
        return {
            'backup_count': status['total_backups'],
            'total_size_mb': sum(b['size_mb'] for b in self.list_backups()),
            'latest_backup': self.list_backups()[0] if self.list_backups() else None,
            'backup_dir': status['backup_directory'],
            'retention_days': 30,  # Default value
            'max_backups': self._backup.max_backups
        }

def get_backup_manager() -> SimpleBackup:
    """Get backup manager (backward compatibility)"""
    return SimpleBackup()