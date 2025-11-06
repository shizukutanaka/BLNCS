#!/usr/bin/env python3
"""
BLNCS Lightweight Backup Manager
Efficient backup and recovery with minimal overhead
Enhanced with integrity verification and encryption
"""

import os
import sys
import json
import time
import shutil
import hashlib
import tempfile
from typing import Dict, Any, List, Optional, Iterable
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timedelta

@dataclass
class BackupInfo:
    """Backup information with integrity verification"""
    path: str
    timestamp: float
    size_bytes: int
    backup_type: str
    checksum: str = ""
    encrypted: bool = False
    compressed: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Calculate checksum if not provided"""
        if not self.checksum and Path(self.path).exists():
            self.checksum = self._calculate_checksum()

    def _calculate_checksum(self) -> str:
        """Calculate SHA256 checksum"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(self.path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception:
            return ""

    def verify_integrity(self) -> bool:
        """Verify backup integrity"""
        if not self.checksum:
            return False
        current_checksum = self._calculate_checksum()
        return current_checksum == self.checksum

class LightweightBackupManager:
    """Lightweight backup management with enhanced features"""

    def __init__(self, backup_dir: str = "backups", encryption_key: Optional[str] = None):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(exist_ok=True)
        self.max_backups = 10
        self.compression_enabled = True
        self.encryption_key = encryption_key
        self.manifest_file = self.backup_dir / "backup_manifest.json"

        # Load existing backups
        self.backups: List[BackupInfo] = []
        self._load_manifest()

    def _load_manifest(self):
        """Load backup manifest"""
        if self.manifest_file.exists():
            try:
                with open(self.manifest_file, 'r') as f:
                    data = json.load(f)
                    for item in data.get('backups', []):
                        backup = BackupInfo(**item)
                        if Path(backup.path).exists():
                            self.backups.append(backup)
            except Exception as e:
                print(f"Failed to load backup manifest: {e}")

    def _save_manifest(self):
        """Save backup manifest"""
        try:
            data = {
                'version': '2.0',
                'last_updated': datetime.now().isoformat(),
                'backups': [vars(backup) for backup in self.backups]
            }

            with open(self.manifest_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)

        except Exception as e:
            print(f"Failed to save backup manifest: {e}")

    def create_backup(self, source_path: str, backup_name: Optional[str] = None,
                     backup_type: str = "manual", encrypt: bool = False) -> Optional[BackupInfo]:
        """Create a backup with integrity verification"""
        source = Path(source_path)
        if not source.exists():
            return None

        # Generate backup name
        if backup_name is None:
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            backup_name = f"{source.name}_{timestamp}"

        backup_path = self.backup_dir / backup_name

        try:
            if source.is_file():
                # Backup single file
                final_path = self._backup_file(source, backup_path, encrypt)
            else:
                # Backup directory
                final_path = self._backup_directory(source, backup_path, encrypt)

            # Create backup info
            backup_info = BackupInfo(
                path=str(final_path),
                timestamp=time.time(),
                size_bytes=final_path.stat().st_size,
                backup_type=backup_type,
                encrypted=encrypt,
                compressed=self.compression_enabled,
                metadata={'source': str(source), 'original_name': source.name}
            )

            self.backups.append(backup_info)
            self._save_manifest()

            # Cleanup old backups
            self._cleanup_old_backups()

            return backup_info

        except Exception as e:
            print(f"Backup failed: {e}")
            return None

    def _backup_file(self, source: Path, destination: Path, encrypt: bool) -> Path:
        """Backup a single file with optional encryption"""
        if encrypt and self.encryption_key:
            # Encrypt the file
            return self._encrypt_file(source, destination)
        elif self.compression_enabled:
            # Compress the file
            import gzip
            compressed_path = destination.with_suffix('.gz')
            with open(source, 'rb') as f_in:
                with gzip.open(compressed_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            return compressed_path
        else:
            # Plain copy
            shutil.copy2(source, destination)
            return destination

    def _backup_directory(self, source: Path, destination: Path, encrypt: bool) -> Path:
        """Backup a directory with optional encryption"""
        # Create tar archive
        import tarfile

        if self.compression_enabled:
            archive_path = destination.with_suffix('.tar.gz')
            mode = 'w:gz'
        else:
            archive_path = destination.with_suffix('.tar')
            mode = 'w'

        with tarfile.open(archive_path, mode) as tar:
            tar.add(source, arcname=source.name)

        if encrypt and self.encryption_key:
            # Encrypt the archive
            return self._encrypt_file(archive_path, destination.with_suffix('.enc'))
        else:
            return archive_path
        if not backup_file.exists():
            return False

        try:
            if backup_file.suffix == '.gz':
                # Decompress gzipped file
                import gzip
                with gzip.open(backup_file, 'rb') as f_in:
                    with open(target, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
            elif backup_file.suffixes == ['.tar', '.gz']:
                # Extract tar.gz file
                import tarfile
                with tarfile.open(backup_file, 'r:gz') as tar:
                    tar.extractall(target.parent)
            else:
                # Copy file directly
                shutil.copy2(backup_file, target)

            return True

        except Exception as e:
            print(f"Restore failed: {e}")
            return False

    def _cleanup_old_backups(self):
        """Clean up old backups"""
        backups = self.list_backups()

        # Remove excess backups
        while len(backups) > self.max_backups:
            oldest = backups.pop()
            try:
                Path(oldest.path).unlink()
            except Exception:
                pass

    def get_backup_stats(self) -> Dict[str, Any]:
        """Get backup statistics"""
        backups = self.list_backups()
        total_size = sum(b.size_bytes for b in backups)

        backup_types = {}
        for backup in backups:
            backup_types[backup.backup_type] = backup_types.get(backup.backup_type, 0) + 1

        return {
            'total_backups': len(backups),
            'total_size_bytes': total_size,
            'backup_types': backup_types,
            'oldest_backup': backups[-1].timestamp if backups else None,
            'newest_backup': backups[0].timestamp if backups else None
        }

# Global backup manager instance
_backup_manager_instance = None

def get_lightweight_backup_manager(backup_dir: str = "backups") -> LightweightBackupManager:
    """Get global backup manager instance"""
    global _backup_manager_instance
    if _backup_manager_instance is None:
        _backup_manager_instance = LightweightBackupManager(backup_dir)
    return _backup_manager_instance

def create_backup(source_path: str, backup_name: Optional[str] = None, backup_type: str = "manual") -> Optional[BackupInfo]:
    """Create a backup"""
    manager = get_lightweight_backup_manager()
    return manager.create_backup(source_path, backup_name, backup_type)

def list_backups() -> List[BackupInfo]:
    """List all backups"""
    manager = get_lightweight_backup_manager()
    return manager.list_backups()

def restore_backup(backup_path: str, target_path: str) -> bool:
    """Restore a backup"""
    manager = get_lightweight_backup_manager()
    return manager.restore_backup(backup_path, target_path)

def get_backup_stats() -> Dict[str, Any]:
    """Get backup statistics"""
    manager = get_lightweight_backup_manager()
    return manager.get_backup_stats()


def auto_backup(
    include_paths: Optional[Iterable[str]] = None,
    backup_root: Optional[str] = None,
    backup_type: str = "auto",
) -> List[BackupInfo]:
    """Create automated backups for the provided paths.

    Args:
        include_paths: Iterable of filesystem paths to back up.
        backup_root: Optional backup directory override.
        backup_type: Label describing the backup origin.

    Returns:
        List of BackupInfo entries for successfully created backups.
    """

    manager = get_lightweight_backup_manager(backup_root or "backups")
    created_backups: List[BackupInfo] = []

    for source in include_paths or []:
        info = manager.create_backup(str(source), backup_type=backup_type)
        if info:
            created_backups.append(info)

    return created_backups

if __name__ == '__main__':
    # Test lightweight backup manager
    backup_manager = get_lightweight_backup_manager()

    # Create test file
    test_file = Path("test_backup.txt")
    test_file.write_text("This is a test file for backup")

    # Create backup
    backup_info = create_backup(str(test_file))
    if backup_info:
        print(f"✅ Backup created: {backup_info.path}")

    # List backups
    backups = list_backups()
    print(f"✅ Found {len(backups)} backups")

    # Get backup stats
    stats = get_backup_stats()
    print(f"✅ Backup stats: {stats}")

    # Cleanup
    test_file.unlink()
    if backup_info:
        Path(backup_info.path).unlink()

    print("🎉 Lightweight backup manager test completed!")
