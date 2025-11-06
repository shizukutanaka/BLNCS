#!/usr/bin/env python3
"""
BLNCS Backup and Recovery

Lightweight backup and recovery utilities.
"""

import asyncio
import json
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass
from datetime import datetime, timezone
import logging

from ..core.exceptions import ValidationError

logger = logging.getLogger(__name__)


@dataclass
class BackupConfig:
    """Backup configuration"""
    name: str
    source_paths: List[str]
    destination_path: str
    compression: str = 'gzip'  # 'gzip', 'bz2', 'none'
    encryption: bool = False
    retention_days: int = 30
    include_patterns: Optional[List[str]] = None
    exclude_patterns: Optional[List[str]] = None


@dataclass
class BackupResult:
    """Backup operation result"""
    success: bool
    backup_path: Optional[str] = None
    file_count: int = 0
    total_size: int = 0
    duration: float = 0.0
    error_message: Optional[str] = None


class BackupManager:
    """Lightweight backup manager"""

    def __init__(self, base_backup_dir: str = "backups"):
        self.base_backup_dir = Path(base_backup_dir)
        self.base_backup_dir.mkdir(exist_ok=True)
        self._active_backups: Set[str] = set()

    def create_backup(self, config: BackupConfig) -> BackupResult:
        """Create a backup"""
        start_time = asyncio.get_event_loop().time if asyncio.get_event_loop().is_running() else time.time()

        try:
            # Generate backup filename
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            backup_name = f"{config.name}_{timestamp}"

            if config.compression == 'none':
                backup_path = self.base_backup_dir / f"{backup_name}.backup"
            else:
                backup_path = self.base_backup_dir / f"{backup_name}.tar.{config.compression}"

            # Check if backup already in progress
            if str(backup_path) in self._active_backups:
                return BackupResult(
                    success=False,
                    error_message="Backup already in progress"
                )

            self._active_backups.add(str(backup_path))

            try:
                if config.compression == 'none':
                    result = self._create_uncompressed_backup(config, backup_path)
                else:
                    result = self._create_compressed_backup(config, backup_path)

                duration = asyncio.get_event_loop().time() - start_time if asyncio.get_event_loop().is_running() else time.time() - start_time

                return BackupResult(
                    success=True,
                    backup_path=str(backup_path),
                    file_count=result['file_count'],
                    total_size=result['total_size'],
                    duration=duration
                )

            finally:
                self._active_backups.discard(str(backup_path))

        except Exception as e:
            duration = asyncio.get_event_loop().time() - start_time if asyncio.get_event_loop().is_running() else time.time() - start_time
            return BackupResult(
                success=False,
                duration=duration,
                error_message=str(e)
            )

    def _create_uncompressed_backup(self, config: BackupConfig, backup_path: Path) -> Dict[str, Any]:
        """Create uncompressed backup"""
        import tempfile

        file_count = 0
        total_size = 0

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Copy files to temp directory
            for source_path in config.source_paths:
                source = Path(source_path)
                if source.exists():
                    if source.is_file():
                        dest = temp_path / source.name
                        shutil.copy2(source, dest)
                        file_count += 1
                        total_size += dest.stat().st_size
                    elif source.is_dir():
                        dest = temp_path / source.name
                        result = self._copy_directory_filtered(source, dest, config)
                        file_count += result['file_count']
                        total_size += result['total_size']

            # Create final backup
            if config.compression == 'none':
                # Just move the temp directory to final location
                if temp_path.exists():
                    shutil.move(str(temp_path), str(backup_path))
            else:
                # Create tar archive
                with tarfile.open(backup_path, f'w:{config.compression}') as tar:
                    for file_path in temp_path.rglob('*'):
                        if file_path.is_file():
                            arcname = file_path.relative_to(temp_path)
                            tar.add(file_path, arcname=str(arcname))

        return {'file_count': file_count, 'total_size': total_size}

    def _create_compressed_backup(self, config: BackupConfig, backup_path: Path) -> Dict[str, Any]:
        """Create compressed backup"""
        file_count = 0
        total_size = 0

        with tarfile.open(backup_path, f'w:{config.compression}') as tar:
            for source_path in config.source_paths:
                source = Path(source_path)
                if source.exists():
                    if source.is_file():
                        if self._should_include_file(source, config):
                            arcname = source.name
                            tar.add(source, arcname=arcname)
                            file_count += 1
                            total_size += source.stat().st_size
                    elif source.is_dir():
                        result = self._add_directory_to_tar(source, tar, config)
                        file_count += result['file_count']
                        total_size += result['total_size']

        return {'file_count': file_count, 'total_size': total_size}

    def _copy_directory_filtered(self,
                                 source: Path,
                                 dest: Path,
                                 config: BackupConfig) -> Dict[str, Any]:
        """Copy directory with filtering"""
        file_count = 0
        total_size = 0

        dest.mkdir(exist_ok=True)

        for file_path in source.rglob('*'):
            if file_path.is_file() and self._should_include_file(file_path, config):
                relative_path = file_path.relative_to(source)
                dest_file = dest / relative_path
                dest_file.parent.mkdir(parents=True, exist_ok=True)

                shutil.copy2(file_path, dest_file)
                file_count += 1
                total_size += dest_file.stat().st_size

        return {'file_count': file_count, 'total_size': total_size}

    def _add_directory_to_tar(self,
                             source: Path,
                             tar: tarfile.TarFile,
                             config: BackupConfig) -> Dict[str, Any]:
        """Add directory to tar with filtering"""
        file_count = 0
        total_size = 0

        for file_path in source.rglob('*'):
            if file_path.is_file() and self._should_include_file(file_path, config):
                arcname = str(file_path.relative_to(source.parent))
                tar.add(file_path, arcname=arcname)
                file_count += 1
                total_size += file_path.stat().st_size

        return {'file_count': file_count, 'total_size': total_size}

    def _should_include_file(self, file_path: Path, config: BackupConfig) -> bool:
        """Check if file should be included in backup"""
        # Check exclude patterns
        if config.exclude_patterns:
            for pattern in config.exclude_patterns:
                if file_path.match(pattern):
                    return False

        # Check include patterns (if specified)
        if config.include_patterns:
            for pattern in config.include_patterns:
                if file_path.match(pattern):
                    return True
            return False  # Not in include patterns

        return True  # Default: include all files

    def list_backups(self) -> List[Dict[str, Any]]:
        """List available backups"""
        backups = []

        for backup_path in self.base_backup_dir.glob("*"):
            if backup_path.is_file():
                stat = backup_path.stat()
                backups.append({
                    'name': backup_path.stem,
                    'path': str(backup_path),
                    'size': stat.st_size,
                    'created': datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
                    'type': 'compressed' if backup_path.suffix.startswith('.tar') else 'uncompressed'
                })

        # Sort by creation time (newest first)
        backups.sort(key=lambda x: x['created'], reverse=True)
        return backups

    def cleanup_old_backups(self, retention_days: int = 30) -> int:
        """Remove backups older than retention period"""
        cutoff_time = time.time() - (retention_days * 24 * 3600)
        removed_count = 0

        for backup_path in self.base_backup_dir.glob("*"):
            if backup_path.is_file() and backup_path.stat().st_mtime < cutoff_time:
                try:
                    backup_path.unlink()
                    removed_count += 1
                except Exception as e:
                    logger.warning(f"Failed to remove old backup {backup_path}: {e}")

        return removed_count

    def restore_backup(self, backup_path: str, restore_to: str) -> bool:
        """Restore from backup"""
        backup_path = Path(backup_path)
        restore_to = Path(restore_to)

        if not backup_path.exists():
            raise ValidationError(f"Backup file not found: {backup_path}")

        try:
            if backup_path.suffix.startswith('.tar'):
                # Extract tar archive
                with tarfile.open(backup_path, 'r:*') as tar:
                    tar.extractall(restore_to)
            else:
                # Copy uncompressed backup
                if backup_path.is_dir():
                    shutil.copytree(backup_path, restore_to, dirs_exist_ok=True)
                else:
                    # Single file backup
                    shutil.copy2(backup_path, restore_to)

            return True

        except Exception as e:
            raise ValidationError(f"Restore failed: {e}")


class ConfigurationBackup:
    """Specialized backup for configuration files"""

    def __init__(self, config_paths: List[str]):
        self.config_paths = [Path(p) for p in config_paths]

    def create_config_backup(self) -> BackupResult:
        """Create configuration backup"""
        config = BackupConfig(
            name="blncs_config",
            source_paths=[str(p) for p in self.config_paths],
            destination_path="backups",
            compression="gzip",
            retention_days=90
        )

        manager = BackupManager()
        return manager.create_backup(config)

    def restore_config(self, backup_path: str, target_dir: str = "config") -> bool:
        """Restore configuration from backup"""
        manager = BackupManager()
        return manager.restore_backup(backup_path, target_dir)


# Global backup manager
_backup_manager = None

def get_backup_manager() -> BackupManager:
    """Get global backup manager instance"""
    global _backup_manager
    if _backup_manager is None:
        _backup_manager = BackupManager()
    return _backup_manager
