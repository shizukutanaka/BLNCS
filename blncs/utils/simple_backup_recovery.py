"""Simple backup and recovery utilities.

A deliberately small backup helper: copy files into a backup
directory with a manifest-free, timestamped layout. Used by the
scheduler's automated backup job and by the lightweight test suites.
"""

import logging
import os
import shutil
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class BackupItem:
    """One backup entry stored on disk."""

    path: str
    timestamp: float
    size_bytes: int
    backup_type: str = "manual"
    source: Optional[str] = None


class SimpleBackup:
    """Create and list simple file backups under a backup directory."""

    def __init__(self, backup_dir: str = "backups", max_backups: int = 10):
        self.backup_dir = Path(backup_dir)
        self.max_backups = max_backups
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    # -- creation -----------------------------------------------------

    def backup_file(
        self, source_path: str, backup_type: str = "manual"
    ) -> Optional[BackupItem]:
        """Copy a single file into the backup directory."""
        source = Path(source_path)
        if not source.exists() or not source.is_file():
            logger.warning(f"Backup source not found: {source_path}")
            return None

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        # Keep the original file name and suffix intact.
        destination = self.backup_dir / f"{source.stem}_{timestamp}{source.suffix}"
        shutil.copy2(source, destination)

        item = BackupItem(
            path=str(destination),
            timestamp=time.time(),
            size_bytes=destination.stat().st_size,
            backup_type=backup_type,
            source=str(source),
        )
        self._enforce_retention()
        return item

    def create_backup(
        self, backup_name: str = "backup", backup_type: str = "manual"
    ) -> Dict[str, Any]:
        """Archive the current directory's top-level files into one tar.gz.

        Returns a result dict with ``success`` and ``backup_path`` keys.
        """
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        archive_path = self.backup_dir / f"{backup_name}_{timestamp}.tar.gz"
        try:
            with tarfile.open(archive_path, "w:gz") as tar:
                for entry in sorted(Path(".").iterdir()):
                    if entry.is_file():
                        tar.add(entry, arcname=entry.name)
        except OSError as e:
            logger.error(f"Backup failed: {e}")
            return {"success": False, "error": str(e)}

        self._enforce_retention()
        return {"success": True, "backup_path": str(archive_path)}

    # -- inspection ---------------------------------------------------

    def list_backups(self) -> List[BackupItem]:
        """List backup entries currently stored, oldest first."""
        items: List[BackupItem] = []
        if not self.backup_dir.exists():
            return items
        for entry in sorted(self.backup_dir.iterdir()):
            if entry.is_file():
                stat = entry.stat()
                items.append(
                    BackupItem(
                        path=str(entry),
                        timestamp=stat.st_mtime,
                        size_bytes=stat.st_size,
                    )
                )
        return items

    def get_backup_stats(self) -> Dict[str, Any]:
        """Return summary statistics for the backup directory."""
        items = self.list_backups()
        return {
            "total_backups": len(items),
            "backup_dir": str(self.backup_dir),
            "total_size_bytes": sum(item.size_bytes for item in items),
        }

    def get_backup_size(self) -> Dict[str, Any]:
        """Return the total size of all stored backups."""
        total = sum(item.size_bytes for item in self.list_backups())
        return {
            "total_size_bytes": total,
            "total_size_mb": total / (1024 * 1024),
        }

    # -- internals ------------------------------------------------------

    def _enforce_retention(self) -> None:
        items = self.list_backups()
        excess = len(items) - self.max_backups
        for item in items[: max(0, excess)]:
            try:
                os.remove(item.path)
            except OSError:
                pass


def emergency_backup(backup_root: str = "emergency_backups") -> Dict[str, Any]:
    """Back up the BLNCS database and config files on a best-effort basis."""
    manager = SimpleBackup(backup_root)
    created: List[BackupItem] = []
    candidates = [
        Path("data/blncs.db"),
        Path("config/blncs.json"),
        Path("blncs.json"),
    ]
    for candidate in candidates:
        if candidate.exists():
            item = manager.backup_file(str(candidate), backup_type="emergency")
            if item is not None:
                created.append(item)
    return {"emergency_backups": created}


def auto_backup(
    include_paths: List[str],
    backup_root: str = "backups",
    backup_type: str = "auto",
) -> List[BackupItem]:
    """Back up each existing path in ``include_paths``; return the items."""
    manager = SimpleBackup(backup_root)
    created: List[BackupItem] = []
    for path in include_paths:
        item = manager.backup_file(path, backup_type=backup_type)
        if item is not None:
            created.append(item)
    return created
