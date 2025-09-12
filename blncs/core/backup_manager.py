#!/usr/bin/env python3
"""
BLNCS Backup Manager - Simplified wrapper for main backup system
This module provides backward compatibility and simplified access.
"""

from ..backup.backup_manager import BackupManager as MainBackupManager
from ..backup.backup_scheduler import BackupScheduler
from ..backup.recovery_engine import RecoveryEngine

# Create singleton instance
_backup_manager_instance = None

def get_backup_manager(config_manager=None):
    """Get or create backup manager instance"""
    global _backup_manager_instance
    if _backup_manager_instance is None:
        _backup_manager_instance = MainBackupManager(config_manager)
    return _backup_manager_instance

# Re-export main classes for compatibility
BackupManager = MainBackupManager

__all__ = ['BackupManager', 'BackupScheduler', 'RecoveryEngine', 'get_backup_manager']