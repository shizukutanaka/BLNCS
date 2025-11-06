#!/usr/bin/env python3
"""
BLNCS Duplicate File Cleanup Script
重複ファイルのクリーンアップスクリプト
"""

import os
import shutil
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Files to remove (duplicates that have been consolidated)
DUPLICATE_FILES_TO_REMOVE = [
    # Performance duplicates (consolidated into unified_performance.py)
    'blncs/core/high_performance_engine.py',
    'blncs/core/performance_optimizations.py',
    'blncs/core/ultra_performance_optimizer.py',
    'blncs/core/ultra_performance_system.py',
    # Keep performance_optimizer.py for now as it's referenced in tests

    # Security duplicates (consolidated into unified_security.py)
    'blncs/security/commercial_security_system.py',
    'blncs/security/enhanced_security.py',
    'blncs/security/enterprise_security_system.py',
    'blncs/security/national_security_framework.py',

    # Large unused files identified
    'blncs/gui/mobile_web_interface.py',  # 1720 lines - seems experimental
    'blncs/core/market_intelligence.py',  # 950 lines - not core functionality
    'blncs/api/advanced_graphql_api.py',  # 925 lines - advanced feature
    'blncs/monitoring/comprehensive.py',  # 903 lines - replaced by unified systems
    'blncs/integration/enterprise.py',   # 862 lines - enterprise only
    'blncs/sustainability/optimization.py', # 834 lines - optional feature
    'blncs/stability/mission_critical/resilience.py', # 830 lines - overly complex
    'blncs/maintenance/professional/devops.py', # 821 lines - unnecessary complexity
    'blncs/ai/ethics/guardrails.py',     # 817 lines - future feature
    'blncs/auth/advanced.py',            # 789 lines - replaced by unified_security
    'blncs/cdn/global.py',               # 781 lines - not needed for core
    'blncs/scalability/global.py',       # 777 lines - premature optimization
    'blncs/backup/comprehensive.py',     # 777 lines - overly complex
    'blncs/core/intelligent_cache_system.py', # 765 lines - replaced by simple_cache
    'blncs/security/ai/powered.py',      # 763 lines - experimental AI feature
    'blncs/core/national_compliance.py', # 758 lines - specific to certain regions
    'blncs/monitoring/realtime_monitoring_system.py', # 755 lines - duplicate functionality
    'blncs/crypto/advanced.py',          # 736 lines - not core crypto needs
    'blncs/deployment/production_deployer.py', # 715 lines - will be replaced
    'blncs/core/advanced_error_recovery.py', # 740 lines - overly complex
]

# Directories to remove (entire unused modules)
DIRECTORIES_TO_REMOVE = [
    'blncs/ai',           # AI features not core to Lightning
    'blncs/audit',        # Basic auditing in unified_security
    'blncs/auth',         # Replaced by unified_security
    'blncs/backup',       # Basic backup in core modules
    'blncs/blockchain',   # Not needed for Lightning focus
    'blncs/cdn',          # CDN not needed for node software
    'blncs/crypto',       # Basic crypto in unified_security
    'blncs/edge',         # Edge computing not core
    'blncs/enterprise',   # Enterprise features separate
    'blncs/identity',     # Basic identity in unified_security
    'blncs/integration',  # Basic integration in core
    'blncs/maintenance',  # Basic maintenance sufficient
    'blncs/network',      # Network utils in core
    'blncs/quantum',      # Quantum features premature
    'blncs/scalability',  # Premature optimization
    'blncs/stability',    # Basic stability in core
    'blncs/storage',      # Storage handled by database
    'blncs/sustainability', # Not core functionality
    'blncs/threat_intel', # Basic security sufficient
    'blncs/ux',           # UX separate from core
]

def backup_file(file_path: Path, backup_dir: Path):
    """Backup a file before deletion"""
    try:
        backup_dir.mkdir(parents=True, exist_ok=True)
        relative_path = file_path.relative_to(Path.cwd())
        backup_path = backup_dir / relative_path
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(file_path, backup_path)
        logger.info(f"Backed up: {file_path} -> {backup_path}")
    except Exception as e:
        logger.error(f"Failed to backup {file_path}: {e}")

def remove_file(file_path: str, backup_dir: Path):
    """Remove a single file with backup"""
    path = Path(file_path)
    if path.exists():
        backup_file(path, backup_dir)
        try:
            path.unlink()
            logger.info(f"Removed file: {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to remove {file_path}: {e}")
    else:
        logger.warning(f"File not found: {file_path}")
    return False

def remove_directory(dir_path: str, backup_dir: Path):
    """Remove a directory with backup"""
    path = Path(dir_path)
    if path.exists() and path.is_dir():
        # Backup entire directory
        try:
            backup_target = backup_dir / path.name
            shutil.copytree(path, backup_target, dirs_exist_ok=True)
            logger.info(f"Backed up directory: {path} -> {backup_target}")
        except Exception as e:
            logger.error(f"Failed to backup directory {path}: {e}")
            return False

        # Remove directory
        try:
            shutil.rmtree(path)
            logger.info(f"Removed directory: {dir_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to remove directory {dir_path}: {e}")
    else:
        logger.warning(f"Directory not found: {dir_path}")
    return False

def cleanup_duplicates():
    """Main cleanup function"""
    backup_dir = Path("backup_removed_files")

    logger.info("Starting duplicate file cleanup...")

    removed_files = 0
    removed_dirs = 0

    # Remove duplicate files
    logger.info("Removing duplicate files...")
    for file_path in DUPLICATE_FILES_TO_REMOVE:
        if remove_file(file_path, backup_dir):
            removed_files += 1

    # Remove unused directories
    logger.info("Removing unused directories...")
    for dir_path in DIRECTORIES_TO_REMOVE:
        if remove_directory(dir_path, backup_dir):
            removed_dirs += 1

    # Remove empty directories
    logger.info("Removing empty directories...")
    for root, dirs, files in os.walk("blncs", topdown=False):
        for dir_name in dirs:
            dir_path = Path(root) / dir_name
            if dir_path.is_dir():
                try:
                    if not any(dir_path.iterdir()):  # Check if empty
                        dir_path.rmdir()
                        logger.info(f"Removed empty directory: {dir_path}")
                        removed_dirs += 1
                except OSError:
                    pass  # Directory not empty or other error

    logger.info(f"Cleanup completed: {removed_files} files, {removed_dirs} directories removed")
    logger.info(f"Backups saved to: {backup_dir.absolute()}")

    return removed_files, removed_dirs

if __name__ == "__main__":
    cleanup_duplicates()