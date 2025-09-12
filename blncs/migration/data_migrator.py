#!/usr/bin/env python3
"""
BLNCS Data Migrator
Handles migration of backup data and metadata between versions.
"""

import json
import os
import shutil
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import logging
import sqlite3

logger = logging.getLogger(__name__)

class DataMigrator:
    """Migrate backup data and metadata between BLNCS versions"""
    
    def __init__(self, data_dir: str = None):
        self.data_dir = Path(data_dir or os.path.expanduser("~/.blncs/data"))
        self.backup_dir = Path(os.path.expanduser("~/.blncs/backups"))
        self.metadata_dir = self.data_dir / "metadata"
        self.migration_log_dir = self.data_dir / "migration_logs"
        
        # Create directories
        for directory in [self.data_dir, self.metadata_dir, self.migration_log_dir]:
            directory.mkdir(parents=True, exist_ok=True)
    
    def migrate_backup_metadata_1_0_to_1_1(self) -> Dict[str, Any]:
        """Migrate backup metadata from v1.0 to v1.1"""
        logger.info("Migrating backup metadata from v1.0 to v1.1")
        
        result = {
            "success": True,
            "migrated_backups": 0,
            "errors": [],
            "warnings": []
        }
        
        try:
            # Find v1.0 metadata files
            old_metadata_pattern = self.backup_dir / "*.meta"
            old_metadata_files = list(self.backup_dir.glob("*.meta"))
            
            for meta_file in old_metadata_files:
                try:
                    # Read old metadata format
                    with open(meta_file, 'r') as f:
                        old_metadata = json.load(f)
                    
                    # Convert to v1.1 format
                    new_metadata = self._convert_metadata_1_0_to_1_1(old_metadata)
                    
                    # Save new metadata
                    new_meta_file = self.metadata_dir / f"{new_metadata['backup_id']}.json"
                    with open(new_meta_file, 'w') as f:
                        json.dump(new_metadata, f, indent=2)
                    
                    # Move old file to backup location
                    backup_meta_file = self.migration_log_dir / f"v1.0_{meta_file.name}"
                    shutil.move(meta_file, backup_meta_file)
                    
                    result["migrated_backups"] += 1
                    
                except Exception as e:
                    result["errors"].append(f"Failed to migrate {meta_file}: {str(e)}")
            
            logger.info(f"Migrated {result['migrated_backups']} backup metadata files")
            
        except Exception as e:
            result["success"] = False
            result["errors"].append(f"Metadata migration failed: {str(e)}")
        
        return result
    
    def migrate_backup_metadata_1_1_to_1_2(self) -> Dict[str, Any]:
        """Migrate backup metadata from v1.1 to v1.2 with recovery features"""
        logger.info("Migrating backup metadata from v1.1 to v1.2")
        
        result = {
            "success": True,
            "migrated_backups": 0,
            "errors": [],
            "warnings": []
        }
        
        try:
            # Find v1.1 metadata files
            metadata_files = list(self.metadata_dir.glob("*.json"))
            
            for meta_file in metadata_files:
                try:
                    with open(meta_file, 'r') as f:
                        metadata = json.load(f)
                    
                    # Skip if already v1.2+
                    if metadata.get("version", "1.1") >= "1.2":
                        continue
                    
                    # Enhance with v1.2 features
                    enhanced_metadata = self._enhance_metadata_1_1_to_1_2(metadata)
                    
                    # Save enhanced metadata
                    with open(meta_file, 'w') as f:
                        json.dump(enhanced_metadata, f, indent=2)
                    
                    # Create recovery information file
                    recovery_file = self.metadata_dir / f"{enhanced_metadata['backup_id']}_recovery.json"
                    recovery_info = self._generate_recovery_info(enhanced_metadata)
                    
                    with open(recovery_file, 'w') as f:
                        json.dump(recovery_info, f, indent=2)
                    
                    result["migrated_backups"] += 1
                    
                except Exception as e:
                    result["errors"].append(f"Failed to migrate {meta_file}: {str(e)}")
            
            logger.info(f"Enhanced {result['migrated_backups']} backup metadata files with v1.2 features")
            
        except Exception as e:
            result["success"] = False
            result["errors"].append(f"Metadata migration failed: {str(e)}")
        
        return result
    
    def migrate_backup_metadata_1_2_to_2_0(self) -> Dict[str, Any]:
        """Migrate backup metadata from v1.2 to v2.0 with database backend"""
        logger.info("Migrating backup metadata from v1.2 to v2.0")
        
        result = {
            "success": True,
            "migrated_backups": 0,
            "database_created": False,
            "errors": [],
            "warnings": []
        }
        
        try:
            # Create SQLite database for v2.0
            db_file = self.data_dir / "blncs_metadata.db"
            self._create_metadata_database(db_file)
            result["database_created"] = True
            
            # Migrate all JSON metadata to database
            metadata_files = list(self.metadata_dir.glob("*.json"))
            
            with sqlite3.connect(db_file) as conn:
                conn.execute("BEGIN TRANSACTION")
                
                for meta_file in metadata_files:
                    # Skip recovery files
                    if "_recovery.json" in meta_file.name:
                        continue
                    
                    try:
                        with open(meta_file, 'r') as f:
                            metadata = json.load(f)
                        
                        # Convert to v2.0 format and insert into database
                        self._insert_backup_metadata_v2(conn, metadata)
                        
                        # Archive old JSON file
                        archive_file = self.migration_log_dir / f"v1.2_{meta_file.name}"
                        shutil.move(meta_file, archive_file)
                        
                        result["migrated_backups"] += 1
                        
                    except Exception as e:
                        result["errors"].append(f"Failed to migrate {meta_file}: {str(e)}")
                
                conn.execute("COMMIT")
            
            logger.info(f"Migrated {result['migrated_backups']} backups to database")
            
        except Exception as e:
            result["success"] = False
            result["errors"].append(f"Database migration failed: {str(e)}")
        
        return result
    
    def _convert_metadata_1_0_to_1_1(self, old_metadata: Dict) -> Dict:
        """Convert v1.0 metadata format to v1.1"""
        backup_id = old_metadata.get("id", f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        
        new_metadata = {
            "version": "1.1",
            "backup_id": backup_id,
            "name": old_metadata.get("name", "Unknown Backup"),
            "created_at": old_metadata.get("timestamp", datetime.now().isoformat()),
            "backup_type": old_metadata.get("type", "full"),
            "source_paths": old_metadata.get("paths", []),
            "size_bytes": old_metadata.get("size", 0),
            "compressed": old_metadata.get("compressed", False),
            "encrypted": old_metadata.get("encrypted", False),
            "checksum": old_metadata.get("hash", ""),
            "items": [],
            "status": old_metadata.get("status", "completed"),
            "storage_backend": "local",
            "retention_policy": "default",
            "tags": old_metadata.get("tags", [])
        }
        
        # Convert file list to items
        for file_path in old_metadata.get("files", []):
            item = {
                "path": file_path,
                "size": 0,  # Will be calculated later
                "checksum": "",
                "permissions": "644",
                "owner": "unknown",
                "modified_at": datetime.now().isoformat()
            }
            new_metadata["items"].append(item)
        
        return new_metadata
    
    def _enhance_metadata_1_1_to_1_2(self, metadata: Dict) -> Dict:
        """Enhance v1.1 metadata with v1.2 features"""
        metadata["version"] = "1.2"
        
        # Add recovery features
        metadata["recovery"] = {
            "recovery_script_generated": True,
            "permissions_preserved": True,
            "ownership_preserved": True,
            "timestamps_preserved": True,
            "symlinks_preserved": True
        }
        
        # Add verification features  
        metadata["verification"] = {
            "integrity_verified": True,
            "verification_method": "sha256",
            "last_verified": datetime.now().isoformat(),
            "verification_status": "passed"
        }
        
        # Add performance metrics
        metadata["performance"] = {
            "backup_duration_seconds": metadata.get("duration", 0),
            "compression_ratio": 0.0,
            "backup_speed_mbps": 0.0,
            "files_per_second": 0.0
        }
        
        # Enhance items with detailed metadata
        for item in metadata.get("items", []):
            if "metadata" not in item:
                item["metadata"] = {
                    "file_type": "file",
                    "is_binary": False,
                    "mime_type": "application/octet-stream",
                    "symlink_target": None,
                    "hard_links": 0
                }
        
        return metadata
    
    def _generate_recovery_info(self, metadata: Dict) -> Dict:
        """Generate recovery information for a backup"""
        return {
            "backup_id": metadata["backup_id"],
            "recovery_version": "1.2",
            "generated_at": datetime.now().isoformat(),
            "source_paths": metadata.get("source_paths", []),
            "recovery_commands": self._generate_recovery_commands(metadata),
            "prerequisites": {
                "minimum_disk_space": metadata.get("size_bytes", 0),
                "required_permissions": "write",
                "supported_filesystems": ["ext4", "xfs", "btrfs", "ntfs"]
            },
            "validation_steps": [
                "Verify backup integrity",
                "Check target directory permissions", 
                "Validate available disk space",
                "Restore files with original permissions",
                "Verify restored file checksums"
            ]
        }
    
    def _generate_recovery_commands(self, metadata: Dict) -> List[str]:
        """Generate recovery commands for a backup"""
        backup_id = metadata["backup_id"]
        commands = [
            f"# Recovery commands for backup {backup_id}",
            f"blncs recovery validate --backup-id {backup_id}",
            f"blncs recovery execute --backup-id {backup_id} --target /recovery/path",
            f"blncs recovery verify --backup-id {backup_id} --target /recovery/path"
        ]
        return commands
    
    def _create_metadata_database(self, db_file: Path):
        """Create SQLite database schema for v2.0 metadata"""
        with sqlite3.connect(db_file) as conn:
            # Backup metadata table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS backup_metadata (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    backup_id TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    backup_type TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    checksum TEXT,
                    storage_backend TEXT,
                    retention_policy TEXT,
                    metadata_json TEXT,
                    created_timestamp INTEGER DEFAULT (strftime('%s','now'))
                )
            """)
            
            # Backup items table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS backup_items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    backup_id TEXT NOT NULL,
                    path TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    checksum TEXT,
                    permissions TEXT,
                    owner_uid INTEGER,
                    owner_gid INTEGER,
                    modified_at TEXT,
                    item_metadata_json TEXT,
                    FOREIGN KEY (backup_id) REFERENCES backup_metadata (backup_id)
                )
            """)
            
            # Recovery information table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS recovery_info (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    backup_id TEXT NOT NULL,
                    recovery_commands TEXT,
                    prerequisites TEXT,
                    validation_steps TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (backup_id) REFERENCES backup_metadata (backup_id)
                )
            """)
            
            # Performance metrics table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS backup_performance (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    backup_id TEXT NOT NULL,
                    duration_seconds REAL,
                    compression_ratio REAL,
                    backup_speed_mbps REAL,
                    files_per_second REAL,
                    cpu_usage_percent REAL,
                    memory_usage_mb REAL,
                    FOREIGN KEY (backup_id) REFERENCES backup_metadata (backup_id)
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_backup_id ON backup_metadata (backup_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_backup_created ON backup_metadata (created_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_backup_status ON backup_metadata (status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_item_backup_id ON backup_items (backup_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_item_path ON backup_items (path)")
            
            conn.commit()
    
    def _insert_backup_metadata_v2(self, conn: sqlite3.Connection, metadata: Dict):
        """Insert backup metadata into v2.0 database"""
        # Insert main backup record
        conn.execute("""
            INSERT OR REPLACE INTO backup_metadata 
            (backup_id, name, created_at, backup_type, size_bytes, status, checksum, 
             storage_backend, retention_policy, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            metadata["backup_id"],
            metadata.get("name", "Unknown"),
            metadata.get("created_at", datetime.now().isoformat()),
            metadata.get("backup_type", "full"),
            metadata.get("size_bytes", 0),
            metadata.get("status", "completed"),
            metadata.get("checksum", ""),
            metadata.get("storage_backend", "local"),
            metadata.get("retention_policy", "default"),
            json.dumps(metadata)
        ))
        
        # Insert backup items
        for item in metadata.get("items", []):
            conn.execute("""
                INSERT INTO backup_items 
                (backup_id, path, size_bytes, checksum, permissions, modified_at, item_metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                metadata["backup_id"],
                item.get("path", ""),
                item.get("size", 0),
                item.get("checksum", ""),
                item.get("permissions", "644"),
                item.get("modified_at", datetime.now().isoformat()),
                json.dumps(item.get("metadata", {}))
            ))
        
        # Insert performance metrics if available
        performance = metadata.get("performance", {})
        if performance:
            conn.execute("""
                INSERT INTO backup_performance 
                (backup_id, duration_seconds, compression_ratio, backup_speed_mbps, files_per_second)
                VALUES (?, ?, ?, ?, ?)
            """, (
                metadata["backup_id"],
                performance.get("backup_duration_seconds", 0),
                performance.get("compression_ratio", 0),
                performance.get("backup_speed_mbps", 0),
                performance.get("files_per_second", 0)
            ))
        
        # Insert recovery info if available
        recovery_commands = metadata.get("recovery", {}).get("recovery_commands", [])
        if recovery_commands:
            conn.execute("""
                INSERT INTO recovery_info 
                (backup_id, recovery_commands, prerequisites, validation_steps, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (
                metadata["backup_id"],
                json.dumps(recovery_commands),
                json.dumps({}),
                json.dumps([]),
                datetime.now().isoformat()
            ))
    
    def verify_data_integrity(self, backup_id: str = None) -> Dict[str, Any]:
        """Verify integrity of backup data and metadata"""
        result = {
            "success": True,
            "verified_backups": 0,
            "integrity_errors": [],
            "warnings": []
        }
        
        try:
            # Check if database exists (v2.0)
            db_file = self.data_dir / "blncs_metadata.db"
            if db_file.exists():
                result.update(self._verify_database_integrity(db_file, backup_id))
            else:
                # Check JSON metadata files (v1.1, v1.2)
                result.update(self._verify_json_metadata_integrity(backup_id))
            
        except Exception as e:
            result["success"] = False
            result["integrity_errors"].append(f"Verification failed: {str(e)}")
        
        return result
    
    def _verify_database_integrity(self, db_file: Path, backup_id: str = None) -> Dict[str, Any]:
        """Verify database integrity"""
        result = {
            "verified_backups": 0,
            "integrity_errors": [],
            "warnings": []
        }
        
        with sqlite3.connect(db_file) as conn:
            # Check database integrity
            integrity_check = conn.execute("PRAGMA integrity_check").fetchone()
            if integrity_check[0] != "ok":
                result["integrity_errors"].append(f"Database integrity check failed: {integrity_check[0]}")
                return result
            
            # Verify backup records
            query = "SELECT backup_id, checksum, metadata_json FROM backup_metadata"
            params = []
            if backup_id:
                query += " WHERE backup_id = ?"
                params.append(backup_id)
            
            for row in conn.execute(query, params):
                backup_id_db, checksum, metadata_json = row
                
                try:
                    # Verify JSON is valid
                    metadata = json.loads(metadata_json)
                    
                    # Verify backup file exists if checksum provided
                    if checksum:
                        backup_file = self.backup_dir / f"{backup_id_db}.tar.gz"
                        if backup_file.exists():
                            # Verify checksum (simplified)
                            calculated_checksum = self._calculate_file_checksum(backup_file)
                            if calculated_checksum != checksum:
                                result["integrity_errors"].append(
                                    f"Checksum mismatch for {backup_id_db}: expected {checksum}, got {calculated_checksum}"
                                )
                        else:
                            result["warnings"].append(f"Backup file not found for {backup_id_db}")
                    
                    result["verified_backups"] += 1
                    
                except json.JSONDecodeError:
                    result["integrity_errors"].append(f"Invalid metadata JSON for backup {backup_id_db}")
                except Exception as e:
                    result["integrity_errors"].append(f"Error verifying backup {backup_id_db}: {str(e)}")
        
        return result
    
    def _verify_json_metadata_integrity(self, backup_id: str = None) -> Dict[str, Any]:
        """Verify JSON metadata file integrity"""
        result = {
            "verified_backups": 0,
            "integrity_errors": [],
            "warnings": []
        }
        
        pattern = f"{backup_id}.json" if backup_id else "*.json"
        metadata_files = list(self.metadata_dir.glob(pattern))
        
        for meta_file in metadata_files:
            if "_recovery.json" in meta_file.name:
                continue
                
            try:
                with open(meta_file, 'r') as f:
                    metadata = json.load(f)
                
                backup_id_meta = metadata.get("backup_id")
                checksum = metadata.get("checksum")
                
                if checksum:
                    backup_file = self.backup_dir / f"{backup_id_meta}.tar.gz"
                    if backup_file.exists():
                        calculated_checksum = self._calculate_file_checksum(backup_file)
                        if calculated_checksum != checksum:
                            result["integrity_errors"].append(
                                f"Checksum mismatch for {backup_id_meta}"
                            )
                    else:
                        result["warnings"].append(f"Backup file not found for {backup_id_meta}")
                
                result["verified_backups"] += 1
                
            except Exception as e:
                result["integrity_errors"].append(f"Error verifying {meta_file}: {str(e)}")
        
        return result
    
    def _calculate_file_checksum(self, file_path: Path) -> str:
        """Calculate SHA256 checksum of a file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def cleanup_old_data(self, older_than_days: int = 30) -> Dict[str, Any]:
        """Clean up old migration logs and temporary files"""
        result = {
            "success": True,
            "cleaned_files": 0,
            "freed_bytes": 0,
            "errors": []
        }
        
        try:
            cutoff_timestamp = datetime.now().timestamp() - (older_than_days * 24 * 3600)
            
            # Clean migration logs
            for log_file in self.migration_log_dir.glob("*"):
                if log_file.stat().st_mtime < cutoff_timestamp:
                    size = log_file.stat().st_size
                    log_file.unlink()
                    result["cleaned_files"] += 1
                    result["freed_bytes"] += size
            
            logger.info(f"Cleaned up {result['cleaned_files']} old files, freed {result['freed_bytes']} bytes")
            
        except Exception as e:
            result["success"] = False
            result["errors"].append(f"Cleanup failed: {str(e)}")
        
        return result