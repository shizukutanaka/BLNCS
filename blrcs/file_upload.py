# BLRCS Secure File Upload Module
# Enhanced file upload security with comprehensive validation
import os
import hashlib
import mimetypes
import magic
import tempfile
import shutil
from pathlib import Path
from typing import Optional, Dict, List, Set, Tuple
from dataclasses import dataclass
import asyncio
from datetime import datetime

@dataclass
class FileUploadConfig:
    """File upload configuration"""
    max_file_size: int = 5 * 1024 * 1024  # 5MB
    allowed_extensions: Set[str] = None
    allowed_mime_types: Set[str] = None
    scan_for_malware: bool = True
    quarantine_path: Path = Path("quarantine")
    upload_path: Path = Path("uploads")
    temp_path: Path = Path("temp")
    
    def __post_init__(self):
        if self.allowed_extensions is None:
            # Conservative whitelist of safe file types
            self.allowed_extensions = {
                '.txt', '.json', '.csv', '.xml', '.yaml', '.yml',
                '.pdf', '.doc', '.docx', '.xls', '.xlsx',
                '.jpg', '.jpeg', '.png', '.gif', '.bmp',
                '.mp3', '.wav', '.mp4', '.avi', '.mov'
            }
        
        if self.allowed_mime_types is None:
            self.allowed_mime_types = {
                'text/plain', 'application/json', 'text/csv',
                'application/xml', 'text/xml', 'application/yaml',
                'application/pdf', 'application/msword',
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'application/vnd.ms-excel',
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                'image/jpeg', 'image/png', 'image/gif', 'image/bmp',
                'audio/mpeg', 'audio/wav', 'video/mp4', 'video/avi', 'video/quicktime'
            }

class SecureFileUpload:
    """
    Secure file upload handler with comprehensive validation.
    Implements defense-in-depth security principles.
    """
    
    def __init__(self, config: FileUploadConfig = None):
        self.config = config or FileUploadConfig()
        
        # Create necessary directories
        self.config.upload_path.mkdir(exist_ok=True)
        self.config.quarantine_path.mkdir(exist_ok=True)
        self.config.temp_path.mkdir(exist_ok=True)
        
        # Dangerous file patterns to block
        self.dangerous_patterns = {
            # Executable files
            '.exe', '.bat', '.cmd', '.com', '.scr', '.pif',
            '.msi', '.dll', '.sys', '.drv', '.vbs', '.js',
            '.jar', '.class', '.py', '.pl', '.php', '.asp',
            '.jsp', '.sh', '.bash', '.ps1', '.psm1',
            
            # Archives that might contain executables
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
            
            # Office macros and templates
            '.xlsm', '.xltm', '.docm', '.dotm', '.pptm',
            
            # Other risky types
            '.iso', '.img', '.dmg', '.pkg', '.deb', '.rpm'
        }
        
        # File signature checks (magic bytes)
        self.file_signatures = {
            b'\x89PNG': 'image/png',
            b'\xFF\xD8\xFF': 'image/jpeg',
            b'GIF87a': 'image/gif',
            b'GIF89a': 'image/gif',
            b'%PDF': 'application/pdf',
            b'PK\x03\x04': 'application/zip',  # Also used by Office docs
            b'\xD0\xCF\x11\xE0': 'application/msword',  # Old Office format
        }
        
        # Audit log
        self.audit_log = []
    
    def validate_filename(self, filename: str) -> Tuple[bool, str]:
        """
        Validate filename for security.
        Returns (is_valid, reason)
        """
        if not filename:
            return False, "Empty filename"
        
        # Length check
        if len(filename) > 255:
            return False, "Filename too long"
        
        # Path traversal check
        if '..' in filename or '/' in filename or '\\' in filename:
            return False, "Path traversal detected"
        
        # Null byte check
        if '\x00' in filename:
            return False, "Null byte in filename"
        
        # Control character check
        if any(ord(c) < 32 for c in filename if c not in '\t\n\r'):
            return False, "Control characters in filename"
        
        # Extension check
        ext = Path(filename).suffix.lower()
        if ext in self.dangerous_patterns:
            return False, f"Dangerous file extension: {ext}"
        
        if ext not in self.config.allowed_extensions:
            return False, f"File extension not allowed: {ext}"
        
        # Suspicious patterns
        suspicious_patterns = [
            'autorun', 'desktop.ini', 'thumbs.db',
            '.htaccess', '.htpasswd', 'web.config'
        ]
        
        filename_lower = filename.lower()
        for pattern in suspicious_patterns:
            if pattern in filename_lower:
                return False, f"Suspicious filename pattern: {pattern}"
        
        return True, "Valid"
    
    def validate_file_content(self, file_path: Path) -> Tuple[bool, str]:
        """
        Validate file content using multiple methods.
        Returns (is_valid, reason)
        """
        try:
            # Size check
            file_size = file_path.stat().st_size
            if file_size > self.config.max_file_size:
                return False, f"File too large: {file_size} bytes"
            
            if file_size == 0:
                return False, "Empty file"
            
            # Read first few bytes for signature check
            with open(file_path, 'rb') as f:
                header = f.read(64)
            
            # Check file signature
            detected_type = None
            for signature, mime_type in self.file_signatures.items():
                if header.startswith(signature):
                    detected_type = mime_type
                    break
            
            # Use python-magic for MIME type detection
            try:
                detected_mime = magic.from_file(str(file_path), mime=True)
            except:
                detected_mime = None
            
            # Use mimetypes as fallback
            if not detected_mime:
                detected_mime, _ = mimetypes.guess_type(str(file_path))
            
            # Validate MIME type
            if detected_mime and detected_mime not in self.config.allowed_mime_types:
                return False, f"MIME type not allowed: {detected_mime}"
            
            # Check for embedded executables or scripts
            with open(file_path, 'rb') as f:
                content = f.read(8192)  # Read first 8KB
                
                # Look for suspicious patterns
                suspicious_bytes = [
                    b'MZ',  # PE executable header
                    b'\x7fELF',  # ELF executable header
                    b'#!/bin/',  # Shell script
                    b'<?php',  # PHP script
                    b'<script',  # JavaScript
                    b'javascript:',  # JavaScript URL
                    b'vbscript:',  # VBScript URL
                ]
                
                for pattern in suspicious_bytes:
                    if pattern in content:
                        return False, f"Suspicious content pattern detected: {pattern}"
            
            return True, "Valid content"
            
        except Exception as e:
            return False, f"Content validation error: {str(e)}"
    
    def scan_malware(self, file_path: Path) -> Tuple[bool, str]:
        """
        Basic malware scanning.
        In production, integrate with ClamAV or similar.
        """
        if not self.config.scan_for_malware:
            return True, "Scanning disabled"
        
        try:
            # Calculate file hash
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            file_hash = hasher.hexdigest()
            
            # In production, check against malware hash database
            # For now, just log the hash
            self.audit_log.append({
                "event": "file_scanned",
                "file_hash": file_hash,
                "file_path": str(file_path),
                "timestamp": datetime.now().isoformat()
            })
            
            # Simple heuristic checks
            file_size = file_path.stat().st_size
            
            # Suspiciously small files that claim to be media
            if file_size < 1024:  # Less than 1KB
                ext = file_path.suffix.lower()
                if ext in ['.jpg', '.png', '.mp3', '.mp4']:
                    return False, "File too small for claimed type"
            
            return True, "No malware detected"
            
        except Exception as e:
            return False, f"Malware scan error: {str(e)}"
    
    def quarantine_file(self, file_path: Path, reason: str):
        """Move suspicious file to quarantine"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_name = f"{timestamp}_{file_path.name}"
            quarantine_path = self.config.quarantine_path / quarantine_name
            
            shutil.move(str(file_path), str(quarantine_path))
            
            self.audit_log.append({
                "event": "file_quarantined",
                "original_path": str(file_path),
                "quarantine_path": str(quarantine_path),
                "reason": reason,
                "timestamp": datetime.now().isoformat()
            })
            
        except Exception as e:
            self.audit_log.append({
                "event": "quarantine_error",
                "file_path": str(file_path),
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            })
    
    async def upload_file(self, filename: str, file_data: bytes, 
                         user_id: str = None) -> Dict[str, any]:
        """
        Upload and validate file securely.
        Returns upload result with security details.
        """
        result = {
            "success": False,
            "filename": filename,
            "user_id": user_id,
            "upload_id": None,
            "file_path": None,
            "security_checks": {},
            "errors": [],
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            # Generate unique upload ID
            upload_id = hashlib.sha256(f"{filename}_{user_id}_{datetime.now()}".encode()).hexdigest()
            result["upload_id"] = upload_id
            
            # Validate filename
            filename_valid, filename_reason = self.validate_filename(filename)
            result["security_checks"]["filename"] = {
                "valid": filename_valid,
                "reason": filename_reason
            }
            
            if not filename_valid:
                result["errors"].append(f"Invalid filename: {filename_reason}")
                return result
            
            # Create temporary file
            temp_file = self.config.temp_path / f"{upload_id}_{filename}"
            
            # Write file data
            with open(temp_file, 'wb') as f:
                f.write(file_data)
            
            # Validate content
            content_valid, content_reason = self.validate_file_content(temp_file)
            result["security_checks"]["content"] = {
                "valid": content_valid,
                "reason": content_reason
            }
            
            if not content_valid:
                result["errors"].append(f"Invalid content: {content_reason}")
                self.quarantine_file(temp_file, content_reason)
                return result
            
            # Malware scan
            malware_clean, malware_reason = self.scan_malware(temp_file)
            result["security_checks"]["malware"] = {
                "clean": malware_clean,
                "reason": malware_reason
            }
            
            if not malware_clean:
                result["errors"].append(f"Malware detected: {malware_reason}")
                self.quarantine_file(temp_file, malware_reason)
                return result
            
            # Move to final upload location
            final_path = self.config.upload_path / f"{upload_id}_{filename}"
            shutil.move(str(temp_file), str(final_path))
            
            result["success"] = True
            result["file_path"] = str(final_path)
            
            # Log successful upload
            self.audit_log.append({
                "event": "file_uploaded",
                "upload_id": upload_id,
                "filename": filename,
                "user_id": user_id,
                "file_path": str(final_path),
                "file_size": len(file_data),
                "timestamp": datetime.now().isoformat()
            })
            
        except Exception as e:
            result["errors"].append(f"Upload error: {str(e)}")
            
            # Log error
            self.audit_log.append({
                "event": "upload_error",
                "filename": filename,
                "user_id": user_id,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            })
        
        return result
    
    def get_audit_log(self) -> List[Dict]:
        """Get audit log entries"""
        return self.audit_log.copy()
    
    def clean_temp_files(self, max_age_hours: int = 24):
        """Clean old temporary files"""
        import time
        current_time = time.time()
        
        for temp_file in self.config.temp_path.glob("*"):
            if temp_file.is_file():
                file_age = current_time - temp_file.stat().st_mtime
                if file_age > (max_age_hours * 3600):
                    try:
                        temp_file.unlink()
                    except:
                        pass

# Global file upload instance
_file_upload: Optional[SecureFileUpload] = None

def get_file_upload(config: FileUploadConfig = None) -> SecureFileUpload:
    """Get global file upload instance"""
    global _file_upload
    
    if _file_upload is None:
        _file_upload = SecureFileUpload(config)
    
    return _file_upload