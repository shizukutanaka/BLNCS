# BLRCS Utilities Module
# Practical utility functions and helpers
import os
import re
import sys
import time
import uuid
import json
import base64
import hashlib
import tempfile
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple, Iterator
from datetime import datetime, timedelta
from dataclasses import dataclass
import zipfile
import tarfile
import csv
import xml.etree.ElementTree as ET

@dataclass
class FileInfo:
    """File information structure"""
    path: Path
    size: int
    modified: float
    created: float
    is_directory: bool
    permissions: str
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None

class FileUtils:
    """File system utilities"""
    
    @staticmethod
    def get_file_info(file_path: Path, calculate_hash: bool = False) -> FileInfo:
        """Get comprehensive file information"""
        file_path = Path(file_path)
        stat = file_path.stat()
        
        info = FileInfo(
            path=file_path,
            size=stat.st_size,
            modified=stat.st_mtime,
            created=stat.st_ctime,
            is_directory=file_path.is_dir(),
            permissions=oct(stat.st_mode)[-3:]
        )
        
        if calculate_hash and file_path.is_file():
            info.hash_md5 = FileUtils.calculate_hash(file_path, 'md5')
            info.hash_sha256 = FileUtils.calculate_hash(file_path, 'sha256')
        
        return info
    
    @staticmethod
    def calculate_hash(file_path: Path, algorithm: str = 'sha256') -> str:
        """Calculate file hash"""
        hash_obj = hashlib.new(algorithm)
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
    
    @staticmethod
    def find_files(directory: Path, pattern: str = "*", 
                  recursive: bool = True, include_dirs: bool = False) -> List[Path]:
        """Find files matching pattern"""
        directory = Path(directory)
        
        if recursive:
            files = directory.rglob(pattern)
        else:
            files = directory.glob(pattern)
        
        result = []
        for file_path in files:
            if include_dirs or file_path.is_file():
                result.append(file_path)
        
        return sorted(result)
    
    @staticmethod
    def find_duplicates(directory: Path) -> Dict[str, List[Path]]:
        """Find duplicate files by hash"""
        file_hashes = {}
        duplicates = {}
        
        for file_path in FileUtils.find_files(directory):
            if file_path.is_file():
                file_hash = FileUtils.calculate_hash(file_path)
                
                if file_hash in file_hashes:
                    if file_hash not in duplicates:
                        duplicates[file_hash] = [file_hashes[file_hash]]
                    duplicates[file_hash].append(file_path)
                else:
                    file_hashes[file_hash] = file_path
        
        return duplicates
    
    @staticmethod
    def clean_directory(directory: Path, patterns: List[str], 
                       dry_run: bool = True) -> List[Path]:
        """Clean directory by removing files matching patterns"""
        directory = Path(directory)
        removed_files = []
        
        for pattern in patterns:
            for file_path in directory.rglob(pattern):
                if file_path.is_file():
                    removed_files.append(file_path)
                    
                    if not dry_run:
                        file_path.unlink()
        
        return removed_files
    
    @staticmethod
    def archive_directory(source: Path, archive_path: Path, 
                         format: str = 'zip') -> bool:
        """Archive directory"""
        source = Path(source)
        archive_path = Path(archive_path)
        
        try:
            if format == 'zip':
                with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                    for file_path in source.rglob('*'):
                        if file_path.is_file():
                            arcname = file_path.relative_to(source)
                            zf.write(file_path, arcname)
            
            elif format in ['tar', 'tar.gz', 'tar.bz2']:
                mode = 'w'
                if format == 'tar.gz':
                    mode = 'w:gz'
                elif format == 'tar.bz2':
                    mode = 'w:bz2'
                
                with tarfile.open(archive_path, mode) as tf:
                    tf.add(source, arcname=source.name)
            
            return True
        
        except Exception:
            return False

class DataUtils:
    """Data processing utilities"""
    
    @staticmethod
    def csv_to_json(csv_path: Path, json_path: Path, 
                   delimiter: str = ',') -> bool:
        """Convert CSV file to JSON"""
        try:
            data = []
            
            with open(csv_path, 'r', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile, delimiter=delimiter)
                for row in reader:
                    data.append(row)
            
            with open(json_path, 'w', encoding='utf-8') as jsonfile:
                json.dump(data, jsonfile, indent=2, ensure_ascii=False)
            
            return True
        
        except Exception:
            return False
    
    @staticmethod
    def json_to_csv(json_path: Path, csv_path: Path, 
                   delimiter: str = ',') -> bool:
        """Convert JSON file to CSV"""
        try:
            with open(json_path, 'r', encoding='utf-8') as jsonfile:
                data = json.load(jsonfile)
            
            if not data or not isinstance(data, list):
                return False
            
            fieldnames = set()
            for item in data:
                if isinstance(item, dict):
                    fieldnames.update(item.keys())
            
            fieldnames = sorted(fieldnames)
            
            with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, 
                                       delimiter=delimiter)
                writer.writeheader()
                for item in data:
                    if isinstance(item, dict):
                        writer.writerow(item)
            
            return True
        
        except Exception:
            return False
    
    @staticmethod
    def xml_to_json(xml_path: Path, json_path: Path) -> bool:
        """Convert XML file to JSON"""
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            def element_to_dict(element):
                result = {}
                
                # Attributes
                if element.attrib:
                    result['@attributes'] = element.attrib
                
                # Text content
                if element.text and element.text.strip():
                    if len(element) == 0:  # No children
                        return element.text.strip()
                    else:
                        result['#text'] = element.text.strip()
                
                # Children
                for child in element:
                    child_data = element_to_dict(child)
                    
                    if child.tag in result:
                        if not isinstance(result[child.tag], list):
                            result[child.tag] = [result[child.tag]]
                        result[child.tag].append(child_data)
                    else:
                        result[child.tag] = child_data
                
                return result
            
            data = {root.tag: element_to_dict(root)}
            
            with open(json_path, 'w', encoding='utf-8') as jsonfile:
                json.dump(data, jsonfile, indent=2, ensure_ascii=False)
            
            return True
        
        except Exception:
            return False
    
    @staticmethod
    def validate_json(json_path: Path) -> Tuple[bool, str]:
        """Validate JSON file"""
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                json.load(f)
            return True, "Valid JSON"
        
        except json.JSONDecodeError as e:
            return False, f"JSON Error: {e}"
        except Exception as e:
            return False, f"File Error: {e}"

class SystemUtils:
    """System management utilities"""
    
    @staticmethod
    def get_system_info() -> Dict[str, Any]:
        """Get comprehensive system information"""
        import platform
        import psutil
        
        try:
            boot_time = psutil.boot_time()
            boot_datetime = datetime.fromtimestamp(boot_time)
        except:
            boot_datetime = None
        
        return {
            "platform": {
                "system": platform.system(),
                "node": platform.node(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "python_version": platform.python_version(),
                "python_implementation": platform.python_implementation()
            },
            "cpu": {
                "physical_cores": psutil.cpu_count(logical=False),
                "total_cores": psutil.cpu_count(logical=True),
                "max_frequency": psutil.cpu_freq().max if psutil.cpu_freq() else None,
                "current_frequency": psutil.cpu_freq().current if psutil.cpu_freq() else None,
                "cpu_usage": psutil.cpu_percent(interval=1)
            },
            "memory": {
                "total": psutil.virtual_memory().total,
                "available": psutil.virtual_memory().available,
                "used": psutil.virtual_memory().used,
                "percentage": psutil.virtual_memory().percent
            },
            "disk": {
                "total": psutil.disk_usage('/').total,
                "used": psutil.disk_usage('/').used,
                "free": psutil.disk_usage('/').free,
                "percentage": psutil.disk_usage('/').percent
            },
            "network": {
                "bytes_sent": psutil.net_io_counters().bytes_sent,
                "bytes_received": psutil.net_io_counters().bytes_recv,
                "packets_sent": psutil.net_io_counters().packets_sent,
                "packets_received": psutil.net_io_counters().packets_recv
            },
            "boot_time": boot_datetime.isoformat() if boot_datetime else None,
            "uptime_hours": (time.time() - boot_time) / 3600 if boot_time else None
        }
    
    @staticmethod
    def get_running_processes() -> List[Dict[str, Any]]:
        """Get list of running processes"""
        import psutil
        
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        return sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)
    
    @staticmethod
    def kill_process(pid: int) -> bool:
        """Kill process by PID"""
        import psutil
        
        try:
            process = psutil.Process(pid)
            process.terminate()
            return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
    
    @staticmethod
    def run_command(command: str, timeout: int = 30) -> Tuple[bool, str, str]:
        """Run system command safely"""
        try:
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return result.returncode == 0, result.stdout, result.stderr
        
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)

class TextUtils:
    """Text processing utilities"""
    
    @staticmethod
    def extract_emails(text: str) -> List[str]:
        """Extract email addresses from text"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return re.findall(email_pattern, text)
    
    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extract URLs from text"""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        return re.findall(url_pattern, text)
    
    @staticmethod
    def extract_phone_numbers(text: str) -> List[str]:
        """Extract phone numbers from text"""
        phone_patterns = [
            r'\b\d{3}-\d{3}-\d{4}\b',  # 123-456-7890
            r'\b\(\d{3}\)\s\d{3}-\d{4}\b',  # (123) 456-7890
            r'\b\d{3}\.\d{3}\.\d{4}\b',  # 123.456.7890
            r'\b\d{10}\b'  # 1234567890
        ]
        
        phone_numbers = []
        for pattern in phone_patterns:
            phone_numbers.extend(re.findall(pattern, text))
        
        return phone_numbers
    
    @staticmethod
    def clean_text(text: str, remove_extra_spaces: bool = True,
                  remove_special_chars: bool = False) -> str:
        """Clean and normalize text"""
        cleaned = text.strip()
        
        if remove_extra_spaces:
            cleaned = re.sub(r'\s+', ' ', cleaned)
        
        if remove_special_chars:
            cleaned = re.sub(r'[^\w\s]', '', cleaned)
        
        return cleaned
    
    @staticmethod
    def word_count(text: str) -> Dict[str, int]:
        """Count words in text"""
        words = re.findall(r'\b\w+\b', text.lower())
        word_counts = {}
        
        for word in words:
            word_counts[word] = word_counts.get(word, 0) + 1
        
        return dict(sorted(word_counts.items(), key=lambda x: x[1], reverse=True))

class NetworkUtils:
    """Network utilities"""
    
    @staticmethod
    def ping_host(host: str, timeout: int = 5) -> Tuple[bool, float]:
        """Ping a host and return success and response time"""
        import subprocess
        import platform
        
        system = platform.system().lower()
        
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout), host]
        
        try:
            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 1)
            response_time = time.time() - start_time
            
            return result.returncode == 0, response_time
        
        except subprocess.TimeoutExpired:
            return False, timeout
        except Exception:
            return False, -1
    
    @staticmethod
    def check_port(host: str, port: int, timeout: int = 5) -> bool:
        """Check if a port is open on a host"""
        import socket
        
        try:
            with socket.create_connection((host, port), timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False
    
    @staticmethod
    def get_local_ip() -> str:
        """Get local IP address"""
        import socket
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

class DateTimeUtils:
    """Date and time utilities"""
    
    @staticmethod
    def format_duration(seconds: float) -> str:
        """Format duration in human-readable format"""
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        else:
            return f"{seconds/86400:.1f} days"
    
    @staticmethod
    def parse_duration(duration_str: str) -> Optional[float]:
        """Parse duration string to seconds"""
        duration_str = duration_str.lower().strip()
        
        patterns = [
            (r'(\d+(?:\.\d+)?)\s*s(?:ec(?:onds?)?)?', 1),
            (r'(\d+(?:\.\d+)?)\s*m(?:in(?:utes?)?)?', 60),
            (r'(\d+(?:\.\d+)?)\s*h(?:our(?:s)?)?', 3600),
            (r'(\d+(?:\.\d+)?)\s*d(?:ay(?:s)?)?', 86400)
        ]
        
        for pattern, multiplier in patterns:
            match = re.search(pattern, duration_str)
            if match:
                return float(match.group(1)) * multiplier
        
        return None
    
    @staticmethod
    def get_timezone_offset() -> str:
        """Get current timezone offset"""
        import time
        
        offset = time.timezone if (time.daylight == 0) else time.altzone
        hours, remainder = divmod(abs(offset), 3600)
        minutes = remainder // 60
        sign = '-' if offset > 0 else '+'
        
        return f"{sign}{hours:02d}:{minutes:02d}"

# Convenience functions
def generate_uuid() -> str:
    """Generate UUID string"""
    return str(uuid.uuid4())

def generate_random_string(length: int = 16) -> str:
    """Generate random string"""
    import secrets
    import string
    
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def encode_base64(data: Union[str, bytes]) -> str:
    """Encode data to base64"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    return base64.b64encode(data).decode('ascii')

def decode_base64(encoded: str) -> bytes:
    """Decode base64 data"""
    return base64.b64decode(encoded)

def safe_filename(filename: str) -> str:
    """Make filename safe for filesystem"""
    # Remove or replace dangerous characters
    safe = re.sub(r'[<>:"/\\|?*]', '_', filename)
    safe = re.sub(r'[\x00-\x1f\x7f]', '', safe)  # Remove control characters
    safe = safe.strip('. ')  # Remove leading/trailing dots and spaces
    
    # Ensure not empty
    if not safe:
        safe = "file"
    
    # Limit length
    if len(safe) > 255:
        safe = safe[:255]
    
    return safe

def human_readable_size(size_bytes: int) -> str:
    """Convert bytes to human readable format"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB", "PB"]
    import math
    
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    
    return f"{s} {size_names[i]}"