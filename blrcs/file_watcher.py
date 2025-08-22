# BLRCS File Watcher Module  
# Lightweight file monitoring following Carmack's efficiency principles
import os
import time
import threading
from pathlib import Path
from typing import Dict, List, Callable, Optional, Set
from dataclasses import dataclass
from collections import defaultdict

@dataclass
class FileInfo:
    """File information for tracking changes"""
    path: Path
    size: int
    mtime: float
    
    @classmethod
    def from_path(cls, path: Path) -> 'FileInfo':
        """Create FileInfo from path"""
        stat = path.stat()
        return cls(path=path, size=stat.st_size, mtime=stat.st_mtime)
    
    def has_changed(self, other: 'FileInfo') -> bool:
        """Check if file has changed"""
        return self.size != other.size or self.mtime != other.mtime

class FileWatcher:
    """
    Simple and efficient file watcher.
    No external dependencies, just Python.
    """
    
    def __init__(self, interval: float = 1.0):
        self.interval = interval
        self.watched_files: Dict[Path, FileInfo] = {}
        self.watched_dirs: Dict[Path, Set[Path]] = {}
        self.callbacks: Dict[str, List[Callable]] = defaultdict(list)
        self.running = False
        self.thread: Optional[threading.Thread] = None
    
    def watch_file(self, path: Path, callback: Optional[Callable] = None):
        """Watch a single file for changes"""
        path = Path(path).resolve()
        if path.exists() and path.is_file():
            self.watched_files[path] = FileInfo.from_path(path)
            if callback:
                self.callbacks['file_changed'].append(callback)
    
    def watch_directory(self, path: Path, pattern: str = "*", callback: Optional[Callable] = None):
        """Watch directory for changes"""
        path = Path(path).resolve()
        if path.exists() and path.is_dir():
            # Get initial file list
            files = set(path.glob(pattern))
            self.watched_dirs[path] = files
            
            # Track individual files
            for file_path in files:
                if file_path.is_file():
                    self.watched_files[file_path] = FileInfo.from_path(file_path)
            
            if callback:
                self.callbacks['dir_changed'].append(callback)
    
    def unwatch_file(self, path: Path):
        """Stop watching a file"""
        path = Path(path).resolve()
        if path in self.watched_files:
            del self.watched_files[path]
    
    def unwatch_directory(self, path: Path):
        """Stop watching a directory"""
        path = Path(path).resolve()
        if path in self.watched_dirs:
            # Remove files from this directory
            for file_path in self.watched_dirs[path]:
                if file_path in self.watched_files:
                    del self.watched_files[file_path]
            del self.watched_dirs[path]
    
    def on(self, event: str, callback: Callable):
        """Register event callback"""
        self.callbacks[event].append(callback)
    
    def start(self):
        """Start watching"""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._watch_loop, daemon=True)
        self.thread.start()
    
    def stop(self):
        """Stop watching"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=self.interval * 2)
    
    def _watch_loop(self):
        """Main watch loop"""
        while self.running:
            try:
                self._check_changes()
                time.sleep(self.interval)
            except Exception:
                pass  # Continue watching even if check fails
    
    def _check_changes(self):
        """Check for file changes"""
        # Check watched files
        for path, old_info in list(self.watched_files.items()):
            if not path.exists():
                # File deleted
                self._trigger_event('file_deleted', path)
                del self.watched_files[path]
            else:
                # Check if modified
                try:
                    new_info = FileInfo.from_path(path)
                    if old_info.has_changed(new_info):
                        self.watched_files[path] = new_info
                        self._trigger_event('file_changed', path)
                except:
                    pass  # File might be locked
        
        # Check watched directories
        for dir_path, old_files in list(self.watched_dirs.items()):
            if not dir_path.exists():
                # Directory deleted
                self._trigger_event('dir_deleted', dir_path)
                del self.watched_dirs[dir_path]
            else:
                # Check for new/deleted files
                current_files = set(dir_path.glob("*"))
                
                # New files
                new_files = current_files - old_files
                for file_path in new_files:
                    if file_path.is_file():
                        self.watched_files[file_path] = FileInfo.from_path(file_path)
                        self._trigger_event('file_created', file_path)
                
                # Deleted files
                deleted_files = old_files - current_files
                for file_path in deleted_files:
                    if file_path in self.watched_files:
                        del self.watched_files[file_path]
                    self._trigger_event('file_deleted', file_path)
                
                # Update watched files
                self.watched_dirs[dir_path] = current_files
    
    def _trigger_event(self, event: str, path: Path):
        """Trigger event callbacks"""
        for callback in self.callbacks[event]:
            try:
                callback(path)
            except:
                pass  # Don't let callback errors stop watching

class SimpleFileMonitor:
    """
    Even simpler file monitor for basic needs.
    Polling-based, no threads.
    """
    
    def __init__(self):
        self.files: Dict[str, float] = {}
    
    def add_file(self, path: str):
        """Add file to monitor"""
        if os.path.exists(path):
            self.files[path] = os.path.getmtime(path)
    
    def check_changes(self) -> List[str]:
        """Check for changed files"""
        changed = []
        
        for path, old_mtime in list(self.files.items()):
            if not os.path.exists(path):
                # File deleted
                del self.files[path]
                changed.append(path)
            else:
                new_mtime = os.path.getmtime(path)
                if new_mtime != old_mtime:
                    self.files[path] = new_mtime
                    changed.append(path)
        
        return changed
    
    def clear(self):
        """Clear all monitored files"""
        self.files.clear()

# Global watcher instance
_file_watcher: Optional[FileWatcher] = None

def get_file_watcher() -> FileWatcher:
    """Get global file watcher instance"""
    global _file_watcher
    if _file_watcher is None:
        _file_watcher = FileWatcher()
    return _file_watcher

def watch_config_files(callback: Callable):
    """Watch configuration files for changes"""
    watcher = get_file_watcher()
    
    # Watch common config files
    config_files = [
        Path('.env'),
        Path('config.json'),
        Path('settings.json'),
        Path('blrcs.conf')
    ]
    
    for config_file in config_files:
        if config_file.exists():
            watcher.watch_file(config_file, callback)
    
    return watcher