# BLRCS Crash Reporter Module
# Automatic crash reporting following Martin's clean code principles
import sys
import traceback
import json
import platform
import time
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List
import threading

class CrashReporter:
    """
    Crash reporting and recovery.
    Simple, automatic, and informative.
    """
    
    def __init__(self, crash_dir: Path = Path("crash_reports")):
        self.crash_dir = Path(crash_dir)
        self.crash_dir.mkdir(exist_ok=True)
        
        self.enabled = True
        self.include_system_info = True
        self.include_traceback = True
        self.max_reports = 10
        
        # Install exception hook
        self.original_hook = sys.excepthook
        sys.excepthook = self._exception_hook
        
        # Thread exception hook (Python 3.8+)
        if hasattr(threading, 'excepthook'):
            self.original_thread_hook = threading.excepthook
            threading.excepthook = self._thread_exception_hook
    
    def _exception_hook(self, exc_type, exc_value, exc_traceback):
        """Handle uncaught exceptions"""
        if self.enabled:
            self.create_crash_report(exc_type, exc_value, exc_traceback)
        
        # Call original hook
        self.original_hook(exc_type, exc_value, exc_traceback)
    
    def _thread_exception_hook(self, args):
        """Handle uncaught thread exceptions"""
        if self.enabled:
            self.create_crash_report(
                args.exc_type,
                args.exc_value,
                args.exc_traceback,
                thread_info={"thread": args.thread.name}
            )
        
        # Call original hook if exists
        if hasattr(self, 'original_thread_hook'):
            self.original_thread_hook(args)
    
    def create_crash_report(self, exc_type, exc_value, exc_traceback, 
                          thread_info: Optional[Dict] = None) -> Optional[Path]:
        """Create crash report file"""
        try:
            # Generate report ID
            timestamp = datetime.now()
            report_id = timestamp.strftime("%Y%m%d_%H%M%S")
            report_file = self.crash_dir / f"crash_{report_id}.json"
            
            # Build report
            report = {
                'id': report_id,
                'timestamp': timestamp.isoformat(),
                'exception': {
                    'type': exc_type.__name__ if exc_type else 'Unknown',
                    'message': str(exc_value) if exc_value else '',
                    'module': exc_type.__module__ if exc_type else ''
                }
            }
            
            # Add traceback
            if self.include_traceback and exc_traceback:
                tb_lines = traceback.format_tb(exc_traceback)
                report['traceback'] = tb_lines
                
                # Extract location
                tb_summary = traceback.extract_tb(exc_traceback)
                if tb_summary:
                    last_frame = tb_summary[-1]
                    report['location'] = {
                        'file': last_frame.filename,
                        'line': last_frame.lineno,
                        'function': last_frame.name
                    }
            
            # Add system info
            if self.include_system_info:
                report['system'] = self._get_system_info()
            
            # Add thread info if provided
            if thread_info:
                report['thread'] = thread_info
            
            # Add context
            report['context'] = self._get_context()
            
            # Save report
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            # Cleanup old reports
            self._cleanup_old_reports()
            
            return report_file
            
        except:
            # Failed to create report
            return None
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Collect system information"""
        try:
            import psutil
            memory = psutil.virtual_memory()
            memory_info = {
                'total_mb': memory.total / 1024 / 1024,
                'available_mb': memory.available / 1024 / 1024,
                'percent': memory.percent
            }
        except:
            memory_info = {}
        
        return {
            'platform': platform.platform(),
            'python_version': platform.python_version(),
            'processor': platform.processor(),
            'architecture': platform.machine(),
            'memory': memory_info
        }
    
    def _get_context(self) -> Dict[str, Any]:
        """Get application context"""
        context = {
            'argv': sys.argv,
            'cwd': str(Path.cwd()),
            'modules': list(sys.modules.keys())[:50]  # First 50 modules
        }
        
        # Add config if available
        try:
            from blrcs.config import get_config
            config = get_config()
            context['config'] = {
                'mode': config.mode,
                'debug': config.debug,
                'log_level': config.log_level
            }
        except:
            pass
        
        return context
    
    def _cleanup_old_reports(self):
        """Remove old crash reports"""
        reports = sorted(self.crash_dir.glob("crash_*.json"))
        
        while len(reports) > self.max_reports:
            oldest = reports.pop(0)
            try:
                oldest.unlink()
            except:
                pass
    
    def list_crash_reports(self) -> List[Dict[str, Any]]:
        """List all crash reports"""
        reports = []
        
        for report_file in sorted(self.crash_dir.glob("crash_*.json")):
            try:
                with open(report_file, 'r') as f:
                    data = json.load(f)
                    reports.append({
                        'file': str(report_file),
                        'id': data.get('id'),
                        'timestamp': data.get('timestamp'),
                        'exception': data.get('exception', {}).get('type')
                    })
            except:
                pass
        
        return reports
    
    def get_report(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Get specific crash report"""
        report_file = self.crash_dir / f"crash_{report_id}.json"
        
        if not report_file.exists():
            return None
        
        try:
            with open(report_file, 'r') as f:
                return json.load(f)
        except:
            return None
    
    def clear_reports(self):
        """Clear all crash reports"""
        for report_file in self.crash_dir.glob("crash_*.json"):
            try:
                report_file.unlink()
            except:
                pass
    
    def disable(self):
        """Disable crash reporting"""
        self.enabled = False
        sys.excepthook = self.original_hook
        
        if hasattr(threading, 'excepthook'):
            threading.excepthook = self.original_thread_hook
    
    def enable(self):
        """Enable crash reporting"""
        self.enabled = True
        sys.excepthook = self._exception_hook
        
        if hasattr(threading, 'excepthook'):
            threading.excepthook = self._thread_exception_hook

class SafeExecutor:
    """
    Execute code with crash protection.
    Following Pike's simplicity principle.
    """
    
    def __init__(self, crash_reporter: Optional[CrashReporter] = None):
        self.crash_reporter = crash_reporter or CrashReporter()
    
    def run(self, func, *args, **kwargs):
        """Run function with crash protection"""
        try:
            return func(*args, **kwargs)
        except Exception as e:
            # Create crash report
            exc_info = sys.exc_info()
            self.crash_reporter.create_crash_report(*exc_info)
            
            # Re-raise
            raise
    
    def run_safe(self, func, *args, default=None, **kwargs):
        """Run function safely, return default on crash"""
        try:
            return func(*args, **kwargs)
        except Exception as e:
            # Create crash report
            exc_info = sys.exc_info()
            self.crash_reporter.create_crash_report(*exc_info)
            
            # Return default
            return default

# Global crash reporter
_crash_reporter: Optional[CrashReporter] = None

def get_crash_reporter() -> CrashReporter:
    """Get global crash reporter"""
    global _crash_reporter
    if _crash_reporter is None:
        _crash_reporter = CrashReporter()
    return _crash_reporter

def enable_crash_reporting(crash_dir: str = "crash_reports"):
    """Enable global crash reporting"""
    reporter = get_crash_reporter()
    reporter.crash_dir = Path(crash_dir)
    reporter.enable()
    return reporter

def report_crash(exception: Exception, context: Optional[Dict] = None):
    """Manually report a crash"""
    reporter = get_crash_reporter()
    exc_info = (type(exception), exception, exception.__traceback__)
    return reporter.create_crash_report(*exc_info)

def get_last_crash() -> Optional[Dict[str, Any]]:
    """Get the most recent crash report"""
    reporter = get_crash_reporter()
    reports = reporter.list_crash_reports()
    
    if reports:
        latest = reports[-1]
        return reporter.get_report(latest['id'])
    
    return None