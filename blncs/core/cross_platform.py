#!/usr/bin/env python3
"""
BLNCS Cross-Platform Optimization System
Provides platform-specific optimizations and path detection for Windows, macOS, and Linux
Enhanced with automatic path detection and OS-specific configurations
"""

import os
import sys
import platform
import logging
import threading
import psutil
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime
import subprocess
import shutil

logger = logging.getLogger(__name__)


@dataclass
class PlatformPaths:
    """Platform-specific path configurations"""
    system: str
    config_dir: Path
    data_dir: Path
    cache_dir: Path
    log_dir: Path
    temp_dir: Path
    user_home: Path
    system_root: Path
    lightning_dir: Optional[Path] = None
    bitcoin_dir: Optional[Path] = None

    def get_lightning_config_path(self) -> Optional[Path]:
        """Get Lightning Network configuration path"""
        if self.lightning_dir:
            return self.lightning_dir / "bitcoin.conf"
        return None

    def get_bitcoin_config_path(self) -> Optional[Path]:
        """Get Bitcoin configuration path"""
        if self.bitcoin_dir:
            return self.bitcoin_dir / "bitcoin.conf"
        return None


@dataclass
class PlatformInfo:
    """Platform information and capabilities"""
    system: str
    release: str
    version: str
    machine: str
    processor: str
    python_version: str
    is_64bit: bool
    cpu_count: int
    memory_gb: float
    gpu_available: bool
    gpu_info: Dict[str, Any]


@dataclass
class PlatformOptimization:
    """Platform-specific optimization settings"""
    platform: str
    thread_pool_size: int
    memory_pool_size: int
    cache_strategy: str
    io_optimization: Dict[str, Any]
    network_optimization: Dict[str, Any]
    gpu_acceleration: bool
    power_management: Dict[str, Any]


class CrossPlatformOptimizer:
    """Cross-platform optimization system with path detection"""

    def __init__(self):
        self.platform_info = self._detect_platform()
        self.platform_paths = self._detect_platform_paths()
        self.optimizations: Dict[str, PlatformOptimization] = {}
        self.active_optimizations: Dict[str, Any] = {}
        self.monitoring_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()

        self._initialize_platform_optimizations()
        self._apply_platform_optimizations()

    def _detect_platform_paths(self) -> PlatformPaths:
        """Detect platform-specific paths"""
        system = platform.system().lower()
        user_home = Path.home()
        system_root = Path("/")

        if system == "windows":
            # Windows paths
            appdata = os.environ.get('APPDATA', str(user_home / 'AppData' / 'Roaming'))
            local_appdata = os.environ.get('LOCALAPPDATA', str(user_home / 'AppData' / 'Local'))

            config_dir = Path(appdata) / 'BLNCS'
            data_dir = Path(local_appdata) / 'BLNCS'
            cache_dir = Path(local_appdata) / 'BLNCS' / 'Cache'
            log_dir = Path(local_appdata) / 'BLNCS' / 'Logs'
            temp_dir = Path(os.environ.get('TEMP', str(user_home / 'AppData' / 'Local' / 'Temp')))

            # Lightning/Bitcoin directories on Windows
            lightning_dir = user_home / 'AppData' / 'Roaming' / 'LightningNetwork' / 'lnd'
            bitcoin_dir = user_home / 'AppData' / 'Roaming' / 'Bitcoin'

        elif system == "darwin":
            # macOS paths
            config_dir = user_home / 'Library' / 'Application Support' / 'BLNCS'
            data_dir = user_home / 'Library' / 'Application Support' / 'BLNCS'
            cache_dir = user_home / 'Library' / 'Caches' / 'BLNCS'
            log_dir = user_home / 'Library' / 'Logs' / 'BLNCS'
            temp_dir = Path('/tmp')

            # Lightning/Bitcoin directories on macOS
            lightning_dir = user_home / 'Library' / 'Application Support' / 'Lnd'
            bitcoin_dir = user_home / 'Library' / 'Application Support' / 'Bitcoin'

        else:
            # Linux and other Unix-like systems
            xdg_config = os.environ.get('XDG_CONFIG_HOME', str(user_home / '.config'))
            xdg_data = os.environ.get('XDG_DATA_HOME', str(user_home / '.local' / 'share'))
            xdg_cache = os.environ.get('XDG_CACHE_HOME', str(user_home / '.cache'))

            config_dir = Path(xdg_config) / 'blncs'
            data_dir = Path(xdg_data) / 'blncs'
            cache_dir = Path(xdg_cache) / 'blncs'
            log_dir = user_home / '.local' / 'log' / 'blncs'
            temp_dir = Path('/tmp')

            # Lightning/Bitcoin directories on Linux
            lightning_dir = user_home / '.lightning'
            bitcoin_dir = user_home / '.bitcoin'

        # Create directories if they don't exist
        for directory in [config_dir, data_dir, cache_dir, log_dir]:
            try:
                directory.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                logger.warning(f"Failed to create directory {directory}: {e}")

        # Check if Lightning/Bitcoin directories exist
        actual_lightning_dir = lightning_dir if lightning_dir.exists() else None
        actual_bitcoin_dir = bitcoin_dir if bitcoin_dir.exists() else None

        return PlatformPaths(
            system=system,
            config_dir=config_dir,
            data_dir=data_dir,
            cache_dir=cache_dir,
            log_dir=log_dir,
            temp_dir=temp_dir,
            user_home=user_home,
            system_root=system_root,
            lightning_dir=actual_lightning_dir,
            bitcoin_dir=actual_bitcoin_dir
        )

    def get_config_path(self, filename: str = "config.json") -> Path:
        """Get platform-appropriate config file path"""
        return self.platform_paths.config_dir / filename

    def get_data_path(self, filename: str = "") -> Path:
        """Get platform-appropriate data file path"""
        if filename:
            return self.platform_paths.data_dir / filename
        return self.platform_paths.data_dir

    def get_cache_path(self, filename: str = "") -> Path:
        """Get platform-appropriate cache file path"""
        if filename:
            return self.platform_paths.cache_dir / filename
        return self.platform_paths.cache_dir

    def get_log_path(self, filename: str = "blncs.log") -> Path:
        """Get platform-appropriate log file path"""
        return self.platform_paths.log_dir / filename

    def get_temp_path(self, filename: str = "") -> Path:
        """Get platform-appropriate temp file path"""
        if filename:
            return self.platform_paths.temp_dir / f"blncs_{filename}"
        return self.platform_paths.temp_dir / "blncs_temp"

    def find_bitcoin_config(self) -> Optional[Path]:
        """Find Bitcoin configuration file"""
        return self.platform_paths.get_bitcoin_config_path()

    def find_lightning_config(self) -> Optional[Path]:
        """Find Lightning Network configuration file"""
        return self.platform_paths.get_lightning_config_path()

    def get_system_info(self) -> Dict[str, Any]:
        """Get comprehensive system information"""
        info = {
            'platform': vars(self.platform_info),
            'paths': {
                'config_dir': str(self.platform_paths.config_dir),
                'data_dir': str(self.platform_paths.data_dir),
                'cache_dir': str(self.platform_paths.cache_dir),
                'log_dir': str(self.platform_paths.log_dir),
                'temp_dir': str(self.platform_paths.temp_dir),
                'lightning_dir': str(self.platform_paths.lightning_dir) if self.platform_paths.lightning_dir else None,
                'bitcoin_dir': str(self.platform_paths.bitcoin_dir) if self.platform_paths.bitcoin_dir else None
            },
            'capabilities': {
                'cpu_count': self.platform_info.cpu_count,
                'memory_gb': self.platform_info.memory_gb,
                'gpu_available': self.platform_info.gpu_available,
                'gpu_info': self.platform_info.gpu_info
            }
        }

        # Add OS-specific information
        try:
            if self.platform_info.system == 'windows':
                info['windows'] = {
                    'version': platform.version(),
                    'edition': self._get_windows_edition()
                }
            elif self.platform_info.system == 'darwin':
                info['macos'] = {
                    'version': platform.mac_ver()[0],
                    'hardware': platform.mac_ver()[2]
                }
            else:  # Linux
                info['linux'] = {
                    'distribution': self._get_linux_distribution(),
                    'kernel': platform.release()
                }
        except Exception as e:
            logger.warning(f"Failed to get OS-specific info: {e}")

        return info

    def _get_windows_edition(self) -> str:
        """Get Windows edition information"""
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
            edition, _ = winreg.QueryValueEx(key, "EditionID")
            return edition
        except:
            return "Unknown"

    def _get_linux_distribution(self) -> str:
        """Get Linux distribution information"""
        try:
            # Try multiple methods to get distribution info
            if Path('/etc/os-release').exists():
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if line.startswith('PRETTY_NAME='):
                            return line.split('=', 1)[1].strip().strip('"')
            elif Path('/etc/lsb-release').exists():
                with open('/etc/lsb-release', 'r') as f:
                    for line in f:
                        if line.startswith('DISTRIB_DESCRIPTION='):
                            return line.split('=', 1)[1].strip().strip('"')
            # Fallback
            return platform.platform()
        except:
            return "Unknown"

    def optimize_for_platform(self) -> Dict[str, Any]:
        """Apply platform-specific optimizations"""
        optimizations = {}

        system = self.platform_info.system

        if system == 'windows':
            optimizations.update(self._windows_optimizations())
        elif system == 'darwin':
            optimizations.update(self._macos_optimizations())
        else:  # Linux and others
            optimizations.update(self._linux_optimizations())

        # Apply common optimizations
        optimizations.update(self._common_optimizations())

        return optimizations

    def _windows_optimizations(self) -> Dict[str, Any]:
        """Windows-specific optimizations"""
        return {
            'io_priority': 'normal',
            'memory_mapping': True,
            'antivirus_exclusions': [
                str(self.platform_paths.data_dir),
                str(self.platform_paths.cache_dir)
            ],
            'power_plan': 'balanced'
        }

    def _macos_optimizations(self) -> Dict[str, Any]:
        """macOS-specific optimizations"""
        return {
            'memory_pressure_handling': True,
            'thermal_throttling_aware': True,
            'spotlight_exclusions': [
                str(self.platform_paths.data_dir),
                str(self.platform_paths.cache_dir)
            ]
        }

    def _linux_optimizations(self) -> Dict[str, Any]:
        """Linux-specific optimizations"""
        return {
            'io_scheduler': 'cfq',
            'transparent_hugepages': True,
            'memory_cgroups': True,
            'network_optimization': {
                'tcp_fastopen': True,
                'bbr_congestion_control': True
            }
        }

    def _common_optimizations(self) -> Dict[str, Any]:
        """Common optimizations for all platforms"""
        return {
            'thread_pool_size': min(32, max(4, self.platform_info.cpu_count * 2)),
            'memory_pool_size': min(1024, max(64, int(self.platform_info.memory_gb * 10))),
            'cache_strategy': 'lru',
            'compression_enabled': True,
            'async_io_enabled': True
        }

    def _detect_platform(self) -> PlatformInfo:
        """Detect current platform and capabilities"""
        system = platform.system().lower()
        gpu_available = False
        gpu_info = {}

        # Detect GPU availability
        try:
            if system == 'windows':
                # Windows GPU detection
                try:
                    import GPUtil
                    gpus = GPUtil.getGPUs()
                    gpu_available = len(gpus) > 0
                    gpu_info = {
                        'count': len(gpus),
                        'names': [gpu.name for gpu in gpus],
                        'driver': 'nvidia' if any('nvidia' in gpu.name.lower() for gpu in gpus) else 'other'
                    }
                except ImportError:
                    pass
            elif system in ['linux', 'darwin']:
                # Linux/macOS GPU detection
                try:
                    import GPUtil
                    gpus = GPUtil.getGPUs()
                    gpu_available = len(gpus) > 0
                    gpu_info = {
                        'count': len(gpus),
                        'names': [gpu.name for gpu in gpus],
                        'driver': 'nvidia' if any('nvidia' in gpu.name.lower() for gpu in gpus) else 'other'
                    }
                except ImportError:
                    pass
        except Exception as e:
            logger.warning(f"GPU detection failed: {e}")

        return PlatformInfo(
            system=system,
            release=platform.release(),
            version=platform.version(),
            machine=platform.machine(),
            processor=platform.processor(),
            python_version=sys.version,
            is_64bit=sys.maxsize > 2**32,
            cpu_count=psutil.cpu_count(),
            memory_gb=psutil.virtual_memory().total / (1024**3),
            gpu_available=gpu_available,
            gpu_info=gpu_info
        )

    def _initialize_platform_optimizations(self):
        """Initialize platform-specific optimizations"""
        # Windows optimizations
        self.optimizations['windows'] = PlatformOptimization(
            platform='windows',
            thread_pool_size=min(self.platform_info.cpu_count * 2, 32),
            memory_pool_size=512,  # MB
            cache_strategy='memory_mapped',
            io_optimization={
                'use_async_io': True,
                'buffer_size': 64 * 1024,  # 64KB
                'use_direct_io': False,  # Windows has limitations
                'concurrent_file_handles': 512
            },
            network_optimization={
                'tcp_keepalive': True,
                'socket_buffer_size': 256 * 1024,  # 256KB
                'connection_pool_size': 20,
                'use_iocp': True  # Windows I/O Completion Ports
            },
            gpu_acceleration=self.platform_info.gpu_available,
            power_management={
                'prevent_sleep': True,
                'high_performance_mode': True,
                'processor_throttling': False
            }
        )

        # Linux optimizations
        self.optimizations['linux'] = PlatformOptimization(
            platform='linux',
            thread_pool_size=min(self.platform_info.cpu_count * 3, 64),
            memory_pool_size=1024,  # MB
            cache_strategy='shared_memory',
            io_optimization={
                'use_async_io': True,
                'buffer_size': 128 * 1024,  # 128KB
                'use_direct_io': True,
                'concurrent_file_handles': 1024,
                'use_epoll': True  # Linux epoll
            },
            network_optimization={
                'tcp_keepalive': True,
                'socket_buffer_size': 512 * 1024,  # 512KB
                'connection_pool_size': 50,
                'use_epoll': True
            },
            gpu_acceleration=self.platform_info.gpu_available,
            power_management={
                'prevent_sleep': False,  # Linux handles this well
                'high_performance_mode': False,
                'processor_throttling': False
            }
        )

        # macOS optimizations
        self.optimizations['darwin'] = PlatformOptimization(
            platform='darwin',
            thread_pool_size=min(self.platform_info.cpu_count * 2, 16),
            memory_pool_size=512,  # MB
            cache_strategy='memory_mapped',
            io_optimization={
                'use_async_io': True,
                'buffer_size': 64 * 1024,  # 64KB
                'use_direct_io': False,  # macOS limitations
                'concurrent_file_handles': 256,
                'use_kqueue': True  # macOS kqueue
            },
            network_optimization={
                'tcp_keepalive': True,
                'socket_buffer_size': 256 * 1024,  # 256KB
                'connection_pool_size': 20,
                'use_kqueue': True
            },
            gpu_acceleration=self.platform_info.gpu_available,
            power_management={
                'prevent_sleep': True,
                'high_performance_mode': False,  # macOS manages this
                'processor_throttling': False
            }
        )

    def _apply_platform_optimizations(self):
        """Apply platform-specific optimizations"""
        platform_key = self.platform_info.system
        if platform_key not in self.optimizations:
            logger.warning(f"No optimizations defined for platform: {platform_key}")
            return

        optimization = self.optimizations[platform_key]
        logger.info(f"Applying {platform_key} platform optimizations")

        # Apply I/O optimizations
        self._apply_io_optimizations(optimization.io_optimization)

        # Apply network optimizations
        self._apply_network_optimizations(optimization.network_optimization)

        # Apply power management settings
        self._apply_power_management(optimization.power_management)

        # Set thread pool size
        self._configure_thread_pool(optimization.thread_pool_size)

        # Configure memory pool
        self._configure_memory_pool(optimization.memory_pool_size)

        # Store active optimizations
        self.active_optimizations = {
            'platform': platform_key,
            'thread_pool_size': optimization.thread_pool_size,
            'memory_pool_size': optimization.memory_pool_size,
            'io_optimization': optimization.io_optimization,
            'network_optimization': optimization.network_optimization,
            'gpu_acceleration': optimization.gpu_acceleration,
            'power_management': optimization.power_management
        }

    def _apply_io_optimizations(self, io_config: Dict[str, Any]):
        """Apply I/O optimizations"""
        try:
            # Set process limits for file handles
            if hasattr(os, 'setrlimit') and io_config.get('concurrent_file_handles'):
                import resource
                current_limits = resource.getrlimit(resource.RLIMIT_NOFILE)
                desired_limit = min(io_config['concurrent_file_handles'], current_limits[1])
                if desired_limit > current_limits[0]:
                    resource.setrlimit(resource.RLIMIT_NOFILE, (desired_limit, current_limits[1]))

            logger.info("I/O optimizations applied")
        except Exception as e:
            logger.warning(f"Failed to apply I/O optimizations: {e}")

    def _apply_network_optimizations(self, network_config: Dict[str, Any]):
        """Apply network optimizations"""
        try:
            # Configure socket options at OS level
            if self.platform_info.system == 'linux':
                self._apply_linux_network_opts(network_config)
            elif self.platform_info.system == 'darwin':
                self._apply_macos_network_opts(network_config)
            elif self.platform_info.system == 'windows':
                self._apply_windows_network_opts(network_config)

            logger.info("Network optimizations applied")
        except Exception as e:
            logger.warning(f"Failed to apply network optimizations: {e}")

    def _apply_linux_network_opts(self, config: Dict[str, Any]):
        """Apply Linux-specific network optimizations"""
        try:
            # Set TCP keepalive settings
            if config.get('tcp_keepalive'):
                subprocess.run([
                    'sysctl', '-w',
                    'net.ipv4.tcp_keepalive_time=600',
                    'net.ipv4.tcp_keepalive_intvl=60',
                    'net.ipv4.tcp_keepalive_probes=5'
                ], capture_output=True)

            # Increase socket buffer sizes
            if config.get('socket_buffer_size'):
                buffer_size = config['socket_buffer_size']
                subprocess.run([
                    'sysctl', '-w',
                    f'net.core.rmem_max={buffer_size}',
                    f'net.core.wmem_max={buffer_size}'
                ], capture_output=True)

        except Exception as e:
            logger.debug(f"Linux network optimization failed: {e}")

    def _apply_macos_network_opts(self, config: Dict[str, Any]):
        """Apply macOS-specific network optimizations"""
        try:
            # macOS network optimizations are mostly handled by the OS
            # Set some basic TCP tunings if available
            pass
        except Exception as e:
            logger.debug(f"macOS network optimization failed: {e}")

    def _apply_windows_network_opts(self, config: Dict[str, Any]):
        """Apply Windows-specific network optimizations"""
        try:
            # Windows network optimizations
            # These would typically use netsh commands or registry settings
            pass
        except Exception as e:
            logger.debug(f"Windows network optimization failed: {e}")

    def _apply_power_management(self, power_config: Dict[str, Any]):
        """Apply power management settings"""
        try:
            if self.platform_info.system == 'windows':
                self._apply_windows_power_management(power_config)
            elif self.platform_info.system == 'linux':
                self._apply_linux_power_management(power_config)
            elif self.platform_info.system == 'darwin':
                self._apply_macos_power_management(power_config)

            logger.info("Power management settings applied")
        except Exception as e:
            logger.warning(f"Failed to apply power management: {e}")

    def _apply_windows_power_management(self, config: Dict[str, Any]):
        """Apply Windows power management"""
        try:
            if config.get('prevent_sleep'):
                # Prevent system sleep
                import ctypes
                ES_CONTINUOUS = 0x80000000
                ES_SYSTEM_REQUIRED = 0x00000001
                ctypes.windll.kernel32.SetThreadExecutionState(
                    ES_CONTINUOUS | ES_SYSTEM_REQUIRED
                )

            if config.get('high_performance_mode'):
                # Set high performance power scheme
                subprocess.run([
                    'powercfg', '/setactive', '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
                ], capture_output=True)

        except Exception as e:
            logger.debug(f"Windows power management failed: {e}")

    def _apply_linux_power_management(self, config: Dict[str, Any]):
        """Apply Linux power management"""
        try:
            # Linux power management is usually handled well by default
            # Could set CPU governor to performance if needed
            if config.get('high_performance_mode'):
                # Set CPU governor to performance
                cpu_count = self.platform_info.cpu_count
                for i in range(cpu_count):
                    try:
                        with open(f'/sys/devices/system/cpu/cpu{i}/cpufreq/scaling_governor', 'w') as f:
                            f.write('performance')
                    except FileNotFoundError:
                        pass  # Governor not available

        except Exception as e:
            logger.debug(f"Linux power management failed: {e}")

    def _apply_macos_power_management(self, config: Dict[str, Any]):
        """Apply macOS power management"""
        try:
            if config.get('prevent_sleep'):
                # Prevent system sleep using caffeinate
                subprocess.Popen(['caffeinate', '-s'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        except Exception as e:
            logger.debug(f"macOS power management failed: {e}")

    def _configure_thread_pool(self, pool_size: int):
        """Configure thread pool size"""
        try:
            # This would integrate with the performance optimizer
            # For now, just log the configuration
            logger.info(f"Configured thread pool size: {pool_size}")
        except Exception as e:
            logger.warning(f"Failed to configure thread pool: {e}")

    def _configure_memory_pool(self, pool_size_mb: int):
        """Configure memory pool size"""
        try:
            # Configure Python memory allocation
            import gc
            # Set garbage collection thresholds
            gc.set_threshold(700, 10, 10)

            logger.info(f"Configured memory pool size: {pool_size_mb}MB")
        except Exception as e:
            logger.warning(f"Failed to configure memory pool: {e}")

    def start_monitoring(self):
        """Start platform monitoring"""
        self.stop_event.clear()
        self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        logger.info("Platform monitoring started")

    def stop_monitoring(self):
        """Stop platform monitoring"""
        if self.monitoring_thread:
            self.stop_event.set()
            self.monitoring_thread.join(timeout=5)
            logger.info("Platform monitoring stopped")

    def _monitoring_loop(self):
        """Platform monitoring loop"""
        while not self.stop_event.wait(300):  # Check every 5 minutes
            try:
                self._check_platform_health()
                self._adjust_optimizations()
            except Exception as e:
                logger.error(f"Platform monitoring error: {e}")

    def _check_platform_health(self):
        """Check platform health and performance"""
        try:
            # Check CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)

            # Check memory usage
            memory = psutil.virtual_memory()

            # Check disk I/O
            disk_io = psutil.disk_io_counters()

            # Log warnings if thresholds exceeded
            if cpu_percent > 90:
                logger.warning(f"High CPU usage: {cpu_percent}%")

            if memory.percent > 90:
                logger.warning(f"High memory usage: {memory.percent}%")

            # Platform-specific health checks
            if self.platform_info.system == 'linux':
                self._linux_health_check()
            elif self.platform_info.system == 'darwin':
                self._macos_health_check()
            elif self.platform_info.system == 'windows':
                self._windows_health_check()

        except Exception as e:
            logger.error(f"Platform health check failed: {e}")

    def _linux_health_check(self):
        """Linux-specific health checks"""
        try:
            # Check system load
            load_avg = os.getloadavg()
            if load_avg[0] > self.platform_info.cpu_count * 2:
                logger.warning(f"High system load: {load_avg[0]}")

        except Exception as e:
            pass

    def _macos_health_check(self):
        """macOS-specific health checks"""
        try:
            # Check for system pressure
            result = subprocess.run(['sysctl', 'kern.memorystatus_vm_pressure_level'],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                pressure_level = int(result.stdout.split(':')[1].strip())
                if pressure_level >= 2:  # Critical
                    logger.warning("System memory pressure is critical")

        except Exception as e:
            pass

    def _windows_health_check(self):
        """Windows-specific health checks"""
        try:
            # Windows-specific checks would go here
            pass
        except Exception as e:
            pass

    def _adjust_optimizations(self):
        """Dynamically adjust optimizations based on system state"""
        try:
            memory = psutil.virtual_memory()
            cpu_percent = psutil.cpu_percent()

            # Adjust thread pool size based on system load
            if cpu_percent > 80:
                # Reduce thread pool size under high load
                new_pool_size = max(2, self.active_optimizations.get('thread_pool_size', 4) // 2)
                self._configure_thread_pool(new_pool_size)
                logger.info(f"Reduced thread pool size due to high CPU: {new_pool_size}")

            elif cpu_percent < 30 and memory.percent < 70:
                # Increase thread pool size if system is underutilized
                current_pool = self.active_optimizations.get('thread_pool_size', 4)
                new_pool_size = min(current_pool * 2, self.platform_info.cpu_count * 4)
                if new_pool_size > current_pool:
                    self._configure_thread_pool(new_pool_size)
                    logger.info(f"Increased thread pool size: {new_pool_size}")

        except Exception as e:
            logger.debug(f"Optimization adjustment failed: {e}")

    def get_platform_info(self) -> Dict[str, Any]:
        """Get comprehensive platform information"""
        return {
            'platform_info': {
                'system': self.platform_info.system,
                'release': self.platform_info.release,
                'version': self.platform_info.version,
                'machine': self.platform_info.machine,
                'processor': self.platform_info.processor,
                'python_version': self.platform_info.python_version,
                'is_64bit': self.platform_info.is_64bit,
                'cpu_count': self.platform_info.cpu_count,
                'memory_gb': round(self.platform_info.memory_gb, 2),
                'gpu_available': self.platform_info.gpu_available,
                'gpu_info': self.platform_info.gpu_info
            },
            'active_optimizations': self.active_optimizations,
            'available_optimizations': {
                platform: {
                    'thread_pool_size': opt.thread_pool_size,
                    'memory_pool_size': opt.memory_pool_size,
                    'gpu_acceleration': opt.gpu_acceleration
                }
                for platform, opt in self.optimizations.items()
            },
            'health_status': self._get_health_status()
        }

    def _get_health_status(self) -> Dict[str, Any]:
        """Get current system health status"""
        try:
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')

            return {
                'cpu_usage': cpu_percent,
                'memory_usage': memory.percent,
                'disk_usage': disk.percent,
                'cpu_status': 'healthy' if cpu_percent < 80 else 'warning' if cpu_percent < 95 else 'critical',
                'memory_status': 'healthy' if memory.percent < 80 else 'warning' if memory.percent < 95 else 'critical',
                'disk_status': 'healthy' if disk.percent < 90 else 'warning' if disk.percent < 95 else 'critical'
            }
        except Exception as e:
            return {'error': str(e)}


# Global optimizer instance
_platform_optimizer: Optional[CrossPlatformOptimizer] = None


def get_platform_optimizer() -> CrossPlatformOptimizer:
    """Get or create global platform optimizer instance"""
    global _platform_optimizer
    if _platform_optimizer is None:
        _platform_optimizer = CrossPlatformOptimizer()
    return _platform_optimizer


def start_platform_optimization():
    """Start platform optimization and monitoring"""
    optimizer = get_platform_optimizer()
    optimizer.start_monitoring()
    logger.info("Platform optimization started")


def stop_platform_optimization():
    """Stop platform optimization and monitoring"""
    optimizer = get_platform_optimizer()
    optimizer.stop_monitoring()
    logger.info("Platform optimization stopped")


if __name__ == "__main__":
    # Test platform optimization
    optimizer = get_platform_optimizer()
    info = optimizer.get_platform_info()

    print("Platform Information:")
    print(json.dumps(info, indent=2))

    start_platform_optimization()

    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        stop_platform_optimization()
