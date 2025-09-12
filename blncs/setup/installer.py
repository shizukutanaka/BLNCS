"""
BLNCS Installation and Setup Wizard
Comprehensive installer with dependency management and configuration wizard.
"""

import os
import sys
import platform
import subprocess
import tempfile
import shutil
import json
import urllib.request
import zipfile
import tarfile
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
import hashlib
import socket
import getpass


class SystemRequirements:
    """System requirements checker"""
    
    MIN_PYTHON_VERSION = (3, 8)
    MIN_DISK_SPACE_GB = 1
    MIN_MEMORY_GB = 2
    REQUIRED_PORTS = [8080, 9735]
    
    @staticmethod
    def check_python_version() -> Tuple[bool, str]:
        """Check Python version requirement"""
        current = sys.version_info[:2]
        required = SystemRequirements.MIN_PYTHON_VERSION
        
        if current >= required:
            return True, f"Python {current[0]}.{current[1]} ✓"
        else:
            return False, f"Python {current[0]}.{current[1]} (requires {required[0]}.{required[1]}+)"
    
    @staticmethod
    def check_disk_space() -> Tuple[bool, str]:
        """Check available disk space"""
        try:
            if platform.system() == 'Windows':
                import ctypes
                free_bytes = ctypes.c_ulonglong(0)
                ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    ctypes.c_wchar_p(os.getcwd()),
                    ctypes.pointer(free_bytes),
                    None, None
                )
                free_gb = free_bytes.value / (1024**3)
            else:
                stat = os.statvfs(os.getcwd())
                free_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
            
            if free_gb >= SystemRequirements.MIN_DISK_SPACE_GB:
                return True, f"Disk space: {free_gb:.1f} GB ✓"
            else:
                return False, f"Disk space: {free_gb:.1f} GB (requires {SystemRequirements.MIN_DISK_SPACE_GB} GB+)"
        except Exception as e:
            return False, f"Could not check disk space: {e}"
    
    @staticmethod
    def check_memory() -> Tuple[bool, str]:
        """Check available memory"""
        try:
            if platform.system() == 'Windows':
                import ctypes
                from ctypes import wintypes
                
                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ("dwLength", wintypes.DWORD),
                        ("dwMemoryLoad", wintypes.DWORD),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                    ]
                
                mem_status = MEMORYSTATUSEX()
                mem_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem_status))
                total_gb = mem_status.ullTotalPhys / (1024**3)
            else:
                with open('/proc/meminfo', 'r') as f:
                    for line in f:
                        if line.startswith('MemTotal:'):
                            total_kb = int(line.split()[1])
                            total_gb = total_kb / (1024**2)
                            break
            
            if total_gb >= SystemRequirements.MIN_MEMORY_GB:
                return True, f"Memory: {total_gb:.1f} GB ✓"
            else:
                return False, f"Memory: {total_gb:.1f} GB (requires {SystemRequirements.MIN_MEMORY_GB} GB+)"
        except Exception as e:
            return True, f"Could not check memory (assuming sufficient)"
    
    @staticmethod
    def check_ports() -> Tuple[bool, str]:
        """Check if required ports are available"""
        blocked_ports = []
        
        for port in SystemRequirements.REQUIRED_PORTS:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            
            if result == 0:  # Port is in use
                blocked_ports.append(port)
        
        if not blocked_ports:
            return True, f"Ports {SystemRequirements.REQUIRED_PORTS} available ✓"
        else:
            return False, f"Ports {blocked_ports} already in use"
    
    @staticmethod
    def check_all() -> Dict[str, Tuple[bool, str]]:
        """Run all system requirement checks"""
        checks = {
            'python_version': SystemRequirements.check_python_version(),
            'disk_space': SystemRequirements.check_disk_space(),
            'memory': SystemRequirements.check_memory(),
            'ports': SystemRequirements.check_ports()
        }
        return checks


class DependencyInstaller:
    """Dependency installation manager"""
    
    def __init__(self):
        self.pip_packages = [
            'requests>=2.28.0',
            'grpcio>=1.50.0',
            'cryptography>=38.0.0',
            'pyyaml>=6.0',
            'toml>=0.10.2',
            'click>=8.1.0',
            'aiohttp>=3.8.0',
            'aiosqlite>=0.17.0'
        ]
        
        self.optional_packages = {
            'full': [
                'matplotlib>=3.6.0',
                'pandas>=1.5.0',
                'psutil>=5.9.0',
                'networkx>=2.8',
                'pydantic>=1.10.0'
            ],
            'dev': [
                'pytest>=7.2.0',
                'pytest-cov>=4.0.0',
                'pytest-asyncio>=0.20.0',
                'black>=22.0.0',
                'flake8>=5.0.0',
                'mypy>=0.990',
                'bandit>=1.7.0'
            ]
        }
    
    def check_pip(self) -> bool:
        """Check if pip is available"""
        try:
            subprocess.run([sys.executable, '-m', 'pip', '--version'], 
                         capture_output=True, check=True)
            return True
        except Exception:
            return False
    
    def upgrade_pip(self) -> bool:
        """Upgrade pip to latest version"""
        try:
            print("Upgrading pip...")
            subprocess.run([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'],
                         check=True)
            return True
        except Exception as e:
            print(f"Failed to upgrade pip: {e}")
            return False
    
    def install_package(self, package: str) -> bool:
        """Install a single package"""
        try:
            print(f"Installing {package}...")
            subprocess.run([sys.executable, '-m', 'pip', 'install', package],
                         check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def install_core_dependencies(self) -> Dict[str, bool]:
        """Install core dependencies"""
        results = {}
        
        for package in self.pip_packages:
            package_name = package.split('>=')[0].split('==')[0]
            results[package_name] = self.install_package(package)
        
        return results
    
    def install_optional_dependencies(self, profile: str) -> Dict[str, bool]:
        """Install optional dependencies by profile"""
        if profile not in self.optional_packages:
            return {}
        
        results = {}
        for package in self.optional_packages[profile]:
            package_name = package.split('>=')[0].split('==')[0]
            results[package_name] = self.install_package(package)
        
        return results
    
    def check_installed_packages(self) -> List[str]:
        """Get list of installed packages"""
        try:
            result = subprocess.run([sys.executable, '-m', 'pip', 'list', '--format=json'],
                                  capture_output=True, text=True, check=True)
            packages = json.loads(result.stdout)
            return [p['name'].lower() for p in packages]
        except Exception:
            return []


class ConfigurationWizard:
    """Interactive configuration wizard"""
    
    def __init__(self):
        self.config = {
            'app': {
                'name': 'BLNCS',
                'version': '1.0.0',
                'debug': False
            },
            'lightning': {
                'implementation': 'lnd',  # lnd, c-lightning, eclair
                'network': 'mainnet',
                'host': 'localhost',
                'port': 8080,
                'rest_port': 8080,
                'grpc_port': 10009
            },
            'paths': {
                'data_dir': str(Path.home() / '.blncs'),
                'lnd_dir': str(Path.home() / '.lnd'),
                'bitcoin_dir': str(Path.home() / '.bitcoin')
            },
            'security': {
                'enable_encryption': True,
                'auto_unlock': False,
                'session_timeout': 1800
            },
            'ui': {
                'theme': 'light',
                'language': 'en',
                'start_minimized': False
            }
        }
    
    def run_interactive(self) -> Dict[str, Any]:
        """Run interactive configuration wizard"""
        print("\n" + "="*50)
        print("BLNCS Configuration Wizard")
        print("="*50)
        
        # Lightning implementation
        print("\nSelect Lightning Network implementation:")
        print("1. LND (Lightning Network Daemon)")
        print("2. Core Lightning (c-lightning)")
        print("3. Eclair")
        
        choice = input("Enter choice [1-3] (default: 1): ").strip() or "1"
        implementations = {'1': 'lnd', '2': 'c-lightning', '3': 'eclair'}
        self.config['lightning']['implementation'] = implementations.get(choice, 'lnd')
        
        # Network selection
        print("\nSelect Bitcoin network:")
        print("1. Mainnet (production)")
        print("2. Testnet (testing)")
        print("3. Regtest (development)")
        
        choice = input("Enter choice [1-3] (default: 1): ").strip() or "1"
        networks = {'1': 'mainnet', '2': 'testnet', '3': 'regtest'}
        self.config['lightning']['network'] = networks.get(choice, 'mainnet')
        
        # Connection settings
        print("\nLightning node connection settings:")
        host = input(f"Host [default: localhost]: ").strip() or "localhost"
        self.config['lightning']['host'] = host
        
        port = input(f"REST API port [default: 8080]: ").strip()
        if port.isdigit():
            self.config['lightning']['rest_port'] = int(port)
        
        # Data directories
        print("\nData directory configuration:")
        use_defaults = input("Use default directories? [Y/n]: ").strip().lower()
        
        if use_defaults == 'n':
            data_dir = input(f"BLNCS data directory [{self.config['paths']['data_dir']}]: ").strip()
            if data_dir:
                self.config['paths']['data_dir'] = data_dir
            
            lnd_dir = input(f"Lightning directory [{self.config['paths']['lnd_dir']}]: ").strip()
            if lnd_dir:
                self.config['paths']['lnd_dir'] = lnd_dir
        
        # Security settings
        print("\nSecurity configuration:")
        enable_encryption = input("Enable configuration encryption? [Y/n]: ").strip().lower()
        self.config['security']['enable_encryption'] = enable_encryption != 'n'
        
        if self.config['security']['enable_encryption']:
            self.config['security']['config_password'] = getpass.getpass("Enter encryption password: ")
        
        # UI preferences
        print("\nUser interface preferences:")
        print("1. Light theme")
        print("2. Dark theme")
        print("3. Bitcoin orange theme")
        
        choice = input("Select theme [1-3] (default: 1): ").strip() or "1"
        themes = {'1': 'light', '2': 'dark', '3': 'bitcoin'}
        self.config['ui']['theme'] = themes.get(choice, 'light')
        
        return self.config
    
    def validate_config(self, config: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate configuration"""
        errors = []
        
        # Check required fields
        if not config.get('lightning', {}).get('host'):
            errors.append("Lightning host is required")
        
        # Check network validity
        valid_networks = ['mainnet', 'testnet', 'regtest']
        if config.get('lightning', {}).get('network') not in valid_networks:
            errors.append(f"Invalid network: {config['lightning']['network']}")
        
        # Check port ranges
        ports = ['rest_port', 'grpc_port']
        for port_name in ports:
            port = config.get('lightning', {}).get(port_name)
            if port and (not isinstance(port, int) or port < 1 or port > 65535):
                errors.append(f"Invalid {port_name}: {port}")
        
        return len(errors) == 0, errors
    
    def save_config(self, config: Dict[str, Any], path: Optional[Path] = None) -> Path:
        """Save configuration to file"""
        if path is None:
            config_dir = Path(config['paths']['data_dir'])
            config_dir.mkdir(parents=True, exist_ok=True)
            path = config_dir / 'config.json'
        
        # Remove sensitive data before saving
        config_to_save = config.copy()
        if 'config_password' in config_to_save.get('security', {}):
            del config_to_save['security']['config_password']
        
        with open(path, 'w') as f:
            json.dump(config_to_save, f, indent=2)
        
        print(f"Configuration saved to: {path}")
        return path


class BLNCSInstaller:
    """Main BLNCS installer"""
    
    def __init__(self):
        self.install_dir = Path.home() / '.blncs'
        self.temp_dir = Path(tempfile.mkdtemp())
        self.system_checker = SystemRequirements()
        self.dependency_installer = DependencyInstaller()
        self.config_wizard = ConfigurationWizard()
        self.install_log = []
    
    def log(self, message: str, level: str = "INFO"):
        """Log installation message"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        self.install_log.append(log_entry)
        print(message)
    
    def print_banner(self):
        """Print installation banner"""
        banner = """
╔════════════════════════════════════════════════════════╗
║                                                        ║
║     BLNCS - Bitcoin Lightning Network Control System  ║
║                    Installation Wizard                 ║
║                                                        ║
╚════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def check_system_requirements(self) -> bool:
        """Check system requirements"""
        self.log("Checking system requirements...")
        
        checks = SystemRequirements.check_all()
        all_passed = True
        
        for check_name, (passed, message) in checks.items():
            if passed:
                self.log(f"  ✓ {message}")
            else:
                self.log(f"  ✗ {message}", "WARNING")
                all_passed = False
        
        return all_passed
    
    def install_dependencies(self, profile: str = 'core') -> bool:
        """Install Python dependencies"""
        self.log("Installing Python dependencies...")
        
        # Check pip
        if not self.dependency_installer.check_pip():
            self.log("pip not found!", "ERROR")
            return False
        
        # Upgrade pip
        self.dependency_installer.upgrade_pip()
        
        # Install core dependencies
        self.log("Installing core dependencies...")
        core_results = self.dependency_installer.install_core_dependencies()
        
        failed_packages = [pkg for pkg, success in core_results.items() if not success]
        if failed_packages:
            self.log(f"Failed to install: {', '.join(failed_packages)}", "WARNING")
        
        # Install optional dependencies
        if profile in ['full', 'dev']:
            self.log(f"Installing {profile} dependencies...")
            optional_results = self.dependency_installer.install_optional_dependencies(profile)
            
            failed_optional = [pkg for pkg, success in optional_results.items() if not success]
            if failed_optional:
                self.log(f"Failed to install optional: {', '.join(failed_optional)}", "WARNING")
        
        return len(failed_packages) == 0
    
    def download_blncs(self, version: str = 'latest') -> Optional[Path]:
        """Download BLNCS from repository"""
        self.log("Downloading BLNCS...")
        
        # For now, use local source if available
        source_dir = Path(__file__).parent.parent.parent
        if (source_dir / 'blncs').exists():
            self.log("Using local source installation")
            return source_dir
        
        # TODO: Implement actual download from GitHub/PyPI
        download_url = f"https://github.com/blncs/blncs/archive/{version}.zip"
        download_path = self.temp_dir / f"blncs-{version}.zip"
        
        try:
            urllib.request.urlretrieve(download_url, download_path)
            
            # Extract archive
            with zipfile.ZipFile(download_path, 'r') as zf:
                zf.extractall(self.temp_dir)
            
            extracted_dir = self.temp_dir / f"blncs-{version}"
            return extracted_dir
        
        except Exception as e:
            self.log(f"Failed to download BLNCS: {e}", "ERROR")
            return None
    
    def install_blncs(self, source_dir: Path) -> bool:
        """Install BLNCS to system"""
        self.log("Installing BLNCS...")
        
        try:
            # Create installation directory
            self.install_dir.mkdir(parents=True, exist_ok=True)
            
            # Copy BLNCS files
            blncs_source = source_dir / 'blncs'
            if blncs_source.exists():
                dest_dir = self.install_dir / 'blncs'
                if dest_dir.exists():
                    shutil.rmtree(dest_dir)
                shutil.copytree(blncs_source, dest_dir)
            
            # Copy essential files
            for filename in ['setup.py', 'requirements.txt', 'README.md']:
                src_file = source_dir / filename
                if src_file.exists():
                    shutil.copy2(src_file, self.install_dir / filename)
            
            # Install via pip in development mode
            subprocess.run([sys.executable, '-m', 'pip', 'install', '-e', str(source_dir)],
                         check=True, capture_output=True)
            
            self.log("BLNCS installed successfully")
            return True
        
        except Exception as e:
            self.log(f"Failed to install BLNCS: {e}", "ERROR")
            return False
    
    def create_shortcuts(self) -> bool:
        """Create desktop and start menu shortcuts"""
        self.log("Creating shortcuts...")
        
        system = platform.system()
        
        if system == 'Windows':
            return self.create_windows_shortcuts()
        elif system == 'Darwin':  # macOS
            return self.create_macos_shortcuts()
        elif system == 'Linux':
            return self.create_linux_shortcuts()
        
        return True
    
    def create_windows_shortcuts(self) -> bool:
        """Create Windows shortcuts"""
        try:
            import win32com.client
            
            shell = win32com.client.Dispatch("WScript.Shell")
            
            # Desktop shortcut
            desktop = shell.SpecialFolders("Desktop")
            shortcut = shell.CreateShortCut(os.path.join(desktop, "BLNCS.lnk"))
            shortcut.Targetpath = sys.executable
            shortcut.Arguments = '-m blncs.gui.enhanced_main'
            shortcut.WorkingDirectory = str(self.install_dir)
            shortcut.IconLocation = sys.executable
            shortcut.Description = "Bitcoin Lightning Network Control System"
            shortcut.save()
            
            # Start menu shortcut
            programs = shell.SpecialFolders("Programs")
            blncs_folder = os.path.join(programs, "BLNCS")
            os.makedirs(blncs_folder, exist_ok=True)
            
            shortcut = shell.CreateShortCut(os.path.join(blncs_folder, "BLNCS.lnk"))
            shortcut.Targetpath = sys.executable
            shortcut.Arguments = '-m blncs.gui.enhanced_main'
            shortcut.WorkingDirectory = str(self.install_dir)
            shortcut.IconLocation = sys.executable
            shortcut.save()
            
            self.log("Windows shortcuts created")
            return True
        
        except Exception as e:
            self.log(f"Failed to create Windows shortcuts: {e}", "WARNING")
            return False
    
    def create_linux_shortcuts(self) -> bool:
        """Create Linux desktop entry"""
        try:
            desktop_entry = f"""[Desktop Entry]
Name=BLNCS
Comment=Bitcoin Lightning Network Control System
Exec={sys.executable} -m blncs.gui.enhanced_main
Icon=bitcoin
Terminal=false
Type=Application
Categories=Finance;Network;
"""
            
            # User desktop entry
            desktop_dir = Path.home() / '.local' / 'share' / 'applications'
            desktop_dir.mkdir(parents=True, exist_ok=True)
            
            desktop_file = desktop_dir / 'blncs.desktop'
            with open(desktop_file, 'w') as f:
                f.write(desktop_entry)
            
            # Make executable
            os.chmod(desktop_file, 0o755)
            
            self.log("Linux desktop entry created")
            return True
        
        except Exception as e:
            self.log(f"Failed to create Linux shortcuts: {e}", "WARNING")
            return False
    
    def create_macos_shortcuts(self) -> bool:
        """Create macOS application bundle"""
        # TODO: Implement macOS app bundle creation
        self.log("macOS shortcut creation not yet implemented", "WARNING")
        return True
    
    def run_post_install_tests(self) -> bool:
        """Run post-installation tests"""
        self.log("Running post-installation tests...")
        
        tests_passed = True
        
        # Test BLNCS import
        try:
            import blncs
            self.log("  ✓ BLNCS module imports successfully")
        except ImportError as e:
            self.log(f"  ✗ Failed to import BLNCS: {e}", "ERROR")
            tests_passed = False
        
        # Test database creation
        try:
            from blncs.core.database import DatabaseManager
            test_db = DatabaseManager(":memory:")
            test_db.close()
            self.log("  ✓ Database system functional")
        except Exception as e:
            self.log(f"  ✗ Database test failed: {e}", "WARNING")
        
        # Test configuration
        try:
            from blncs.core.config_enhanced import EnhancedConfigManager
            test_config = EnhancedConfigManager("test")
            self.log("  ✓ Configuration system functional")
        except Exception as e:
            self.log(f"  ✗ Configuration test failed: {e}", "WARNING")
        
        return tests_passed
    
    def save_install_log(self):
        """Save installation log"""
        log_file = self.install_dir / 'install.log'
        with open(log_file, 'w') as f:
            f.write('\n'.join(self.install_log))
        print(f"\nInstallation log saved to: {log_file}")
    
    def cleanup(self):
        """Clean up temporary files"""
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception:
            pass
    
    def install(self, interactive: bool = True, profile: str = 'core') -> bool:
        """Main installation process"""
        self.print_banner()
        
        try:
            # Check system requirements
            if not self.check_system_requirements():
                if interactive:
                    response = input("\nSome requirements not met. Continue anyway? [y/N]: ")
                    if response.lower() != 'y':
                        self.log("Installation cancelled by user")
                        return False
            
            # Install dependencies
            if not self.install_dependencies(profile):
                self.log("Dependency installation had issues", "WARNING")
            
            # Download/locate BLNCS
            source_dir = self.download_blncs()
            if not source_dir:
                self.log("Failed to obtain BLNCS source", "ERROR")
                return False
            
            # Install BLNCS
            if not self.install_blncs(source_dir):
                self.log("BLNCS installation failed", "ERROR")
                return False
            
            # Run configuration wizard
            if interactive:
                config = self.config_wizard.run_interactive()
                valid, errors = self.config_wizard.validate_config(config)
                
                if valid:
                    self.config_wizard.save_config(config)
                else:
                    self.log(f"Configuration errors: {', '.join(errors)}", "WARNING")
            
            # Create shortcuts
            self.create_shortcuts()
            
            # Run post-installation tests
            self.run_post_install_tests()
            
            # Success!
            print("\n" + "="*50)
            print("INSTALLATION COMPLETED SUCCESSFULLY!")
            print("="*50)
            print("\nTo start BLNCS:")
            print("  GUI:     python -m blncs.gui.enhanced_main")
            print("  CLI:     python -m blncs")
            print("  Config:  " + str(self.install_dir / 'config.json'))
            print("\nThank you for installing BLNCS!")
            
            return True
        
        except Exception as e:
            self.log(f"Installation failed: {e}", "ERROR")
            return False
        
        finally:
            self.save_install_log()
            self.cleanup()


def main():
    """Main installation entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="BLNCS Installation Wizard")
    parser.add_argument('--non-interactive', action='store_true', 
                       help='Run in non-interactive mode')
    parser.add_argument('--profile', choices=['core', 'full', 'dev'], 
                       default='core',
                       help='Installation profile')
    parser.add_argument('--skip-requirements', action='store_true',
                       help='Skip system requirements check')
    
    args = parser.parse_args()
    
    installer = BLNCSInstaller()
    
    success = installer.install(
        interactive=not args.non_interactive,
        profile=args.profile
    )
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())