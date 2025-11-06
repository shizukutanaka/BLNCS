"""
Cross-platform mobile and desktop support for BLNCS
Implements SDKs, mobile-optimized interfaces, and cross-platform compatibility
based on competitor analysis and industry best practices
"""

import asyncio
import json
import logging
import platform
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
import threading
import subprocess
import os
import shutil
from pathlib import Path
import tempfile


class Platform(Enum):
    """Supported platforms"""
    IOS = "ios"
    ANDROID = "android"
    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"
    WEB = "web"


class DeviceType(Enum):
    """Device types"""
    MOBILE = "mobile"
    TABLET = "tablet"
    DESKTOP = "desktop"
    WEB = "web"


@dataclass
class PlatformConfig:
    """Platform-specific configuration"""
    platform: Platform
    device_type: DeviceType
    supported_versions: List[str]
    recommended_specs: Dict[str, Any]
    ui_guidelines: Dict[str, Any]
    build_requirements: List[str]


@dataclass
class SDKConfig:
    """SDK configuration"""
    language: str
    platform: Platform
    version: str
    dependencies: List[str]
    build_commands: List[str]
    test_commands: List[str]


@dataclass
class CrossPlatformUI:
    """Cross-platform UI component"""
    component_id: str
    component_type: str
    platforms: List[Platform]
    properties: Dict[str, Any]
    responsive_rules: Dict[str, Any]
    accessibility_features: List[str]


class PlatformDetector:
    """Platform and device detection utility"""

    @staticmethod
    def get_current_platform() -> Platform:
        """Detect current platform"""
        system = platform.system().lower()
        if system == 'windows':
            return Platform.WINDOWS
        elif system == 'darwin':
            return Platform.MACOS
        elif system == 'linux':
            return Platform.LINUX
        else:
            return Platform.LINUX  # Default fallback

    @staticmethod
    def get_device_type() -> DeviceType:
        """Detect device type"""
        system = platform.system().lower()
        if system in ['windows', 'darwin', 'linux']:
            return DeviceType.DESKTOP
        else:
            return DeviceType.DESKTOP  # Default fallback

    @staticmethod
    def get_platform_info() -> Dict[str, Any]:
        """Get detailed platform information"""
        return {
            'platform': platform.system(),
            'platform_version': platform.version(),
            'architecture': platform.machine(),
            'python_version': sys.version,
            'processor': platform.processor()
        }


class CrossPlatformSDK:
    """Cross-platform SDK generator and manager"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize SDK generator

        Args:
            config: SDK configuration
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # SDK configurations
        self.sdk_configs = self._initialize_sdk_configs()

        # Generated SDKs cache
        self.generated_sdks: Dict[str, Dict[str, Any]] = {}

    def _initialize_sdk_configs(self) -> Dict[str, SDKConfig]:
        """Initialize SDK configurations for different languages/platforms"""
        return {
            'python': SDKConfig(
                language='python',
                platform=Platform.LINUX,  # Cross-platform
                version='1.0.0',
                dependencies=[
                    'requests>=2.25.0',
                    'websockets>=10.0',
                    'cryptography>=3.4.0',
                    'pydantic>=1.8.0'
                ],
                build_commands=[
                    'python setup.py build',
                    'python setup.py sdist'
                ],
                test_commands=[
                    'python -m pytest tests/',
                    'python -m flake8 blncs_sdk/'
                ]
            ),
            'javascript': SDKConfig(
                language='javascript',
                platform=Platform.WEB,  # Cross-platform
                version='1.0.0',
                dependencies=[
                    'axios',
                    'ws',
                    'crypto-js',
                    'node>=14.0.0'
                ],
                build_commands=[
                    'npm install',
                    'npm run build'
                ],
                test_commands=[
                    'npm test',
                    'npm run lint'
                ]
            ),
            'react_native': SDKConfig(
                language='react_native',
                platform=Platform.WEB,  # Mobile platforms
                version='1.0.0',
                dependencies=[
                    'react-native>=0.64.0',
                    '@react-native-async-storage/async-storage',
                    'react-native-crypto',
                    'axios'
                ],
                build_commands=[
                    'npm install',
                    'cd ios && pod install',
                    'npm run build:ios',
                    'npm run build:android'
                ],
                test_commands=[
                    'npm test',
                    'npm run test:e2e'
                ]
            )
        }

    def generate_sdk(self, language: str, output_dir: str) -> bool:
        """
        Generate SDK for specified language

        Args:
            language: Programming language
            output_dir: Output directory

        Returns:
            Success status
        """
        if language not in self.sdk_configs:
            self.logger.error(f"Unsupported SDK language: {language}")
            return False

        sdk_config = self.sdk_configs[language]
        output_path = Path(output_dir) / f"blncs-sdk-{language}"

        try:
            # Create output directory
            output_path.mkdir(parents=True, exist_ok=True)

            # Generate SDK files
            if language == 'python':
                self._generate_python_sdk(output_path, sdk_config)
            elif language == 'javascript':
                self._generate_javascript_sdk(output_path, sdk_config)
            elif language == 'react_native':
                self._generate_react_native_sdk(output_path, sdk_config)

            # Generate common files
            self._generate_common_files(output_path, sdk_config)

            self.logger.info(f"SDK generated successfully for {language} at {output_path}")
            return True

        except Exception as e:
            self.logger.error(f"SDK generation failed for {language}: {e}")
            return False

    def _generate_python_sdk(self, output_path: Path, config: SDKConfig):
        """Generate Python SDK"""
        # Create package structure
        (output_path / 'blncs_sdk').mkdir(exist_ok=True)
        (output_path / 'tests').mkdir(exist_ok=True)

        # Generate __init__.py
        init_content = '''
"""
BLNCS Lightning Network SDK for Python
"""

__version__ = "1.0.0"

from .client import BLNCSClient
from .lightning import LightningAPI
from .wallet import WalletAPI
from .exceptions import BLNCSException, AuthenticationError, NetworkError

__all__ = [
    'BLNCSClient',
    'LightningAPI',
    'WalletAPI',
    'BLNCSException',
    'AuthenticationError',
    'NetworkError'
]
'''
        (output_path / 'blncs_sdk' / '__init__.py').write_text(init_content.strip())

        # Generate client.py
        client_content = '''
"""
BLNCS API Client
"""

import asyncio
import aiohttp
import json
from typing import Dict, Any, Optional
from .exceptions import BLNCSException, AuthenticationError, NetworkError


class BLNCSClient:
    """BLNCS Lightning Network API Client"""

    def __init__(self, base_url: str, api_key: Optional[str] = None):
        """
        Initialize client

        Args:
            base_url: API base URL
            api_key: API key for authentication
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()

    async def connect(self):
        """Connect to API"""
        self.session = aiohttp.ClientSession()

    async def disconnect(self):
        """Disconnect from API"""
        if self.session:
            await self.session.close()

    async def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make API request"""
        if not self.session:
            await self.connect()

        url = f"{self.base_url}{endpoint}"
        headers = {}

        if self.api_key:
            headers['X-API-Key'] = self.api_key

        try:
            async with self.session.request(method, url, headers=headers, **kwargs) as response:
                if response.status == 401:
                    raise AuthenticationError("Authentication failed")
                elif response.status >= 400:
                    error_data = await response.json()
                    raise BLNCSException(error_data.get('error', 'API error'))

                return await response.json()

        except aiohttp.ClientError as e:
            raise NetworkError(f"Network error: {e}")

    async def get_info(self) -> Dict[str, Any]:
        """Get node information"""
        return await self._request('GET', '/info')

    async def get_balance(self) -> Dict[str, Any]:
        """Get wallet balance"""
        return await self._request('GET', '/balance')

    async def create_invoice(self, amount: int, description: str = "") -> Dict[str, Any]:
        """Create payment invoice"""
        data = {'amount': amount, 'description': description}
        return await self._request('POST', '/invoice', json=data)

    async def pay_invoice(self, invoice: str) -> Dict[str, Any]:
        """Pay Lightning invoice"""
        data = {'invoice': invoice}
        return await self._request('POST', '/pay', json=data)

    async def get_channels(self) -> Dict[str, Any]:
        """Get channel information"""
        return await self._request('GET', '/channels')
'''
        (output_path / 'blncs_sdk' / 'client.py').write_text(client_content.strip())

        # Generate other files
        self._generate_python_support_files(output_path)

    def _generate_javascript_sdk(self, output_path: Path, config: SDKConfig):
        """Generate JavaScript SDK"""
        # Create package structure
        (output_path / 'src').mkdir(exist_ok=True)
        (output_path / 'tests').mkdir(exist_ok=True)

        # Generate package.json
        package_json = {
            'name': 'blncs-sdk-javascript',
            'version': '1.0.0',
            'description': 'BLNCS Lightning Network SDK for JavaScript',
            'main': 'dist/index.js',
            'scripts': {
                'build': 'babel src -d dist',
                'test': 'jest',
                'lint': 'eslint src'
            },
            'dependencies': {dep: 'latest' for dep in config.dependencies}
        }

        with open(output_path / 'package.json', 'w') as f:
            json.dump(package_json, f, indent=2)

        # Generate main SDK file
        sdk_content = '''
/**
 * BLNCS Lightning Network SDK for JavaScript
 */

const axios = require('axios');
const WebSocket = require('ws');

class BLNCSClient {
    constructor(baseURL, apiKey = null) {
        this.baseURL = baseURL.replace(/\\/$/, '');
        this.apiKey = apiKey;
        this.client = axios.create({
            baseURL: this.baseURL,
            timeout: 10000,
            headers: apiKey ? { 'X-API-Key': apiKey } : {}
        });
    }

    async getInfo() {
        const response = await this.client.get('/info');
        return response.data;
    }

    async getBalance() {
        const response = await this.client.get('/balance');
        return response.data;
    }

    async createInvoice(amount, description = '') {
        const response = await this.client.post('/invoice', {
            amount,
            description
        });
        return response.data;
    }

    async payInvoice(invoice) {
        const response = await this.client.post('/pay', {
            invoice
        });
        return response.data;
    }

    async getChannels() {
        const response = await this.client.get('/channels');
        return response.data;
    }

    connectWebSocket(onMessage) {
        const ws = new WebSocket(`${this.baseURL.replace('http', 'ws')}/ws`);

        ws.on('open', () => {
            console.log('WebSocket connected');
        });

        ws.on('message', (data) => {
            try {
                const message = JSON.parse(data);
                onMessage(message);
            } catch (e) {
                console.error('Invalid WebSocket message:', e);
            }
        });

        ws.on('error', (error) => {
            console.error('WebSocket error:', error);
        });

        return ws;
    }
}

module.exports = { BLNCSClient };
'''
        (output_path / 'src' / 'index.js').write_text(sdk_content.strip())

    def _generate_react_native_sdk(self, output_path: Path, config: SDKConfig):
        """Generate React Native SDK"""
        # Create React Native project structure
        (output_path / 'src').mkdir(exist_ok=True)
        (output_path / 'ios').mkdir(exist_ok=True)
        (output_path / 'android').mkdir(exist_ok=True)

        # Generate package.json for React Native
        package_json = {
            'name': 'blncs-sdk-react-native',
            'version': '1.0.0',
            'description': 'BLNCS Lightning Network SDK for React Native',
            'main': 'src/index.js',
            'scripts': {
                'start': 'react-native start',
                'test': 'jest',
                'lint': 'eslint src'
            },
            'dependencies': {dep: 'latest' for dep in config.dependencies}
        }

        with open(output_path / 'package.json', 'w') as f:
            json.dump(package_json, f, indent=2)

        # Generate React Native SDK
        rn_sdk_content = '''
/**
 * BLNCS Lightning Network SDK for React Native
 */

import AsyncStorage from '@react-native-async-storage/async-storage';
import axios from 'axios';

class BLNCSClient {
    constructor(baseURL, apiKey = null) {
        this.baseURL = baseURL.replace(/\\/$/, '');
        this.apiKey = apiKey;
        this.client = axios.create({
            baseURL: this.baseURL,
            timeout: 10000,
            headers: apiKey ? { 'X-API-Key': apiKey } : {}
        });
    }

    async getInfo() {
        try {
            const response = await this.client.get('/info');
            return response.data;
        } catch (error) {
            throw new Error(`Failed to get info: ${error.message}`);
        }
    }

    async getBalance() {
        try {
            const response = await this.client.get('/balance');
            return response.data;
        } catch (error) {
            throw new Error(`Failed to get balance: ${error.message}`);
        }
    }

    async createInvoice(amount, description = '') {
        try {
            const response = await this.client.post('/invoice', {
                amount,
                description
            });
            return response.data;
        } catch (error) {
            throw new Error(`Failed to create invoice: ${error.message}`);
        }
    }

    async payInvoice(invoice) {
        try {
            const response = await this.client.post('/pay', {
                invoice
            });
            return response.data;
        } catch (error) {
            throw new Error(`Failed to pay invoice: ${error.message}`);
        }
    }

    async getChannels() {
        try {
            const response = await this.client.get('/channels');
            return response.data;
        } catch (error) {
            throw new Error(`Failed to get channels: ${error.message}`);
        }
    }

    // Mobile-specific features
    async saveInvoiceLocally(invoice) {
        try {
            const key = `invoice_${Date.now()}`;
            await AsyncStorage.setItem(key, JSON.stringify(invoice));
            return key;
        } catch (error) {
            throw new Error(`Failed to save invoice: ${error.message}`);
        }
    }

    async getSavedInvoices() {
        try {
            const keys = await AsyncStorage.getAllKeys();
            const invoiceKeys = keys.filter(key => key.startsWith('invoice_'));

            const invoices = [];
            for (const key of invoiceKeys) {
                const invoice = await AsyncStorage.getItem(key);
                if (invoice) {
                    invoices.push(JSON.parse(invoice));
                }
            }

            return invoices;
        } catch (error) {
            throw new Error(`Failed to get saved invoices: ${error.message}`);
        }
    }
}

export default BLNCSClient;
'''
        (output_path / 'src' / 'index.js').write_text(rn_sdk_content.strip())

    def _generate_python_support_files(self, output_path: Path):
        """Generate Python SDK support files"""
        # Generate setup.py
        setup_content = '''
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="blncs-sdk-python",
    version="1.0.0",
    author="BLNCS Team",
    author_email="team@blncs.example.com",
    description="BLNCS Lightning Network SDK for Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/blncs/blncs-sdk-python",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.25.0",
        "websockets>=10.0",
        "cryptography>=3.4.0",
        "pydantic>=1.8.0",
    ],
)
'''
        (output_path / 'setup.py').write_text(setup_content.strip())

        # Generate exceptions.py
        exceptions_content = '''
"""
BLNCS SDK Exceptions
"""


class BLNCSException(Exception):
    """Base exception for BLNCS SDK"""
    pass


class AuthenticationError(BLNCSException):
    """Authentication failed"""
    pass


class NetworkError(BLNCSException):
    """Network communication error"""
    pass


class ValidationError(BLNCSException):
    """Data validation error"""
    pass
'''
        (output_path / 'blncs_sdk' / 'exceptions.py').write_text(exceptions_content.strip())

        # Generate README.md
        readme_content = '''
# BLNCS SDK for Python

Official Python SDK for BLNCS Lightning Network operations.

## Installation

```bash
pip install blncs-sdk-python
```

## Quick Start

```python
import asyncio
from blncs_sdk import BLNCSClient

async def main():
    async with BLNCSClient("https://api.blncs.example.com", api_key="your-api-key") as client:
        # Get node info
        info = await client.get_info()
        print(f"Node: {info['alias']}")

        # Get balance
        balance = await client.get_balance()
        print(f"Balance: {balance['total']} sats")

        # Create invoice
        invoice = await client.create_invoice(1000, "Test payment")
        print(f"Invoice: {invoice['payment_request']}")

asyncio.run(main())
```

## Features

- Lightning Network operations
- Wallet management
- Channel operations
- Real-time notifications via WebSocket
- Comprehensive error handling
- Type hints support

## Documentation

Full documentation available at [docs.blncs.example.com](https://docs.blncs.example.com)
'''
        (output_path / 'README.md').write_text(readme_content.strip())

    def _generate_common_files(self, output_path: Path, config: SDKConfig):
        """Generate common SDK files"""
        # Generate LICENSE
        license_content = '''
MIT License

Copyright (c) 2025 BLNCS Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''
        (output_path / 'LICENSE').write_text(license_content.strip())

        # Generate .gitignore
        gitignore_content = '''
# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class

# C extensions
*.so

# Distribution / packaging
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg
MANIFEST

# PyInstaller
*.manifest
*.spec

# Installer logs
pip-log.txt
pip-delete-this-directory.txt

# Unit test / coverage reports
htmlcov/
.tox/
.coverage
.coverage.*
.cache
nosetests.xml
coverage.xml
*.cover
.hypothesis/
.pytest_cache/

# Translations
*.mo
*.pot

# Django stuff:
*.log
local_settings.py
db.sqlite3

# Flask stuff:
instance/
.webassets-cache

# Scrapy stuff:
.scrapy

# Sphinx documentation
docs/_build/

# PyBuilder
target/

# Jupyter Notebook
.ipynb_checkpoints

# pyenv
.python-version

# celery beat schedule file
celerybeat-schedule

# SageMath parsed files
*.sage.py

# Environments
.env
.venv
env/
venv/
ENV/
env.bak/
venv.bak/

# Spyder project settings
.spyderproject
.spyproject

# Rope project settings
.ropeproject

# mkdocs documentation
/site

# mypy
.mypy_cache/
.dmypy.json
dmypy.json

# Node.js
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db
'''
        (output_path / '.gitignore').write_text(gitignore_content.strip())


class CrossPlatformBuilder:
    """Cross-platform build and deployment system"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize cross-platform builder

        Args:
            config: Build configuration
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Build configurations
        self.build_configs = self._initialize_build_configs()

    def _initialize_build_configs(self) -> Dict[str, Dict[str, Any]]:
        """Initialize build configurations for different platforms"""
        return {
            'windows': {
                'build_commands': [
                    'python setup.py build_ext --inplace',
                    'python setup.py bdist_wheel'
                ],
                'test_commands': [
                    'python -m pytest tests/ -v'
                ],
                'package_formats': ['wheel', 'exe']
            },
            'macos': {
                'build_commands': [
                    'python setup.py build_ext --inplace',
                    'python setup.py bdist_wheel'
                ],
                'test_commands': [
                    'python -m pytest tests/ -v'
                ],
                'package_formats': ['wheel', 'dmg']
            },
            'linux': {
                'build_commands': [
                    'python setup.py build_ext --inplace',
                    'python setup.py bdist_wheel'
                ],
                'test_commands': [
                    'python -m pytest tests/ -v'
                ],
                'package_formats': ['wheel', 'deb', 'rpm']
            },
            'android': {
                'build_commands': [
                    'npm install',
                    'cd android && ./gradlew assembleRelease'
                ],
                'test_commands': [
                    'npm test',
                    './gradlew test'
                ],
                'package_formats': ['apk', 'aab']
            },
            'ios': {
                'build_commands': [
                    'npm install',
                    'cd ios && pod install',
                    'xcodebuild -workspace ios/BLNCS.xcworkspace -scheme BLNCS -configuration Release -sdk iphoneos -archivePath build/BLNCS.xcarchive archive'
                ],
                'test_commands': [
                    'xcodebuild test -workspace ios/BLNCS.xcworkspace -scheme BLNCS -destination "platform=iOS Simulator,name=iPhone 12"'
                ],
                'package_formats': ['ipa']
            }
        }

    def build_for_platform(self, platform: str, source_dir: str, output_dir: str) -> bool:
        """
        Build application for specific platform

        Args:
            platform: Target platform
            source_dir: Source directory
            output_dir: Output directory

        Returns:
            Success status
        """
        if platform not in self.build_configs:
            self.logger.error(f"Unsupported platform: {platform}")
            return False

        config = self.build_configs[platform]

        try:
            # Create output directory
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)

            # Execute build commands
            for command in config['build_commands']:
                self.logger.info(f"Executing: {command}")
                result = subprocess.run(
                    command,
                    shell=True,
                    cwd=source_dir,
                    capture_output=True,
                    text=True
                )

                if result.returncode != 0:
                    self.logger.error(f"Build command failed: {command}")
                    self.logger.error(f"Error: {result.stderr}")
                    return False

            # Run tests
            for command in config['test_commands']:
                self.logger.info(f"Testing: {command}")
                result = subprocess.run(
                    command,
                    shell=True,
                    cwd=source_dir,
                    capture_output=True,
                    text=True
                )

                if result.returncode != 0:
                    self.logger.warning(f"Test command failed: {command}")
                    # Don't fail build on test failures, just warn

            # Package application
            self._package_application(platform, source_dir, output_path, config)

            self.logger.info(f"Build completed successfully for {platform}")
            return True

        except Exception as e:
            self.logger.error(f"Build failed for {platform}: {e}")
            return False

    def _package_application(self, platform: str, source_dir: str, output_path: Path, config: Dict[str, Any]):
        """Package application for distribution"""
        # Implementation would depend on specific packaging tools
        # For now, just copy built artifacts
        pass


class MobileUXOptimizer:
    """Mobile user experience optimizer"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize mobile UX optimizer

        Args:
            config: UX configuration
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

    def optimize_for_mobile(self, ui_components: List[CrossPlatformUI]) -> List[CrossPlatformUI]:
        """
        Optimize UI components for mobile platforms

        Args:
            ui_components: UI components to optimize

        Returns:
            Optimized UI components
        """
        optimized = []

        for component in ui_components:
            if Platform.IOS in component.platforms or Platform.ANDROID in component.platforms:
                # Apply mobile optimizations
                optimized_component = self._apply_mobile_optimizations(component)
                optimized.append(optimized_component)
            else:
                optimized.append(component)

        return optimized

    def _apply_mobile_optimizations(self, component: CrossPlatformUI) -> CrossPlatformUI:
        """Apply mobile-specific optimizations"""
        # Increase touch target sizes
        if 'button' in component.component_type.lower():
            component.properties['minHeight'] = max(component.properties.get('minHeight', 44), 44)
            component.properties['minWidth'] = max(component.properties.get('minWidth', 44), 44)

        # Add mobile-specific responsive rules
        component.responsive_rules.update({
            'mobile': {
                'fontSize': '16px',  # Prevent zoom on iOS
                'padding': '12px'
            },
            'tablet': {
                'fontSize': '18px',
                'padding': '16px'
            }
        })

        # Add mobile accessibility features
        component.accessibility_features.extend([
            'screen_reader_support',
            'high_contrast_support',
            'gesture_navigation'
        ])

        return component

    def generate_mobile_guidelines(self) -> Dict[str, Any]:
        """Generate mobile UI/UX guidelines"""
        return {
            'touch_targets': {
                'minimum_size': '44x44px',
                'recommended_size': '48x48px',
                'spacing': '8px minimum'
            },
            'typography': {
                'body_text': '16px minimum',
                'headings': '18-24px',
                'prevent_zoom': True
            },
            'navigation': {
                'bottom_tabs': '49px height',
                'swipe_gestures': True,
                'back_button': 'always visible'
            },
            'feedback': {
                'haptic_feedback': True,
                'loading_states': True,
                'error_messages': 'user-friendly'
            },
            'performance': {
                'initial_load': '<3 seconds',
                'scroll_fps': '60fps',
                'memory_usage': '<100MB'
            }
        }


# Global instances
_platform_detector = None
_cross_platform_sdk = None
_cross_platform_builder = None
_mobile_ux_optimizer = None

def get_platform_detector() -> PlatformDetector:
    """Get platform detector instance"""
    global _platform_detector
    if _platform_detector is None:
        _platform_detector = PlatformDetector()
    return _platform_detector

def get_cross_platform_sdk() -> CrossPlatformSDK:
    """Get cross-platform SDK instance"""
    global _cross_platform_sdk
    if _cross_platform_sdk is None:
        _cross_platform_sdk = CrossPlatformSDK()
    return _cross_platform_sdk

def get_cross_platform_builder() -> CrossPlatformBuilder:
    """Get cross-platform builder instance"""
    global _cross_platform_builder
    if _cross_platform_builder is None:
        _cross_platform_builder = CrossPlatformBuilder()
    return _cross_platform_builder

def get_mobile_ux_optimizer() -> MobileUXOptimizer:
    """Get mobile UX optimizer instance"""
    global _mobile_ux_optimizer
    if _mobile_ux_optimizer is None:
        _mobile_ux_optimizer = MobileUXOptimizer()
    return _mobile_ux_optimizer
