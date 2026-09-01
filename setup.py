#!/usr/bin/env python3
"""
BLNCS Setup - Lightweight Edition
Simplified Bitcoin Lightning Network Control System
"""

from setuptools import setup, find_packages
from pathlib import Path
import os
import re

# Read version from __init__.py
def get_version():
    init_path = Path(__file__).parent / "blncs" / "__init__.py"
    if init_path.exists():
        with open(init_path, 'r') as f:
            content = f.read()
            match = re.search(r"__version__\s*=\s*['\"]([^'\"]*)['\"]", content)
            if match:
                return match.group(1)
    return "1.0.0"

# Read long description from README
def get_long_description():
    readme_path = Path(__file__).parent / "README.md"
    if readme_path.exists():
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return ""

# Read requirements from requirements.txt
def get_requirements():
    req_path = Path(__file__).parent / "requirements.txt"
    requirements = []
    
    if req_path.exists():
        with open(req_path, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if line and not line.startswith('#'):
                    requirements.append(line)
    
    return requirements

# Development requirements
dev_requirements = [
    'pytest>=7.4.0',
    'pytest-cov>=4.1.0', 
    'pytest-asyncio>=0.21.0',
    'black>=23.0.0',
    'flake8>=6.0.0',
    'mypy>=1.5.0',
    'safety>=2.3.0',
    'bandit>=1.7.0',
    'pre-commit>=3.4.0'
]

# Production requirements (core only)
prod_requirements = [
    'pyyaml>=6.0.0',
    'requests>=2.31.0',
    'click>=8.1.0',
    'psutil>=5.9.0',
    'validators>=0.22.0',
    'pydantic>=2.0.0',
    'qrcode[pil]>=7.4.0',
    'cryptography>=41.0.0',
    'grpcio>=1.59.0',
    'grpcio-tools>=1.59.0',
    'protobuf>=4.24.0',
    'googleapis-common-protos>=1.60.0',
    'urllib3>=2.0.0',
    'prometheus-client>=0.17.0'
]

setup(
    name="blncs",
    version=get_version(),
    author="BLNCS Development Team",
    author_email="contact@yourdomain.com",
    description="Bitcoin Lightning Network Control System - Professional Lightning Network Management",
    long_description=get_long_description(),
    long_description_content_type="text/markdown",
    url=os.getenv("BLNCS_REPO_URL", "https://github.com/blncs/blncs"),
    project_urls={
        "Documentation": os.getenv("BLNCS_DOCS_URL", "https://github.com/blncs/blncs/wiki"),
        "Source Code": os.getenv("BLNCS_REPO_URL", "https://github.com/blncs/blncs"),
        "Issue Tracker": os.getenv("BLNCS_ISSUES_URL", "https://github.com/blncs/blncs/issues"),
        "Changelog": os.getenv("BLNCS_CHANGELOG_URL", "https://github.com/blncs/blncs/blob/main/CHANGELOG.md")
    },
    packages=find_packages(exclude=['tests*', 'docs*', 'examples*']),
    package_data={
        'blncs': [
            'config/*.yaml',
            'templates/*.json',
            'static/*.*',
        ]
    },
    include_package_data=True,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Financial and Insurance Industry", 
        "Topic :: Office/Business :: Financial",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Environment :: Web Environment"
    ],
    keywords=[
        "bitcoin", "lightning-network", "cryptocurrency", "payments", 
        "blockchain", "finance", "monitoring", "management", "automation"
    ],
    python_requires=">=3.9",
    install_requires=prod_requirements,
    extras_require={
        "dev": dev_requirements,
        "all": get_requirements(),
        "monitoring": ["prometheus-client>=0.17.0", "grafana-api>=1.0.0"],
        "security": ["cryptography>=41.0.0", "pyotp>=2.9.0"],
        "performance": ["uvloop>=0.17.0", "orjson>=3.9.0"],
        "testing": ["pytest>=7.4.0", "pytest-cov>=4.1.0", "factory-boy>=3.3.0"]
    },
    entry_points={
        "console_scripts": [
            "blncs=blncs.cli.main:main",
            "blncs-daemon=blncs.daemon.main:main",
            "blncs-monitor=blncs.monitoring.main:main",
            "blncs-setup=blncs.setup.main:main"
        ]
    },
    scripts=[
        "scripts/blncs-install.sh",
        "scripts/blncs-health-check.sh"
    ],
    zip_safe=False,  # Required for package data access
    platforms=["any"],
    
    # Configuration for distribution
    options={
        "bdist_wheel": {
            "universal": False  # Not universal due to platform-specific dependencies
        }
    },
    
    # Metadata for PyPI
    project={
        "readme": "README.md",
        "license": {"text": "MIT"},
        "requires-python": ">=3.9",
        "dynamic": ["version"],
        "dependencies": prod_requirements
    }
)