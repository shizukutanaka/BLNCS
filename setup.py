"""
BLNCS Setup Configuration
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

setup(
    name="blncs",
    version="0.0.1",
    author="BLNCS Team",
    author_email="",
    description="Bitcoin Lightning Routing Control System - One-click routing optimization",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/shizukutanaka/BLNCS",
    project_urls={
        "Source": "https://github.com/shizukutanaka/BLNCS",
        "Tracker": "https://github.com/shizukutanaka/BLNCS/issues",
    },
    packages=find_packages(exclude=["tests", "tests.*", "docs", "docs.*"]),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Financial and Insurance Industry",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Office/Business :: Financial",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
        "Framework :: FastAPI",
    ],
    python_requires=">=3.8",
    install_requires=[
        "fastapi>=0.100.0",
        "uvicorn>=0.23.0",
        "sqlalchemy>=2.0.0",
        "pydantic>=2.0.0",
        "httpx>=0.24.0",
        "python-dotenv>=1.0.0",
        "cryptography>=41.0.0",
        "passlib>=1.7.4",
        "python-jose>=3.3.0",
        "python-multipart>=0.0.6",
        "aiofiles>=23.0.0",
        "asyncio>=3.4.3",
        "redis>=4.5.0",
        "celery>=5.3.0",
        "prometheus-client>=0.17.0",
        "structlog>=23.0.0",
        "click>=8.1.0",
        "rich>=13.0.0",
        "pyyaml>=6.0",
        "toml>=0.10.2",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "ruff>=0.0.280",
            "mypy>=1.4.0",
            "pre-commit>=3.3.0",
        ],
        "monitoring": [
            "psutil>=5.9.0",
            "websockets>=11.0.0",
            "aiohttp>=3.8.0",
        ],
        "database": [
            "aiosqlite>=0.19.0",
            "asyncpg>=0.28.0",
            "pymongo>=4.4.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "blncs=blncs.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "blncs": [
            "templates/*.html",
            "static/css/*.css",
            "static/js/*.js",
            "config/*.yaml",
            "config/*.toml",
        ],
    },
    zip_safe=False,
    keywords=[
        "bitcoin",
        "lightning",
        "network",
        "routing",
        "lnd",
        "payment",
        "channels",
        "optimization",
    ],
)