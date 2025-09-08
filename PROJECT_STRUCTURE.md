# BLNCS Project Structure

## Overview
BLNCS (Bitcoin Lightning Network Control System) - A lightweight Lightning Network management tool.

## Directory Structure

```
BLNCS/
├── blncs/                      # Main package
│   ├── __init__.py            # Package initialization with lazy loading
│   ├── core/                  # Core functionality
│   │   ├── config.py          # Configuration management
│   │   ├── exceptions.py      # Exception definitions
│   │   ├── logger.py          # Logging system
│   │   ├── health.py          # Health monitoring
│   │   ├── cache.py           # Caching system
│   │   ├── channel_manager.py # Channel management
│   │   ├── connection_pool.py # Connection pooling
│   │   ├── fee_optimizer.py   # Fee optimization
│   │   ├── history.py         # Transaction history
│   │   ├── liquidity_manager.py # Liquidity management
│   │   ├── recovery.py        # Recovery mechanisms
│   │   ├── security.py        # Security features
│   │   ├── setup.py           # Setup utilities
│   │   ├── shutdown.py        # Graceful shutdown
│   │   ├── simple_backup.py   # Backup system
│   │   ├── performance/       # Performance monitoring
│   │   │   ├── auto_tuner.py
│   │   │   ├── metrics_collector.py
│   │   │   ├── monitoring_thread.py
│   │   │   ├── unified_monitor.py
│   │   │   └── wallet_monitor.py
│   │   └── validation/        # Configuration validation
│   │       ├── config_validator.py
│   │       ├── field_validators.py
│   │       └── validation_rules.py
│   ├── lightning/             # Lightning Network integration
│   │   ├── __init__.py       
│   │   └── client.py          # LN node client
│   ├── cli/                   # Command-line interface
│   │   ├── main.py            # CLI entry point
│   │   └── commands/          # CLI commands
│   │       ├── channel_commands.py
│   │       ├── config_commands.py
│   │       ├── info_commands.py
│   │       ├── liquidity_commands.py
│   │       ├── management_commands.py
│   │       └── network_commands.py
│   └── utils/                 # Utility functions
│       ├── __init__.py
│       ├── lightning_helpers.py
│       ├── network_test.py
│       ├── qr_generator.py
│       ├── setup_helper.py
│       └── system_info.py
├── tests/                      # Test suite
│   ├── test_basic.py          # Basic functionality tests
│   ├── test_comprehensive.py  # Comprehensive tests
│   ├── test_integration.py    # Integration tests
│   └── test_quality.py        # Quality tests
├── docs/                       # Documentation
│   └── API.md                 # API documentation
├── config/                     # Configuration files
│   └── config.yaml            # Default configuration
├── pyproject.toml             # Project metadata and dependencies
├── requirements.txt           # Python dependencies
├── run_quick_tests.py         # Quick test runner
├── README.md                  # Project documentation
├── Makefile                   # Build automation
├── Dockerfile                 # Docker configuration
├── docker-compose.yml         # Docker Compose setup
└── docker-compose.dev.yml     # Development Docker setup

```

## Key Components

### Core System
- **config.py**: Configuration management with YAML support
- **exceptions.py**: Custom exception hierarchy  
- **logger.py**: Centralized logging system
- **health.py**: System health monitoring
- **performance/**: Performance monitoring and optimization
- **backup/**: Backup and restore functionality
- **validation/**: Configuration validation

### Lightning Integration
- **client.py**: Lightning node client with automatic fallback

### CLI Interface
- **main.py**: CLI entry point with 20+ commands
- **commands/**: Individual CLI command implementations

### Additional Components
- **api/**: Basic API functionality
- **monitoring/**: System monitoring and metrics
- **reporting/**: Report generation
- **ui/**: User interface enhancements
- **utils/**: Utility functions including QR generation

### Testing
- **test_basic.py**: Core functionality tests
- **run_quick_tests.py**: Fast test runner for development

## Installation

```bash
# Clone repository
git clone https://github.com/yourusername/blncs.git
cd blncs

# Install dependencies
pip install -r requirements.txt
pip install -e .
```

## Usage

```bash
# Setup configuration
python -m blncs.cli.main setup

# Check status
python -m blncs.cli.main status

# View all commands
python -m blncs.cli.main --help

# Run tests
python run_quick_tests.py
```

## Development

The project follows Python best practices with:
- Type hints and proper documentation
- Comprehensive error handling
- Modular architecture with lazy loading
- Clear separation of concerns
- Minimal dependencies for portability
- Focus on practical Lightning Network functionality