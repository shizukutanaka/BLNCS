# BLNCS Project Structure

## Directory Layout

```
BLNCS/
├── blrcs/                    # Main package directory
│   ├── __init__.py          # Package initialization, version 0.0.1
│   ├── lightning/           # Lightning Network core functionality
│   │   ├── __init__.py     
│   │   ├── lightning.py     # LND REST client for connectivity
│   │   ├── lnd_connector.py # LND node connection manager
│   │   ├── channel_manager.py # Channel management and rebalancing
│   │   ├── payment_router.py  # Payment routing algorithms
│   │   └── one_click_routing.py # One-click routing automation
│   ├── api/                 # REST API and WebSocket
│   │   ├── __init__.py
│   │   ├── server.py        # FastAPI server implementation
│   │   └── websocket.py     # WebSocket real-time updates
│   ├── cli/                 # Command-line interface
│   │   ├── __init__.py
│   │   └── main.py          # CLI entry point and commands
│   ├── utils/               # Utility functions
│   │   ├── __init__.py
│   │   ├── backup.py        # Backup utilities
│   │   ├── error_handler.py # Error handling
│   │   ├── file_upload.py   # File operations
│   │   ├── file_watcher.py  # File monitoring
│   │   ├── input_validator.py # Input validation
│   │   ├── recovery.py      # Recovery utilities
│   │   └── utilities.py     # General utilities
│   └── translations/        # Internationalization
│       ├── en.json          # English translations
│       └── ja.json          # Japanese translations
├── docs/                    # Documentation
│   └── api/                # API documentation
├── plugins/                 # Plugin system
│   └── builtin/            # Built-in plugins
├── .github/                # GitHub configuration
├── CHANGELOG.md            # Version history
├── LICENSE                 # MIT License
├── README.md              # Project documentation
├── setup.py               # Package configuration
├── pyproject.toml         # Python project metadata
├── requirements.txt       # Production dependencies
├── requirements-dev.txt   # Development dependencies
├── mypy.ini              # Type checking configuration
├── .gitignore            # Git ignore rules
├── .env.sample           # Environment variables template
└── .pre-commit-config.yaml # Pre-commit hooks

```

## Module Descriptions

### `/blrcs/lightning/`
Core Lightning Network functionality:
- **lightning.py**: Minimal LND REST client for health checks and connectivity
- **lnd_connector.py**: Manages connection to LND node, handles macaroons and TLS
- **channel_manager.py**: Channel rebalancing, fee optimization, channel health monitoring
- **payment_router.py**: Route finding algorithms, payment path optimization
- **one_click_routing.py**: Automated routing with one-click operation

### `/blrcs/api/`
REST API and real-time communication:
- **server.py**: FastAPI server with endpoints for routing, channels, and monitoring
- **websocket.py**: WebSocket handler for real-time updates and notifications

### `/blrcs/cli/`
Command-line interface:
- **main.py**: CLI commands for starting, stopping, status checks, and manual operations

### `/blrcs/utils/`
Support utilities:
- **backup.py**: Channel backup and recovery
- **error_handler.py**: Centralized error handling and logging
- **file operations**: Upload, watching, and validation
- **recovery.py**: System recovery procedures

## Key Features (Planned)

1. **LND Integration**: Connect to LND nodes
2. **Channel Management**: Basic channel operations
3. **Payment Routing**: Route payments through Lightning Network
4. **Monitoring**: Track channel states and metrics
5. **REST API**: HTTP API for integration
6. **CLI Interface**: Command-line management tools
7. **Plugin System**: Extensible architecture

## Usage

### Quick Start (Development)
```bash
git clone https://github.com/shizukutanaka/BLNCS.git
cd BLNCS
pip install -e .
blncs start --lnd-dir ~/.lnd
```

### Python API (Example)
```python
from blncs.lightning import LNDConnector

connector = LNDConnector()
await connector.connect()
```

### REST API
```bash
curl http://localhost:8080/api/status
```

### CLI Commands (Planned)
```bash
blncs status       # Check node status
blncs channels     # List channels
blncs monitor      # Monitor resources
```

## Development

### Setup Development Environment
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

### Run Tests
```bash
pytest tests/
```

### Type Checking
```bash
mypy blrcs/
```

## Version

Current: v0.0.1 (Alpha)

## License

MIT License - See LICENSE file for details