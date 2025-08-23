# BLNCS - Bitcoin Lightning Network Control System

**Lightning Network Node Management Tool**

```bash
# Clone and install from source
git clone https://github.com/shizukutanaka/BLNCS.git
cd BLNCS
pip install -e .
```

## Features (In Development)

### Lightning Network Integration
- LND node connection support
- Basic channel management
- Payment routing functionality

### Monitoring
- Channel state monitoring
- Basic metrics collection
- Simple dashboard interface

### API
- REST API endpoints
- WebSocket support for real-time updates

## インストール

### 必要要件
- Python 3.8+
- LNDノード (v0.15.0+)
- 2GB以上のRAM

### Installation from Source

```bash
# Clone repository
git clone https://github.com/shizukutanaka/BLNCS.git
cd BLNCS

# Install dependencies
pip install -r requirements.txt

# Run development server
python -m blncs.cli.main start
```

## Version

Current version: v0.0.1 (Alpha Release)

## License

MIT License - See [LICENSE](LICENSE) file for details

## Status

This project is in early development stage. Features are being actively developed and APIs may change.