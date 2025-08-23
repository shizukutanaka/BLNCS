# Changelog

All notable changes to BLNCS will be documented in this file.

## [0.0.1] - 2024-01-23

### Added
- Initial alpha release of Bitcoin Lightning Network Control System
- Basic LND node connection support
- Simple channel management interface
- REST API framework
- WebSocket support structure
- Command-line interface
- Plugin system foundation

### Features
- LND integration support
- Basic channel operations
- Multi-language support (English/Japanese)

### Technical
- Python 3.8+ support
- LND v0.15.0+ compatibility
- Modular architecture with clear separation:
  - Core: Lightning business logic
  - Utils: LND connection and utilities
  - Interfaces: API, CLI, WebSocket
  - Infrastructure: Monitoring and health checks

### Documentation
- README with installation instructions
- Basic API documentation
- Configuration examples

### Known Issues
- Alpha release - not recommended for production use
- Limited testing with real Lightning Network
- Performance optimization needed for large nodes

---

This is an early development release. APIs and features are subject to change.