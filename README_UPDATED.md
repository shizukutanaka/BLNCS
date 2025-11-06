# BLNCS – Bitcoin Lightning Network Control System

## Overview (English)

BLNCS is an operator-focused toolkit for Lightning Network infrastructure. It delivers a consistent command-line interface, a Flask-based REST API, lightweight metrics collectors, and an optional Tkinter dashboard. Every component is designed to stay lightweight, auditable, and easy to automate so teams can deploy BLNCS on laptops, data-center hosts, or sovereign-grade installations without unnecessary dependencies.

### What you can do with BLNCS
- Configure once, run anywhere: `blncs_main.py` provisions and validates `config/blncs.json`, including health checks and backup triggers.
- Automate safely: `blncs/api/unified_rest_api.py` exposes JSON endpoints for health, cache inspection, Lightning helpers, and performance optimizations with rate limiting support from `blncs/core/rate_limiter.py`.
- Observe with low overhead: `blncs/core/lightweight_metrics.py` surfaces CPU, memory, disk, network, and GC counters using adaptive polls.
- Operate visually when needed: `blncs/gui/dashboard_gui.py` pairs REST polling with resilient WebSocket reconnection logic.
- Harden deployments: `blncs/core/resource_manager.py` coordinates graceful shutdown, while `blncs/utils/simple_backup_recovery.py` provides responsive `AutoBackup` scheduling.
- **Automate maintenance**: `blncs/utils/maintenance_scheduler.py` provides comprehensive system maintenance automation with intelligent scheduling, priority bundles, and synchronous task execution.

### Supported environments
- Python 3.10 or newer (3.10–3.12 regularly exercised; 3.8 compatibility remains but is not a primary target).
- Linux, macOS, and Windows (use WSL on Windows for full feature parity across CLI, REST, and GUI components).
- LND or Core Lightning connectivity when operating against live nodes. BLNCS can run in mock mode for evaluation without a node.

### First 15 minutes
```bash
git clone <repository-url>
cd BLNCS
python -m venv .venv
. .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Generate default configuration and validate connectivity
python blncs_main.py config --template
python blncs_main.py status
python blncs_main.py health

# Optional diagnostics and focused tests
python blncs/utils/system_info.py --json --sections system,cpu
python -m pytest tests/test_unified_comprehensive.py -k optimize_endpoint
```

### Operator workflow highlights
- Launch REST API service: `python blncs_main.py server`
- Inspect metrics: `python blncs_main.py info --stats` or `GET /api/system/metrics`
- Manage Lightning invoices: `python blncs_main.py invoice --amount 500 --memo "Ops Test" --qr`
- Trigger controlled performance tuning: `curl -X POST http://localhost:5000/api/system/optimize`
- Review cached log buffer: `python blncs_main.py logs --action view --lines 120`
- **Run maintenance bundles immediately**: `python blncs_main.py maintenance --bundle high --respect-windows`
- **Execute specific maintenance tasks synchronously**: `python blncs_main.py maintenance --run daily_log_rotation`
- **List available maintenance tasks**: `python blncs_main.py maintenance --list`
- **Generate maintenance reports**: `python blncs_main.py maintenance --json` (for automation pipelines)

### Maintenance Automation Features

BLNCS includes comprehensive maintenance automation to reduce operational overhead:

#### Automated Maintenance Tasks
- **System Cleanup**: Clean temporary files and caches daily
- **Database Optimization**: Optimize SQLite databases weekly
- **Log Rotation**: Compress and rotate logs daily
- **Security Updates**: Check and apply security patches weekly
- **Health Checks**: Monitor system health hourly
- **Performance Tuning**: Optimize system performance daily

#### Maintenance Command Usage
```bash
# List all available maintenance tasks
python blncs_main.py maintenance --list

# Run specific maintenance tasks immediately
python blncs_main.py maintenance --run daily_system_cleanup hourly_health_check

# Execute maintenance tasks by priority level
python blncs_main.py maintenance --bundle critical    # Critical priority only
python blncs_main.py maintenance --bundle high       # High and critical priority
python blncs_main.py maintenance --bundle normal     # Normal, high, and critical priority
python blncs_main.py maintenance --bundle low        # All priority levels

# Respect maintenance windows (run only during scheduled times)
python blncs_main.py maintenance --bundle high --respect-windows

# Generate JSON output for automation pipelines
python blncs_main.py maintenance --list --json
```

#### Maintenance Windows
- **Daily Window**: 02:00-06:00 UTC (all tasks)
- **Weekend Window**: 01:00-07:00 UTC (extended hours for intensive tasks)
- Critical tasks can run outside maintenance windows if needed

### Configuration essentials
- `config/blncs.json`: single JSON source consumed by CLI and server (`SimpleConfig`).
- `lightning.node_url`: switch from mock to real node endpoints.
- `security.enable_auth`: enable token guard for REST API calls; pair with reverse proxy TLS for production.
- `monitoring.interval`: tune metrics cadence (default 30 seconds) based on host constraints.
- `logging`: configure console/file sinks exposed by `blncs/core/logger.py`.

### Security and hardening guidance
- Run REST API behind a TLS-enabled proxy (nginx, Caddy, Traefik) and restrict `/api/system/*` endpoints to authenticated operators.
- Use the optional `--no-proxy` CLI flag (`blncs_gui.py --no-proxy`) or `BLNCS_GUI_NO_PROXY=1` environment variable to bypass untrusted proxy settings.
- Rotate automatic backups by pointing `blncs/utils/simple_backup_recovery.AutoBackup` at encrypted storage and monitoring results for errors.
- Integrate `blncs/core/rate_limiter.py` with REST endpoints receiving Lightning payments to mitigate brute-force attempts.

### Performance & observability practices
- Enable `PerformanceOptimizer` via `/api/system/optimize` during maintenance windows to warm imports and adjust GC thresholds.
- Collect host reports with `blncs/utils/system_info.py --json` and archive alongside incident response logs.
- Monitor WebSocket connectivity by querying `GET /api/websocket/status`; use CLI `--poll-interval` to size dashboard refresh rates.

### Documentation map
- `docs/QUICK_START.md`: evaluation workflow and everyday commands.
- `docs/README_UNIFIED.md`: architecture summary and component ledger.
- `docs/DEPLOYMENT_GUIDE_UNIFIED.md`: virtualenv, systemd, and Docker Compose deployment references.
- `docs/API_REFERENCE_UNIFIED.md`: request/response formats for REST clients.
- `docs/500_PRACTICAL_IMPROVEMENTS.md`: prioritized backlog of safety, performance, UX, stability, and maintainability enhancements (500 items).

---
