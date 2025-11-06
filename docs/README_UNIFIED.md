# BLNCS – Bitcoin Lightning Network Control System
## Overview (English)

BLNCS bundles a headless service layer, a command-line and scripting toolkit, and an optional Tkinter dashboard so operators can monitor Lightning infrastructure and automate common actions. The project emphasizes minimal dependencies, structured configuration, and easy packaging for laptops, servers, and containers.

### Core components
- `blncs_main.py` – CLI entry point providing status, configuration, Lightning helpers, and backup commands
- `blncs/api/unified_rest_api.py` – Flask application exposing `/health`, `/api/*`, and WebSocket status endpoints
### CLI highlights
```bash
# Create configuration template if missing
python blncs_main.py config --template

# Run API server (uses config/blncs.json by default)
python blncs_main.py server

# Inspect health and info
python blncs_main.py status
python blncs_main.py info --stats

# Lightning helpers (mock-friendly)
python blncs_main.py invoice --amount 500 --memo Demo --qr
python blncs_main.py decode lnbc1...

# Security helpers
python blncs_main.py security --show-auth-limits
python blncs_main.py security --set-auth-limits 5 120
python blncs_main.py security --reset-auth-failures
```

### Getting started
```bash
git clone <your-repository-url>
cd BLNCS
python -m venv .venv
. .venv/bin/activate  # Windows: .venv\Scripts\activate