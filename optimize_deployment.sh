#!/bin/bash
# BLNCS Deployment Optimization Script
# 実用的な本番環境最適化

set -e

echo "🚀 BLNCS Deployment Optimization"
echo "================================"

# Configuration
BLNCS_HOME="${BLNCS_HOME:-/opt/blncs}"
BLNCS_USER="${BLNCS_USER:-blncs}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
PYTHON_BIN="${PYTHON_BIN:-$BLNCS_HOME/.venv/bin/python}"
CONFIG_FILE="$BLNCS_HOME/config/blncs.json"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# System optimization
optimize_system() {
    log_info "Optimizing system settings..."

    # Python optimization
    export PYTHONOPTIMIZE=2
    export PYTHONDONTWRITEBYTECODE=1
    export PYTHONUNBUFFERED=1

    # Memory settings
    if [ -w /proc/sys/vm/swappiness ]; then
        echo 10 > /proc/sys/vm/swappiness 2>/dev/null || true
        log_info "Swappiness set to 10"
    fi

    # Network optimization
    if [ -w /proc/sys/net/core/somaxconn ]; then
        echo 1024 > /proc/sys/net/core/somaxconn 2>/dev/null || true
        log_info "Socket backlog optimized"
    fi
}

# Database optimization
optimize_database() {
    log_info "Optimizing database..."

    local db_file="$BLNCS_HOME/data/blncs.db"

    if [ -f "$db_file" ]; then
        if command -v sqlite3 >/dev/null 2>&1; then
            sqlite3 "$db_file" "PRAGMA optimize;"
            sqlite3 "$db_file" "VACUUM;"
            log_info "Database optimized and vacuumed"
        else
            log_warn "sqlite3 not available; skipping direct VACUUM"
        fi
    else
        log_warn "Database file not found: $db_file"
    fi
}

# Log optimization
optimize_logs() {
    log_info "Setting up log rotation..."

    # Create logrotate config
    cat > /tmp/blncs-logrotate <<EOF
$BLNCS_HOME/logs/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 644 $BLNCS_USER $BLNCS_USER
    postrotate
        systemctl reload blncs 2>/dev/null || true
    endscript
}
EOF

    if [ -w /etc/logrotate.d ]; then
        cp /tmp/blncs-logrotate /etc/logrotate.d/blncs
        log_info "Log rotation configured"
    else
        log_warn "Cannot write to /etc/logrotate.d - manual setup required"
    fi
}

# Process optimization
optimize_processes() {
    log_info "Optimizing process limits..."

    # Create limits config
    cat > /tmp/blncs-limits.conf <<EOF
$BLNCS_USER soft nofile 8192
$BLNCS_USER hard nofile 16384
$BLNCS_USER soft nproc 4096
$BLNCS_USER hard nproc 8192
EOF

    if [ -w /etc/security/limits.d ]; then
        cp /tmp/blncs-limits.conf /etc/security/limits.d/blncs.conf
        log_info "Process limits configured"
    fi
}

# Cleanup old files
cleanup_old_files() {
    log_info "Cleaning up old files..."

    # Remove old logs (older than 30 days)
    find "$BLNCS_HOME/logs" -name "*.log.*" -mtime +30 -delete 2>/dev/null || true

    # Remove old backups (keep last 10)
    if [ -d "$BLNCS_HOME/backups" ]; then
        find "$BLNCS_HOME/backups" -name "*.gz" -type f | \
            sort -t_ -k2 -nr | tail -n +11 | xargs rm -f 2>/dev/null || true
    fi

    # Clean Python cache
    find "$BLNCS_HOME" -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
    find "$BLNCS_HOME" -name "*.pyc" -delete 2>/dev/null || true

    log_info "Cleanup completed"
}

# Performance tuning
tune_performance() {
    log_info "Tuning performance settings..."

    # Create optimized config
    mkdir -p "$BLNCS_HOME/config"

    cat > "$BLNCS_HOME/config/performance.json" <<EOF
{
    "cache": {
        "max_size": 2000,
        "ttl": 1800,
        "cleanup_interval": 300
    },
    "database": {
        "pool_size": 10,
        "timeout": 30,
        "wal_checkpoint": 1000
    },
    "api": {
        "workers": $(nproc),
        "max_connections": 1000,
        "keepalive_timeout": 65
    },
    "websocket": {
        "ping_interval": 20,
        "ping_timeout": 10,
        "max_clients": 100
    }
}
EOF

    log_info "Performance config created"
}

# Security hardening
harden_security() {
    log_info "Applying security hardening..."

    # File permissions
    chmod 750 "$BLNCS_HOME"
    chmod -R 640 "$BLNCS_HOME/config"
    chmod -R 750 "$BLNCS_HOME/logs"
    chmod +x "$BLNCS_HOME/blncs_main.py"

    # Create security config
    cat > "$BLNCS_HOME/config/security.json" <<EOF
{
    "api": {
        "rate_limit": 1000,
        "rate_window": 3600,
        "require_https": false,
        "cors_origins": ["localhost", "127.0.0.1"]
    },
    "auth": {
        "session_timeout": 3600,
        "max_failed_attempts": 5,
        "lockout_duration": 300
    }
}
EOF

    log_info "Security hardening applied"
}

# Monitor setup
setup_monitoring() {
    log_info "Setting up basic monitoring..."

    # Create simple monitoring script
    cat > "$BLNCS_HOME/monitor.sh" <<'EOF'
#!/bin/bash
# Simple BLNCS monitoring

    BLNCS_HOME="${BLNCS_HOME:-/opt/blncs}"
    LOG_FILE="$BLNCS_HOME/logs/monitor.log"
    VENV_DIR="$BLNCS_HOME/venv"
    CONFIG_FILE="$BLNCS_HOME/config/blncs.json"

check_service() {
    if [ -d "$VENV_DIR" ] && [ -f "$CONFIG_FILE" ]; then
        if systemctl is-active --quiet blncs; then
            echo "$(date): Service OK" >> "$LOG_FILE"
            return 0
        else
            echo "$(date): Service DOWN - Restarting" >> "$LOG_FILE"
            systemctl restart blncs
            return 1
        fi
    else
        echo "$(date): Service DOWN - Missing venv/config" >> "$LOG_FILE"
        echo "$(date): Service DOWN - Restarting" >> "$LOG_FILE"
        systemctl restart blncs
        return 1
    fi
}

check_disk() {
    USAGE=$(df "$BLNCS_HOME" | awk 'NR==2 {print $5}' | tr -d '%')
    if [ "$USAGE" -gt 80 ]; then
        echo "$(date): Disk usage high: ${USAGE}%" >> "$LOG_FILE"
    fi
}

check_memory() {
    MEM_USAGE=$(ps -o pid,vsz,comm -C python | grep blncs | awk '{sum+=$2} END {print sum/1024}')
    if [ -n "$MEM_USAGE" ] && [ "${MEM_USAGE%%.*}" -gt 500 ]; then
        echo "$(date): High memory usage: ${MEM_USAGE}MB" >> "$LOG_FILE"
    fi
}

# Run checks
check_service
check_disk
check_memory
EOF

    chmod +x "$BLNCS_HOME/monitor.sh"

    # Add to cron if possible
    if command -v crontab >/dev/null; then
        (crontab -l 2>/dev/null; echo "*/5 * * * * $BLNCS_HOME/monitor.sh") | crontab -
        log_info "Monitoring cron job added"
    fi
}

# Backup optimization
optimize_backups() {
    log_info "Optimizing backup strategy..."

    # Create backup script
    cat > "$BLNCS_HOME/backup_optimized.sh" <<EOF
#!/bin/bash
# Optimized BLNCS backup

BACKUP_DIR="$BLNCS_HOME/backups"
DATE=\$(date +%Y%m%d_%H%M%S)

# Stop services temporarily
systemctl stop blncs || true

# Create compressed backup
tar -czf "\$BACKUP_DIR/full_backup_\$DATE.tar.gz" \
    --exclude="*.log*" \
    --exclude="__pycache__" \
    --exclude="*.pyc" \
    -C "$BLNCS_HOME" .

# Restart services
systemctl start blncs || true

# Keep only last 5 full backups
ls -t "\$BACKUP_DIR"/full_backup_*.tar.gz | tail -n +6 | xargs rm -f

echo "Backup completed: full_backup_\$DATE.tar.gz"
EOF

    chmod +x "$BLNCS_HOME/backup_optimized.sh"
    log_info "Optimized backup script created"
}

# Health check endpoint
setup_health_check() {
    log_info "Setting up health check endpoint..."

    # Create health check script
    cat > "$BLNCS_HOME/health_check.py" <<'EOF'
#!/usr/bin/env python3
import sys
import requests
import subprocess
import time

def check_api():
    try:
        port = int(os.environ.get('BLNCS_API_PORT', '8080'))
        response = requests.get(f'http://localhost:{port}/health', timeout=5)
        return response.status_code == 200
    except:
        return False

def check_service():
    try:
        result = subprocess.run(['systemctl', 'is-active', 'blncs'],
                              capture_output=True, text=True)
        return result.stdout.strip() == 'active'
    except:
        return False

def main():
    api_ok = check_api()
    service_ok = check_service()

    if api_ok and service_ok:
        print("HEALTHY")
        return 0
    else:
        print(f"UNHEALTHY - API: {api_ok}, Service: {service_ok}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
EOF

    chmod +x "$BLNCS_HOME/health_check.py"
    log_info "Health check script created"
}

# Main optimization routine
main() {
    echo "Starting optimization process..."

    # Check if running as root/sudo
    if [ "$EUID" -eq 0 ]; then
        optimize_system
        optimize_processes
        optimize_logs
    else
        log_warn "Some optimizations require root privileges"
    fi

    # User-level optimizations
    optimize_database
    cleanup_old_files
    tune_performance
    harden_security
    setup_monitoring
    optimize_backups
    setup_health_check

    echo ""
    log_info "Optimization completed successfully!"
    log_info "Next steps:"
    echo "  1. Review configs in $BLNCS_HOME/config/"
    echo "  2. Test with: $BLNCS_HOME/health_check.py"
    echo "  3. Monitor logs in $BLNCS_HOME/logs/"
    echo "  4. Run backup: $BLNCS_HOME/backup_optimized.sh"
    echo ""
    log_info "For monitoring, check $BLNCS_HOME/monitor.sh runs every 5 minutes"
}

# Run optimization
main "$@"