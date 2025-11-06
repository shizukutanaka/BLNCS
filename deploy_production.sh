#!/bin/bash

# BLNCS Production Deployment Script
# Comprehensive deployment automation with safety checks and rollback capability

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOYMENT_LOG="/var/log/blncs/deployment.log"
BACKUP_DIR="/var/backup/blncs"
SERVICE_NAME="blncs"
DEPLOY_USER="${DEPLOY_USER:-blncs}"
ENVIRONMENT="${ENVIRONMENT:-production}"
VERSION="${VERSION:-$(date +%Y%m%d_%H%M%S)}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    echo -e "${timestamp} [${level}] ${message}" | tee -a "${DEPLOYMENT_LOG}"

    case "${level}" in
        "ERROR")
            echo -e "${RED}${message}${NC}" >&2
            ;;
        "WARN")
            echo -e "${YELLOW}${message}${NC}"
            ;;
        "SUCCESS")
            echo -e "${GREEN}${message}${NC}"
            ;;
        "INFO")
            echo -e "${BLUE}${message}${NC}"
            ;;
    esac
}

# Error handler
error_handler() {
    local line_number="$1"
    log "ERROR" "Deployment failed at line ${line_number}. Starting rollback..."
    rollback_deployment
    exit 1
}

trap 'error_handler ${LINENO}' ERR

# Pre-deployment checks
pre_deployment_checks() {
    log "INFO" "Starting pre-deployment checks..."

    # Check if running as correct user
    if [[ "$(whoami)" != "root" ]] && [[ "$(whoami)" != "${DEPLOY_USER}" ]]; then
        log "ERROR" "Must run as root or ${DEPLOY_USER}"
        exit 1
    fi

    # Check system resources
    local available_memory=$(free -m | awk '/^Mem:/{print $7}')
    local available_disk=$(df / | awk 'NR==2{print $4}')

    if [[ ${available_memory} -lt 512 ]]; then
        log "ERROR" "Insufficient memory: ${available_memory}MB available (minimum 512MB required)"
        exit 1
    fi

    if [[ ${available_disk} -lt 1048576 ]]; then # 1GB in KB
        log "ERROR" "Insufficient disk space: ${available_disk}KB available (minimum 1GB required)"
        exit 1
    fi

    # Check Python version
    if ! python3 --version | grep -E "3\.(8|9|10|11|12)" > /dev/null; then
        log "ERROR" "Python 3.8+ required"
        exit 1
    fi

    # Check if service is running (for update scenarios)
    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        log "INFO" "Service ${SERVICE_NAME} is currently running"
        EXISTING_SERVICE=true
    else
        log "INFO" "Service ${SERVICE_NAME} is not running (new installation)"
        EXISTING_SERVICE=false
    fi

    log "SUCCESS" "Pre-deployment checks passed"
}

# Backup current installation
backup_current_installation() {
    if [[ "${EXISTING_SERVICE}" == "true" ]]; then
        log "INFO" "Creating backup of current installation..."

        local backup_path="${BACKUP_DIR}/backup_${VERSION}"
        mkdir -p "${backup_path}"

        # Backup application files
        if [[ -d "/opt/blncs" ]]; then
            cp -r /opt/blncs "${backup_path}/app"
        fi

        # Backup configuration
        if [[ -d "/etc/blncs" ]]; then
            cp -r /etc/blncs "${backup_path}/config"
        fi

        # Backup database
        if [[ -f "/var/lib/blncs/blncs.db" ]]; then
            cp /var/lib/blncs/blncs.db "${backup_path}/database.db"
        fi

        # Backup logs
        if [[ -d "/var/log/blncs" ]]; then
            tar -czf "${backup_path}/logs.tar.gz" /var/log/blncs/
        fi

        echo "${backup_path}" > "${BACKUP_DIR}/latest_backup"
        log "SUCCESS" "Backup created at ${backup_path}"
    else
        log "INFO" "No existing installation to backup"
    fi
}

# Setup system user and directories
setup_system() {
    log "INFO" "Setting up system user and directories..."

    # Create system user if it doesn't exist
    if ! id "${DEPLOY_USER}" &>/dev/null; then
        useradd --system --shell /bin/bash --home /opt/blncs \
                --comment "BLNCS Service User" "${DEPLOY_USER}"
        log "INFO" "Created system user: ${DEPLOY_USER}"
    fi

    # Create directories
    local directories=(
        "/opt/blncs"
        "/etc/blncs"
        "/var/lib/blncs"
        "/var/log/blncs"
        "/var/run/blncs"
        "${BACKUP_DIR}"
    )

    for dir in "${directories[@]}"; do
        mkdir -p "${dir}"
        chown "${DEPLOY_USER}:${DEPLOY_USER}" "${dir}"
        chmod 750 "${dir}"
    done

    # Set special permissions for sensitive directories
    chmod 700 /var/lib/blncs  # Database and keys
    chmod 755 /var/log/blncs  # Logs need to be readable for monitoring

    log "SUCCESS" "System setup completed"
}

# Install dependencies
install_dependencies() {
    log "INFO" "Installing system dependencies..."

    # Update package list
    apt-get update -qq

    # Install required packages
    local packages=(
        "python3"
        "python3-pip"
        "python3-venv"
        "python3-dev"
        "build-essential"
        "libssl-dev"
        "libffi-dev"
        "postgresql-client"
        "sqlite3"
        "nginx"
        "supervisor"
        "logrotate"
        "fail2ban"
        "ufw"
        "htop"
        "curl"
        "wget"
        "unzip"
        "git"
    )

    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  ${package} "; then
            log "INFO" "Installing ${package}..."
            apt-get install -y "${package}"
        fi
    done

    log "SUCCESS" "System dependencies installed"
}

# Deploy application
deploy_application() {
    log "INFO" "Deploying BLNCS application..."

    local app_dir="/opt/blncs"
    local temp_dir="/tmp/blncs_deploy_${VERSION}"

    # Stop service if running
    if [[ "${EXISTING_SERVICE}" == "true" ]]; then
        log "INFO" "Stopping existing service..."
        systemctl stop "${SERVICE_NAME}" || true
    fi

    # Create temporary deployment directory
    rm -rf "${temp_dir}"
    mkdir -p "${temp_dir}"

    # Copy application files
    cp -r "${SCRIPT_DIR}"/* "${temp_dir}/"

    # Create virtual environment
    log "INFO" "Creating Python virtual environment..."
    python3 -m venv "${temp_dir}/venv"
    source "${temp_dir}/venv/bin/activate"

    # Upgrade pip
    pip install --upgrade pip setuptools wheel

    # Install Python dependencies
    if [[ -f "${temp_dir}/requirements.txt" ]]; then
        log "INFO" "Installing Python dependencies..."
        pip install -r "${temp_dir}/requirements.txt"
    fi

    # Install additional production dependencies
    pip install gunicorn psycopg2-binary redis celery

    # Move to final location
    if [[ -d "${app_dir}" ]]; then
        rm -rf "${app_dir}.old"
        mv "${app_dir}" "${app_dir}.old"
    fi

    mv "${temp_dir}" "${app_dir}"
    chown -R "${DEPLOY_USER}:${DEPLOY_USER}" "${app_dir}"

    log "SUCCESS" "Application deployed to ${app_dir}"
}

# Configure application
configure_application() {
    log "INFO" "Configuring BLNCS application..."

    local config_dir="/etc/blncs"
    local app_dir="/opt/blncs"

    # Copy configuration files
    if [[ -f "${app_dir}/config/${ENVIRONMENT}.json" ]]; then
        cp "${app_dir}/config/${ENVIRONMENT}.json" "${config_dir}/blncs.json"
    else
        log "WARN" "No environment-specific config found, using default"
        cp "${app_dir}/config/production.json" "${config_dir}/blncs.json"
    fi

    # Generate encryption key if it doesn't exist
    local key_file="${config_dir}/encryption.key"
    if [[ ! -f "${key_file}" ]]; then
        log "INFO" "Generating encryption key..."
        python3 -c "
from cryptography.fernet import Fernet
with open('${key_file}', 'wb') as f:
    f.write(Fernet.generate_key())
"
        chmod 600 "${key_file}"
        chown "${DEPLOY_USER}:${DEPLOY_USER}" "${key_file}"
    fi

    # Set permissions
    chown -R "${DEPLOY_USER}:${DEPLOY_USER}" "${config_dir}"
    chmod -R 640 "${config_dir}"
    chmod 750 "${config_dir}"

    log "SUCCESS" "Application configured"
}

# Setup systemd service
setup_systemd_service() {
    log "INFO" "Setting up systemd service..."

    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=BLNCS - Bitcoin Lightning Network Connection System
After=network.target
Wants=network-online.target

[Service]
Type=forking
User=${DEPLOY_USER}
Group=${DEPLOY_USER}
WorkingDirectory=/opt/blncs
Environment=BLNCS_ENV=${ENVIRONMENT}
Environment=PYTHONPATH=/opt/blncs
ExecStart=/opt/blncs/venv/bin/python3 /opt/blncs/blncs_fast.py start
ExecReload=/bin/kill -HUP \$MAINPID
ExecStop=/bin/kill -TERM \$MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${SERVICE_NAME}

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/blncs /var/log/blncs /var/run/blncs

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}"

    log "SUCCESS" "Systemd service configured"
}

# Setup nginx reverse proxy
setup_nginx() {
    log "INFO" "Setting up nginx reverse proxy..."

    cat > "/etc/nginx/sites-available/${SERVICE_NAME}" << 'EOF'
upstream blncs_backend {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 80;
    server_name _;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Rate limiting
    limit_req zone=api burst=20 nodelay;

    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml text/javascript;

    location / {
        proxy_pass http://blncs_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;

        # Timeouts
        proxy_connect_timeout 5s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    location /health {
        proxy_pass http://blncs_backend/health;
        access_log off;
    }

    location /metrics {
        proxy_pass http://blncs_backend/metrics;
        allow 127.0.0.1;
        deny all;
    }
}

# Rate limiting zone
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
EOF

    # Enable site
    ln -sf "/etc/nginx/sites-available/${SERVICE_NAME}" "/etc/nginx/sites-enabled/"
    rm -f /etc/nginx/sites-enabled/default

    # Test nginx configuration
    nginx -t

    # Restart nginx
    systemctl restart nginx
    systemctl enable nginx

    log "SUCCESS" "Nginx configured and started"
}

# Setup monitoring and logging
setup_monitoring() {
    log "INFO" "Setting up monitoring and logging..."

    # Setup logrotate
    cat > "/etc/logrotate.d/${SERVICE_NAME}" << EOF
/var/log/blncs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 ${DEPLOY_USER} ${DEPLOY_USER}
    postrotate
        systemctl reload ${SERVICE_NAME} || true
    endscript
}
EOF

    # Setup supervisor for process monitoring
    cat > "/etc/supervisor/conf.d/${SERVICE_NAME}.conf" << EOF
[program:${SERVICE_NAME}]
command=/opt/blncs/venv/bin/python3 /opt/blncs/blncs_fast.py start
directory=/opt/blncs
user=${DEPLOY_USER}
autostart=false
autorestart=false
redirect_stderr=true
stdout_logfile=/var/log/blncs/supervisor.log
EOF

    supervisorctl reread
    supervisorctl update

    log "SUCCESS" "Monitoring and logging configured"
}

# Setup security
setup_security() {
    log "INFO" "Setting up security measures..."

    # Configure UFW firewall
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 9735/tcp  # Lightning Network
    ufw --force enable

    # Configure fail2ban
    cat > "/etc/fail2ban/jail.d/${SERVICE_NAME}.conf" << EOF
[blncs]
enabled = true
port = 80,443
filter = nginx-limit-req
logpath = /var/log/nginx/error.log
maxretry = 5
bantime = 600
findtime = 600

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
EOF

    systemctl restart fail2ban
    systemctl enable fail2ban

    log "SUCCESS" "Security measures configured"
}

# Run health checks
run_health_checks() {
    log "INFO" "Running post-deployment health checks..."

    # Start the service
    systemctl start "${SERVICE_NAME}"

    # Wait for service to start
    sleep 10

    # Check service status
    if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
        log "ERROR" "Service failed to start"
        journalctl -u "${SERVICE_NAME}" -n 50
        return 1
    fi

    # Check if application responds
    local max_attempts=30
    local attempt=0

    while [[ ${attempt} -lt ${max_attempts} ]]; do
        if curl -s -f http://localhost:8080/health > /dev/null; then
            log "SUCCESS" "Application is responding to health checks"
            break
        fi

        ((attempt++))
        if [[ ${attempt} -eq ${max_attempts} ]]; then
            log "ERROR" "Application not responding after ${max_attempts} attempts"
            return 1
        fi

        log "INFO" "Waiting for application to start... (attempt ${attempt}/${max_attempts})"
        sleep 2
    done

    # Run comprehensive health check
    log "INFO" "Running comprehensive health check..."
    /opt/blncs/venv/bin/python3 /opt/blncs/blncs_fast.py check --detailed

    log "SUCCESS" "All health checks passed"
}

# Rollback deployment
rollback_deployment() {
    log "WARN" "Starting deployment rollback..."

    if [[ -f "${BACKUP_DIR}/latest_backup" ]]; then
        local backup_path=$(cat "${BACKUP_DIR}/latest_backup")

        if [[ -d "${backup_path}" ]]; then
            # Stop current service
            systemctl stop "${SERVICE_NAME}" || true

            # Restore application
            if [[ -d "${backup_path}/app" ]]; then
                rm -rf /opt/blncs
                cp -r "${backup_path}/app" /opt/blncs
                chown -R "${DEPLOY_USER}:${DEPLOY_USER}" /opt/blncs
            fi

            # Restore configuration
            if [[ -d "${backup_path}/config" ]]; then
                rm -rf /etc/blncs
                cp -r "${backup_path}/config" /etc/blncs
                chown -R "${DEPLOY_USER}:${DEPLOY_USER}" /etc/blncs
            fi

            # Restore database
            if [[ -f "${backup_path}/database.db" ]]; then
                cp "${backup_path}/database.db" /var/lib/blncs/blncs.db
                chown "${DEPLOY_USER}:${DEPLOY_USER}" /var/lib/blncs/blncs.db
            fi

            # Start service
            systemctl start "${SERVICE_NAME}"

            log "SUCCESS" "Rollback completed"
        else
            log "ERROR" "Backup directory not found: ${backup_path}"
        fi
    else
        log "WARN" "No backup available for rollback"
    fi
}

# Main deployment function
main() {
    log "INFO" "Starting BLNCS production deployment (version: ${VERSION})"

    # Ensure log directory exists
    mkdir -p "$(dirname "${DEPLOYMENT_LOG}")"

    # Run deployment steps
    pre_deployment_checks
    backup_current_installation
    setup_system
    install_dependencies
    deploy_application
    configure_application
    setup_systemd_service
    setup_nginx
    setup_monitoring
    setup_security
    run_health_checks

    log "SUCCESS" "BLNCS deployment completed successfully!"
    log "INFO" "Service status: $(systemctl is-active ${SERVICE_NAME})"
    log "INFO" "Version: ${VERSION}"
    log "INFO" "Access URL: http://$(hostname -I | awk '{print $1}')"

    # Display final status
    echo
    echo "========================================"
    echo "BLNCS Production Deployment Complete"
    echo "========================================"
    echo "Version: ${VERSION}"
    echo "Status: $(systemctl is-active ${SERVICE_NAME})"
    echo "Health: $(curl -s http://localhost:8080/health | grep -o '"healthy":[^,]*' || echo 'Not responding')"
    echo "Logs: journalctl -u ${SERVICE_NAME} -f"
    echo "Config: /etc/blncs/blncs.json"
    echo "========================================"
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi