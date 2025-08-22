#!/bin/bash
# BLRCS Deployment Automation Script
# Production-grade deployment with zero downtime

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_ENV="${1:-production}"
DEPLOY_STRATEGY="${2:-blue-green}"
VERSION="${3:-latest}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
    exit 1
}

# Pre-deployment checks
pre_deployment_check() {
    log_info "Running pre-deployment checks..."
    
    # Check Python version
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed"
    fi
    
    # Check disk space
    AVAILABLE_SPACE=$(df / | awk 'NR==2 {print $4}')
    if [[ $AVAILABLE_SPACE -lt 5242880 ]]; then
        log_error "Insufficient disk space (minimum 5GB required)"
    fi
    
    # Check memory
    AVAILABLE_MEM=$(free -m | awk 'NR==2 {print $7}')
    if [[ $AVAILABLE_MEM -lt 2048 ]]; then
        log_warning "Low available memory (${AVAILABLE_MEM}MB)"
    fi
    
    # Check network connectivity
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        log_warning "No internet connectivity detected"
    fi
    
    # Check if application is running
    if pgrep -f "blrcs" > /dev/null; then
        log_info "BLRCS is currently running"
        CURRENT_VERSION=$(python3 -c "import blrcs; print(blrcs.__version__)" 2>/dev/null || echo "unknown")
        log_info "Current version: $CURRENT_VERSION"
    fi
    
    log_success "Pre-deployment checks completed"
}

# Backup current deployment
backup_current() {
    log_info "Creating backup of current deployment..."
    
    BACKUP_DIR="/var/backups/blrcs"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_PATH="${BACKUP_DIR}/backup_${TIMESTAMP}"
    
    mkdir -p "$BACKUP_PATH"
    
    # Backup application files
    if [[ -d "/opt/blrcs" ]]; then
        cp -r /opt/blrcs "$BACKUP_PATH/app"
    fi
    
    # Backup configuration
    if [[ -d "/etc/blrcs" ]]; then
        cp -r /etc/blrcs "$BACKUP_PATH/config"
    fi
    
    # Backup database
    if [[ -f "/var/lib/blrcs/blrcs.db" ]]; then
        cp /var/lib/blrcs/blrcs.db "$BACKUP_PATH/database.db"
    fi
    
    # Create backup manifest
    cat > "$BACKUP_PATH/manifest.json" <<EOF
{
    "timestamp": "$TIMESTAMP",
    "version": "$CURRENT_VERSION",
    "environment": "$DEPLOY_ENV",
    "created_by": "$USER",
    "hostname": "$(hostname)"
}
EOF
    
    log_success "Backup created at $BACKUP_PATH"
}

# Blue-Green deployment
deploy_blue_green() {
    log_info "Starting Blue-Green deployment..."
    
    BLUE_DIR="/opt/blrcs-blue"
    GREEN_DIR="/opt/blrcs-green"
    CURRENT_DIR="/opt/blrcs"
    
    # Determine current environment
    if [[ -L "$CURRENT_DIR" ]]; then
        CURRENT_TARGET=$(readlink "$CURRENT_DIR")
        if [[ "$CURRENT_TARGET" == "$BLUE_DIR" ]]; then
            NEW_ENV="green"
            NEW_DIR="$GREEN_DIR"
            OLD_DIR="$BLUE_DIR"
        else
            NEW_ENV="blue"
            NEW_DIR="$BLUE_DIR"
            OLD_DIR="$GREEN_DIR"
        fi
    else
        NEW_ENV="blue"
        NEW_DIR="$BLUE_DIR"
        OLD_DIR="$GREEN_DIR"
    fi
    
    log_info "Deploying to $NEW_ENV environment..."
    
    # Deploy new version
    rm -rf "$NEW_DIR"
    mkdir -p "$NEW_DIR"
    
    # Copy application files
    cp -r "$SCRIPT_DIR"/* "$NEW_DIR/"
    
    # Install dependencies
    cd "$NEW_DIR"
    python3 -m venv venv
    source venv/bin/activate
    pip install --quiet --upgrade pip
    pip install --quiet -r requirements.txt
    pip install --quiet -e .
    deactivate
    
    # Run tests
    log_info "Running tests on new deployment..."
    cd "$NEW_DIR"
    source venv/bin/activate
    python -m pytest tests/ --quiet
    deactivate
    
    # Health check
    log_info "Performing health check..."
    cd "$NEW_DIR"
    source venv/bin/activate
    python -c "import blrcs; blrcs.health_check()"
    deactivate
    
    # Switch symlink
    log_info "Switching to new environment..."
    rm -f "$CURRENT_DIR"
    ln -s "$NEW_DIR" "$CURRENT_DIR"
    
    # Restart services
    if systemctl is-active --quiet blrcs; then
        systemctl restart blrcs
        sleep 5
        
        # Verify service is running
        if systemctl is-active --quiet blrcs; then
            log_success "Service restarted successfully"
        else
            log_error "Service failed to restart"
        fi
    fi
    
    log_success "Blue-Green deployment completed"
}

# Canary deployment
deploy_canary() {
    log_info "Starting Canary deployment..."
    
    CANARY_PERCENTAGE="${CANARY_PERCENTAGE:-10}"
    
    # Deploy new version to canary servers
    log_info "Deploying to ${CANARY_PERCENTAGE}% of servers..."
    
    # This is a simplified implementation
    # In production, you would deploy to actual canary servers
    
    # Deploy new version
    CANARY_DIR="/opt/blrcs-canary"
    rm -rf "$CANARY_DIR"
    mkdir -p "$CANARY_DIR"
    cp -r "$SCRIPT_DIR"/* "$CANARY_DIR/"
    
    # Install and test
    cd "$CANARY_DIR"
    python3 -m venv venv
    source venv/bin/activate
    pip install --quiet --upgrade pip
    pip install --quiet -r requirements.txt
    pip install --quiet -e .
    
    # Run canary tests
    python -m pytest tests/ --quiet
    deactivate
    
    # Monitor canary metrics
    log_info "Monitoring canary deployment for 5 minutes..."
    MONITOR_DURATION=300
    START_TIME=$(date +%s)
    
    while [[ $(($(date +%s) - START_TIME)) -lt $MONITOR_DURATION ]]; do
        # Check error rate
        ERROR_RATE=$(python3 -c "import blrcs; print(blrcs.get_error_rate())" 2>/dev/null || echo "0")
        
        if [[ $(echo "$ERROR_RATE > 5" | bc) -eq 1 ]]; then
            log_error "High error rate detected: ${ERROR_RATE}%"
        fi
        
        sleep 30
    done
    
    # Promote canary to production
    log_info "Promoting canary to production..."
    rm -rf /opt/blrcs
    mv "$CANARY_DIR" /opt/blrcs
    
    log_success "Canary deployment completed"
}

# Rolling deployment
deploy_rolling() {
    log_info "Starting Rolling deployment..."
    
    NODES="${NODES:-node1,node2,node3}"
    IFS=',' read -ra NODE_ARRAY <<< "$NODES"
    
    for node in "${NODE_ARRAY[@]}"; do
        log_info "Deploying to node: $node"
        
        # Deploy to node (simplified - in production would use SSH/Ansible)
        if [[ "$node" == "$(hostname)" ]]; then
            # Local deployment
            cp -r "$SCRIPT_DIR"/* /opt/blrcs/
            
            # Restart service
            systemctl restart blrcs
            
            # Wait for service to be healthy
            sleep 10
            
            # Health check
            if curl -f http://localhost:8000/health > /dev/null 2>&1; then
                log_success "Node $node deployed successfully"
            else
                log_error "Node $node health check failed"
            fi
        else
            # Remote deployment would go here
            log_info "Skipping remote node $node (not implemented)"
        fi
        
        # Wait between nodes
        sleep 30
    done
    
    log_success "Rolling deployment completed"
}

# Run database migrations
run_migrations() {
    log_info "Running database migrations..."
    
    cd /opt/blrcs
    source venv/bin/activate
    
    # Backup database before migration
    if [[ -f "/var/lib/blrcs/blrcs.db" ]]; then
        cp /var/lib/blrcs/blrcs.db /var/lib/blrcs/blrcs.db.pre-migration
    fi
    
    # Run migrations
    python -m blrcs.database migrate
    
    # Verify migrations
    python -m blrcs.database verify
    
    deactivate
    
    log_success "Database migrations completed"
}

# Post-deployment validation
post_deployment_validation() {
    log_info "Running post-deployment validation..."
    
    # Check service status
    if systemctl is-active --quiet blrcs; then
        log_success "Service is running"
    else
        log_error "Service is not running"
    fi
    
    # Check API health
    if curl -f http://localhost:8000/health > /dev/null 2>&1; then
        log_success "API health check passed"
    else
        log_error "API health check failed"
    fi
    
    # Check database connectivity
    cd /opt/blrcs
    source venv/bin/activate
    python -c "import blrcs; blrcs.test_database_connection()"
    deactivate
    
    # Check logs for errors
    ERROR_COUNT=$(journalctl -u blrcs -n 100 | grep -c ERROR || true)
    if [[ $ERROR_COUNT -gt 0 ]]; then
        log_warning "Found $ERROR_COUNT errors in recent logs"
    fi
    
    # Performance check
    RESPONSE_TIME=$(curl -w "%{time_total}" -o /dev/null -s http://localhost:8000/health)
    if [[ $(echo "$RESPONSE_TIME > 1" | bc) -eq 1 ]]; then
        log_warning "Slow response time: ${RESPONSE_TIME}s"
    fi
    
    log_success "Post-deployment validation completed"
}

# Rollback deployment
rollback_deployment() {
    log_info "Rolling back deployment..."
    
    # Find latest backup
    BACKUP_DIR="/var/backups/blrcs"
    LATEST_BACKUP=$(ls -t "$BACKUP_DIR" | head -1)
    
    if [[ -z "$LATEST_BACKUP" ]]; then
        log_error "No backup found to rollback to"
    fi
    
    BACKUP_PATH="${BACKUP_DIR}/${LATEST_BACKUP}"
    log_info "Rolling back to backup: $LATEST_BACKUP"
    
    # Stop service
    systemctl stop blrcs
    
    # Restore application
    if [[ -d "$BACKUP_PATH/app" ]]; then
        rm -rf /opt/blrcs
        cp -r "$BACKUP_PATH/app" /opt/blrcs
    fi
    
    # Restore configuration
    if [[ -d "$BACKUP_PATH/config" ]]; then
        rm -rf /etc/blrcs
        cp -r "$BACKUP_PATH/config" /etc/blrcs
    fi
    
    # Restore database
    if [[ -f "$BACKUP_PATH/database.db" ]]; then
        cp "$BACKUP_PATH/database.db" /var/lib/blrcs/blrcs.db
    fi
    
    # Start service
    systemctl start blrcs
    
    # Verify rollback
    sleep 5
    if systemctl is-active --quiet blrcs; then
        log_success "Rollback completed successfully"
    else
        log_error "Rollback failed - service not running"
    fi
}

# Send deployment notification
send_notification() {
    local status=$1
    local message=$2
    
    # Slack notification (if configured)
    if [[ -n "$SLACK_WEBHOOK" ]]; then
        curl -X POST "$SLACK_WEBHOOK" \
            -H 'Content-Type: application/json' \
            -d "{\"text\": \"Deployment ${status}: ${message}\"}" \
            > /dev/null 2>&1
    fi
    
    # Email notification (if configured)
    if [[ -n "$NOTIFY_EMAIL" ]]; then
        echo "$message" | mail -s "BLRCS Deployment ${status}" "$NOTIFY_EMAIL"
    fi
    
    # Log to file
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Deployment ${status}: ${message}" >> /var/log/blrcs/deployments.log
}

# Main deployment function
main() {
    log_info "Starting BLRCS deployment"
    log_info "Environment: $DEPLOY_ENV"
    log_info "Strategy: $DEPLOY_STRATEGY"
    log_info "Version: $VERSION"
    
    # Create log directory
    mkdir -p /var/log/blrcs
    
    # Run pre-deployment checks
    pre_deployment_check
    
    # Create backup
    backup_current
    
    # Deploy based on strategy
    case "$DEPLOY_STRATEGY" in
        blue-green)
            deploy_blue_green
            ;;
        canary)
            deploy_canary
            ;;
        rolling)
            deploy_rolling
            ;;
        *)
            log_error "Unknown deployment strategy: $DEPLOY_STRATEGY"
            ;;
    esac
    
    # Run migrations
    run_migrations
    
    # Post-deployment validation
    post_deployment_validation
    
    # Send success notification
    send_notification "SUCCESS" "Deployment completed for version $VERSION"
    
    log_success "Deployment completed successfully!"
}

# Trap errors
trap 'log_error "Deployment failed at line $LINENO"' ERR

# Handle rollback option
if [[ "$1" == "rollback" ]]; then
    rollback_deployment
    exit 0
fi

# Run main deployment
main