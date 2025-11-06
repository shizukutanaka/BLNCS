#!/bin/bash

# Production Deployment Script for BLNCS
# National-grade deployment with comprehensive validation

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
DEPLOY_ENV="${DEPLOY_ENV:-production}"
BACKUP_DIR="./backups/$(date +%Y%m%d_%H%M%S)"
LOG_FILE="./logs/deployment_$(date +%Y%m%d_%H%M%S).log"
HEALTH_CHECK_TIMEOUT=300
MIN_DISK_SPACE_GB=10

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE" >&2
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

# Pre-deployment validation
validate_environment() {
    log "Validating deployment environment..."

    # Check if running as root
    if [[ $EUID -eq 0 ]]; then
        error "This script should not be run as root"
        exit 1
    fi

    # Check disk space
    AVAILABLE_SPACE=$(df -BG . | awk 'NR==2 {print $4}' | sed 's/G//')
    if [[ $AVAILABLE_SPACE -lt $MIN_DISK_SPACE_GB ]]; then
        error "Insufficient disk space. Available: ${AVAILABLE_SPACE}GB, Required: ${MIN_DISK_SPACE_GB}GB"
        exit 1
    fi

    # Check Docker is running
    if ! docker info > /dev/null 2>&1; then
        error "Docker is not running or accessible"
        exit 1
    fi

    # Check Docker Compose version
    if ! docker-compose --version > /dev/null 2>&1; then
        error "Docker Compose is not installed"
        exit 1
    fi

    # Validate configuration files
    if [[ ! -f "docker-compose.production.yml" ]]; then
        error "Production Docker Compose file not found"
        exit 1
    fi

    if [[ ! -f "config/production.json" ]]; then
        error "Production configuration file not found"
        exit 1
    fi

    # Check for required secrets
    if [[ ! -f "secrets/postgres_password.txt" ]]; then
        error "PostgreSQL password file not found"
        exit 1
    fi

    if [[ ! -f "secrets/grafana_password.txt" ]]; then
        error "Grafana password file not found"
        exit 1
    fi

    # Validate SSL certificates
    if [[ ! -f "nginx/ssl/cert.pem" ]] || [[ ! -f "nginx/ssl/key.pem" ]]; then
        warning "SSL certificates not found, using self-signed certificates"
        generate_ssl_certificates
    fi

    log "Environment validation completed successfully"
}

# Generate self-signed SSL certificates if needed
generate_ssl_certificates() {
    log "Generating self-signed SSL certificates..."

    mkdir -p nginx/ssl

    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout nginx/ssl/key.pem \
        -out nginx/ssl/cert.pem \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=blncs.local" \
        > /dev/null 2>&1

    log "SSL certificates generated"
}

# Create backup
create_backup() {
    log "Creating backup..."

    mkdir -p "$BACKUP_DIR"

    # Backup configuration
    cp -r config/ "$BACKUP_DIR/" 2>/dev/null || true

    # Backup data if containers are running
    if docker-compose -f docker-compose.production.yml ps | grep -q "Up"; then
        # Backup PostgreSQL
        docker-compose -f docker-compose.production.yml exec -T postgres \
            pg_dump -U blncs_user blncs_production > "$BACKUP_DIR/postgres_backup.sql" 2>/dev/null || true

        # Backup Redis
        docker-compose -f docker-compose.production.yml exec -T redis \
            redis-cli --rdb /tmp/dump.rdb > /dev/null 2>&1 || true
        docker-compose -f docker-compose.production.yml cp redis:/tmp/dump.rdb "$BACKUP_DIR/redis_backup.rdb" 2>/dev/null || true
    fi

    log "Backup created at $BACKUP_DIR"
}

# Build and deploy
deploy_services() {
    log "Building and deploying services..."

    # Pull latest images
    docker-compose -f docker-compose.production.yml pull

    # Build application image
    docker-compose -f docker-compose.production.yml build --no-cache

    # Start services
    docker-compose -f docker-compose.production.yml up -d

    log "Services deployed successfully"
}

# Health checks
perform_health_checks() {
    log "Performing health checks..."

    local start_time=$(date +%s)
    local timeout=$((start_time + HEALTH_CHECK_TIMEOUT))

    # Wait for services to be healthy
    while [[ $(date +%s) -lt $timeout ]]; do
        # Check main application
        if curl -f -s "http://localhost:8000/health" > /dev/null 2>&1; then
            log "Application health check passed"
            break
        fi

        sleep 10
        info "Waiting for application to be healthy..."
    done

    if [[ $(date +%s) -ge $timeout ]]; then
        error "Health check timeout - application did not become healthy"
        return 1
    fi

    # Additional service checks
    local services=(
        "postgres:5432"
        "redis:6379"
        "prometheus:9090"
        "grafana:3000"
    )

    for service in "${services[@]}"; do
        local host=$(echo "$service" | cut -d: -f1)
        local port=$(echo "$service" | cut -d: -f2)

        if docker-compose -f docker-compose.production.yml exec -T "$host" \
            sh -c "nc -z localhost $port" > /dev/null 2>&1; then
            log "$host service is healthy"
        else
            warning "$host service health check failed"
        fi
    done

    log "Health checks completed"
}

# Security validation
validate_security() {
    log "Performing security validation..."

    # Check container security
    local insecure_containers=$(docker ps --format "table {{.Names}}\t{{.Status}}" | grep -v "Up" | wc -l)
    if [[ $insecure_containers -gt 0 ]]; then
        warning "$insecure_containers containers are not running properly"
    fi

    # Check for exposed ports
    local exposed_ports=$(docker-compose -f docker-compose.production.yml config | grep -E "^\s*-\s*\"[0-9]" | wc -l)
    if [[ $exposed_ports -gt 6 ]]; then
        warning "Many ports are exposed ($exposed_ports), review security configuration"
    fi

    # Check secrets
    if docker-compose -f docker-compose.production.yml config --quiet 2>/dev/null; then
        log "Docker Compose configuration is valid"
    else
        error "Docker Compose configuration validation failed"
        return 1
    fi

    log "Security validation completed"
}

# Performance validation
validate_performance() {
    log "Validating performance..."

    # Check resource usage
    local cpu_usage=$(docker stats --no-stream --format "table {{.CPUPerc}}" | grep -v "CPU%" | sed 's/%//g' | awk '{sum+=$1} END {print sum/NR}')
    local memory_usage=$(docker stats --no-stream --format "table {{.MemPerc}}" | grep -v "MEM%" | sed 's/%//g' | awk '{sum+=$1} END {print sum/NR}')

    info "Average CPU usage: ${cpu_usage}%"
    info "Average memory usage: ${memory_usage}%"

    if (( $(echo "$cpu_usage > 80" | bc -l) )); then
        warning "High CPU usage detected: ${cpu_usage}%"
    fi

    if (( $(echo "$memory_usage > 80" | bc -l) )); then
        warning "High memory usage detected: ${memory_usage}%"
    fi

    # Test response time
    local response_time=$(curl -o /dev/null -s -w "%{time_total}" "http://localhost:8000/health")
    info "Health endpoint response time: ${response_time}s"

    if (( $(echo "$response_time > 2" | bc -l) )); then
        warning "Slow response time: ${response_time}s"
    fi

    log "Performance validation completed"
}

# Cleanup old resources
cleanup() {
    log "Cleaning up old resources..."

    # Remove old images
    docker image prune -f > /dev/null 2>&1 || true

    # Remove old volumes (with caution)
    docker volume prune -f > /dev/null 2>&1 || true

    # Clean old logs (keep last 30 days)
    find ./logs -name "*.log" -mtime +30 -delete 2>/dev/null || true

    # Clean old backups (keep last 7 days)
    find ./backups -type d -mtime +7 -exec rm -rf {} + 2>/dev/null || true

    log "Cleanup completed"
}

# Setup monitoring
setup_monitoring() {
    log "Setting up monitoring and alerting..."

    # Wait for Prometheus to be ready
    local prometheus_ready=false
    for i in {1..30}; do
        if curl -f -s "http://localhost:9090/-/ready" > /dev/null 2>&1; then
            prometheus_ready=true
            break
        fi
        sleep 2
    done

    if $prometheus_ready; then
        log "Prometheus is ready"
    else
        warning "Prometheus is not ready after 60 seconds"
    fi

    # Wait for Grafana to be ready
    local grafana_ready=false
    for i in {1..30}; do
        if curl -f -s "http://localhost:3000/api/health" > /dev/null 2>&1; then
            grafana_ready=true
            break
        fi
        sleep 2
    done

    if $grafana_ready; then
        log "Grafana is ready"
    else
        warning "Grafana is not ready after 60 seconds"
    fi

    log "Monitoring setup completed"
}

# Rollback function
rollback() {
    error "Deployment failed, initiating rollback..."

    # Stop current deployment
    docker-compose -f docker-compose.production.yml down

    # Restore backup if available
    if [[ -d "$BACKUP_DIR" ]]; then
        log "Restoring from backup..."

        # Restore configuration
        cp -r "$BACKUP_DIR/config/" ./ 2>/dev/null || true

        # Start services
        docker-compose -f docker-compose.production.yml up -d

        # Restore PostgreSQL backup if available
        if [[ -f "$BACKUP_DIR/postgres_backup.sql" ]]; then
            sleep 30  # Wait for PostgreSQL to start
            docker-compose -f docker-compose.production.yml exec -T postgres \
                psql -U blncs_user -d blncs_production < "$BACKUP_DIR/postgres_backup.sql" || true
        fi

        log "Rollback completed"
    else
        error "No backup available for rollback"
    fi
}

# Main deployment function
main() {
    log "Starting BLNCS production deployment..."

    # Create log directory
    mkdir -p logs

    # Set trap for cleanup on exit
    trap 'if [[ $? -ne 0 ]]; then rollback; fi' EXIT

    # Run deployment steps
    validate_environment
    create_backup
    deploy_services
    perform_health_checks
    validate_security
    validate_performance
    setup_monitoring
    cleanup

    # Remove trap on success
    trap - EXIT

    log "Deployment completed successfully!"

    # Display service URLs
    echo
    info "Service URLs:"
    info "Application: http://localhost:8000"
    info "Web Interface: http://localhost:8080"
    info "Prometheus: http://localhost:9090"
    info "Grafana: http://localhost:3000"
    info "Jaeger: http://localhost:16686"
    echo
    info "Log file: $LOG_FILE"
    info "Backup location: $BACKUP_DIR"
}

# Run main function
main "$@"