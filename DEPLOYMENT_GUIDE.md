# BLNCS Deployment Guide

## 🚀 Production Deployment

This guide covers deploying BLNCS in production environments with all integrated systems.

## 📋 Prerequisites

### System Requirements
- **OS**: Linux (Ubuntu 20.04+ recommended), macOS, or Windows 10+
- **Python**: 3.8 or higher
- **Memory**: Minimum 2GB RAM, 4GB+ recommended
- **Storage**: 50GB+ available space for backups
- **Network**: Stable internet connection for Lightning Network operations

### Lightning Network Node
- **LND**: Version 0.15.0+ or **C-Lightning**: Version 0.10.0+
- **Bitcoin Core**: Fully synced node (optional but recommended)
- **Network**: Mainnet or Testnet configuration

## 🔧 Installation Options

### Option 1: Docker Deployment (Recommended)

#### 1. Create Docker Compose Configuration
```yaml
# docker-compose.yml
version: '3.8'

services:
  blncs:
    image: blncs:latest
    container_name: blncs
    restart: unless-stopped
    ports:
      - "8080:8080"  # Web dashboard
      - "9090:9090"  # API endpoint
    volumes:
      - ./data:/app/data
      - ./backups:/app/backups
      - ./config:/app/config
      - ./logs:/app/logs
      - ~/.lnd:/root/.lnd:ro  # LND directory (read-only)
    environment:
      - BLNCS_ENV=production
      - BLNCS_LOG_LEVEL=INFO
      - BLNCS_BACKUP_ENABLED=true
      - BLNCS_MONITORING_ENABLED=true
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:14
    container_name: blncs-db
    restart: unless-stopped
    environment:
      - POSTGRES_DB=blncs
      - POSTGRES_USER=blncs
      - POSTGRES_PASSWORD=secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    container_name: blncs-cache
    restart: unless-stopped
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

#### 2. Deploy with Docker Compose
```bash
# Clone repository
git clone https://github.com/your-org/blncs.git
cd blncs

# Build Docker image
docker build -t blncs:latest .

# Deploy services
docker-compose up -d

# Check deployment status
docker-compose ps
```

### Option 2: Native Installation

#### 1. Install Dependencies
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip python3-venv git

# CentOS/RHEL
sudo yum install python3 python3-pip git

# macOS (with Homebrew)
brew install python3 git

# Create virtual environment
python3 -m venv blncs-env
source blncs-env/bin/activate

# Install BLNCS
pip install -r requirements.txt
pip install -r requirements-backup.txt
pip install -r requirements-minimal.txt
```

#### 2. Run Installation Wizard
```bash
# Navigate to BLNCS directory
cd /path/to/BLNCS

# Run setup wizard
python -m blncs setup wizard

# Configure Lightning node connection
python -m blncs setup node \
  --host localhost \
  --port 10009 \
  --cert-path ~/.lnd/tls.cert \
  --macaroon-path ~/.lnd/data/chain/bitcoin/mainnet/admin.macaroon
```

### Option 3: Kubernetes Deployment

#### 1. Create Kubernetes Manifests
```yaml
# blncs-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: blncs
  namespace: lightning
spec:
  replicas: 2
  selector:
    matchLabels:
      app: blncs
  template:
    metadata:
      labels:
        app: blncs
    spec:
      containers:
      - name: blncs
        image: blncs:latest
        ports:
        - containerPort: 8080
        - containerPort: 9090
        env:
        - name: BLNCS_ENV
          value: "production"
        - name: BLNCS_CLUSTER_MODE
          value: "true"
        volumeMounts:
        - name: blncs-data
          mountPath: /app/data
        - name: blncs-config
          mountPath: /app/config
      volumes:
      - name: blncs-data
        persistentVolumeClaim:
          claimName: blncs-data-pvc
      - name: blncs-config
        configMap:
          name: blncs-config
```

#### 2. Deploy to Kubernetes
```bash
# Create namespace
kubectl create namespace lightning

# Deploy BLNCS
kubectl apply -f blncs-deployment.yaml
kubectl apply -f blncs-service.yaml
kubectl apply -f blncs-ingress.yaml

# Check deployment
kubectl get pods -n lightning
```

## ⚙️ Configuration

### 1. Primary Configuration File
Create `/app/config/blncs.yaml`:
```yaml
# BLNCS Production Configuration
system:
  environment: production
  data_dir: /app/data
  log_level: INFO
  debug: false

lightning:
  node_type: lnd
  host: localhost
  port: 10009
  tls_cert_path: /root/.lnd/tls.cert
  admin_macaroon_path: /root/.lnd/data/chain/bitcoin/mainnet/admin.macaroon
  network: mainnet

backup:
  enabled: true
  encryption: true
  compression: true
  retention_days: 90
  schedule:
    daily_backup:
      type: daily
      hour: 2
      minute: 30
      items: [config, wallet, channels]
    weekly_full:
      type: weekly
      day_of_week: 0  # Sunday
      hour: 1
      minute: 0
      backup_type: full

storage:
  local:
    path: /app/backups
    enabled: true
  s3:
    bucket: lightning-backups
    region: us-west-2
    enabled: false
    # Set credentials via environment variables
    # AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

monitoring:
  enabled: true
  metrics_port: 9090
  dashboard_port: 8080
  alerts:
    email:
      enabled: false
      smtp_host: smtp.gmail.com
      smtp_port: 587
    slack:
      enabled: false
      webhook_url: ""

i18n:
  default_language: en
  supported_languages: [en, ja, es]
  auto_detect: true

security:
  api_key_required: true
  cors_origins: ["http://localhost:3000"]
  rate_limiting:
    enabled: true
    requests_per_minute: 100
```

### 2. Environment Variables
Set these environment variables for production:
```bash
# Core settings
export BLNCS_ENV=production
export BLNCS_CONFIG_PATH=/app/config/blncs.yaml
export BLNCS_DATA_DIR=/app/data

# Security
export BLNCS_SECRET_KEY="your-secret-key-here"
export BLNCS_API_KEY="your-api-key-here"
export BLNCS_ENCRYPTION_KEY="your-32-byte-encryption-key"

# Database (if using external DB)
export BLNCS_DATABASE_URL="postgresql://user:pass@localhost:5432/blncs"

# Cloud storage credentials
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"

# Monitoring
export BLNCS_SENTRY_DSN="your-sentry-dsn"
```

## 🔒 Security Configuration

### 1. TLS/SSL Setup
```bash
# Generate SSL certificates
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Configure nginx reverse proxy
cat > /etc/nginx/sites-available/blncs << EOF
server {
    listen 443 ssl;
    server_name your-domain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
    
    location /api/ {
        proxy_pass http://localhost:9090;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF

# Enable site
ln -s /etc/nginx/sites-available/blncs /etc/nginx/sites-enabled/
systemctl reload nginx
```

### 2. Firewall Configuration
```bash
# Ubuntu/Debian (ufw)
sudo ufw allow 22     # SSH
sudo ufw allow 80     # HTTP
sudo ufw allow 443    # HTTPS
sudo ufw allow 9735   # Lightning P2P
sudo ufw allow 10009  # LND gRPC (internal only)
sudo ufw enable

# CentOS/RHEL (firewalld)
sudo firewall-cmd --permanent --add-port=22/tcp
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --permanent --add-port=9735/tcp
sudo firewall-cmd --reload
```

## 📊 Monitoring Setup

### 1. Prometheus Configuration
```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'blncs'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: /metrics
    scrape_interval: 30s

  - job_name: 'lnd'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: /metrics
```

### 2. Grafana Dashboards
```bash
# Import BLNCS dashboard
curl -X POST \
  http://admin:admin@localhost:3000/api/dashboards/db \
  -H 'Content-Type: application/json' \
  -d @grafana-dashboard.json
```

### 3. Alerting Rules
```yaml
# alerts.yml
groups:
  - name: blncs
    rules:
      - alert: BackupFailed
        expr: blncs_backup_failures_total > 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "BLNCS backup failed"
          
      - alert: NodeDisconnected
        expr: blncs_node_connected == 0
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Lightning node disconnected"
```

## 🔄 Backup Configuration

### 1. Multi-Destination Backup
```bash
# Configure multiple storage backends
blncs storage add \
  --name primary-local \
  --type local \
  --config '{"path": "/app/backups"}'

blncs storage add \
  --name aws-s3 \
  --type s3 \
  --config '{"bucket": "lightning-backups", "region": "us-west-2"}'

blncs storage add \
  --name offsite-sftp \
  --type sftp \
  --config '{"host": "backup.example.com", "username": "backup", "remote_path": "/backups"}'
```

### 2. Automated Scheduling
```bash
# Daily configuration backup
blncs backup schedule create \
  --name "Daily Config" \
  --type daily \
  --hour 2 \
  --minute 0 \
  --items config,logs \
  --backup-type incremental \
  --retention 30

# Weekly full backup
blncs backup schedule create \
  --name "Weekly Full" \
  --type weekly \
  --day-of-week 0 \
  --hour 1 \
  --minute 0 \
  --items config,wallet,channels,database \
  --backup-type full \
  --retention 90

# Start scheduler
blncs backup schedule start
```

## 🔧 Maintenance

### 1. Log Rotation
```bash
# Configure logrotate
cat > /etc/logrotate.d/blncs << EOF
/app/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 blncs blncs
    postrotate
        systemctl reload blncs
    endscript
}
EOF
```

### 2. Database Maintenance
```bash
# Create maintenance script
cat > /app/scripts/maintenance.sh << 'EOF'
#!/bin/bash

# Vacuum SQLite databases
sqlite3 /app/data/backup_history.db "VACUUM;"
sqlite3 /app/data/scheduler.db "VACUUM;"
sqlite3 /app/data/validation_history.db "VACUUM;"

# Clean old temporary files
find /tmp -name "blncs_*" -type f -mtime +7 -delete

# Verify backup integrity
blncs backup validate --all --level standard

# Generate health report
blncs monitor health --report /app/logs/health-$(date +%Y%m%d).json
EOF

chmod +x /app/scripts/maintenance.sh

# Schedule with cron
echo "0 3 * * 0 /app/scripts/maintenance.sh" | crontab -
```

### 3. Updates and Upgrades
```bash
# Create update script
cat > /app/scripts/update.sh << 'EOF'
#!/bin/bash

# Backup current configuration
blncs backup create now --name "Pre-update backup" --all-items

# Stop services
docker-compose down

# Pull latest image
docker pull blncs:latest

# Start services
docker-compose up -d

# Verify deployment
sleep 30
docker-compose ps

# Run health check
blncs monitor health --verbose
EOF
```

## 📈 Performance Tuning

### 1. System Optimization
```bash
# Increase file descriptor limits
echo "blncs soft nofile 65536" >> /etc/security/limits.conf
echo "blncs hard nofile 65536" >> /etc/security/limits.conf

# Optimize kernel parameters
cat >> /etc/sysctl.conf << EOF
# Network optimization
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# File system optimization
fs.file-max = 1000000
vm.swappiness = 10
EOF

sysctl -p
```

### 2. Application Tuning
```yaml
# Performance configuration in blncs.yaml
performance:
  worker_processes: 4
  max_connections: 1000
  backup_parallelism: 4
  validation_threads: 2
  cache_size: 1GB
  database_pool_size: 20
```

## 🚨 Troubleshooting

### Common Issues

#### 1. Connection Issues
```bash
# Test Lightning node connection
blncs node test-connection

# Check certificates
openssl x509 -in ~/.lnd/tls.cert -text -noout

# Verify macaroon
xxd ~/.lnd/data/chain/bitcoin/mainnet/admin.macaroon | head -5
```

#### 2. Backup Failures
```bash
# Check backup system status
blncs backup status

# Validate specific backup
blncs backup validate <backup-id> --level deep

# Test storage backends
blncs storage list
blncs storage test-connection --backend local
```

#### 3. Performance Issues
```bash
# Monitor resource usage
blncs monitor system --real-time

# Check backup performance
blncs backup history --limit 50 --performance

# Analyze slow queries
blncs monitor database --slow-queries
```

### Log Analysis
```bash
# View system logs
docker-compose logs -f blncs

# Search for specific issues
grep -i "error\|failed\|exception" /app/logs/blncs.log

# Monitor real-time logs
tail -f /app/logs/blncs.log | grep -i backup
```

## 📞 Support and Monitoring

### Health Check Endpoints
- **System Health**: `GET /api/v1/health`
- **Backup Status**: `GET /api/v1/backup/status`
- **Node Status**: `GET /api/v1/node/status`
- **Metrics**: `GET /metrics`

### Operational Dashboards
- **Web Dashboard**: `http://localhost:8080`
- **Grafana**: `http://localhost:3000`
- **Prometheus**: `http://localhost:9090`

This deployment guide provides a comprehensive foundation for running BLNCS in production with full backup, monitoring, and management capabilities.