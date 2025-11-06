# BLNCS Production Deployment Guide

## Overview

BLNCS (Bitcoin Lightning Network Connection System) is a comprehensive production-ready system for managing Lightning Network operations. This guide covers deployment, configuration, monitoring, and maintenance in production environments.

## Quick Start

### Prerequisites

- Ubuntu 20.04+ or CentOS 8+ (recommended)
- At least 2GB RAM, 20GB disk space
- Root or sudo access
- Internet connectivity
- Lightning Network node (LND recommended)

### Deployment Script

```bash
git clone https://github.com/your-org/blncs.git
cd blncs
sudo ./deploy_production.sh
```

### Quick Health Check

```bash
# Check service status
sudo systemctl status blncs

# Run health check
sudo -u blncs /opt/blncs/venv/bin/python3 /opt/blncs/blncs_fast.py check

# Access web dashboard
curl http://localhost/health
```

## Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Load Balancer │────│     Nginx        │────│   BLNCS App     │
│   (Optional)    │    │  Reverse Proxy   │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                        │
                                │                        │
                       ┌──────────────────┐    ┌─────────────────┐
                       │   Monitoring     │    │  Lightning Node │
                       │   Dashboard      │    │     (LND)       │
                       └──────────────────┘    └─────────────────┘
                                │                        │
                                │                        │
                       ┌──────────────────┐    ┌─────────────────┐
                       │    Database      │    │   File Storage  │
                       │   (SQLite)       │    │   (Backups)     │
                       └──────────────────┘    └─────────────────┘
```

## Configuration

### Environment-Specific Configurations

BLNCS supports multiple environment configurations:

- `config/development.json` - Development settings
- `config/production.json` - Production settings
- `config/staging.json` - Staging settings (optional)

### Key Configuration Sections

- `config/production.json` は API、セキュリティ、パフォーマンス、メンテナンス設定を JSON 形式で管理します。
- `config/development.json` は開発/検証用のデフォルトを提供します。
- いずれも `UnifiedConfigManager` が読み込み、`BLNCS_` プレフィックスの環境変数でドット区切りキー (`BLNCS_API_PORT` など) を上書きできます。

#### Lightning Network Configuration (抜粋)

```json
{
  "lightning": {
    "network": "mainnet",
    "host": "localhost",
    "port": 10009,
    "tls_cert_path": "/var/lib/lnd/tls.cert",
    "macaroon_path": "/var/lib/lnd/data/chain/bitcoin/mainnet/admin.macaroon",
    "connection_timeout": 30,
    "max_retries": 3,
    "retry_delay": 5
  }
}
```

#### API Configuration (抜粋)

```json
{
  "api": {
    "enabled": true,
    "host": "0.0.0.0",
    "port": 8080,
    "cors_enabled": true,
    "cors_allowed_origins": [
      "https://payments.example.com",
      "https://admin.example.com"
    ],
    "cors_supports_credentials": true,
    "rate_limiting": {
      "enabled": true,
      "requests_per_minute": 100,
      "burst_size": 10
    },
    "authentication": {
      "enabled": true,
      "jwt_secret": "${BLNCS_JWT_SECRET}"
    }
  }
}
```

#### Security Configuration (抜粋)

```json
{
  "security": {
    "enforce_https": true,
    "trusted_hosts": [
      "payments.example.com",
      "admin.example.com"
    ],
    "max_request_size": "10MB",
    "request_timeout": 30,
    "encryption": {
      "algorithm": "AES-256-GCM",
      "key_rotation_interval": 86400,
      "key_rotation_policy": "Rotate daily at 02:00 UTC with dual control approval"
    },
    "audit_logging": {
      "enabled": true,
      "log_file": "/var/log/blncs/audit.log",
      "retention_days": 2555
    }
  }
}
```

### Environment Variables

`UnifiedConfigManager` は `BLNCS_` プレフィックスの環境変数をドット区切りキーに変換します。

```bash
export BLNCS_ENV=production
export BLNCS_API_PORT=8081
export BLNCS_SECURITY_TRUSTED_HOSTS='["payments.example.com"]'
export BLNCS_LIGHTNING_HOST=remote-lnd-server
```

## Deployment Options

### 1. Automated Deployment Script

The included deployment script handles everything:

```bash
sudo ./deploy_production.sh
```

Features:
- ✅ Pre-deployment checks
- ✅ Automatic backups
- ✅ Dependency installation
- ✅ System user creation
- ✅ Service configuration
- ✅ Security hardening
- ✅ Health verification
- ✅ Rollback capability

### 2. Manual Deployment

For custom deployments:

```bash
# 1. Create system user
sudo useradd --system --home /opt/blncs blncs

# 2. Install dependencies
sudo apt update
sudo apt install python3 python3-pip python3-venv nginx

# 3. Deploy application
sudo cp -r . /opt/blncs/
sudo chown -R blncs:blncs /opt/blncs/

# 4. Create virtual environment
sudo -u blncs python3 -m venv /opt/blncs/venv
sudo -u blncs /opt/blncs/venv/bin/pip install -r requirements.txt

# 5. Configure systemd service
sudo cp blncs.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable blncs

# 6. Start services
sudo systemctl start blncs nginx
```

### 3. Docker Deployment

```bash
# Build image
docker build -t blncs:latest .

# Run container
docker run -d \
  --name blncs \
  -p 8080:8080 \
  -v /var/lib/lnd:/var/lib/lnd:ro \
  -v /opt/blncs/config:/app/config \
  blncs:latest
```

### 4. Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: blncs
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
        env:
        - name: BLNCS_ENV
          value: "production"
```

## Monitoring and Observability

### Built-in Monitoring Dashboard

Access the monitoring dashboard:

```
http://your-server:9090
```

Features:
- Real-time system metrics
- Application health status
- Performance analytics
- Alert management
- Historical data

### Metrics Collection

BLNCS exposes Prometheus-compatible metrics covering:

- **System Metrics:** CPU, memory、ディスク、ネットワーク I/O。
- **Application Metrics:** API 応答時間、HTTP ステータス分布、キャッシュヒット率、Lightning ノード状態。
- **Business Metrics:** チャネル残高、支払い成功率、ルーティング統計。

### Alerting

`config/alerts.json` のサンプルに従い、Prometheus/Alertmanager 連携または内部通知を設定します。典型的なアラート例:

- 高負荷検知: `system.cpu.percent` > 85% が 5 分継続
- Lightning 失敗率: `lightning.payment_failure_rate` > 5%
- API 遅延: `http.server.duration.p95` > 500 ms

### Log Management

**Log Locations:**
- Application logs: `/var/log/blncs/blncs.log`
- Audit logs: `/var/log/blncs/audit.log`
- Error logs: `/var/log/blncs/error.log`
- Access logs: `/var/log/nginx/access.log`

**Log Rotation:**
```bash
# Configured automatically by deployment script
/var/log/blncs/*.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
}
```

### External Monitoring Integration

**Prometheus:**
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'blncs'
    static_configs:
      - targets: ['localhost:9091']
```

**Grafana:**
- Import dashboard from `monitoring/grafana-dashboard.json`
- Pre-configured panels for all key metrics

## Security

### Authentication & Authorization

- REST API は `Authorization: Bearer <token>` ヘッダーを期待します。トークンは `blncs.core.simple_auth` を介してファイルベースに管理され、`BLNCS_API_TOKEN` 環境変数で初期化できます。
- CLI から `python blncs_main.py auth --generate` を使用して新規トークンを発行し、権限（`read`/`write`/`admin`）を設定します。

### Network Security

**Firewall Configuration:**
```bash
# UFW rules (applied automatically)
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 9735/tcp  # Lightning Network
sudo ufw enable
```

**Nginx Security Headers:**
```nginx
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
add_header X-XSS-Protection "1; mode=block";
add_header Strict-Transport-Security "max-age=31536000";
```

### SSL/TLS Configuration

**Automatic SSL with Let's Encrypt:**
```bash
# Install certbot
sudo apt install certbot python3-certbot-nginx

# Get certificate
sudo certbot --nginx -d your-domain.com

# Auto-renewal
sudo systemctl enable certbot.timer
```

### Data Encryption

- **At Rest:** SQLite データベースとバックアップファイルは OS レベルの暗号化と `backup.encryption` 設定で保護します。
- **In Transit:** 逆プロキシ（nginx 等）で TLS1.2+ を強制し、Lightning RPC は TLS 証明書とマカロンで保護します。

## Performance Optimization

### Recommended System Specifications

**Minimum Requirements:**
- 2 CPU cores
- 2GB RAM
- 20GB disk space
- 100 Mbps network

**Recommended Production:**
- 4+ CPU cores
- 8GB+ RAM
- 100GB+ SSD storage
- 1 Gbps network

### Performance Tuning

**System-level:**
```bash
# Increase file descriptor limits
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# Optimize network settings
echo "net.core.somaxconn = 65536" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65536" >> /etc/sysctl.conf
```

**Application-level:**
```json
{
  "performance": {
    "cache_enabled": true,
    "cache_ttl": 300,
    "compression_enabled": true,
    "worker_threads": 4,
    "connection_pooling": true
  }
}
```

### Scaling Options

- **Horizontal:** API インスタンスを複数立ち上げ、共通の Redis キャッシュや PostgreSQL を共有する構成を推奨。WebSocket 通知を使用する場合はブローカー層を追加します。
- **Vertical:** CPU・RAM の増設、NVMe SSD の採用、SQLite から PostgreSQL への移行で処理能力を向上します。

## Backup and Recovery

### Automated Backups

`config/production.json` の `backup` セクションでスケジュールと保存先を定義します。例:

```json
{
  "backup": {
    "enabled": true,
    "schedule": "0 2 * * *",
    "retention_days": 30,
    "compression": true,
    "encryption": true,
    "destinations": {
      "local": {
        "enabled": true,
        "path": "/var/backup/blncs"
      }
    }
  }
}
```

### Backup Components

**What gets backed up:**
- Application configuration
- Database (SQLite)
- Lightning Network channel backups
- SSL certificates
- Log files (compressed)
- Application state

### Recovery Procedures

**Full System Recovery:**
```bash
# 1. Install fresh BLNCS
sudo ./deploy_production.sh

# 2. Stop services
sudo systemctl stop blncs nginx

# 3. Restore from backup
sudo tar -xzf /var/backup/blncs/backup_YYYYMMDD_HHMMSS.tar.gz -C /

# 4. Restart services
sudo systemctl start blncs nginx

# 5. Verify recovery
sudo -u blncs /opt/blncs/venv/bin/python3 /opt/blncs/blncs_fast.py check
```

**Database Recovery:**
```bash
# Restore database only
sudo cp /var/backup/blncs/latest/blncs.db /var/lib/blncs/
sudo chown blncs:blncs /var/lib/blncs/blncs.db
sudo systemctl restart blncs
```

## Troubleshooting

### Common Issues

**Service Won't Start:**
```bash
# Check logs
sudo journalctl -u blncs -n 50

# Check configuration
sudo -u blncs /opt/blncs/venv/bin/python3 /opt/blncs/blncs_fast.py check

# Check permissions
sudo ls -la /var/lib/blncs/
```

**High Memory Usage:**
```bash
# Check process memory
ps aux | grep blncs

# Monitor memory over time
watch -n 5 'free -h && ps aux --sort=-%mem | head -10'

# Restart service if needed
sudo systemctl restart blncs
```

**API Not Responding:**
```bash
# Check if port is open
sudo netstat -tlnp | grep 8080

# Check nginx status
sudo systemctl status nginx

# Test direct connection
curl -v http://localhost:8080/health
```

**Lightning Network Connection Issues:**
```bash
# Verify LND is running
sudo systemctl status lnd

# Check TLS certificate
openssl x509 -in /var/lib/lnd/tls.cert -text -noout

# Test connection
lncli getinfo
```

### Diagnostic Commands

```bash
# Complete system health check
sudo -u blncs /opt/blncs/venv/bin/python3 /opt/blncs/blncs_fast.py check --detailed

# Performance benchmark
sudo -u blncs /opt/blncs/venv/bin/python3 /opt/blncs/blncs_fast.py benchmark

# View configuration
sudo -u blncs /opt/blncs/venv/bin/python3 /opt/blncs/blncs_fast.py info

# Export metrics
curl http://localhost:9090/api/metrics?minutes=60 | jq
```

### Performance Analysis

```bash
# CPU profiling
sudo perf record -g -p $(pgrep -f blncs_fast.py)
sudo perf report

# Memory analysis
sudo pmap -x $(pgrep -f blncs_fast.py)

# Network analysis
sudo netstat -i
sudo ss -tuln
```

## Maintenance

### Regular Maintenance Tasks

**Daily:**
- Monitor system health via dashboard
- Check alert notifications
- Verify backup completion

**Weekly:**
- Review performance metrics
- Update system packages
- Rotate logs manually if needed

**Monthly:**
- Security audit and updates
- Capacity planning review
- Disaster recovery testing

### Update Procedures

**Minor Updates:**
```bash
# Backup current installation
sudo ./deploy_production.sh backup

# Pull latest code
cd /opt/blncs
sudo -u blncs git pull origin main

# Restart service
sudo systemctl restart blncs
```

**Major Updates:**
```bash
# Use deployment script for major updates
sudo ./deploy_production.sh
```

### Health Checks

**Automated Health Monitoring:**
```bash
# Add to crontab
*/5 * * * * /opt/blncs/venv/bin/python3 /opt/blncs/blncs_fast.py check --quiet || echo "BLNCS health check failed" | mail -s "BLNCS Alert" admin@yourcompany.com
```

**Manual Health Verification:**
```bash
# Quick health check
curl -f http://localhost/health

# Detailed health check
sudo -u blncs /opt/blncs/venv/bin/python3 /opt/blncs/blncs_fast.py check --detailed

# Performance check
sudo -u blncs /opt/blncs/venv/bin/python3 /opt/blncs/blncs_fast.py benchmark
```

## Support and Resources

### Documentation
- [API Reference](API_REFERENCE.md)
- [Configuration Guide](CONFIGURATION.md)
- [Development Guide](DEVELOPMENT.md)
- [FAQ](FAQ.md)

### Getting Help
- Issues: use the repository issue tracker
- Documentation: see files under `docs/`
- Support teams: follow your organization's escalation process

### Contributing
- [Contributing Guidelines](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security Policy](SECURITY.md)

## License

BLNCS is released under the MIT License. See [LICENSE](LICENSE) for details.

---

**Production Deployment Checklist:**

- [ ] System requirements verified
- [ ] Lightning node configured and running
- [ ] BLNCS deployed and configured
- [ ] SSL certificates installed
- [ ] Monitoring dashboard accessible
- [ ] Backups configured and tested
- [ ] Security hardening applied
- [ ] Performance testing completed
- [ ] Documentation updated
- [ ] Team trained on operations

For additional support, please refer to our [Support Guide](SUPPORT.md) or contact our team.