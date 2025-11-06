# BLNCS Deployment Guide｜導入ガイド

## Overview (English)

This guide explains how to deploy the current BLNCS runtime in three practical scenarios: a local virtual environment, a long-running `systemd` service, and a Docker Compose bundle. The runtime is started with the CLI entry point `blncs_main.py`, reads `config/blncs.json`, and offers optional Lightning connectivity through `blncs/lightning/simple_client`. Each section lists the minimum commands required to reach a working instance and highlights follow-up tasks (configuration, logging, backups).

## 概要 (日本語)

本ガイドでは、最新の BLNCS ランタイムをローカル仮想環境、`systemd` サービス、Docker Compose の 3 パターンで導入する手順を説明します。CLI は `blncs_main.py`、設定ファイルは `config/blncs.json` を使用し、Lightning ノードへの接続は任意ですが `blncs/lightning/simple_client` を介して行えます。各セクションでは最小限のコマンドと、導入後に実施すべき設定・ログ・バックアップに関するポイントをまとめています。

---

## 1. Prerequisites｜前提条件

- **Python**: 3.10 以上 (3.11+ 推奨)
- **Operating systems**: Linux, macOS, Windows (WSL を利用)
- **Hardware**: 2 CPU, 2GB RAM, 10GB SSD 相当 (小規模構成の目安)
- **Lightning node (optional)**: LND または Core Lightning へ接続する場合は証明書・マカロン／RPC ソケットを準備

---

## 2. Option A – Local virtual environment｜ローカル仮想環境

```bash
# 1. Obtain the signed BLNCS release bundle distributed by your organisation
#    (for example blncs-release.tar.gz) and place it in the working directory.

# 2. Verify the release signature if provided
gpg --verify blncs-release.tar.gz.sig blncs-release.tar.gz

# 3. Extract the bundle
tar -xzf blncs-release.tar.gz
cd blncs

# 4. Create and activate a virtual environment
python -m venv .venv
. .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt

# 5. Generate a baseline configuration and start the API server
python blncs_main.py config --template
python blncs_main.py server --config config/blncs.json
```

- **Configuration**: Update `config/blncs.json` (for example `database.path`, `security.enforce_https`, `lightning.node_url`) before exposing the service.
- **Health checks**: Run `python blncs_main.py status` and `python blncs_main.py health` to confirm readiness.
- **Log review**: Logs default to stdout; use `python blncs_main.py logs --action view --lines 100` when file handlers are configured.

---

## 3. Option B – systemd service (Linux)｜systemd サービス

### 3.1 Install under `/opt/blncs`

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin blncs
sudo mkdir -p /opt/blncs
sudo chown blncs:blncs /opt/blncs

# Copy the approved release bundle to the target (example uses scp)
scp blncs-release.tar.gz blncs@your-server:/opt/blncs/

sudo -u blncs bash -lc '
  cd /opt/blncs &&
  tar -xzf blncs-release.tar.gz &&
  mv blncs src &&
  cd src &&
  python -m venv .venv &&
  . .venv/bin/activate &&
  pip install --upgrade pip &&
  pip install -r requirements.txt &&
  python blncs_main.py config --template
'
```

### 3.2 Create `systemd` unit `/etc/systemd/system/blncs.service`

```ini
[Unit]
Description=BLNCS API Server
After=network.target

[Service]
User=blncs
WorkingDirectory=/opt/blncs/src
Environment="PATH=/opt/blncs/src/.venv/bin"
ExecStart=/opt/blncs/src/.venv/bin/python blncs_main.py server --config /opt/blncs/src/config/blncs.json
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable blncs
sudo systemctl start blncs
sudo systemctl status blncs
```

- **Log rotation**: Connect the service log to `journalctl -u blncs`. Optional file logging can be added via `config/logging`.
- **Backups**: Schedule `python blncs_main.py backup --auto start --interval 86400` inside a dedicated timer or cron job.

---

## 4. Option C – Docker Compose｜Docker Compose

`docker-compose.yml` example (place in repository root):

```yaml
version: "3.9"
services:
  blncs:
    build: .
    command: ["python", "blncs_main.py", "server"]
    ports:
      - "8080:8080"
    volumes:
      - ./config/blncs.json:/app/config/blncs.json:ro
      - ./data:/app/data
      - ./backups:/app/backups
    environment:
      - BLNCS_LOG_LEVEL=INFO
    restart: unless-stopped
  lnd:
    image: lightninglabs/lnd:v0.17.4-beta
    ports:
      - "9735:9735"
      - "10009:10009"
    volumes:
      - lnd_data:/root/.lnd
volumes:
  lnd_data:
```

```bash
docker compose build blncs
docker compose up -d
docker compose logs -f blncs
```

- **Configuration**: Edit `config/blncs.json` before starting. For container-only setups move secrets (macaroons, TLS certs) into Docker secrets or mounted volumes.
- **Updates**: Run `docker compose pull && docker compose up -d`.

---

## 5. Configuration essentials｜主要設定項目

- **`api`**: `host`, `port`, `debug`, `enable_cors`.
- **`lightning`**: `node_url` or per-implementation keys (`cert_path`, `macaroon_path`, `socket_path`).
- **`database`**: `path`, `timeout`, and optional `wal_mode`.
- **`backup`**: `enabled`, `schedule`, `retention_days`.
- **`security`** (if configured in your environment): toggle `auth_enabled`, provide hashed credentials, configure rate limiting.

---

## 6. Environment variables｜環境変数

| Variable | Description |
| --- | --- |
| `BLNCS_LIGHTNING_NODE_URL` | Points to Lightning backend (host:port) |
| `BLNCS_LOG_LEVEL` | Sets default logging level (`INFO`, `DEBUG`, etc.) |
| `BLNCS_DATABASE_PATH` | Alternate SQLite path when mounting volumes |
| `BLNCS_CLI_TOKEN` | Auth token for privileged CLI commands |

環境変数は CLI だけでなく Docker Compose の `environment` や `systemd` の `Environment=` でも設定できます。

---

## 7. Security & reliability checklist｜セキュリティ・信頼性チェックリスト

- **Certificates**: Store TLS certificates, macaroons, and API tokens outside of the repository. Mount them read-only when running in Docker.
- **Firewall**: Allow inbound access only to the published API listener; keep the Flask server bound to `127.0.0.1` on bare metal deployments.
- **HTTPS**: Terminate TLS with a reverse proxy (Nginx / Caddy) and forward to `http://127.0.0.1:8080`.
- **Authentication**: Require `BLNCS_CLI_TOKEN` for CLI commands marked `write` or `admin` and create dedicated read-only tokens for automation.
- **Backups**: Verify `/backups` directory retention and test restore procedures monthly.
- **Monitoring**: Poll `/health` and `/api/system/metrics`. Use `python blncs_main.py status` locally for ad-hoc checks.

---

## 7.1 Reverse proxy mutual TLS setup｜リバースプロキシ相互TLS構成

-### English

- **Objective**: Require client certificates between the reverse proxy and external operators while forwarding authenticated requests to the BLNCS API running on `127.0.0.1:8080`.
- **Prerequisites**:
  - A domain pointing to the proxy host.
  - `certbot` (or other ACME client) installed for certificate issuance and renewal.
  - A private certificate authority (CA) bundle for client certificate validation.
- **Set hostname** (replace with your deployed FQDN):
  ```bash
  export BLNCS_PROXY_HOSTNAME="${BLNCS_PROXY_HOSTNAME:?Set BLNCS_PROXY_HOSTNAME to the deployed HTTPS hostname}"
  ```
- **Nginx configuration** (`/etc/nginx/sites-available/blncs.conf`):
  ```nginx
  upstream blncs_api {
      server 127.0.0.1:8080;
  }

  server {
      listen 443 ssl http2;
      server_name ${BLNCS_PROXY_HOSTNAME};

      ssl_certificate /etc/letsencrypt/live/${BLNCS_PROXY_HOSTNAME}/fullchain.pem;
      ssl_certificate_key /etc/letsencrypt/live/${BLNCS_PROXY_HOSTNAME}/privkey.pem;
      ssl_trusted_certificate /etc/letsencrypt/live/${BLNCS_PROXY_HOSTNAME}/chain.pem;

      ssl_client_certificate /etc/nginx/client-ca/ca.crt;
      ssl_verify_client on;
      ssl_verify_depth 2;

      add_header Strict-Transport-Security "max-age=63072000" always;

      location / {
          proxy_pass http://blncs_api;
          proxy_set_header X-Forwarded-For $remote_addr;
          proxy_set_header X-Client-Cert $ssl_client_escaped_cert;
          proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
      }
  }
  ```
- **Client certificate issuance**:
  ```bash
  openssl req -new -newkey rsa:4096 -nodes \
    -keyout client.key \
    -out client.csr \
    -subj "/CN=blncs-operator"

  openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days 365 -sha256
  ```
- **Certificate renewal automation**:
  ```bash
  sudo certbot renew --post-hook "systemctl reload nginx"
  ```
  Schedule the command via `cron` or `systemd` timer. Ensure the client CA bundle (`/etc/nginx/client-ca/`) is version-controlled internally and rotated on revocation.
- **Validation**:
  ```bash
  curl --cert client.crt --key client.key "https://${BLNCS_PROXY_HOSTNAME}/health"
  ```
  The command must return HTTP 200 when the client certificate is trusted.

-### 日本語

- **目的**: リバースプロキシと外部運用者の間でクライアント証明書を必須化し、認証済みリクエストのみを `127.0.0.1:8080` 上の BLNCS API へ転送します。
- **前提条件**:
  - プロキシホストに紐付くドメイン。
  - 証明書発行と更新を行う `certbot`（または他の ACME クライアント）。
  - クライアント証明書検証用のプライベート認証局（CA）バンドル。
- **ホスト名の設定**（稼働中の FQDN を指定）:
  ```bash
  export BLNCS_PROXY_HOSTNAME="${BLNCS_PROXY_HOSTNAME:?運用中の HTTPS ホスト名を BLNCS_PROXY_HOSTNAME に設定してください}"
  ```
- **Nginx 設定**（`/etc/nginx/sites-available/blncs.conf`）:
  ```nginx
  upstream blncs_api {
      server 127.0.0.1:8080;
  }

  server {
      listen 443 ssl http2;
      server_name ${BLNCS_PROXY_HOSTNAME};

      ssl_certificate /etc/letsencrypt/live/${BLNCS_PROXY_HOSTNAME}/fullchain.pem;
      ssl_certificate_key /etc/letsencrypt/live/${BLNCS_PROXY_HOSTNAME}/privkey.pem;
      ssl_trusted_certificate /etc/letsencrypt/live/${BLNCS_PROXY_HOSTNAME}/chain.pem;

      ssl_client_certificate /etc/nginx/client-ca/ca.crt;
      ssl_verify_client on;
      ssl_verify_depth 2;

      add_header Strict-Transport-Security "max-age=63072000" always;

      location / {
          proxy_pass http://blncs_api;
          proxy_set_header X-Forwarded-For $remote_addr;
          proxy_set_header X-Client-Cert $ssl_client_escaped_cert;
          proxy_set_header X-SSL-Client-Verify $ssl_client_verify;
      }
  }
  ```
- **クライアント証明書発行**:
  ```bash
  openssl req -new -newkey rsa:4096 -nodes \
    -keyout client.key \
    -out client.csr \
    -subj "/CN=blncs-operator"

  openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days 365 -sha256
  ```
- **証明書自動更新**:
  ```bash
  sudo certbot renew --post-hook "systemctl reload nginx"
  ```
  `cron` または `systemd` タイマーで定期実行し、クライアント CA バンドル（`/etc/nginx/client-ca/`）は社内でバージョン管理し、失効時は速やかに差し替えます。
- **動作確認**:
  ```bash
  curl --cert client.crt --key client.key "https://${BLNCS_PROXY_HOSTNAME}/health"
  ```
  信頼済みクライアント証明書であれば HTTP 200 を返します。

---

## 8. Operational runbook｜運用ランブック

- **Validate deployment**:
  ```bash
  curl -s http://localhost:8080/health | jq .
  curl -s http://localhost:8080/api/info | jq .
  ```
- **Run CLI diagnostics**: `python blncs_main.py performance --stats`.
- **Rotate logs**: configure `/etc/logrotate.d/blncs` if file logging is enabled.
- **Restore from backup**: stop the service, copy the desired `.db` file from `/backups`, start service, run `python blncs_main.py validate`.

---

## 9. Troubleshooting｜トラブルシューティング

- **Port already in use**: Check `lsof -i :8080` and adjust `api.port`.
- **Lightning connection fails**: Verify `python blncs_main.py connect --host <node> --port <port>` and credentials in `config/blncs.json`.
- **Permissions error**: Ensure directories like `/app/data` and `/app/backups` are writable by the BLNCS process user.
- **Systemd restart loop**: Inspect `journalctl -u blncs`, run `python blncs_main.py status` manually to surface errors.
- **Docker container exits**: View logs with `docker compose logs blncs` and confirm that mounted configuration paths are correct.

---

## 10. Change management｜変更管理

- **Rolling update (systemd)**:
  ```bash
  sudo systemctl stop blncs
  cd /opt/blncs/src && git pull
  . .venv/bin/activate && pip install -r requirements.txt
  python blncs_main.py validate
  sudo systemctl start blncs
  ```
- **Docker image update**:
  ```bash
  docker compose pull blncs
  docker compose up -d
  ```
- **Rollback**: keep a copy of the previous `config/blncs.json` and database snapshot in `/backups` to restore quickly.

---

## 11. Further reading｜参考資料

- `docs/README_UNIFIED.md`: Project overview
- `docs/API_REFERENCE_UNIFIED.md`: REST endpoint documentation
- `docs/QUICK_START.md`: Evaluation workflow and diagnostics

以上で主要な導入パターンをカバーしました。環境に合わせてコマンドやパスを調整し、テスト・監視・バックアップ体制を整備してください。