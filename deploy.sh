#!/bin/bash
set -e
echo "BLNCS Deployment Started"
apt-get update && apt-get install -y python3-pip python3-venv nginx
useradd --system blncs || true
mkdir -p /opt/blncs /var/log/blncs
cp blncs_production.py /opt/blncs/
cp -r blncs/ /opt/blncs/
cp requirements.txt /opt/blncs/
chown -R blncs:blncs /opt/blncs
cd /opt/blncs
sudo -u blncs python3 -m venv venv
sudo -u blncs bash -c "source venv/bin/activate && pip install -r requirements.txt && pip install fastapi uvicorn"
cat > /etc/systemd/system/blncs.service << 'EOF2'
[Unit]
Description=BLNCS
After=network.target
[Service]
Type=simple
User=blncs
WorkingDirectory=/opt/blncs
ExecStart=/opt/blncs/venv/bin/python blncs_production.py --mode server
Restart=always
[Install]
WantedBy=multi-user.target
EOF2
cat > /etc/nginx/sites-available/blncs << 'EOF3'
server {
listen 80;
server_name _;
location / {
proxy_pass http://127.0.0.1:8000;
proxy_set_header Host $host;
}
}
EOF3
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/blncs /etc/nginx/sites-enabled/
systemctl daemon-reload
systemctl enable blncs
systemctl restart nginx
systemctl start blncs
echo "Deployment completed!"
