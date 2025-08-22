#!/bin/bash
# BLRCS Quick Start Installation Script
# One-command installation for production deployment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
BLRCS_VERSION="1.0.0"
INSTALL_DIR="/opt/blrcs"
DATA_DIR="/var/lib/blrcs"
LOG_DIR="/var/log/blrcs"
CONFIG_DIR="/etc/blrcs"

# Functions
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
    exit 1
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

check_requirements() {
    print_status "Checking system requirements..."
    
    # Check OS
    if [[ "$OSTYPE" != "linux-gnu"* ]] && [[ "$OSTYPE" != "darwin"* ]]; then
        print_error "Unsupported operating system: $OSTYPE"
    fi
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is required but not installed"
    fi
    
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    if [[ $(echo "$PYTHON_VERSION < 3.8" | bc) -eq 1 ]]; then
        print_error "Python 3.8 or higher is required (found $PYTHON_VERSION)"
    fi
    
    # Check available space
    AVAILABLE_SPACE=$(df / | awk 'NR==2 {print $4}')
    if [[ $AVAILABLE_SPACE -lt 1048576 ]]; then
        print_error "Insufficient disk space (at least 1GB required)"
    fi
    
    # Check memory
    TOTAL_MEM=$(free -m | awk 'NR==2 {print $2}')
    if [[ $TOTAL_MEM -lt 2048 ]]; then
        print_warning "Low memory detected. Minimum 2GB recommended"
    fi
    
    print_status "System requirements satisfied"
}

detect_environment() {
    print_status "Detecting environment..."
    
    # Check if running as root
    if [[ $EUID -eq 0 ]]; then
        INSTALL_MODE="system"
        print_status "Running as root - System-wide installation"
    else
        INSTALL_MODE="user"
        INSTALL_DIR="$HOME/.local/blrcs"
        DATA_DIR="$HOME/.blrcs/data"
        LOG_DIR="$HOME/.blrcs/logs"
        CONFIG_DIR="$HOME/.blrcs/config"
        print_status "Running as user - Local installation"
    fi
    
    # Detect package manager
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
    elif command -v brew &> /dev/null; then
        PKG_MANAGER="brew"
    else
        PKG_MANAGER="none"
    fi
    
    print_status "Package manager: $PKG_MANAGER"
}

install_dependencies() {
    print_status "Installing dependencies..."
    
    # System dependencies
    if [[ "$INSTALL_MODE" == "system" ]]; then
        case $PKG_MANAGER in
            apt)
                apt-get update -qq
                apt-get install -y -qq python3-pip python3-venv git curl wget
                ;;
            yum|dnf)
                $PKG_MANAGER install -y -q python3-pip python3-virtualenv git curl wget
                ;;
            brew)
                brew install python3 git curl wget
                ;;
        esac
    fi
    
    # Python dependencies
    pip3 install --quiet --upgrade pip setuptools wheel
    
    print_status "Dependencies installed"
}

create_directories() {
    print_status "Creating directories..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$CONFIG_DIR"
    
    # Set permissions
    if [[ "$INSTALL_MODE" == "system" ]]; then
        chmod 755 "$INSTALL_DIR"
        chmod 750 "$DATA_DIR"
        chmod 750 "$LOG_DIR"
        chmod 750 "$CONFIG_DIR"
    fi
    
    print_status "Directories created"
}

download_blrcs() {
    print_status "Downloading BLRCS..."
    
    cd "$INSTALL_DIR"
    
    # Clone repository or download release
    if command -v git &> /dev/null; then
        if [[ -d ".git" ]]; then
            git pull --quiet
        else
            git clone --quiet https://github.com/shizukutanaka/BLRCS.git .
        fi
    else
        # Download release archive
        wget -q "https://github.com/shizukutanaka/BLRCS/archive/v$BLRCS_VERSION.tar.gz" -O blrcs.tar.gz
        tar -xzf blrcs.tar.gz --strip-components=1
        rm blrcs.tar.gz
    fi
    
    print_status "BLRCS downloaded"
}

setup_virtual_environment() {
    print_status "Setting up virtual environment..."
    
    cd "$INSTALL_DIR"
    
    # Create virtual environment
    python3 -m venv venv
    
    # Activate and install packages
    source venv/bin/activate
    pip install --quiet --upgrade pip
    pip install --quiet -r requirements.txt
    pip install --quiet -e .
    
    deactivate
    
    print_status "Virtual environment configured"
}

generate_configuration() {
    print_status "Generating configuration..."
    
    # Generate secure keys
    SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(64))')
    JWT_SECRET=$(python3 -c 'import secrets; print(secrets.token_urlsafe(64))')
    DB_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
    
    # Create main configuration
    cat > "$CONFIG_DIR/blrcs.conf" << EOF
# BLRCS Configuration
# Generated: $(date)

[system]
environment = production
debug = false
workers = auto

[security]
secret_key = $SECRET_KEY
jwt_secret = $JWT_SECRET
encryption = enabled
tls_version = 1.3
session_timeout = 900

[database]
url = sqlite:///$DATA_DIR/blrcs.db
password = $DB_PASSWORD
pool_size = 20
max_overflow = 10

[performance]
cache_enabled = true
cache_size = 10000
compression = enabled
optimization = aggressive

[monitoring]
enabled = true
metrics_port = 9090
log_level = INFO
audit_logging = true

[paths]
data_dir = $DATA_DIR
log_dir = $LOG_DIR
backup_dir = $DATA_DIR/backups
EOF
    
    # Secure the configuration file
    chmod 600 "$CONFIG_DIR/blrcs.conf"
    
    print_status "Configuration generated"
}

initialize_database() {
    print_status "Initializing database..."
    
    cd "$INSTALL_DIR"
    source venv/bin/activate
    
    # Run database migrations
    python -m blrcs.database init
    python -m blrcs.database migrate
    
    deactivate
    
    print_status "Database initialized"
}

create_systemd_service() {
    print_status "Creating system service..."
    
    if [[ "$INSTALL_MODE" == "system" ]] && [[ -d "/etc/systemd/system" ]]; then
        cat > /etc/systemd/system/blrcs.service << EOF
[Unit]
Description=BLRCS Enterprise Security Platform
After=network.target

[Service]
Type=simple
User=blrcs
Group=blrcs
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin"
ExecStart=$INSTALL_DIR/venv/bin/python -m blrcs start
ExecReload=/bin/kill -USR1 \$MAINPID
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        
        # Create service user
        if ! id -u blrcs &> /dev/null; then
            useradd -r -s /bin/false -d "$DATA_DIR" blrcs
        fi
        
        # Set ownership
        chown -R blrcs:blrcs "$INSTALL_DIR"
        chown -R blrcs:blrcs "$DATA_DIR"
        chown -R blrcs:blrcs "$LOG_DIR"
        chown -R blrcs:blrcs "$CONFIG_DIR"
        
        # Enable service
        systemctl daemon-reload
        systemctl enable blrcs.service
        
        print_status "System service created"
    else
        # Create user service script
        cat > "$INSTALL_DIR/start.sh" << EOF
#!/bin/bash
cd $INSTALL_DIR
source venv/bin/activate
python -m blrcs start
EOF
        chmod +x "$INSTALL_DIR/start.sh"
        
        print_status "Start script created"
    fi
}

apply_security_hardening() {
    print_status "Applying security hardening..."
    
    cd "$INSTALL_DIR"
    source venv/bin/activate
    
    # Run security hardening
    python -m blrcs.security_hardening
    
    deactivate
    
    # Set secure permissions
    find "$DATA_DIR" -type f -exec chmod 600 {} \;
    find "$DATA_DIR" -type d -exec chmod 700 {} \;
    find "$LOG_DIR" -type f -exec chmod 640 {} \;
    find "$LOG_DIR" -type d -exec chmod 750 {} \;
    
    print_status "Security hardening applied"
}

perform_initial_checks() {
    print_status "Performing initial system checks..."
    
    cd "$INSTALL_DIR"
    source venv/bin/activate
    
    # Run system checks
    python -m blrcs check
    
    deactivate
    
    print_status "System checks completed"
}

start_services() {
    print_status "Starting BLRCS services..."
    
    if [[ "$INSTALL_MODE" == "system" ]] && [[ -f "/etc/systemd/system/blrcs.service" ]]; then
        systemctl start blrcs.service
        
        # Wait for service to start
        sleep 5
        
        if systemctl is-active --quiet blrcs.service; then
            print_status "BLRCS service started successfully"
        else
            print_error "Failed to start BLRCS service"
        fi
    else
        # Start in background
        nohup "$INSTALL_DIR/start.sh" > "$LOG_DIR/blrcs.log" 2>&1 &
        echo $! > "$DATA_DIR/blrcs.pid"
        
        print_status "BLRCS started in background (PID: $(cat $DATA_DIR/blrcs.pid))"
    fi
}

print_summary() {
    echo ""
    echo "========================================="
    echo "  BLRCS Installation Complete!"
    echo "========================================="
    echo ""
    print_status "Installation directory: $INSTALL_DIR"
    print_status "Configuration: $CONFIG_DIR/blrcs.conf"
    print_status "Data directory: $DATA_DIR"
    print_status "Log directory: $LOG_DIR"
    echo ""
    
    if [[ "$INSTALL_MODE" == "system" ]]; then
        echo "Service commands:"
        echo "  Start:   systemctl start blrcs"
        echo "  Stop:    systemctl stop blrcs"
        echo "  Status:  systemctl status blrcs"
        echo "  Logs:    journalctl -u blrcs -f"
    else
        echo "Commands:"
        echo "  Start:   $INSTALL_DIR/start.sh"
        echo "  Stop:    kill \$(cat $DATA_DIR/blrcs.pid)"
        echo "  Logs:    tail -f $LOG_DIR/blrcs.log"
    fi
    echo ""
    echo "Access the dashboard at: http://localhost:8000"
    echo "Default credentials: admin / changeme"
    echo ""
    print_warning "Please change the default password immediately!"
    echo ""
}

# Main installation flow
main() {
    echo ""
    echo "========================================="
    echo "  BLRCS Quick Start Installation"
    echo "========================================="
    echo ""
    
    check_requirements
    detect_environment
    install_dependencies
    create_directories
    download_blrcs
    setup_virtual_environment
    generate_configuration
    initialize_database
    create_systemd_service
    apply_security_hardening
    perform_initial_checks
    start_services
    print_summary
}

# Run main function
main