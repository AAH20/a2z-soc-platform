#!/bin/bash

# A2Z IDS/IPS Quick Installation Script
# Automates the installation and initial configuration of A2Z IDS/IPS
# with Snort community rules integration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/a2z-ids"
CONFIG_DIR="/etc/a2z-ids"
RULES_DIR="/var/lib/a2z-ids/rules"
LOG_DIR="/var/log/a2z-ids"
SERVICE_USER="a2z-ids"

print_banner() {
    echo -e "${BLUE}"
    echo "  █████╗ ██████╗ ███████╗    ██╗██████╗ ███████╗"
    echo " ██╔══██╗╚════██╗╚══███╔╝    ██║██╔══██╗██╔════╝"
    echo " ███████║ █████╔╝  ███╔╝     ██║██║  ██║███████╗"
    echo " ██╔══██║██╔═══╝  ███╔╝      ██║██║  ██║╚════██║"
    echo " ██║  ██║███████╗███████╗    ██║██████╔╝███████║"
    echo " ╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝╚═════╝ ╚══════╝"
    echo ""
    echo " Next-Generation Intrusion Detection & Prevention"
    echo -e "${NC}"
}

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        error "Cannot detect operating system"
    fi
    
    log "Detected OS: $OS $OS_VERSION"
}

check_network_interfaces() {
    log "Available network interfaces:"
    ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print "  - " $2}' | sed 's/@.*//'
    
    echo -e "\n${YELLOW}Please ensure you have identified your monitoring interface${NC}"
    echo "Example: eth0 (management), eth1 (monitoring)"
}

install_dependencies() {
    log "Installing system dependencies..."
    
    case $OS in
        ubuntu|debian)
            apt update
            apt install -y \
                curl \
                wget \
                git \
                build-essential \
                libpcap-dev \
                libssl-dev \
                pkg-config \
                jq \
                tar \
                gzip \
                docker.io \
                docker-compose \
                net-tools
            ;;
        centos|rhel|fedora)
            if command -v dnf >/dev/null; then
                dnf groupinstall -y "Development Tools"
                dnf install -y \
                    curl \
                    wget \
                    git \
                    libpcap-devel \
                    openssl-devel \
                    jq \
                    tar \
                    gzip \
                    docker \
                    docker-compose \
                    net-tools
            else
                yum groupinstall -y "Development Tools"
                yum install -y \
                    curl \
                    wget \
                    git \
                    libpcap-devel \
                    openssl-devel \
                    jq \
                    tar \
                    gzip \
                    docker \
                    docker-compose \
                    net-tools
            fi
            ;;
        *)
            error "Unsupported operating system: $OS"
            ;;
    esac
}

create_user() {
    log "Creating a2z-ids service user..."
    
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd -r -s /bin/false -d /var/lib/a2z-ids "$SERVICE_USER"
        log "Created user: $SERVICE_USER"
    else
        log "User $SERVICE_USER already exists"
    fi
}

create_directories() {
    log "Creating directory structure..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$RULES_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "/var/lib/a2z-ids/pcap"
    mkdir -p "/var/lib/a2z-ids/models"
    
    # Set ownership
    chown -R "$SERVICE_USER:$SERVICE_USER" /var/lib/a2z-ids
    chown -R "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR"
    
    log "Directory structure created"
}

download_a2z_ids() {
    log "Downloading A2Z IDS/IPS..."
    
    cd /tmp
    if [[ -d "a2z-ids-ips" ]]; then
        rm -rf a2z-ids-ips
    fi
    
    # In production, this would clone from the actual repository
    log "Cloning A2Z IDS/IPS repository..."
    # git clone https://github.com/a2z-soc/a2z-ids-ips.git
    
    # For now, copy from current directory if available
    if [[ -d "/path/to/a2z-ids-ips" ]]; then
        cp -r /path/to/a2z-ids-ips .
    else
        warn "A2Z IDS/IPS source not found. Please clone manually:"
        echo "git clone https://github.com/a2z-soc/a2z-ids-ips.git"
    fi
}

download_snort_rules() {
    log "Downloading Snort community rules..."
    
    cd /tmp
    
    # Download Snort community rules
    wget -O snort-community-rules.tar.gz \
        "https://www.snort.org/rules/community" 2>/dev/null || {
        warn "Failed to download Snort community rules automatically"
        echo "Please download manually from: https://www.snort.org/downloads"
        return 1
    }
    
    # Extract rules
    tar -xzf snort-community-rules.tar.gz
    if [[ -d "community-rules" ]]; then
        cp community-rules/*.rules "$RULES_DIR/"
        mv "$RULES_DIR/community.rules" "$RULES_DIR/snort-community.rules" 2>/dev/null || true
        log "Snort community rules installed"
    fi
}

download_emerging_threats() {
    log "Downloading Emerging Threats rules..."
    
    cd /tmp
    
    # Download ET Open rules
    wget -O emerging-rules.tar.gz \
        "https://rules.emergingthreats.net/open/suricata-6.0.9/emerging.rules.tar.gz" 2>/dev/null || {
        warn "Failed to download Emerging Threats rules"
        return 1
    }
    
    # Extract and combine rules
    tar -xzf emerging-rules.tar.gz
    if [[ -d "rules" ]]; then
        cat rules/emerging-*.rules > "$RULES_DIR/emerging-threats.rules"
        log "Emerging Threats rules installed"
    fi
}

create_configuration() {
    log "Creating default configuration..."
    
    cat > "$CONFIG_DIR/config.yaml" << 'EOF'
# A2Z IDS/IPS Configuration File
system:
  name: "A2Z IDS/IPS"
  version: "1.0.0"
  environment: "production"
  log_level: "info"

# Network Capture Configuration
capture:
  interface: "eth1"  # CHANGE THIS TO YOUR MONITORING INTERFACE
  mode: "passive"
  buffer_size: "256MB"
  workers: 8
  promisc_mode: true
  snaplen: 65535
  timeout: 1000
  
  # Packet filtering (BPF syntax)
  filter: ""  # Empty = capture all traffic

# Detection Engine Configuration
detection:
  rule_files:
    - "/var/lib/a2z-ids/rules/snort-community.rules"
    - "/var/lib/a2z-ids/rules/emerging-threats.rules"
    - "/var/lib/a2z-ids/rules/custom.rules"
  
  enabled_categories:
    - "malware"
    - "exploit"
    - "trojan"
    - "web-application"
    - "network-scan"
    - "dos"
    - "sql-injection"
    - "xss"

# Alerting Configuration
alerting:
  outputs:
    - type: "json"
      file: "/var/log/a2z-ids/alerts.json"
    - type: "syslog"
      facility: "local0"
      severity: "info"

# Performance settings
performance:
  threads: 8
  memory_limit: "4GB"
  optimize_for: "balanced"  # throughput, latency, balanced

# Database Configuration (for Docker deployment)
database:
  postgres:
    host: "localhost"
    port: 5432
    database: "a2z_ids"
    username: "a2z_ids"
    password: "change_me_in_production"
  
  redis:
    host: "localhost"
    port: 6379
    password: ""
EOF

    # Set appropriate permissions
    chown root:$SERVICE_USER "$CONFIG_DIR/config.yaml"
    chmod 640 "$CONFIG_DIR/config.yaml"
    
    log "Configuration file created: $CONFIG_DIR/config.yaml"
}

create_custom_rules() {
    log "Creating sample custom rules..."
    
    cat > "$RULES_DIR/custom.rules" << 'EOF'
# Custom A2Z IDS Rules
# Add your organization-specific detection rules here

alert tcp any any -> $HOME_NET 22 (
    msg:"SSH Brute Force Attempt";
    flow:to_server,established;
    content:"SSH-";
    detection_filter:track by_src, count 5, seconds 60;
    classtype:attempted-recon;
    sid:1000001;
    rev:1;
)

alert tcp any any -> $HOME_NET [80,443] (
    msg:"Potential SQL Injection - Union Select";
    flow:to_server,established;
    content:"union"; nocase;
    content:"select"; nocase; distance:0; within:20;
    http_uri;
    classtype:web-application-attack;
    sid:1000002;
    rev:1;
)

alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (
    msg:"Potential Data Exfiltration - Large HTTPS Upload";
    flow:to_server,established;
    dsize:>1000000;
    threshold:type limit, track by_src, count 1, seconds 300;
    classtype:policy-violation;
    sid:1000003;
    rev:1;
)

alert icmp any any -> $HOME_NET any (
    msg:"ICMP Ping Sweep Detected";
    itype:8;
    detection_filter:track by_src, count 10, seconds 60;
    classtype:attempted-recon;
    sid:1000004;
    rev:1;
)
EOF

    chown $SERVICE_USER:$SERVICE_USER "$RULES_DIR/custom.rules"
    log "Custom rules template created"
}

setup_docker() {
    log "Setting up Docker services..."
    
    # Enable and start Docker
    systemctl enable docker
    systemctl start docker
    
    # Add a2z-ids user to docker group
    usermod -aG docker $SERVICE_USER
    
    log "Docker configured"
}

create_startup_script() {
    log "Creating startup script..."
    
    cat > "/usr/local/bin/a2z-ids" << 'EOF'
#!/bin/bash

# A2Z IDS/IPS Control Script

CONFIG_FILE="/etc/a2z-ids/config.yaml"
LOG_FILE="/var/log/a2z-ids/a2z-ids.log"
PIDFILE="/var/run/a2z-ids.pid"

case "$1" in
    start)
        echo "Starting A2Z IDS/IPS..."
        # For Docker deployment
        cd /opt/a2z-ids && docker-compose up -d
        ;;
    stop)
        echo "Stopping A2Z IDS/IPS..."
        cd /opt/a2z-ids && docker-compose down
        ;;
    restart)
        echo "Restarting A2Z IDS/IPS..."
        cd /opt/a2z-ids && docker-compose restart
        ;;
    status)
        cd /opt/a2z-ids && docker-compose ps
        ;;
    logs)
        cd /opt/a2z-ids && docker-compose logs -f
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        exit 1
        ;;
esac
EOF

    chmod +x /usr/local/bin/a2z-ids
    log "Startup script created: /usr/local/bin/a2z-ids"
}

create_systemd_service() {
    log "Creating systemd service..."
    
    cat > "/etc/systemd/system/a2z-ids.service" << EOF
[Unit]
Description=A2Z IDS/IPS Service
Requires=docker.service
After=docker.service

[Service]
Type=forking
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/local/bin/a2z-ids start
ExecStop=/usr/local/bin/a2z-ids stop
ExecReload=/usr/local/bin/a2z-ids restart
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log "Systemd service created"
}

setup_logging() {
    log "Setting up log rotation..."
    
    cat > "/etc/logrotate.d/a2z-ids" << 'EOF'
/var/log/a2z-ids/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 a2z-ids a2z-ids
    postrotate
        /usr/local/bin/a2z-ids restart > /dev/null 2>&1 || true
    endscript
}
EOF

    log "Log rotation configured"
}

print_next_steps() {
    echo -e "\n${GREEN}🎉 A2Z IDS/IPS Installation Complete!${NC}\n"
    
    echo -e "${YELLOW}Next Steps:${NC}"
    echo "1. Edit the configuration file:"
    echo "   sudo nano $CONFIG_DIR/config.yaml"
    echo ""
    echo "2. Set your monitoring interface in the config file"
    echo ""
    echo "3. Start the service:"
    echo "   sudo systemctl enable a2z-ids"
    echo "   sudo systemctl start a2z-ids"
    echo ""
    echo "4. Check status:"
    echo "   sudo systemctl status a2z-ids"
    echo "   sudo a2z-ids status"
    echo ""
    echo "5. Access the web interface:"
    echo "   http://localhost:3000"
    echo "   Default credentials: admin / a2z-admin-2024"
    echo ""
    echo "6. View logs:"
    echo "   sudo a2z-ids logs"
    echo "   tail -f $LOG_DIR/alerts.json"
    echo ""
    echo -e "${YELLOW}Configuration Files:${NC}"
    echo "  Main config: $CONFIG_DIR/config.yaml"
    echo "  Rules dir:   $RULES_DIR/"
    echo "  Log dir:     $LOG_DIR/"
    echo ""
    echo -e "${YELLOW}Useful Commands:${NC}"
    echo "  Start:       sudo a2z-ids start"
    echo "  Stop:        sudo a2z-ids stop"
    echo "  Status:      sudo a2z-ids status"
    echo "  Logs:        sudo a2z-ids logs"
    echo ""
    echo -e "${GREEN}For support: https://docs.a2zsoc.com/ids-ips${NC}"
}

main() {
    print_banner
    
    log "Starting A2Z IDS/IPS installation..."
    
    check_root
    detect_os
    check_network_interfaces
    
    read -p "Continue with installation? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
    
    install_dependencies
    create_user
    create_directories
    download_snort_rules
    download_emerging_threats
    create_configuration
    create_custom_rules
    setup_docker
    create_startup_script
    create_systemd_service
    setup_logging
    
    print_next_steps
}

# Run main function
main "$@" 