#!/bin/bash

# A2Z IDS/IPS Deployment Script
# Supports Ubuntu/Debian, CentOS/RHEL, macOS
# Usage: ./deploy.sh [options]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
DEFAULT_INTERFACE="eth0"
DEFAULT_MODE="passive"
DEFAULT_INSTALL_DIR="/opt/a2z-ids"
DEFAULT_DATA_DIR="/var/lib/a2z-ids"
DEFAULT_LOG_DIR="/var/log/a2z-ids"
DEFAULT_CONFIG_DIR="/etc/a2z-ids"

# Script variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
INSTALL_DIR="${DEFAULT_INSTALL_DIR}"
NETWORK_INTERFACE="${DEFAULT_INTERFACE}"
DEPLOYMENT_MODE="${DEFAULT_MODE}"
SKIP_DOCKER=false
SKIP_BUILD=false
USE_DOCKER_COMPOSE=true
GRAFANA_PASSWORD="admin123"
JWT_SECRET=""

# Print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Print usage information
usage() {
    cat << EOF
A2Z IDS/IPS Deployment Script

Usage: $0 [OPTIONS]

OPTIONS:
    -h, --help              Show this help message
    -i, --interface IFACE   Network interface to monitor (default: ${DEFAULT_INTERFACE})
    -m, --mode MODE         Deployment mode: passive|inline|hybrid (default: ${DEFAULT_MODE})
    -d, --install-dir DIR   Installation directory (default: ${DEFAULT_INSTALL_DIR})
    --skip-docker           Skip Docker installation
    --skip-build            Skip building from source
    --native                Install natively without Docker
    --grafana-password PWD  Set Grafana admin password (default: admin123)
    --jwt-secret SECRET     Set JWT secret for API authentication

EXAMPLES:
    $0                                          # Default installation
    $0 -i enp0s3 -m inline                     # Monitor enp0s3 interface in inline mode
    $0 --native --install-dir /usr/local/a2z   # Native installation
    $0 --skip-docker --skip-build              # Quick setup with existing Docker

EOF
}

# Detect operating system
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get >/dev/null 2>&1; then
            OS="debian"
            PACKAGE_MANAGER="apt-get"
        elif command -v yum >/dev/null 2>&1; then
            OS="rhel"
            PACKAGE_MANAGER="yum"
        elif command -v dnf >/dev/null 2>&1; then
            OS="rhel"
            PACKAGE_MANAGER="dnf"
        else
            print_error "Unsupported Linux distribution"
            exit 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        PACKAGE_MANAGER="brew"
    else
        print_error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
    
    print_status "Detected OS: $OS with package manager: $PACKAGE_MANAGER"
}

# Check if running as root (required for some operations)
check_privileges() {
    if [[ $EUID -ne 0 && "$USE_DOCKER_COMPOSE" == false ]]; then
        print_error "This script requires root privileges for native installation"
        print_status "Try: sudo $0 $*"
        print_status "Or use Docker: $0 --docker"
        exit 1
    fi
}

# Install system dependencies
install_dependencies() {
    print_status "Installing system dependencies..."
    
    case $OS in
        "debian")
            apt-get update
            apt-get install -y \
                curl \
                wget \
                git \
                build-essential \
                pkg-config \
                libssl-dev \
                libpcap-dev \
                cmake \
                clang \
                libclang-dev \
                net-tools \
                tcpdump
            ;;
        "rhel")
            $PACKAGE_MANAGER update -y
            $PACKAGE_MANAGER install -y \
                curl \
                wget \
                git \
                gcc \
                gcc-c++ \
                make \
                cmake \
                clang \
                clang-devel \
                openssl-devel \
                libpcap-devel \
                pkg-config \
                net-tools \
                tcpdump
            ;;
        "macos")
            if ! command -v brew >/dev/null 2>&1; then
                print_status "Installing Homebrew..."
                /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            fi
            brew update
            brew install \
                curl \
                wget \
                git \
                cmake \
                pkg-config \
                libpcap \
                openssl
            ;;
    esac
    
    print_success "System dependencies installed"
}

# Install Docker and Docker Compose
install_docker() {
    if $SKIP_DOCKER; then
        print_status "Skipping Docker installation"
        return
    fi
    
    if command -v docker >/dev/null 2>&1 && command -v docker-compose >/dev/null 2>&1; then
        print_status "Docker and Docker Compose already installed"
        return
    fi
    
    print_status "Installing Docker and Docker Compose..."
    
    case $OS in
        "debian")
            # Install Docker
            curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
            add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
            apt-get update
            apt-get install -y docker-ce docker-ce-cli containerd.io
            
            # Install Docker Compose
            DOCKER_COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d\" -f4)
            curl -L "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
            chmod +x /usr/local/bin/docker-compose
            ;;
        "rhel")
            $PACKAGE_MANAGER install -y docker docker-compose
            systemctl enable docker
            systemctl start docker
            ;;
        "macos")
            brew install --cask docker
            print_warning "Please start Docker Desktop manually"
            ;;
    esac
    
    # Add current user to docker group
    if [[ "$OS" != "macos" ]]; then
        usermod -aG docker $USER || true
    fi
    
    print_success "Docker and Docker Compose installed"
}

# Install Rust (required for building core engine)
install_rust() {
    if command -v rustc >/dev/null 2>&1; then
        print_status "Rust already installed"
        return
    fi
    
    print_status "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
    print_success "Rust installed"
}

# Install Go (required for management API)
install_go() {
    if command -v go >/dev/null 2>&1; then
        print_status "Go already installed"
        return
    fi
    
    print_status "Installing Go..."
    
    case $OS in
        "debian"|"rhel")
            wget -O go.tar.gz https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
            tar -C /usr/local -xzf go.tar.gz
            echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
            export PATH=$PATH:/usr/local/go/bin
            rm go.tar.gz
            ;;
        "macos")
            brew install go
            ;;
    esac
    
    print_success "Go installed"
}

# Install Node.js (required for web dashboard)
install_nodejs() {
    if command -v node >/dev/null 2>&1; then
        print_status "Node.js already installed"
        return
    fi
    
    print_status "Installing Node.js..."
    
    case $OS in
        "debian")
            curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
            apt-get install -y nodejs
            ;;
        "rhel")
            curl -fsSL https://rpm.nodesource.com/setup_18.x | bash -
            $PACKAGE_MANAGER install -y nodejs npm
            ;;
        "macos")
            brew install node
            ;;
    esac
    
    print_success "Node.js installed"
}

# Generate JWT secret if not provided
generate_jwt_secret() {
    if [[ -z "$JWT_SECRET" ]]; then
        JWT_SECRET=$(openssl rand -hex 32)
        print_status "Generated JWT secret"
    fi
}

# Create system directories
create_directories() {
    print_status "Creating system directories..."
    
    mkdir -p "${DEFAULT_DATA_DIR}"/{rules,models,pcap,data}
    mkdir -p "${DEFAULT_LOG_DIR}"
    mkdir -p "${DEFAULT_CONFIG_DIR}"
    
    # Set permissions
    if [[ "$OS" != "macos" ]]; then
        useradd -r -s /bin/false a2z-ids || true
        chown -R a2z-ids:a2z-ids "${DEFAULT_DATA_DIR}" "${DEFAULT_LOG_DIR}"
    fi
    
    print_success "Directories created"
}

# Build the application
build_application() {
    if $SKIP_BUILD; then
        print_status "Skipping build process"
        return
    fi
    
    print_status "Building A2Z IDS/IPS..."
    
    cd "$PROJECT_DIR"
    
    # Build with Docker Compose
    if $USE_DOCKER_COMPOSE; then
        print_status "Building with Docker Compose..."
        docker-compose -f docker-compose.standalone.yml build
    else
        # Native build
        print_status "Building core engine..."
        cd core-engine
        cargo build --release
        cp target/release/a2z-ids /usr/local/bin/
        cd ..
        
        print_status "Building management API..."
        cd management-api
        go build -o a2z-ids-api
        cp a2z-ids-api /usr/local/bin/
        cd ..
        
        print_status "Building web dashboard..."
        cd web-interface
        npm install
        npm run build
        cp -r dist/* /var/www/a2z-ids/
        cd ..
    fi
    
    print_success "Application built successfully"
}

# Configure the system
configure_system() {
    print_status "Configuring A2Z IDS/IPS..."
    
    # Copy configuration files
    cp -r "$PROJECT_DIR/config/"* "$DEFAULT_CONFIG_DIR/"
    
    # Create environment file
    cat > "$PROJECT_DIR/.env" << EOF
NETWORK_INTERFACE=$NETWORK_INTERFACE
DEPLOYMENT_MODE=$DEPLOYMENT_MODE
GRAFANA_PASSWORD=$GRAFANA_PASSWORD
JWT_SECRET=$JWT_SECRET
EOF
    
    # Update configuration for selected interface
    sed -i "s/interface: \"eth0\"/interface: \"$NETWORK_INTERFACE\"/" "$DEFAULT_CONFIG_DIR/config.yaml"
    sed -i "s/mode: \"passive\"/mode: \"$DEPLOYMENT_MODE\"/" "$DEFAULT_CONFIG_DIR/config.yaml"
    
    print_success "System configured"
}

# Start the services
start_services() {
    print_status "Starting A2Z IDS/IPS services..."
    
    cd "$PROJECT_DIR"
    
    if $USE_DOCKER_COMPOSE; then
        docker-compose -f docker-compose.standalone.yml up -d
        
        # Wait for services to be ready
        print_status "Waiting for services to start..."
        sleep 30
        
        # Check service health
        if docker-compose -f docker-compose.standalone.yml ps | grep -q "Up"; then
            print_success "Services started successfully"
        else
            print_error "Some services failed to start"
            docker-compose -f docker-compose.standalone.yml logs
            exit 1
        fi
    else
        # Start services with systemd
        print_status "Creating systemd services..."
        # TODO: Add systemd service files for native installation
        print_warning "Native systemd integration not yet implemented"
    fi
}

# Display access information
show_access_info() {
    print_success "A2Z IDS/IPS deployment completed!"
    echo
    echo "Access Information:"
    echo "=================="
    echo "🌐 Web Dashboard:     http://localhost:3000"
    echo "📊 Grafana:           http://localhost:3001 (admin:$GRAFANA_PASSWORD)"
    echo "🔧 API:               http://localhost:8080"
    echo "📈 Prometheus:        http://localhost:9090"
    echo
    echo "Configuration:"
    echo "=============="
    echo "📁 Config Dir:        $DEFAULT_CONFIG_DIR"
    echo "📊 Data Dir:          $DEFAULT_DATA_DIR"
    echo "📝 Log Dir:           $DEFAULT_LOG_DIR"
    echo "🔌 Interface:         $NETWORK_INTERFACE"
    echo "⚙️  Mode:             $DEPLOYMENT_MODE"
    echo
    echo "Useful Commands:"
    echo "==============="
    if $USE_DOCKER_COMPOSE; then
        echo "View logs:    docker-compose -f docker-compose.standalone.yml logs -f"
        echo "Stop:         docker-compose -f docker-compose.standalone.yml down"
        echo "Restart:      docker-compose -f docker-compose.standalone.yml restart"
    else
        echo "Check status: systemctl status a2z-ids"
        echo "View logs:    journalctl -u a2z-ids -f"
        echo "Stop:         systemctl stop a2z-ids"
        echo "Start:        systemctl start a2z-ids"
    fi
    echo
}

# Main function
main() {
    print_status "Starting A2Z IDS/IPS deployment..."
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -i|--interface)
                NETWORK_INTERFACE="$2"
                shift 2
                ;;
            -m|--mode)
                DEPLOYMENT_MODE="$2"
                shift 2
                ;;
            -d|--install-dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            --skip-docker)
                SKIP_DOCKER=true
                shift
                ;;
            --skip-build)
                SKIP_BUILD=true
                shift
                ;;
            --native)
                USE_DOCKER_COMPOSE=false
                shift
                ;;
            --grafana-password)
                GRAFANA_PASSWORD="$2"
                shift 2
                ;;
            --jwt-secret)
                JWT_SECRET="$2"
                shift 2
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Run deployment steps
    detect_os
    check_privileges
    install_dependencies
    
    if $USE_DOCKER_COMPOSE; then
        install_docker
    else
        install_rust
        install_go
        install_nodejs
        create_directories
    fi
    
    generate_jwt_secret
    configure_system
    build_application
    start_services
    show_access_info
    
    print_success "Deployment completed successfully!"
}

# Run main function
main "$@" 