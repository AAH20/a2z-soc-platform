#!/bin/bash

# A2Z SOC Network Agent MacOS Build Script
# Creates a functional MacOS agent package with improved network monitoring

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
AGENT_NAME="a2z-network-agent"
VERSION="1.2.4"
BUILD_DIR="build/macos"
DIST_DIR="dist"
BUNDLE_ID="com.a2zsoc.network-agent"
INSTALL_PREFIX="/usr/local/a2z-soc"
APP_NAME="A2Z SOC Network Agent"

# Function to print colored output
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

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check for Node.js
    if ! command -v node &> /dev/null; then
        print_error "Node.js is required but not installed"
        print_status "Installing Node.js via Homebrew..."
        if command -v brew &> /dev/null; then
            brew install node
        else
            print_error "Please install Node.js manually: https://nodejs.org/"
        exit 1
        fi
    fi
    
    # Check Node.js version
    NODE_VERSION=$(node --version | cut -d'v' -f2)
    if [[ "$(printf '%s\n' "18.0.0" "$NODE_VERSION" | sort -V | head -n1)" != "18.0.0" ]]; then
        print_error "Node.js version 18.0.0 or higher is required (found: $NODE_VERSION)"
        exit 1
    fi
    
    # Check for npm
    if ! command -v npm &> /dev/null; then
        print_error "npm is required but not installed"
        exit 1
    fi
    
    # Check for system tools
    for tool in xcode-select security codesign; do
        if ! command -v $tool &> /dev/null; then
            print_warning "$tool not found - some features may be limited"
        fi
    done
    
    print_success "Prerequisites check passed"
}

# Install dependencies
install_dependencies() {
    print_status "Installing and verifying dependencies..."
    
    # Install Node.js dependencies (without problematic native modules)
    npm install --production --no-optional
    
    # Check if we have required system tools for network monitoring
    if command -v brew &> /dev/null; then
        print_status "Checking system dependencies via Homebrew..."
        
        # Check for useful network tools (optional)
        for tool in nmap tcpdump netstat lsof; do
            if ! command -v $tool &> /dev/null; then
                print_warning "$tool not available - consider installing with: brew install $tool"
            fi
        done
        
    else
        print_warning "Homebrew not found. Some optional features may not be available."
        print_status "Consider installing Homebrew: https://brew.sh/"
    fi
    
    print_success "Dependencies verified"
}

# Create build directory structure
create_build_structure() {
    print_status "Creating build directory structure..."
    
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"/{bin,lib,config,logs,scripts,Resources,Contents/{MacOS,Resources}}
    
    # Create app bundle structure
    mkdir -p "$BUILD_DIR/Contents/MacOS"
    mkdir -p "$BUILD_DIR/Contents/Resources"
    
    print_success "Build structure created"
}

# Build the agent core
build_agent_core() {
    print_status "Building agent core..."
    
    # Copy source files
    cp -r src/ "$BUILD_DIR/lib/"
    cp index.js "$BUILD_DIR/lib/"
    cp package.json "$BUILD_DIR/lib/"
    
    # Install dependencies in build directory (production only, no optional deps)
    (cd "$BUILD_DIR/lib" && npm install --production --no-optional --silent)
    
    # Create main executable script
    cat > "$BUILD_DIR/bin/a2z-agent" << 'EOF'
#!/usr/bin/env node

// A2Z SOC Network Agent - MacOS
const path = require('path');
const fs = require('fs');

// Get the directory where this script is located
const scriptDir = __dirname;
const agentRoot = path.join(scriptDir, '..');
const libPath = path.join(agentRoot, 'lib');
const indexPath = path.join(libPath, 'index.js');

// Check if the main agent file exists
if (!fs.existsSync(indexPath)) {
    console.error('❌ Error: Agent library not found at', indexPath);
    console.error('Please ensure the agent is properly installed.');
    process.exit(1);
}

// Set up environment
process.chdir(libPath);

// Check for macOS compatibility
if (process.platform !== 'darwin') {
    console.warn('⚠️  Warning: This agent is optimized for macOS');
}

// Check privileges for advanced features
if (process.getuid && process.getuid() === 0) {
    console.log('🔐 Running with root privileges - full features available');
} else {
    console.log('💡 Running in user mode - some features may be limited');
    console.log('   For full packet capture: sudo ./a2z-agent');
}

try {
    // Load and run the main agent
    require(indexPath);
} catch (error) {
    console.error('❌ Error starting agent:', error.message);
    if (error.stack) {
        console.error('Stack trace:', error.stack);
    }
    process.exit(1);
}
EOF
    
    chmod +x "$BUILD_DIR/bin/a2z-agent"
    
    # Create MacOS app bundle executable
    cat > "$BUILD_DIR/Contents/MacOS/$APP_NAME" << 'EOF'
#!/bin/bash

# Get the directory of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
AGENT_ROOT="$(dirname "$(dirname "$DIR")")"

# Set up environment
export PATH="$AGENT_ROOT/bin:$PATH"
export A2Z_AGENT_ROOT="$AGENT_ROOT"

# Check for root privileges if needed
if [ "$1" = "--privileged" ] || [ "$1" = "--root" ]; then
    if [ "$EUID" -ne 0 ]; then
        echo "🔐 Root privileges required for advanced packet capture"
        echo "💡 Requesting administrator access..."
        exec sudo "$0" "$@"
    fi
fi

# Run the agent
cd "$AGENT_ROOT"
exec "$AGENT_ROOT/bin/a2z-agent" "$@"
EOF
    
    chmod +x "$BUILD_DIR/Contents/MacOS/$APP_NAME"
    
    print_success "Agent core built"
}

# Create configuration files
create_configuration() {
    print_status "Creating configuration files..."
    
    # Create agent configuration
    cat > "$BUILD_DIR/config/agent.json" << 'EOF'
{
    "agent": {
        "id": "a2z-macos-agent",
        "version": "1.2.4",
        "name": "A2Z SOC Network Agent",
        "platform": "darwin"
    },
    "network": {
        "interface": "auto",
        "monitoring": {
            "enabled": true,
            "connectionInterval": 5000,
            "maxConnections": 1000,
            "useSystemTools": true,
            "enablePacketCapture": false
        }
    },
    "logging": {
        "level": "info",
        "enableFileLogging": true,
        "logDirectory": "./logs",
        "maxLogSize": "10MB",
        "maxLogFiles": 5
    },
    "security": {
        "enableThreatDetection": true,
        "enableLogAnalysis": true,
        "alertThreshold": "medium"
    },
    "api": {
        "enabled": true,
        "port": 5200,
        "host": "127.0.0.1"
    },
    "cloud": {
        "enabled": false,
        "endpoint": "",
        "apiKey": ""
    },
    "macos": {
        "useUnifiedLogging": true,
        "monitorSecurityEvents": true,
        "requireRoot": false,
        "systemToolsPath": "/usr/bin:/usr/sbin:/bin:/sbin"
    }
}
EOF

    # Create logging configuration
    cat > "$BUILD_DIR/config/logging.json" << 'EOF'
{
    "loggers": {
        "root": {
            "level": "INFO",
            "handlers": ["console", "file"]
        },
        "network": {
            "level": "DEBUG",
            "handlers": ["file"]
        },
        "security": {
            "level": "INFO",
            "handlers": ["console", "file", "alert"]
        }
    },
    "handlers": {
        "console": {
            "type": "console",
            "format": "%(timestamp)s [%(level)s] %(message)s"
        },
        "file": {
            "type": "file",
            "filename": "./logs/agent.log",
            "maxSize": "10MB",
            "backupCount": 5,
            "format": "%(timestamp)s [%(level)s] %(logger)s: %(message)s"
        },
        "alert": {
            "type": "alert",
            "minLevel": "WARNING"
        }
    }
}
EOF

    # Create service configuration
    cat > "$BUILD_DIR/config/service.json" << 'EOF'
{
    "service": {
        "name": "a2z-network-agent",
        "displayName": "A2Z SOC Network Agent",
        "description": "A2Z SOC Network Security Monitoring Agent for macOS",
        "execPath": "./bin/a2z-agent",
        "workingDirectory": "./",
        "autoStart": false,
        "restart": true,
        "restartDelay": 5000
    },
    "launchd": {
        "label": "com.a2zsoc.network-agent",
        "programArguments": ["./bin/a2z-agent"],
        "runAtLoad": false,
        "keepAlive": true,
        "standardOutPath": "./logs/stdout.log",
        "standardErrorPath": "./logs/stderr.log"
    }
}
EOF
    
    print_success "Configuration files created"
}

# Create App Bundle Info.plist
create_app_bundle() {
    print_status "Creating macOS app bundle..."
    
    cat > "$BUILD_DIR/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDisplayName</key>
    <string>$APP_NAME</string>
    <key>CFBundleExecutable</key>
    <string>$APP_NAME</string>
    <key>CFBundleIdentifier</key>
    <string>$BUNDLE_ID</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>$AGENT_NAME</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>$VERSION</string>
    <key>CFBundleVersion</key>
    <string>$VERSION</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.14.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSAppTransportSecurity</key>
    <dict>
        <key>NSAllowsArbitraryLoads</key>
        <true/>
    </dict>
    <key>NSRequiresAquaSystemAppearance</key>
    <false/>
</dict>
</plist>
EOF
    
    # Create app icon (placeholder)
    cat > "$BUILD_DIR/Contents/Resources/app.icns" << 'EOF'
# Placeholder for app icon
# In a real deployment, this would be a proper .icns file
EOF
    
    print_success "App bundle created"
}

# Create helper scripts
create_helper_scripts() {
    print_status "Creating helper scripts..."
    
    # Install script
    cat > "$BUILD_DIR/scripts/install.sh" << 'EOF'
#!/bin/bash

echo "🍎 Installing A2Z SOC Network Agent for macOS..."

INSTALL_DIR="/usr/local/a2z-soc"
AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  This script requires administrator privileges"
    echo "💡 Please run with: sudo ./install.sh"
    exit 1
fi

# Create installation directory
mkdir -p "$INSTALL_DIR"

# Copy agent files
cp -r "$AGENT_DIR"/* "$INSTALL_DIR/"

# Set permissions
chmod +x "$INSTALL_DIR/bin/a2z-agent"
chmod +x "$INSTALL_DIR/scripts/"*.sh

# Create symlink
ln -sf "$INSTALL_DIR/bin/a2z-agent" /usr/local/bin/a2z-agent

echo "✅ A2Z SOC Network Agent installed successfully"
echo "💡 Start with: a2z-agent"
echo "💡 For full features: sudo a2z-agent"
EOF

    chmod +x "$BUILD_DIR/scripts/install.sh"
    
    # Uninstall script
    cat > "$BUILD_DIR/scripts/uninstall.sh" << 'EOF'
#!/bin/bash

echo "🗑️  Uninstalling A2Z SOC Network Agent..."

INSTALL_DIR="/usr/local/a2z-soc"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  This script requires administrator privileges"
    echo "💡 Please run with: sudo ./uninstall.sh"
    exit 1
fi

# Stop agent if running
pkill -f "a2z-agent" || true

# Remove files
rm -rf "$INSTALL_DIR"
rm -f /usr/local/bin/a2z-agent

echo "✅ A2Z SOC Network Agent uninstalled"
EOF

    chmod +x "$BUILD_DIR/scripts/uninstall.sh"
    
    # Test script
    cat > "$BUILD_DIR/scripts/test.sh" << 'EOF'
#!/bin/bash

echo "🧪 Testing A2Z SOC Network Agent..."

AGENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Test Node.js availability
if ! command -v node &> /dev/null; then
    echo "❌ Node.js not found"
    exit 1
fi

# Test agent startup
cd "$AGENT_DIR"
timeout 10s "$AGENT_DIR/bin/a2z-agent" --test || {
    echo "❌ Agent test failed"
    exit 1
}

echo "✅ Agent test passed"
EOF

    chmod +x "$BUILD_DIR/scripts/test.sh"
    
    print_success "Helper scripts created"
}

# Package the agent
package_agent() {
    print_status "Packaging agent..."
    
    mkdir -p "$DIST_DIR"
    
    # Create tarball
    tar -czf "$DIST_DIR/a2z-network-agent-macos-$VERSION.tar.gz" -C "$BUILD_DIR" .
    
    # Create installer package
    if command -v pkgbuild &> /dev/null; then
        pkgbuild --root "$BUILD_DIR" \
                 --identifier "$BUNDLE_ID" \
                 --version "$VERSION" \
                 --install-location "$INSTALL_PREFIX" \
                 "$DIST_DIR/a2z-network-agent-$VERSION.pkg" || {
            print_warning "Package creation failed - installer not available"
        }
    fi
    
    print_success "Agent packaged: $DIST_DIR/"
}

# Test the built agent
test_agent() {
    print_status "Testing built agent..."
    
    # Test agent executable
    if [ -x "$BUILD_DIR/bin/a2z-agent" ]; then
        print_success "Agent executable is valid"
    else
        print_error "Agent executable is not valid"
        exit 1
    fi
    
    # Test configuration
    if [ -f "$BUILD_DIR/config/agent.json" ]; then
        print_success "Configuration files are present"
    else
        print_error "Configuration files are missing"
        exit 1
    fi
    
    # Test dependencies
    cd "$BUILD_DIR/lib"
    if node -e "require('./index.js')" 2>/dev/null; then
        print_success "Dependencies are satisfied"
    else
        print_warning "Some dependencies may be missing"
    fi
    
    print_success "Agent testing completed"
}

# Generate documentation
generate_docs() {
    print_status "Generating documentation..."
    
    cat > "$BUILD_DIR/README.md" << 'EOF'
# A2Z SOC Network Agent for macOS

A cross-platform network security monitoring agent optimized for macOS.

## Features

- Real-time network monitoring using system tools
- macOS unified logging integration
- Threat detection and alerting
- System security monitoring
- RESTful API interface
- Cloud connectivity support

## Installation

### Option 1: Simple Installation
```bash
sudo ./scripts/install.sh
```

### Option 2: Manual Installation
```bash
# Copy to desired location
cp -r . /usr/local/a2z-soc/

# Create symlink
ln -s /usr/local/a2z-soc/bin/a2z-agent /usr/local/bin/a2z-agent
```

## Usage

### Basic Usage
```bash
# Start agent (user mode)
./bin/a2z-agent

# Start with full privileges
sudo ./bin/a2z-agent
```

### Configuration

Edit `config/agent.json` to customize:
- Network interfaces to monitor
- Security alert thresholds
- API settings
- Cloud connectivity

### System Requirements

- macOS 10.14 or later
- Node.js 18.0 or later
- Network administrative privileges (for full features)

### Optional Tools

For enhanced monitoring:
```bash
brew install nmap tcpdump
```

## API

The agent provides a REST API on port 5200:

- `GET /status` - Agent status
- `GET /metrics` - Performance metrics
- `GET /alerts` - Recent security alerts
- `GET /config` - Current configuration

## Troubleshooting

### Permission Issues
```bash
# Check current permissions
id

# Run with elevated privileges
sudo ./bin/a2z-agent
```

### Network Monitoring Issues
```bash
# Check available network interfaces
ifconfig -a

# Test network tools
which netstat lsof tcpdump
```

### Log Analysis
```bash
# Check agent logs
tail -f logs/agent.log

# Check system logs
log stream --predicate 'subsystem contains "a2z"'
```

## Support

For issues and support:
- Check logs in `./logs/`
- Review configuration in `./config/`
- Run diagnostic: `./scripts/test.sh`

## Version

1.2.4 - macOS Optimized Release
EOF

    print_success "Documentation generated"
}

# Main build process
main() {
    print_status "Starting A2Z SOC Network Agent build for macOS..."
    print_status "Version: $VERSION"
    
    check_prerequisites
    install_dependencies
    create_build_structure
    build_agent_core
    create_configuration
    create_app_bundle
    create_helper_scripts
    test_agent
    package_agent
    generate_docs
    
    print_success "Build completed successfully!"
    print_status "Build artifacts:"
    print_status "  - Build directory: $BUILD_DIR"
    print_status "  - Distribution: $DIST_DIR"
    print_status ""
    print_status "Next steps:"
    print_status "  1. Test: cd $BUILD_DIR && ./scripts/test.sh"
    print_status "  2. Install: cd $BUILD_DIR && sudo ./scripts/install.sh"
    print_status "  3. Run: a2z-agent"
    print_status ""
    print_status "For full packet capture capabilities, run with root privileges:"
    print_status "  sudo a2z-agent"
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "A2Z SOC Network Agent - macOS Build Script"
    echo ""
        echo "Usage: $0 [options]"
    echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --clean        Clean build directory before building"
        echo "  --test-only    Only run tests on existing build"
    echo ""
        exit 0
        ;;
    --clean)
        print_status "Cleaning build directory..."
        rm -rf "$BUILD_DIR" "$DIST_DIR"
        print_success "Clean completed"
        main
        ;;
    --test-only)
        if [ -d "$BUILD_DIR" ]; then
            test_agent
        else
            print_error "No build directory found. Run build first."
            exit 1
        fi
        ;;
    *)
        main
        ;;
esac 