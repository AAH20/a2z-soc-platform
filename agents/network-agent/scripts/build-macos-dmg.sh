#!/bin/bash

# A2Z SOC Network Agent - MacOS DMG Builder
# Creates a proper .dmg installer package

set -e

# Configuration
AGENT_NAME="A2Z SOC Network Agent"
AGENT_VERSION="1.2.3"
BUNDLE_ID="com.a2zsoc.network-agent"
DMG_NAME="A2Z-SOC-Network-Agent-${AGENT_VERSION}"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
BUILD_DIR="$PROJECT_ROOT/build"
DMG_BUILD_DIR="$BUILD_DIR/dmg-build"
DMG_OUTPUT_DIR="$BUILD_DIR/dmg"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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
    
    # Check if we're on macOS
    if [[ "$OSTYPE" != "darwin"* ]]; then
        print_error "This script must be run on macOS"
        exit 1
    fi
    
    # Check for required tools
    command -v hdiutil >/dev/null 2>&1 || { print_error "hdiutil not found"; exit 1; }
    command -v node >/dev/null 2>&1 || { print_error "Node.js not found"; exit 1; }
    command -v npm >/dev/null 2>&1 || { print_error "npm not found"; exit 1; }
    
    print_success "Prerequisites check passed"
}

# Create directory structure
create_dmg_structure() {
    print_status "Creating DMG build structure..."
    
    rm -rf "$DMG_BUILD_DIR"
    mkdir -p "$DMG_BUILD_DIR"
    mkdir -p "$DMG_OUTPUT_DIR"
    
    # Create the app bundle structure
    APP_BUNDLE="$DMG_BUILD_DIR/${AGENT_NAME}.app"
    mkdir -p "$APP_BUNDLE/Contents/"{MacOS,Resources,Frameworks}
    
    print_success "DMG structure created"
}

# Build the agent
build_agent() {
    print_status "Building agent components..."
    
    # Build agent directly here instead of calling external script
    AGENT_DIR="$(dirname "$SCRIPT_DIR")"
    APP_BUNDLE="$DMG_BUILD_DIR/${AGENT_NAME}.app"
    
    # Create agent lib directory
    mkdir -p "$APP_BUNDLE/Contents/lib"
    mkdir -p "$APP_BUNDLE/Contents/MacOS"
    mkdir -p "$APP_BUNDLE/Contents/Resources"
    mkdir -p "$APP_BUNDLE/Contents/config"
    mkdir -p "$APP_BUNDLE/Contents/bin"
    
    # Copy source files
    cp -r "$AGENT_DIR/src/"* "$APP_BUNDLE/Contents/lib/"
    cp "$AGENT_DIR/index.js" "$APP_BUNDLE/Contents/lib/"
    cp "$AGENT_DIR/package.json" "$APP_BUNDLE/Contents/lib/"
    
    # Install dependencies
    (cd "$APP_BUNDLE/Contents/lib" && npm install --production --silent)
    
    # Create configuration
    cat > "$APP_BUNDLE/Contents/config/agent.json" << 'EOF'
{
    "agentId": "",
    "version": "1.2.3",
    "platform": "darwin",
    "tenantId": "",
    "apiKey": "",
    "cloudEndpoint": "wss://api.a2zsoc.com",
    "networkInterface": "any",
    "apiPort": 5200,
    "apiHost": "127.0.0.1",
    "logLevel": "info",
    "pcapFilter": "ip",
    "bufferSize": 10485760,
    "bufferTimeout": 1000,
    "maxBufferSize": 1000,
    "heartbeatInterval": 30000,
    "dataTransmissionInterval": 60000,
    "logCollection": {
        "enabled": true,
        "sources": [
            "unified-log",
            "system-logs",
            "application-logs",
            "crash-reports"
        ],
        "filters": {
            "excludePatterns": [
                ".*debug.*",
                ".*verbose.*"
            ],
            "includePatterns": [
                ".*error.*",
                ".*warning.*",
                ".*security.*",
                ".*network.*"
            ]
        }
    },
    "security": {
        "tlsVerify": true,
        "encryptData": true,
        "anonymizeIPs": false
    },
    "storage": {
        "localBuffer": true,
        "maxLocalStorage": "100MB",
        "retentionDays": 7
    }
}
EOF
    
    # Create the main executable
    cat > "$APP_BUNDLE/Contents/bin/a2z-agent" << 'EOF'
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

try {
    // Load and run the main agent
    require(indexPath);
} catch (error) {
    console.error('❌ Error starting agent:', error.message);
    process.exit(1);
}
EOF
    
    chmod +x "$APP_BUNDLE/Contents/bin/a2z-agent"
    
    print_success "Agent components built"
}

# Create Info.plist
create_info_plist() {
    print_status "Creating Info.plist..."
    
    APP_BUNDLE="$DMG_BUILD_DIR/${AGENT_NAME}.app"
    
    cat > "$APP_BUNDLE/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDisplayName</key>
    <string>${AGENT_NAME}</string>
    <key>CFBundleExecutable</key>
    <string>a2z-agent</string>
    <key>CFBundleIdentifier</key>
    <string>${BUNDLE_ID}</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>${AGENT_NAME}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>${AGENT_VERSION}</string>
    <key>CFBundleVersion</key>
    <string>${AGENT_VERSION}</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.14</string>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>LSBackgroundOnly</key>
    <true/>
    <key>NSAppleEventsUsageDescription</key>
    <string>A2Z SOC Network Agent needs to monitor system events for security analysis.</string>
    <key>NSSystemAdministrationUsageDescription</key>
    <string>A2Z SOC Network Agent requires administrative access to monitor network traffic and system logs.</string>
</dict>
</plist>
EOF
    
    print_success "Info.plist created"
}

# Create launcher script
create_launcher() {
    print_status "Creating launcher script..."
    
    APP_BUNDLE="$DMG_BUILD_DIR/${AGENT_NAME}.app"
    
    # Move the binary to MacOS folder and create launcher
    mv "$APP_BUNDLE/Contents/bin/a2z-agent" "$APP_BUNDLE/Contents/MacOS/a2z-agent"
    chmod +x "$APP_BUNDLE/Contents/MacOS/a2z-agent"
    
    # Create a GUI launcher script
    cat > "$APP_BUNDLE/Contents/MacOS/A2Z-SOC-Agent-Launcher" << 'EOF'
#!/bin/bash

# A2Z SOC Network Agent Launcher
BUNDLE_DIR="$(dirname "$(dirname "$0")")"
AGENT_PATH="$BUNDLE_DIR/MacOS/a2z-agent"

# Function to show notification
show_notification() {
    osascript -e "display notification \"$1\" with title \"A2Z SOC Network Agent\""
}

# Check if agent is already running
if curl -s http://localhost:5200/health >/dev/null 2>&1; then
    show_notification "Agent is already running"
    open "http://localhost:5200/status"
    exit 0
fi

# Start the agent in background
"$AGENT_PATH" start &

# Wait a moment and check if it started
sleep 3
if curl -s http://localhost:5200/health >/dev/null 2>&1; then
    show_notification "Agent started successfully"
    open "http://localhost:5200/status"
else
    show_notification "Failed to start agent"
    # Try to show error in Terminal
    osascript -e 'tell application "Terminal" to do script "'"$AGENT_PATH"' start"'
fi
EOF
    
    chmod +x "$APP_BUNDLE/Contents/MacOS/A2Z-SOC-Agent-Launcher"
    
    print_success "Launcher script created"
}

# Create installer scripts
create_installer_scripts() {
    print_status "Creating installer scripts..."
    
    # Create installation script
    cat > "$DMG_BUILD_DIR/Install A2Z SOC Agent.command" << 'EOF'
#!/bin/bash

# A2Z SOC Network Agent Installer
echo "🚀 Installing A2Z SOC Network Agent..."

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
APP_BUNDLE="$SCRIPT_DIR/A2Z SOC Network Agent.app"

# Check if running as root/admin
if [[ $EUID -ne 0 ]]; then
    echo "⚠️  This installer requires administrator privileges."
    echo "Please run: sudo '$0'"
    exit 1
fi

# Create installation directory
INSTALL_DIR="/Applications/A2Z SOC"
mkdir -p "$INSTALL_DIR"

# Copy the app bundle
echo "📦 Copying application files..."
cp -r "$APP_BUNDLE" "$INSTALL_DIR/"

# Create LaunchDaemon for automatic startup
echo "⚙️  Creating system service..."
cat > /Library/LaunchDaemons/com.a2zsoc.network-agent.plist << PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.a2zsoc.network-agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/A2Z SOC Network Agent.app/Contents/MacOS/a2z-agent</string>
        <string>start</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/a2z-soc-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/a2z-soc-agent-error.log</string>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR/A2Z SOC Network Agent.app/Contents</string>
</dict>
</plist>
PLIST_EOF

# Set proper permissions
chown root:wheel /Library/LaunchDaemons/com.a2zsoc.network-agent.plist
chmod 644 /Library/LaunchDaemons/com.a2zsoc.network-agent.plist

# Load the LaunchDaemon
launchctl load /Library/LaunchDaemons/com.a2zsoc.network-agent.plist

# Create uninstaller
cat > "$INSTALL_DIR/Uninstall A2Z SOC Agent.command" << UNINSTALL_EOF
#!/bin/bash
echo "🗑️  Uninstalling A2Z SOC Network Agent..."

# Stop and unload the service
sudo launchctl unload /Library/LaunchDaemons/com.a2zsoc.network-agent.plist 2>/dev/null
sudo rm -f /Library/LaunchDaemons/com.a2zsoc.network-agent.plist

# Remove application files
sudo rm -rf "$INSTALL_DIR"

# Remove log files
sudo rm -f /var/log/a2z-soc-agent*.log

echo "✅ A2Z SOC Network Agent has been uninstalled."
UNINSTALL_EOF

chmod +x "$INSTALL_DIR/Uninstall A2Z SOC Agent.command"

echo ""
echo "✅ A2Z SOC Network Agent installation completed!"
echo ""
echo "🌐 API Access: http://localhost:5200/status"
echo "📊 Dashboard: http://localhost:5200"
echo "📋 Logs: tail -f /var/log/a2z-soc-agent.log"
echo ""
echo "To uninstall, run: '$INSTALL_DIR/Uninstall A2Z SOC Agent.command'"
echo ""
EOF
    
    chmod +x "$DMG_BUILD_DIR/Install A2Z SOC Agent.command"
    
    # Create README
    cat > "$DMG_BUILD_DIR/README.txt" << EOF
A2Z SOC Network Agent for macOS v${AGENT_VERSION}

INSTALLATION:
1. Double-click "Install A2Z SOC Agent.command"
2. Enter your administrator password when prompted
3. The agent will start automatically

USAGE:
- API Access: http://localhost:5200/status
- View logs: tail -f /var/log/a2z-soc-agent.log
- Manual start: /Applications/A2Z SOC/A2Z SOC Network Agent.app/Contents/MacOS/a2z-agent start

FEATURES:
✓ Real-time log collection from macOS Unified Logging
✓ Network traffic monitoring and analysis
✓ Security threat detection and alerting
✓ REST API for integration with A2Z SOC Platform
✓ Automatic startup on system boot

SUPPORT:
Documentation: https://docs.a2zsoc.com/agents/macos
Support: support@a2zsoc.com

Copyright © 2024 A2Z SOC. All rights reserved.
EOF
    
    print_success "Installer scripts created"
}

# Create the DMG
create_dmg() {
    print_status "Creating DMG package..."
    
    DMG_PATH="$DMG_OUTPUT_DIR/${DMG_NAME}.dmg"
    TEMP_DMG="$DMG_OUTPUT_DIR/${DMG_NAME}_temp.dmg"
    
    # Remove existing DMG
    rm -f "$DMG_PATH" "$TEMP_DMG"
    
    # Create temporary DMG with enough space
    hdiutil create -size 200m -fs HFS+ -volname "A2Z SOC Network Agent" "$TEMP_DMG"
    
    # Mount the DMG
    MOUNT_POINT="/tmp/A2Z_SOC_DMG_$$"
    mkdir -p "$MOUNT_POINT"
    hdiutil attach "$TEMP_DMG" -mountpoint "$MOUNT_POINT" -nobrowse
    
    # Copy files to DMG
    cp -r "$DMG_BUILD_DIR/"* "$MOUNT_POINT/"
    
    # Create symbolic link to Applications folder
    ln -s /Applications "$MOUNT_POINT/Applications"
    
    # Unmount the DMG
    hdiutil detach "$MOUNT_POINT"
    rmdir "$MOUNT_POINT"
    
    # Convert to compressed DMG
    hdiutil convert "$TEMP_DMG" -format UDZO -o "$DMG_PATH"
    rm "$TEMP_DMG"
    
    print_success "DMG created: $DMG_PATH"
}

# Main execution
main() {
    echo "🚀 Building A2Z SOC Network Agent DMG for macOS..."
    echo "Version: $AGENT_VERSION"
    echo ""
    
    check_prerequisites
    create_dmg_structure
    build_agent
    create_info_plist
    create_launcher
    create_installer_scripts
    create_dmg
    
    echo ""
    print_success "✅ DMG build completed successfully!"
    echo ""
    echo "📋 Build output:"
    echo "   DMG: $DMG_OUTPUT_DIR/${DMG_NAME}.dmg"
    echo "   Size: $(du -h "$DMG_OUTPUT_DIR/${DMG_NAME}.dmg" | cut -f1)"
    echo ""
}

# Run main function
main "$@" 