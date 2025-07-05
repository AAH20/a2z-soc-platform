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
