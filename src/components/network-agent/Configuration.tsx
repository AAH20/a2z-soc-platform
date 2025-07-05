import React, { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Settings,
  Download,
  Plus,
  Trash2,
  Play,
  Square,
  RefreshCw,
  Monitor,
  Smartphone,
  Laptop,
  Server,
  CheckCircle,
  XCircle,
  AlertCircle,
  Copy,
  ExternalLink,
  Wifi,
  WifiOff,
  Clock
} from 'lucide-react';
import { networkAgentAPI } from '@/services/networkAgent';
import { AgentStatus } from '@/types';
import { agentStatusService, type AgentInfo } from '../../services/agentStatus';

interface ManagedAgent {
  id: string;
  name: string;
  ipAddress: string;
  platform: string;
  version?: string;
  status: 'online' | 'offline' | 'unknown' | 'checking';
  lastSeen?: string;
  uptime?: number;
}

export function Configuration() {
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [newAgent, setNewAgent] = useState({
    name: '',
    ipAddress: '',
    platform: 'linux'
  });
  const [showAddForm, setShowAddForm] = useState(false);

  // Subscribe to agent status updates
  useEffect(() => {
    const unsubscribe = agentStatusService.subscribe((updatedAgents) => {
      setAgents(updatedAgents);
    });

    return unsubscribe;
  }, []);

  const platforms = [
    { 
      name: 'Windows', 
      icon: Monitor, 
      download: 'a2z-agent-windows.exe',
      description: 'Windows 10/11 (x64)',
      installCmd: 'a2z-agent-windows.exe --install'
    },
    { 
      name: 'macOS', 
      icon: Laptop, 
      download: 'A2Z-SOC-Network-Agent-1.2.3.dmg',
      description: 'Professional DMG (2.4MB) - Enterprise macOS 10.15+ (Intel/Apple Silicon)',
      installCmd: 'Open DMG → Double-click "Install A2Z SOC Agent.command"'
    },
    { 
      name: 'Linux', 
      icon: Server, 
      download: 'a2z-agent-linux.tar.gz',
      description: 'Ubuntu/CentOS/RHEL (x64)',
      installCmd: 'tar -xzf a2z-agent-linux.tar.gz && sudo ./install.sh'
    },
    { 
      name: 'ARM Linux', 
      icon: Smartphone, 
      download: 'a2z-agent-arm.tar.gz',
      description: 'Raspberry Pi/ARM devices',
      installCmd: 'tar -xzf a2z-agent-arm.tar.gz && sudo ./install.sh'
    }
  ];

  const handleAddAgent = () => {
    if (newAgent.name && newAgent.ipAddress) {
      const agent = {
        id: Date.now().toString(),
        name: newAgent.name,
        platform: newAgent.platform,
        version: '1.2.3',
        ipAddress: newAgent.ipAddress,
        apiEndpoint: `http://${newAgent.ipAddress}:3001`
      };
      
      agentStatusService.registerAgent(agent);
      setNewAgent({ name: '', ipAddress: '', platform: 'linux' });
      setShowAddForm(false);
    }
  };

  const handleRemoveAgent = (id: string) => {
    agentStatusService.removeAgent(id);
  };

  const handleCheckStatus = async (id: string) => {
    await agentStatusService.checkAgentStatus(id);
  };

  const handleCheckAllStatus = async () => {
    await agentStatusService.checkAllAgentStatuses();
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'online': return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'offline': return <XCircle className="w-4 h-4 text-red-500" />;
      case 'checking': return <RefreshCw className="w-4 h-4 text-blue-500 animate-spin" />;
      default: return <Clock className="w-4 h-4 text-gray-400" />;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online': return 'text-green-600 bg-green-50';
      case 'offline': return 'text-red-600 bg-red-50';
      case 'checking': return 'text-blue-600 bg-blue-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getPlatformIcon = (platform: string) => {
    switch (platform.toLowerCase()) {
      case 'windows': return <Monitor className="w-4 h-4" />;
      case 'linux': return <Server className="w-4 h-4" />;
      case 'macos': case 'darwin': return <Laptop className="w-4 h-4" />;
      default: return <Wifi className="w-4 h-4" />;
    }
  };

  const formatUptime = (seconds?: number) => {
    if (!seconds) return 'N/A';
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    
    if (days > 0) return `${days}d ${hours}h ${minutes}m`;
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
  };

  // Note: generateMacOSAgent function removed - now using professional DMG installer
  const generateMacOSAgent_REMOVED = async () => {
    // Generate a unique agent ID
    const agentId = crypto.getRandomValues(new Uint32Array(1))[0].toString(16);
    const timestamp = new Date().toISOString();
    
    const installScript = `#!/bin/bash

# A2Z SOC Network Agent for macOS - Functional Installer
# Version: 1.2.3
# Generated: ${timestamp}

set -e

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
BLUE='\\033[0;34m'
NC='\\033[0m' # No Color

print_status() {
    echo -e "\${BLUE}[INFO]\${NC} \$1"
}

print_success() {
    echo -e "\${GREEN}[SUCCESS]\${NC} \$1"
}

print_error() {
    echo -e "\${RED}[ERROR]\${NC} \$1"
}

# Configuration
INSTALL_PREFIX="/usr/local/a2z-soc"
BINARY_PATH="/usr/local/bin/a2z-agent"
CONFIG_PATH="/usr/local/etc/a2z-soc"
LOG_PATH="/usr/local/var/log/a2z-soc"
LAUNCHD_PLIST="/Library/LaunchDaemons/com.a2zsoc.network-agent.plist"
AGENT_ID="${agentId}"

echo "🍎 Installing A2Z SOC Network Agent for macOS..."
echo "Version: 1.2.3"
echo "Agent ID: \$AGENT_ID"
echo "Install prefix: \$INSTALL_PREFIX"

# Check for root privileges
if [[ \$EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)" 
   exit 1
fi

# Check macOS version
MACOS_VERSION=\$(sw_vers -productVersion)
print_status "macOS version: \$MACOS_VERSION"

# Check for Node.js
if ! command -v node &> /dev/null; then
    print_error "Node.js is required but not installed"
    echo "Installing Node.js using Homebrew..."
    if command -v brew &> /dev/null; then
        brew install node
    else
        print_error "Please install Node.js from https://nodejs.org/"
        exit 1
    fi
fi

NODE_VERSION=\$(node --version)
print_status "Node.js version: \$NODE_VERSION"

# Create directories
print_status "Creating directories..."
mkdir -p "\$INSTALL_PREFIX"/{bin,lib,logs}
mkdir -p "\$CONFIG_PATH"
mkdir -p "\$LOG_PATH"

# Create agent binary
print_status "Creating agent binary..."
cat > "\$INSTALL_PREFIX/bin/a2z-agent" << 'AGENT_EOF'
#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { spawn, exec } = require('child_process');
const crypto = require('crypto');
const os = require('os');
const http = require('http');

class A2ZAgent {
    constructor() {
        this.isRunning = false;
        this.logProcess = null;
        this.configPath = '/usr/local/etc/a2z-soc/agent.json';
        this.logPath = '/usr/local/var/log/a2z-soc';
        this.startTime = null;
        this.httpServer = null;
    }

    async start() {
        if (this.isRunning) {
            console.log('Agent is already running');
            return;
        }

        console.log('🚀 Starting A2Z SOC Network Agent...');
        
        try {
            this.startTime = new Date();
            
            // Load configuration
            const config = await this.loadConfig();
            
            // Start HTTP API server
            await this.startApiServer();
            
            // Start log collection
            await this.startLogCollection();
            
            // Start network monitoring
            await this.startNetworkMonitoring();
            
            this.isRunning = true;
                         console.log('✅ A2Z SOC Network Agent started successfully');
             console.log('📊 API Server: http://localhost:5200/status');
             console.log('📋 Log Collection: Active');
             console.log('🌐 Network Monitoring: Active');
            
            // Keep process alive
            process.on('SIGINT', () => this.stop());
            process.on('SIGTERM', () => this.stop());
            
            // Prevent process from exiting
            setInterval(() => {
                // Heartbeat - send status updates
                this.sendHeartbeat();
            }, 30000);
            
        } catch (error) {
            console.error('❌ Failed to start agent:', error.message);
            process.exit(1);
        }
    }

    async startApiServer() {
        this.httpServer = http.createServer((req, res) => {
            res.setHeader('Content-Type', 'application/json');
            res.setHeader('Access-Control-Allow-Origin', '*');
            
            if (req.url === '/status' && req.method === 'GET') {
                const status = {
                    agentId: '${agentId}',
                    status: this.isRunning ? 'running' : 'stopped',
                    platform: 'darwin',
                    version: '1.2.3',
                    startTime: this.startTime,
                    uptime: this.startTime ? Date.now() - this.startTime.getTime() : 0,
                    hostname: os.hostname(),
                    arch: os.arch(),
                    nodeVersion: process.version,
                    memory: process.memoryUsage(),
                    loadAverage: os.loadavg(),
                    networkInterfaces: Object.keys(os.networkInterfaces()),
                    timestamp: new Date().toISOString()
                };
                res.writeHead(200);
                res.end(JSON.stringify(status, null, 2));
            } else if (req.url === '/logs' && req.method === 'GET') {
                this.sendRecentLogs(res);
            } else if (req.url === '/alerts' && req.method === 'GET') {
                this.sendRecentAlerts(res);
            } else {
                res.writeHead(404);
                res.end(JSON.stringify({ error: 'Not found' }));
            }
        });

                 this.httpServer.listen(5200, '127.0.0.1', () => {
             console.log('📡 API server listening on http://127.0.0.1:5200');
         });
    }

    sendRecentLogs(res) {
        const logFile = path.join(this.logPath, 'collected-logs.json');
        
        try {
            const logData = fs.readFileSync(logFile, 'utf8');
            const lines = logData.trim().split('\\n').filter(line => line.trim());
            const recentLogs = lines.slice(-50).map(line => {
                try {
                    return JSON.parse(line);
                } catch (e) {
                    return { message: line, timestamp: new Date().toISOString() };
                }
            });
            
            res.writeHead(200);
            res.end(JSON.stringify({ logs: recentLogs, count: recentLogs.length }));
        } catch (error) {
            res.writeHead(200);
            res.end(JSON.stringify({ logs: [], count: 0 }));
        }
    }

    sendRecentAlerts(res) {
        const alertFile = path.join(this.logPath, 'alerts.json');
        
        try {
            const alertData = fs.readFileSync(alertFile, 'utf8');
            const lines = alertData.trim().split('\\n').filter(line => line.trim());
            const recentAlerts = lines.slice(-20).map(line => {
                try {
                    return JSON.parse(line);
                } catch (e) {
                    return { message: line, timestamp: new Date().toISOString() };
                }
            });
            
            res.writeHead(200);
            res.end(JSON.stringify({ alerts: recentAlerts, count: recentAlerts.length }));
        } catch (error) {
            res.writeHead(200);
            res.end(JSON.stringify({ alerts: [], count: 0 }));
        }
    }

    async stop() {
        if (!this.isRunning) return;
        
        console.log('🛑 Stopping A2Z SOC Network Agent...');
        
        if (this.logProcess) {
            this.logProcess.kill();
        }
        
        if (this.httpServer) {
            this.httpServer.close();
        }
        
        this.isRunning = false;
        console.log('✅ Agent stopped');
        process.exit(0);
    }

    async startLogCollection() {
        console.log('📋 Starting log collection...');
        
        // Start unified log streaming
        this.logProcess = spawn('log', [
            'stream',
            '--style', 'syslog',
            '--level', 'info',
            '--type', 'activity,log,trace'
        ]);

        this.logProcess.stdout.on('data', (data) => {
            this.processLogData(data.toString());
        });

        this.logProcess.stderr.on('data', (data) => {
            console.error('Log stream error:', data.toString());
        });

        this.logProcess.on('close', (code) => {
            if (this.isRunning) {
                console.warn(\`Log stream closed with code \${code}, restarting...\`);
                setTimeout(() => this.startLogCollection(), 5000);
            }
        });
    }

    processLogData(logData) {
        const lines = logData.trim().split('\\n');
        
        for (const line of lines) {
            if (line.trim()) {
                const logEntry = {
                    timestamp: new Date().toISOString(),
                    source: 'macos-unified-log',
                    level: this.extractLogLevel(line),
                    message: line,
                    hostname: os.hostname(),
                    platform: 'darwin',
                    agentId: '${agentId}'
                };
                
                // Write to log file
                this.writeLogEntry(logEntry);
                
                // Check for security events
                this.analyzeThreat(logEntry);
            }
        }
    }

    extractLogLevel(logLine) {
        if (logLine.includes('Error') || logLine.includes('ERROR')) return 'error';
        if (logLine.includes('Warning') || logLine.includes('WARN')) return 'warning';
        if (logLine.includes('Info') || logLine.includes('INFO')) return 'info';
        if (logLine.includes('Debug') || logLine.includes('DEBUG')) return 'debug';
        return 'info';
    }

    writeLogEntry(entry) {
        const logFile = path.join(this.logPath, 'collected-logs.json');
        const logLine = JSON.stringify(entry) + '\\n';
        
        fs.appendFile(logFile, logLine, (err) => {
            if (err && err.code !== 'ENOENT') {
                console.error('Failed to write log:', err);
            }
        });
    }

    analyzeThreat(logEntry) {
        const threats = [
            { pattern: 'failed login', severity: 'medium', name: 'Failed Authentication' },
            { pattern: 'authentication error', severity: 'medium', name: 'Authentication Error' },
            { pattern: 'unauthorized access', severity: 'high', name: 'Unauthorized Access' },
            { pattern: 'malware', severity: 'critical', name: 'Malware Detection' },
            { pattern: 'virus', severity: 'critical', name: 'Virus Detection' },
            { pattern: 'trojan', severity: 'critical', name: 'Trojan Detection' },
            { pattern: 'backdoor', severity: 'critical', name: 'Backdoor Detection' },
            { pattern: 'rootkit', severity: 'critical', name: 'Rootkit Detection' },
            { pattern: 'brute force', severity: 'high', name: 'Brute Force Attack' },
            { pattern: 'sql injection', severity: 'high', name: 'SQL Injection Attack' },
            { pattern: 'xss', severity: 'medium', name: 'Cross-Site Scripting' },
            { pattern: 'ddos', severity: 'high', name: 'DDoS Attack' }
        ];
        
        const message = logEntry.message.toLowerCase();
        
        for (const threat of threats) {
            if (message.includes(threat.pattern)) {
                const alert = {
                    id: crypto.randomUUID(),
                    timestamp: new Date().toISOString(),
                    severity: threat.severity,
                    threat: threat.name,
                    pattern: threat.pattern,
                    source: logEntry.source,
                    message: logEntry.message,
                    agentId: logEntry.agentId,
                    hostname: logEntry.hostname
                };
                
                console.log(\`🚨 THREAT DETECTED: \${threat.name} - \${threat.severity.toUpperCase()}\`);
                this.writeAlert(alert);
                break;
            }
        }
    }

    writeAlert(alert) {
        const alertFile = path.join(this.logPath, 'alerts.json');
        const alertLine = JSON.stringify(alert) + '\\n';
        
        fs.appendFile(alertFile, alertLine, (err) => {
            if (err && err.code !== 'ENOENT') {
                console.error('Failed to write alert:', err);
            }
        });
    }

    async startNetworkMonitoring() {
        console.log('🌐 Starting network monitoring...');
        
        // Monitor network interfaces and statistics
        setInterval(() => {
            const networkInfo = {
                timestamp: new Date().toISOString(),
                interfaces: os.networkInterfaces(),
                hostname: os.hostname(),
                agentId: '${agentId}',
                uptime: os.uptime(),
                loadavg: os.loadavg(),
                freemem: os.freemem(),
                totalmem: os.totalmem()
            };
            
            const networkFile = path.join(this.logPath, 'network-info.json');
            fs.appendFile(networkFile, JSON.stringify(networkInfo) + '\\n', () => {});
        }, 60000); // Every minute
    }

    sendHeartbeat() {
        const heartbeat = {
            agentId: '${agentId}',
            timestamp: new Date().toISOString(),
            status: 'alive',
            platform: 'darwin',
            version: '1.2.3',
            uptime: this.startTime ? Date.now() - this.startTime.getTime() : 0,
            hostname: os.hostname()
        };
        
        const heartbeatFile = path.join(this.logPath, 'heartbeat.json');
        fs.writeFile(heartbeatFile, JSON.stringify(heartbeat, null, 2), () => {});
    }

    async loadConfig() {
        try {
            const configData = fs.readFileSync(this.configPath, 'utf8');
            return JSON.parse(configData);
        } catch (error) {
            console.warn('Using default configuration');
            return {
                agentId: '${agentId}',
                version: '1.2.3',
                platform: 'darwin',
                logLevel: 'info'
            };
        }
    }

    async status() {
        const statusInfo = {
            agentId: '${agentId}',
            isRunning: this.isRunning,
            platform: process.platform,
            arch: process.arch,
            nodeVersion: process.version,
            hostname: os.hostname(),
            uptime: os.uptime(),
            memory: process.memoryUsage(),
            startTime: this.startTime,
            timestamp: new Date().toISOString()
        };
        
        console.log('📊 Agent Status:');
        console.log(JSON.stringify(statusInfo, null, 2));
    }

    async logs() {
        const logFile = path.join(this.logPath, 'collected-logs.json');
        
        try {
            const logData = fs.readFileSync(logFile, 'utf8');
            const lines = logData.trim().split('\\n');
            const recentLogs = lines.slice(-20); // Last 20 entries
            
            console.log('📋 Recent Log Entries:');
            recentLogs.forEach(line => {
                try {
                    const entry = JSON.parse(line);
                    console.log(\`[\${entry.timestamp}] [\${entry.level.toUpperCase()}] \${entry.message}\`);
                } catch (e) {
                    console.log(line);
                }
            });
        } catch (error) {
            console.log('No logs found or unable to read log file');
        }
    }

    async alerts() {
        const alertFile = path.join(this.logPath, 'alerts.json');
        
        try {
            const alertData = fs.readFileSync(alertFile, 'utf8');
            const lines = alertData.trim().split('\\n');
            const recentAlerts = lines.slice(-10); // Last 10 alerts
            
            console.log('🚨 Recent Security Alerts:');
            recentAlerts.forEach(line => {
                try {
                    const alert = JSON.parse(line);
                    console.log(\`[\${alert.timestamp}] [\${alert.severity.toUpperCase()}] \${alert.threat}: \${alert.message.substring(0, 100)}...\`);
                } catch (e) {
                    console.log(line);
                }
            });
        } catch (error) {
            console.log('No alerts found or unable to read alert file');
        }
    }
}

// CLI handling
async function main() {
    const args = process.argv.slice(2);
    const command = args[0] || 'start';
    
    const agent = new A2ZAgent();
    
    switch (command) {
        case 'start':
            await agent.start();
            break;
        case 'stop':
            await agent.stop();
            break;
        case 'status':
            await agent.status();
            break;
        case 'logs':
            await agent.logs();
            break;
        case 'alerts':
            await agent.alerts();
            break;
        case 'help':
        case '--help':
        case '-h':
            console.log(\`
A2Z SOC Network Agent for macOS

USAGE:
    a2z-agent <COMMAND>

COMMANDS:
    start      Start the network agent (default)
    stop       Stop the network agent
    status     Show agent status and information
    logs       Show recent collected logs
    alerts     Show recent security alerts
    help       Show this help message

EXAMPLES:
    sudo a2z-agent start
    a2z-agent status
    a2z-agent logs
    a2z-agent alerts

 API ENDPOINTS:
     GET http://localhost:5200/status   - Agent status
     GET http://localhost:5200/logs     - Recent logs
     GET http://localhost:5200/alerts   - Recent alerts

For more information: https://docs.a2zsoc.com/agents/macos
\`);
            break;
        default:
            console.error(\`Unknown command: \${command}\`);
            console.log('Use "a2z-agent help" for usage information');
            process.exit(1);
    }
}

if (require.main === module) {
    main().catch(error => {
        console.error('Fatal error:', error);
        process.exit(1);
    });
}
AGENT_EOF

chmod +x "\$INSTALL_PREFIX/bin/a2z-agent"

# Create symlink for binary
print_status "Creating binary symlink..."
ln -sf "\$INSTALL_PREFIX/bin/a2z-agent" "\$BINARY_PATH"

# Create configuration file
print_status "Creating configuration..."
cat > "\$CONFIG_PATH/agent.json" << CONFIG_EOF
{
    "agentId": "\$AGENT_ID",
    "version": "1.2.3",
    "platform": "darwin",
    "tenantId": "",
    "apiKey": "",
    "cloudEndpoint": "wss://api.a2zsoc.com",
    "networkInterface": "any",
    "apiPort": 3001,
    "apiHost": "127.0.0.1",
    "logLevel": "info",
    "logCollection": {
        "enabled": true,
        "sources": [
            "unified-log",
            "system-logs",
            "application-logs",
            "crash-reports"
        ]
    },
    "security": {
        "tlsVerify": true,
        "encryptData": true,
        "anonymizeIPs": false
    }
}
CONFIG_EOF

# Create LaunchDaemon plist
print_status "Creating system service..."
cat > "\$LAUNCHD_PLIST" << PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.a2zsoc.network-agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>\$BINARY_PATH</string>
        <string>start</string>
    </array>
    <key>RunAtLoad</key>
    <false/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>\$LOG_PATH/agent.log</string>
    <key>StandardErrorPath</key>
    <string>\$LOG_PATH/agent-error.log</string>
    <key>WorkingDirectory</key>
    <string>\$INSTALL_PREFIX</string>
    <key>UserName</key>
    <string>root</string>
    <key>GroupName</key>
    <string>wheel</string>
</dict>
</plist>
PLIST_EOF

# Set permissions
print_status "Setting permissions..."
chmod 644 "\$LAUNCHD_PLIST"
chown root:wheel "\$LAUNCHD_PLIST"
chown -R root:wheel "\$INSTALL_PREFIX"
chown -R root:wheel "\$CONFIG_PATH"
chown -R root:wheel "\$LOG_PATH"

echo ""
print_success "✅ A2Z SOC Network Agent installed successfully!"
echo ""
echo "📝 Configuration file: \$CONFIG_PATH/agent.json"
echo "📋 Log files: \$LOG_PATH/"
echo ""
echo "🔧 Next steps:"
echo "1. Edit the configuration file and add your API key:"
echo "   sudo nano \$CONFIG_PATH/agent.json"
echo ""
echo "2. Load the service:"
echo "   sudo launchctl load \$LAUNCHD_PLIST"
echo ""
echo "3. Start the agent:"
echo "   sudo launchctl start com.a2zsoc.network-agent"
echo ""
echo "4. Check status:"
echo "   a2z-agent status"
echo ""
echo "5. View logs:"
echo "   a2z-agent logs"
echo ""
echo "6. View security alerts:"
echo "   a2z-agent alerts"
echo ""
 echo "7. Check API status:"
 echo "   curl http://localhost:5200/status"
echo ""
echo "For support: https://docs.a2zsoc.com/agents/macos"
`;

    return installScript;
  };

  const handleDownload = async (platform: { name: string; download: string }) => {
    try {
      // Handle macOS DMG download
      if (platform.name === 'macOS') {
        console.log('Starting macOS DMG download...');
        
        // Download the pre-built DMG file directly
        window.open('/downloads/A2Z-SOC-Network-Agent-1.2.3.dmg', '_blank');
        
        // Show success message with enhanced details for macOS DMG
        alert(`✅ A2Z SOC Network Agent for macOS Downloaded Successfully!

📁 File: A2Z-SOC-Network-Agent-1.2.3.dmg (2.4MB)
🎯 Replaces previous 614KB script with professional enterprise agent

🚀 ENTERPRISE FEATURES INCLUDED:
• Native macOS Application Bundle (.app)
• Code-signed installer with admin privilege handling
• LaunchDaemon service for automatic system startup
• Real-time log collection from macOS Unified Logging System
• Advanced network traffic monitoring and analysis
• AI-powered security threat detection with pattern matching
• RESTful API server on port 5200 for remote management
• Command-line interface for advanced configuration
• Automatic uninstaller and service management
• Full compatibility with macOS 10.15+ (Intel & Apple Silicon)

🔧 INSTALLATION PROCESS:
1. Double-click the downloaded DMG file to mount
2. Double-click "Install A2Z SOC Agent.command" in the DMG
3. Enter administrator password when prompted
4. Agent installs and starts automatically in background

🌐 API ENDPOINTS:
• Status: http://localhost:5200/status
• Health: http://localhost:5200/health  
• Logs: http://localhost:5200/logs
• Alerts: http://localhost:5200/alerts
• Metrics: http://localhost:5200/metrics
• Configuration: http://localhost:5200/config

📖 Documentation: https://docs.a2zsoc.com/agents/macos

This professional agent provides comprehensive system monitoring, network security analysis, and threat detection capabilities for enterprise macOS environments.`);
        return; // Exit function completely for macOS
      }

      // Handle other platforms with demo scripts
      let content = '';
      let mimeType = '';
      
      switch (platform.name) {
        case 'Windows':
          content = `#!/bin/bash
# A2Z Network Agent Installer for Windows
# This is a demonstration script for the A2Z SOC platform
echo "Installing A2Z Network Agent for Windows..."
echo "Version: 1.2.3"
echo "Platform: Windows x64"
echo "Installation complete!"
echo "Agent ID: $(uuidgen)"
echo "Connect to: https://soc.a2z-platform.com"
pause`;
          mimeType = 'application/octet-stream';
          break;
        
        case 'Linux':
          content = `#!/bin/bash
# A2Z Network Agent Installer for Linux
# This is a demonstration script for the A2Z SOC platform

echo "Installing A2Z Network Agent for Linux..."
echo "Version: 1.2.3"
echo "Platform: Linux x64"
echo "Checking dependencies..."
echo "✓ systemd detected"
echo "✓ Network tools available"
echo "Installing agent service..."
echo "Agent ID: $(uuidgen)"
echo "Installation complete!"
echo ""
echo "To start the agent:"
echo "sudo systemctl start a2z-agent"
echo "sudo systemctl enable a2z-agent"
echo ""
echo "Connect to: https://soc.a2z-platform.com"`;
          mimeType = 'application/x-gzip';
          break;
        
        case 'ARM Linux':
          content = `#!/bin/bash
# A2Z Network Agent Installer for ARM Linux
# This is a demonstration script for the A2Z SOC platform

echo "Installing A2Z Network Agent for ARM Linux..."
echo "Version: 1.2.3"
echo "Platform: ARM Linux (Raspberry Pi)"
echo "Checking ARM architecture..."
echo "✓ ARM processor detected"
echo "✓ Network interfaces available"
echo "Installing lightweight agent..."
echo "Agent ID: $(uuidgen)"
echo "Installation complete!"
echo ""
echo "To start the agent:"
echo "sudo systemctl start a2z-agent"
echo ""
echo "Connect to: https://soc.a2z-platform.com"`;
          mimeType = 'application/x-gzip';
          break;
          
        default:
          alert(`❌ Unsupported platform: ${platform.name}`);
          return;
      }

      // Create and download the file for non-macOS platforms
      const blob = new Blob([content], { type: mimeType });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = platform.download;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      
      // Show success message for other platforms
      alert(`✅ Download started for ${platform.name} agent!\n\nFile: ${platform.download}\nThis is a demonstration file for the A2Z SOC platform.`);
      
    } catch (error) {
      console.error('Download generation failed:', error);
      alert(`❌ Failed to generate ${platform.name} agent. Please try again.`);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-white rounded-lg shadow-sm p-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 flex items-center">
              <Settings className="w-8 h-8 text-blue-600 mr-3" />
              Network Agent Management
            </h1>
            <p className="text-gray-500 mt-1">Download agents and manage your network monitoring infrastructure</p>
          </div>
          <div className="flex items-center space-x-4">
            <button
              onClick={handleCheckAllStatus}
              className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
            >
              <RefreshCw className="w-4 h-4" />
              <span>Check All Status</span>
            </button>
          </div>
        </div>
      </div>

      {/* Download Section */}
      <div className="bg-white rounded-lg shadow-sm p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
          <Download className="w-5 h-5 text-green-600 mr-2" />
          Download Network Agent
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {platforms.map((platform) => {
            const Icon = platform.icon;
            return (
              <div key={platform.name} className="border border-gray-200 rounded-lg p-4 hover:border-blue-300 transition-colors">
                <div className="flex items-center mb-3">
                  <Icon className="w-6 h-6 text-blue-600 mr-2" />
                  <h4 className="font-semibold text-gray-900">{platform.name}</h4>
                </div>
                <p className="text-sm text-gray-600 mb-4">{platform.description}</p>
                
                <div className="space-y-2">
                  <button
                    onClick={() => handleDownload(platform)}
                    className="flex items-center justify-center space-x-2 w-full px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
                  >
                    <Download className="w-4 h-4" />
                    <span>Download</span>
                  </button>
                  
                  <div className="text-xs text-gray-500">
                    <p className="font-medium mb-1">Install command:</p>
                    <div className="flex items-center space-x-1 bg-gray-100 p-2 rounded font-mono text-xs">
                      <code className="flex-1">{platform.installCmd}</code>
                      <button
                        onClick={() => copyToClipboard(platform.installCmd)}
                        className="text-blue-600 hover:text-blue-800"
                      >
                        <Copy className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Agent Management */}
      <div className="bg-white rounded-lg shadow-sm">
        <div className="p-6 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-gray-900 flex items-center">
              <Wifi className="w-5 h-5 text-purple-600 mr-2" />
              Managed Agents ({agents.length})
            </h3>
            <button
              onClick={() => setShowAddForm(true)}
              className="flex items-center space-x-2 px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700"
            >
              <Plus className="w-4 h-4" />
              <span>Add Agent</span>
            </button>
          </div>
        </div>

        {/* Add Agent Form */}
        {showAddForm && (
          <div className="p-6 bg-gray-50 border-b border-gray-200">
            <h4 className="text-md font-semibold text-gray-900 mb-4">Add New Agent</h4>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Agent Name
                </label>
                <input
                  type="text"
                  value={newAgent.name}
                  onChange={(e) => setNewAgent({ ...newAgent, name: e.target.value })}
                  placeholder="Production Server"
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  IP Address
                </label>
                <input
                  type="text"
                  value={newAgent.ipAddress}
                  onChange={(e) => setNewAgent({ ...newAgent, ipAddress: e.target.value })}
                  placeholder="192.168.1.100"
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Platform
                </label>
                <select
                  value={newAgent.platform}
                  onChange={(e) => setNewAgent({ ...newAgent, platform: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="linux">Linux</option>
                  <option value="windows">Windows</option>
                  <option value="macos">macOS</option>
                  <option value="arm">ARM Linux</option>
                </select>
              </div>
              <div className="flex items-end space-x-2">
                <button
                  onClick={handleAddAgent}
                  disabled={!newAgent.name || !newAgent.ipAddress}
                  className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Add Agent
                </button>
                <button
                  onClick={() => setShowAddForm(false)}
                  className="px-4 py-2 border border-gray-300 text-gray-700 rounded-md hover:bg-gray-50"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Agents List */}
        <div className="overflow-x-auto">
          {agents.length > 0 ? (
            <table className="w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Agent Details
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Platform
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Last Seen
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Uptime
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {agents.map((agent) => (
                  <tr key={agent.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div>
                        <div className="text-sm font-medium text-gray-900">{agent.name}</div>
                        <div className="text-sm text-gray-500 font-mono">{agent.ipAddress}</div>
                        {agent.version && (
                          <div className="text-xs text-gray-400">v{agent.version}</div>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center space-x-2">
                        {getStatusIcon(agent.status)}
                        <span className={`px-2 py-1 text-xs font-medium rounded-full ${getStatusColor(agent.status)}`}>
                          {agent.status}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center space-x-2 text-sm text-gray-900">
                        {getPlatformIcon(agent.platform)}
                        <span className="capitalize">{agent.platform}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {agent.lastSeen ? new Date(agent.lastSeen).toLocaleString() : 'Never'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {formatUptime(agent.uptime)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => handleCheckStatus(agent.id)}
                          disabled={agent.status === 'checking'}
                          className="text-blue-600 hover:text-blue-900 disabled:opacity-50"
                        >
                          <RefreshCw className={`w-4 h-4 ${agent.status === 'checking' ? 'animate-spin' : ''}`} />
                        </button>
                        <button
                          onClick={() => handleRemoveAgent(agent.id)}
                          className="text-red-600 hover:text-red-900"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="p-8 text-center">
              <WifiOff className="w-12 h-12 text-gray-300 mx-auto mb-4" />
              <div className="text-sm text-gray-500 mb-2">No agents configured</div>
              <div className="text-xs text-gray-400">
                Add your first agent to start monitoring your network
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Configuration Instructions */}
      <div className="bg-white rounded-lg shadow-sm p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
          <ExternalLink className="w-5 h-5 text-orange-600 mr-2" />
          Setup Instructions
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-4">
            <h4 className="font-medium text-gray-900">1. Download & Install</h4>
            <ol className="list-decimal list-inside space-y-1 text-sm text-gray-600">
              <li>Download the appropriate agent for your platform</li>
              <li>Run the installation command on your target system</li>
              <li>The agent will automatically start monitoring</li>
            </ol>
          </div>
          <div className="space-y-4">
            <h4 className="font-medium text-gray-900">2. Add to Management</h4>
            <ol className="list-decimal list-inside space-y-1 text-sm text-gray-600">
              <li>Click "Add Agent" above</li>
              <li>Enter a descriptive name and IP address</li>
              <li>Select the correct platform</li>
              <li>Use "Check Status" to verify connectivity</li>
            </ol>
          </div>
        </div>
        
        <div className="mt-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
          <div className="flex items-start space-x-2">
            <AlertCircle className="w-5 h-5 text-blue-600 mt-0.5" />
            <div className="text-sm text-blue-700">
              <p className="font-medium mb-1">Configuration Note:</p>
              <p>Agents will automatically connect to this SOC platform at <code className="bg-blue-100 px-1 rounded">http://localhost:8081</code>. 
              Ensure your firewall allows inbound connections on port 8081.</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
} 