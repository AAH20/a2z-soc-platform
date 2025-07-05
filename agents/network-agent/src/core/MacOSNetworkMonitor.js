const EventEmitter = require('events');
const { spawn, exec } = require('child_process');
const fs = require('fs').promises;
const path = require('path');

class MacOSNetworkMonitor extends EventEmitter {
    constructor(config) {
        super();
        this.config = config;
        this.isMonitoring = false;
        this.processes = new Map();
        this.statistics = {
            packetsProcessed: 0,
            connectionsDetected: 0,
            bytesProcessed: 0,
            activeConnections: 0
        };
    }

    async initialize() {
        console.log('🍎 Initializing macOS Network Monitor...');
        
        // Check for required tools
        await this.checkSystemRequirements();
        
        // Setup monitoring tools
        await this.setupMonitoringTools();
        
        console.log('✅ macOS Network Monitor initialized');
    }

    async checkSystemRequirements() {
        const requiredTools = ['netstat', 'lsof', 'tcpdump', 'nettop'];
        const missingTools = [];
        
        for (const tool of requiredTools) {
            try {
                await this.execCommand(`which ${tool}`);
            } catch (error) {
                missingTools.push(tool);
            }
        }
        
        if (missingTools.length > 0) {
            console.warn(`⚠️  Missing tools: ${missingTools.join(', ')}`);
            console.warn('💡 Some monitoring features may be limited');
        }
    }

    async setupMonitoringTools() {
        // Configure monitoring parameters
        this.monitoringConfig = {
            connectionInterval: this.config.connectionMonitorInterval || 5000,
            packetCaptureInterface: this.config.interface || 'any',
            captureFilter: this.config.captureFilter || 'tcp or udp',
            maxConnections: this.config.maxConnections || 1000
        };
    }

    async startMonitoring(networkInterface) {
        if (this.isMonitoring) {
            throw new Error('Monitoring is already active');
        }

        console.log(`🎯 Starting network monitoring on interface: ${networkInterface.name}`);
        
        this.targetInterface = networkInterface;
        this.isMonitoring = true;
        
        // Start different monitoring methods
        await Promise.all([
            this.startConnectionMonitoring(),
            this.startNetworkStatistics(),
            this.startTrafficAnalysis()
        ]);
        
        console.log('✅ Network monitoring started');
    }

    async stopMonitoring() {
        if (!this.isMonitoring) {
            return;
        }

        console.log('🛑 Stopping network monitoring...');
        
        this.isMonitoring = false;
        
        // Stop all monitoring processes
        for (const [name, process] of this.processes) {
            if (process && process.kill) {
                console.log(`Stopping ${name} process...`);
                process.kill('SIGTERM');
            }
        }
        
        this.processes.clear();
        console.log('✅ Network monitoring stopped');
    }

    async startConnectionMonitoring() {
        console.log('🔗 Starting connection monitoring...');
        
        // Monitor active connections using netstat
        const monitorConnections = () => {
            if (!this.isMonitoring) return;
            
            this.execCommand('netstat -i -n -p tcp')
                .then(output => this.parseNetstatOutput(output))
                .catch(error => console.error('Connection monitoring error:', error));
            
            setTimeout(monitorConnections, this.monitoringConfig.connectionInterval);
        };
        
        monitorConnections();
        
        // Monitor network processes using lsof
        const monitorProcesses = () => {
            if (!this.isMonitoring) return;
            
            this.execCommand('lsof -i -P -n')
                .then(output => this.parseLsofOutput(output))
                .catch(error => console.error('Process monitoring error:', error));
            
            setTimeout(monitorProcesses, this.monitoringConfig.connectionInterval * 2);
        };
        
        monitorProcesses();
    }

    async startNetworkStatistics() {
        console.log('📊 Starting network statistics collection...');
        
        // Use nettop for real-time network statistics (if available and root)
        try {
            const nettopProcess = spawn('nettop', ['-P', '-l', '1', '-t', 'external'], {
                stdio: ['ignore', 'pipe', 'pipe']
            });
            
            nettopProcess.stdout.on('data', (data) => {
                this.parseNettopOutput(data.toString());
            });
            
            nettopProcess.stderr.on('data', (data) => {
                console.debug('nettop stderr:', data.toString());
            });
            
            nettopProcess.on('close', (code) => {
                if (this.isMonitoring && code !== 0) {
                    console.warn(`nettop process exited with code ${code}`);
                }
            });
            
            this.processes.set('nettop', nettopProcess);
            
        } catch (error) {
            console.warn('nettop not available, using alternative statistics');
            this.startAlternativeStatistics();
        }
    }

    async startAlternativeStatistics() {
        // Alternative statistics using built-in tools
        const collectStats = () => {
            if (!this.isMonitoring) return;
            
            Promise.all([
                this.execCommand('netstat -I en0'),
                this.execCommand('netstat -r -n')
            ]).then(([interfaceStats, routingTable]) => {
                this.parseInterfaceStats(interfaceStats);
                this.parseRoutingTable(routingTable);
            }).catch(error => {
                console.error('Statistics collection error:', error);
            });
            
            setTimeout(collectStats, 10000); // Every 10 seconds
        };
        
        collectStats();
    }

    async startTrafficAnalysis() {
        console.log('🔍 Starting traffic analysis...');
        
        // Check if we can use tcpdump (requires root privileges)
        try {
            await this.execCommand('tcpdump --version');
            
            if (process.getuid && process.getuid() === 0) {
                this.startTcpdumpCapture();
            } else {
                console.warn('⚠️  Root privileges required for packet capture');
                console.warn('💡 Running in connection monitoring mode only');
            }
        } catch (error) {
            console.warn('tcpdump not available, using alternative monitoring');
        }
        
        // Always start connection-based analysis
        this.startConnectionAnalysis();
    }

    async startTcpdumpCapture() {
        console.log('📦 Starting packet capture with tcpdump...');
        
        const tcpdumpArgs = [
            '-i', this.targetInterface.name,
            '-n',  // Don't resolve hostnames
            '-q',  // Quiet output
            '-t',  // Don't print timestamps
            '-c', '100',  // Capture 100 packets then restart
            this.monitoringConfig.captureFilter
        ];
        
        const startCapture = () => {
            if (!this.isMonitoring) return;
            
            const tcpdumpProcess = spawn('tcpdump', tcpdumpArgs, {
                stdio: ['ignore', 'pipe', 'pipe']
            });
            
            tcpdumpProcess.stdout.on('data', (data) => {
                this.parseTcpdumpOutput(data.toString());
            });
            
            tcpdumpProcess.stderr.on('data', (data) => {
                // tcpdump outputs some info to stderr, filter out noise
                const errorMsg = data.toString();
                if (!errorMsg.includes('listening on') && !errorMsg.includes('packets captured')) {
                    console.debug('tcpdump stderr:', errorMsg);
                }
            });
            
            tcpdumpProcess.on('close', (code) => {
                if (this.isMonitoring) {
                    // Restart capture after a short delay
                    setTimeout(startCapture, 1000);
                }
            });
            
            this.processes.set('tcpdump', tcpdumpProcess);
        };
        
        startCapture();
    }

    async startConnectionAnalysis() {
        console.log('🔗 Starting connection-based analysis...');
        
        const analyzeConnections = () => {
            if (!this.isMonitoring) return;
            
            // Get system network connections
            this.execCommand('netstat -an')
                .then(output => {
                    const connections = this.parseNetstatConnections(output);
                    connections.forEach(conn => this.analyzeConnection(conn));
                })
                .catch(error => console.error('Connection analysis error:', error));
            
            setTimeout(analyzeConnections, 5000); // Every 5 seconds
        };
        
        analyzeConnections();
    }

    parseNetstatOutput(output) {
        const lines = output.split('\n');
        const interfaces = [];
        
        for (const line of lines) {
            if (line.includes('Link') || line.includes('Mtu')) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 7) {
                    interfaces.push({
                        name: parts[0],
                        mtu: parts[1],
                        network: parts[2],
                        address: parts[3]
                    });
                }
            }
        }
        
        return interfaces;
    }

    parseLsofOutput(output) {
        const lines = output.split('\n');
        const processes = [];
        
        for (const line of lines) {
            if (line.includes('TCP') || line.includes('UDP')) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 9) {
                    const process = {
                        command: parts[0],
                        pid: parts[1],
                        user: parts[2],
                        type: parts[4],
                        protocol: parts[7],
                        address: parts[8]
                    };
                    processes.push(process);
                    
                    // Emit connection event
                    this.emit('connection', {
                        local: this.parseAddress(process.address, true),
                        remote: this.parseAddress(process.address, false),
                        protocol: process.protocol.toLowerCase(),
                        pid: process.pid,
                        process: process.command,
                        state: 'established'
                    });
                }
            }
        }
        
        this.statistics.connectionsDetected += processes.length;
        return processes;
    }

    parseNetstatConnections(output) {
        const lines = output.split('\n');
        const connections = [];
        
        for (const line of lines) {
            if (line.includes('tcp') || line.includes('udp')) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 6) {
                    connections.push({
                        protocol: parts[0],
                        localAddress: parts[3],
                        remoteAddress: parts[4],
                        state: parts[5] || 'unknown'
                    });
                }
            }
        }
        
        return connections;
    }

    parseNettopOutput(output) {
        const lines = output.split('\n');
        
        for (const line of lines) {
            if (line.includes('.') && (line.includes('TCP') || line.includes('UDP'))) {
                this.statistics.packetsProcessed++;
                
                // Create a simulated packet for analysis
                const packet = this.parseNettopLine(line);
                if (packet) {
                    this.emit('packet', packet);
                }
            }
        }
    }

    parseNettopLine(line) {
        try {
            const parts = line.trim().split(/\s+/);
            if (parts.length < 6) return null;
            
            return {
                timestamp: new Date(),
                protocol: parts[0].toLowerCase(),
                sourceIp: this.extractIp(parts[1]),
                sourcePort: this.extractPort(parts[1]),
                destinationIp: this.extractIp(parts[2]),
                destinationPort: this.extractPort(parts[2]),
                bytes: parseInt(parts[3]) || 0,
                interface: this.targetInterface.name,
                direction: 'outbound'
            };
        } catch (error) {
            return null;
        }
    }

    parseTcpdumpOutput(output) {
        const lines = output.split('\n');
        
        for (const line of lines) {
            if (line.trim() && !line.includes('listening') && !line.includes('captured')) {
                const packet = this.parseTcpdumpLine(line);
                if (packet) {
                    this.statistics.packetsProcessed++;
                    this.statistics.bytesProcessed += packet.length || 0;
                    this.emit('packet', packet);
                }
            }
        }
    }

    parseTcpdumpLine(line) {
        try {
            // Parse tcpdump output format
            // Example: "IP 192.168.1.100.12345 > 10.0.0.1.80: Flags [S], seq 123, length 0"
            
            if (!line.includes('>')) return null;
            
            const parts = line.split('>');
            if (parts.length < 2) return null;
            
            const source = parts[0].trim().split(' ').pop();
            const destAndRest = parts[1].trim().split(':');
            const destination = destAndRest[0].trim();
            
            const [sourceIp, sourcePort] = this.splitAddress(source);
            const [destIp, destPort] = this.splitAddress(destination);
            
            const lengthMatch = line.match(/length (\d+)/);
            const length = lengthMatch ? parseInt(lengthMatch[1]) : 0;
            
            return {
                timestamp: new Date(),
                protocol: line.includes('UDP') ? 'udp' : 'tcp',
                sourceIp: sourceIp,
                sourcePort: sourcePort,
                destinationIp: destIp,
                destinationPort: destPort,
                length: length,
                flags: this.extractTcpFlags(line),
                interface: this.targetInterface.name,
                direction: this.determineDirection(sourceIp, destIp)
            };
        } catch (error) {
            return null;
        }
    }

    analyzeConnection(connection) {
        // Emit connection for threat analysis
        this.emit('connection', {
            local: connection.localAddress,
            remote: connection.remoteAddress,
            protocol: connection.protocol,
            state: connection.state,
            timestamp: new Date()
        });
    }

    parseInterfaceStats(output) {
        // Parse interface statistics from netstat -I
        const lines = output.split('\n');
        for (const line of lines) {
            if (line.includes(this.targetInterface.name)) {
                const parts = line.trim().split(/\s+/);
                if (parts.length >= 10) {
                    this.statistics.packetsReceived = parseInt(parts[4]) || 0;
                    this.statistics.packetsSent = parseInt(parts[7]) || 0;
                    this.statistics.bytesReceived = parseInt(parts[5]) || 0;
                    this.statistics.bytesSent = parseInt(parts[8]) || 0;
                }
            }
        }
    }

    parseRoutingTable(output) {
        // Parse routing table for network topology information
        // This could be used for advanced threat detection
    }

    splitAddress(address) {
        const lastDotIndex = address.lastIndexOf('.');
        if (lastDotIndex === -1) return [address, 0];
        
        const ip = address.substring(0, lastDotIndex);
        const port = parseInt(address.substring(lastDotIndex + 1)) || 0;
        
        return [ip, port];
    }

    extractIp(address) {
        return address.split('.').slice(0, 4).join('.');
    }

    extractPort(address) {
        const parts = address.split('.');
        return parseInt(parts[parts.length - 1]) || 0;
    }

    extractTcpFlags(line) {
        const flagsMatch = line.match(/Flags \[([^\]]+)\]/);
        return flagsMatch ? flagsMatch[1] : '';
    }

    determineDirection(sourceIp, destIp) {
        // Simple logic to determine packet direction
        if (this.isLocalIp(sourceIp)) {
            return 'outbound';
        } else if (this.isLocalIp(destIp)) {
            return 'inbound';
        }
        return 'transit';
    }

    isLocalIp(ip) {
        return ip.startsWith('192.168.') || 
               ip.startsWith('10.') || 
               ip.startsWith('172.16.') ||
               ip === '127.0.0.1';
    }

    parseAddress(address, isLocal) {
        // Parse lsof address format
        if (address.includes('->')) {
            const parts = address.split('->');
            return isLocal ? parts[0].trim() : parts[1].trim();
        }
        return address;
    }

    async execCommand(command) {
        return new Promise((resolve, reject) => {
            exec(command, (error, stdout, stderr) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(stdout);
                }
            });
        });
    }

    getStatistics() {
        return {
            ...this.statistics,
            isMonitoring: this.isMonitoring,
            targetInterface: this.targetInterface?.name || 'none',
            activeProcesses: this.processes.size
        };
    }

    async getDetailedStatistics() {
        const baseStats = this.getStatistics();
        
        try {
            // Get additional system network statistics
            const netstatOutput = await this.execCommand('netstat -s');
            const additionalStats = this.parseNetstatStats(netstatOutput);
            
            return {
                ...baseStats,
                system: additionalStats
            };
        } catch (error) {
            return baseStats;
        }
    }

    parseNetstatStats(output) {
        const stats = {};
        const lines = output.split('\n');
        
        for (const line of lines) {
            if (line.includes('packets sent')) {
                const match = line.match(/(\d+) packets sent/);
                if (match) stats.totalPacketsSent = parseInt(match[1]);
            }
            if (line.includes('packets received')) {
                const match = line.match(/(\d+) packets received/);
                if (match) stats.totalPacketsReceived = parseInt(match[1]);
            }
        }
        
        return stats;
    }
}

module.exports = MacOSNetworkMonitor; 