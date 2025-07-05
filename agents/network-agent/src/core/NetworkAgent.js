const EventEmitter = require('events');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const PacketAnalyzer = require('./PacketAnalyzer');
const ThreatDetector = require('./ThreatDetector');
const DataCompressor = require('../utils/DataCompressor');
const MetricsCollector = require('../utils/MetricsCollector');
const ApiServer = require('../api/ApiServer');
const MacOSNetworkMonitor = require('./MacOSNetworkMonitor');
const si = require('systeminformation');
const { spawn, exec } = require('child_process');

// Platform-specific log collectors
let LogCollector = null;
try {
    if (process.platform === 'darwin') {
        LogCollector = require('../collectors/MacOSLogCollector');
    } else if (process.platform === 'linux') {
        LogCollector = require('../collectors/LinuxLogCollector');
    } else if (process.platform === 'win32') {
        LogCollector = require('../collectors/WindowsLogCollector');
    }
} catch (error) {
    console.warn(`Platform-specific log collector not available: ${error.message}`);
}

class NetworkAgent extends EventEmitter {
    constructor(config, cloudConnection) {
        super();
        this.config = config;
        this.cloudConnection = cloudConnection;
        this.isRunning = false;
        this.startTime = null;
        
        // Core components
        this.packetAnalyzer = new PacketAnalyzer(config);
        this.threatDetector = new ThreatDetector(config);
        this.dataCompressor = new DataCompressor();
        this.metricsCollector = new MetricsCollector();
        this.apiServer = new ApiServer(this, {
            port: config.apiPort || 5200,
            host: config.apiHost || '0.0.0.0'
        });
        
        // Platform-specific network monitor (improved macOS support)
        this.networkMonitor = new MacOSNetworkMonitor(config);
        
        // Log collector (platform-specific)
        if (LogCollector && config.logCollection?.enabled) {
            this.logCollector = new LogCollector(config.logCollection);
        } else {
            this.logCollector = null;
        }
        
        // Store reference to config manager if provided
        this.configManager = null;
        
        // Network interfaces and capture
        this.interfaces = [];
        this.activeCaptures = new Map();
        
        // Data buffers
        this.eventBuffer = [];
        this.alertBuffer = [];
        this.logBuffer = [];
        this.maxBufferSize = config.maxBufferSize || 1000;
        
        // Performance tracking
        this.packetsProcessed = 0;
        this.threatsDetected = 0;
        this.alertsGenerated = 0;
        this.logsCollected = 0;
        
        // Heartbeat
        this.heartbeatInterval = null;
        
        // macOS-specific privilege check
        this.privilegeLevel = this.checkPrivileges();
    }

    // Add method to set config manager reference
    setConfigManager(configManager) {
        this.configManager = configManager;
    }

    checkPrivileges() {
        if (process.platform === 'darwin') {
            // Check if running as root on macOS
            return process.getuid && process.getuid() === 0;
        }
        return false;
    }

    async initialize() {
        try {
            console.log(`🍎 Initializing A2Z Network Agent on ${process.platform}`);
            
            if (process.platform === 'darwin') {
                console.log(`🔐 Privilege level: ${this.privilegeLevel ? 'Root (Full features)' : 'User (Limited features)'}`);
                if (!this.privilegeLevel) {
                    console.log('💡 For full packet capture capabilities, run with: sudo npm start');
                }
            }
            
            // Detect available network interfaces using cross-platform method
            this.interfaces = await this.getNetworkInterfaces();
            
            // Initialize packet analyzer
            await this.packetAnalyzer.initialize();
            
            // Initialize threat detector
            await this.threatDetector.initialize();
            
            // Load threat intelligence rules
            await this.threatDetector.loadRules();
            
            // Initialize network monitor
            await this.networkMonitor.initialize();
            
            // Initialize log collector if available
            if (this.logCollector) {
                this.setupLogCollectorEvents();
                console.log(`📋 Log collector initialized for ${process.platform}`);
            }
            
            // Start metrics collection
            this.metricsCollector.startCollection();
            
            // Start API server
            await this.apiServer.start();
            
            // Setup event handlers
            this.setupEventHandlers();
            
            console.log(`✅ Network Agent initialized with ${this.interfaces.length} interfaces`);
            
        } catch (error) {
            throw new Error(`Failed to initialize NetworkAgent: ${error.message}`);
        }
    }

    async start() {
        if (this.isRunning) {
            throw new Error('NetworkAgent is already running');
        }

        try {
            this.startTime = new Date();
            
            // Start network monitoring
            await this.startNetworkMonitoring();
            
            // Start log collection
            if (this.logCollector) {
                await this.logCollector.start();
                console.log('📋 Log collection started');
            }
            
            // Start heartbeat
            this.startHeartbeat();
            
            // Start data transmission
            this.startDataTransmission();
            
            this.isRunning = true;
            this.emit('started');
            
            console.log(`✅ Network Agent started successfully`);
            
        } catch (error) {
            throw new Error(`Failed to start NetworkAgent: ${error.message}`);
        }
    }

    async stop() {
        if (!this.isRunning) {
            return;
        }

        try {
            // Stop network monitoring
            await this.stopNetworkMonitoring();
            
            // Stop log collection
            if (this.logCollector) {
                await this.logCollector.stop();
                console.log('📋 Log collection stopped');
            }
            
            // Stop heartbeat
            if (this.heartbeatInterval) {
                clearInterval(this.heartbeatInterval);
                this.heartbeatInterval = null;
            }
            
            // Stop metrics collection
            this.metricsCollector.stopCollection();
            
            // Stop API server
            await this.apiServer.stop();
            
            // Flush remaining data
            await this.flushBuffers();
            
            this.isRunning = false;
            this.emit('stopped');
            
            console.log(`🛑 Network Agent stopped`);
            
        } catch (error) {
            throw new Error(`Failed to stop NetworkAgent: ${error.message}`);
        }
    }

    async restart() {
        console.log('🔄 Restarting Network Agent...');
        await this.stop();
        await this.start();
        console.log('✅ Network Agent restarted successfully');
    }

    async getNetworkInterfaces() {
        try {
            // Use systeminformation for cross-platform interface detection
            const networkInterfaces = await si.networkInterfaces();
            
            return networkInterfaces
                .filter(iface => {
                    // Filter for active, non-loopback interfaces
                    return !iface.internal && 
                           iface.operstate === 'up' && 
                           (iface.ip4 || iface.ip6);
                })
                .map(iface => ({
                    name: iface.iface,
                    description: iface.ifaceName || iface.iface,
                    mac: iface.mac,
                    ip4: iface.ip4,
                    ip6: iface.ip6,
                    type: iface.type,
                    speed: iface.speed,
                    operstate: iface.operstate,
                    internal: iface.internal
            }));
        } catch (error) {
            console.error('Error getting network interfaces:', error);
            // Fallback to basic interface detection
            return [{
                name: process.platform === 'darwin' ? 'en0' : 'eth0',
                description: 'Default interface',
                mac: '00:00:00:00:00:00',
                ip4: '0.0.0.0',
                type: 'ethernet',
                operstate: 'up',
                internal: false
            }];
        }
    }

    async startNetworkMonitoring() {
        console.log('🔍 Starting network monitoring...');
        
        try {
            // Select default interface if none specified
            const targetInterface = this.getDefaultInterface();
            console.log(`📡 Monitoring interface: ${targetInterface.name} (${targetInterface.description})`);
            
            // Start monitoring with the selected interface
            await this.networkMonitor.startMonitoring(targetInterface);
            
            // Set up event handlers for captured data
            this.networkMonitor.on('packet', (packet) => this.handlePacket(packet));
            this.networkMonitor.on('connection', (connection) => this.handleConnection(connection));
            this.networkMonitor.on('error', (error) => this.handleMonitorError(error));
            
            console.log('✅ Network monitoring started');
            
        } catch (error) {
            console.error('❌ Failed to start network monitoring:', error.message);
            throw error;
        }
    }

    async stopNetworkMonitoring() {
        console.log('🛑 Stopping network monitoring...');
        
        try {
            await this.networkMonitor.stopMonitoring();
            
            // Clear active captures
            for (const [name, capture] of this.activeCaptures) {
                if (capture && typeof capture.stop === 'function') {
                    await capture.stop();
                }
            }
            this.activeCaptures.clear();
            
            console.log('✅ Network monitoring stopped');
            
        } catch (error) {
            console.error('❌ Error stopping network monitoring:', error.message);
            throw error;
        }
    }

    getDefaultInterface() {
        if (!this.interfaces || this.interfaces.length === 0) {
            return {
                name: process.platform === 'darwin' ? 'en0' : 'eth0',
                description: 'Default interface'
            };
        }
        
        // Prefer ethernet interfaces, then wifi, then others
        const preferred = this.interfaces.find(iface => 
            iface.type === 'ethernet' || iface.name.startsWith('en') || iface.name.startsWith('eth')
        );
        
        return preferred || this.interfaces[0];
    }

    async handlePacket(packet) {
        try {
            this.packetsProcessed++;
            
            // Analyze packet with packet analyzer
            const analysis = await this.packetAnalyzer.analyze(packet);
            
            // Check for threats
            const threats = await this.threatDetector.analyzePacket(packet, analysis);
            
            if (threats && threats.length > 0) {
                this.threatsDetected++;
                
                // Create security event
                const securityEvent = this.createSecurityEvent(packet, threats);
                this.bufferEvent(securityEvent);
                
                // Generate alert if needed
                await this.generateAlert(threats[0], packet);
            }
            
        } catch (error) {
            console.error('Error handling packet:', error);
        }
    }

    async handleConnection(connection) {
        try {
            // Analyze connection for threats
            const threats = await this.threatDetector.analyzeConnection(connection);
            
            if (threats && threats.length > 0) {
                this.threatsDetected++;
                
                // Create connection event
                const connectionEvent = this.createConnectionEvent(connection, threats);
                this.bufferEvent(connectionEvent);
                
                // Generate alert if needed
                await this.generateAlert(threats[0], connection);
            }
            
        } catch (error) {
            console.error('Error handling connection:', error);
        }
    }

    handleMonitorError(error) {
        console.error('Network monitor error:', error);
        this.emit('monitor-error', error);
    }

    createSecurityEvent(packet, threats = []) {
        return {
            id: uuidv4(),
            timestamp: new Date().toISOString(),
            type: 'packet',
            agent: {
                id: this.config.agentId || 'unknown',
                hostname: require('os').hostname(),
                platform: process.platform
            },
            network: {
                interface: packet.interface || 'unknown',
                protocol: packet.protocol,
                srcIp: packet.srcIp,
                dstIp: packet.dstIp,
                srcPort: packet.srcPort,
                dstPort: packet.dstPort,
                size: packet.size
            },
            threats: threats.map(threat => ({
                type: threat.type,
                severity: threat.severity,
                description: threat.description,
                confidence: threat.confidence
            })),
            metadata: {
                processed: this.packetsProcessed,
                detected: this.threatsDetected
            }
        };
    }

    createConnectionEvent(connection, threats = []) {
        return {
            id: uuidv4(),
            timestamp: new Date().toISOString(),
            type: 'connection',
            agent: {
                id: this.config.agentId || 'unknown',
                hostname: require('os').hostname(),
                platform: process.platform
            },
            connection: {
                state: connection.state,
                protocol: connection.protocol,
                localAddress: connection.localAddress,
                localPort: connection.localPort,
                remoteAddress: connection.remoteAddress,
                remotePort: connection.remotePort,
                processName: connection.processName,
                pid: connection.pid
            },
            threats: threats.map(threat => ({
                type: threat.type,
            severity: threat.severity,
            description: threat.description,
                confidence: threat.confidence
            })),
            metadata: {
                processed: this.packetsProcessed,
                detected: this.threatsDetected
            }
        };
    }

    async generateAlert(threat, source) {
        try {
            const alert = {
                id: uuidv4(),
                timestamp: new Date().toISOString(),
                severity: this.getSeverityName(threat.severity),
                type: threat.type,
                title: threat.description,
                description: `${threat.type} detected: ${threat.description}`,
                source: {
                    type: source.srcIp ? 'packet' : 'connection',
                    details: source
                },
                agent: {
                    id: this.config.agentId || 'unknown',
                    hostname: require('os').hostname(),
                    platform: process.platform
                },
                metadata: {
                    confidence: threat.confidence,
                    riskScore: this.calculateRiskScore(threat),
                    recommendations: this.getRecommendations(threat)
            }
        };

        this.alertsGenerated++;
        this.bufferAlert(alert);
            this.emit('alert', alert);
            
            console.log(`🚨 Alert generated: ${alert.severity} - ${alert.title}`);
            
        } catch (error) {
            console.error('Error generating alert:', error);
        }
    }

    getSeverityName(level) {
        const severities = {
            1: 'info',
            2: 'low',
            3: 'medium',
            4: 'high',
            5: 'critical'
        };
        return severities[level] || 'unknown';
    }

    calculateRiskScore(threat) {
        // Simple risk calculation based on severity and confidence
        return Math.min(10, (threat.severity * 2) + (threat.confidence / 10));
    }

    getRecommendations(threat) {
        const recommendations = {
            'port_scan': ['Monitor for additional scanning activity', 'Check firewall rules'],
            'suspicious_connection': ['Investigate process', 'Check for malware'],
            'ddos': ['Implement rate limiting', 'Contact ISP if needed'],
            'malware': ['Run antivirus scan', 'Isolate affected system']
        };
        
        return recommendations[threat.type] || ['Investigate further', 'Monitor for related activity'];
    }

    async resolveHostname(ip) {
        try {
            const dns = require('dns').promises;
            const result = await dns.reverse(ip);
            return result[0] || ip;
        } catch (error) {
            return ip;
        }
    }

    bufferEvent(event) {
        this.eventBuffer.push(event);
        if (this.eventBuffer.length >= this.maxBufferSize) {
            this.flushEventBuffer();
        }
    }

    bufferAlert(alert) {
        this.alertBuffer.push(alert);
        if (this.alertBuffer.length >= Math.min(100, this.maxBufferSize / 10)) {
            this.flushAlertBuffer();
        }
    }

    async flushEventBuffer() {
        if (this.eventBuffer.length === 0) return;
        
        try {
            const events = [...this.eventBuffer];
            this.eventBuffer = [];
            
            // Compress events if enabled
            let payload = events;
            if (this.config.compression?.enabled) {
                payload = await this.dataCompressor.compress(events);
            }
            
            // Send to cloud or local storage
            if (this.cloudConnection && this.cloudConnection.isConnected()) {
                await this.cloudConnection.sendEvents(payload);
            } else {
                await this.storeLocalBackup('events', events);
            }
            
        } catch (error) {
            console.error('Error flushing event buffer:', error);
            // Re-add events to buffer if sending failed
            this.eventBuffer.unshift(...this.eventBuffer);
        }
    }

    async flushAlertBuffer() {
        if (this.alertBuffer.length === 0) return;
        
        try {
            const alerts = [...this.alertBuffer];
            this.alertBuffer = [];
            
            // Send alerts with high priority
            if (this.cloudConnection && this.cloudConnection.isConnected()) {
                await this.cloudConnection.sendAlerts(alerts);
            } else {
                await this.storeLocalBackup('alerts', alerts);
            }
            
            console.log(`📤 Flushed ${alerts.length} alerts`);
            
        } catch (error) {
            console.error('Error flushing alert buffer:', error);
            // Re-add alerts to buffer if sending failed
            this.alertBuffer.unshift(...alerts);
        }
    }

    async storeLocalBackup(type, data) {
        try {
            const fs = require('fs').promises;
            const path = require('path');
            
            const backupDir = path.join(process.cwd(), 'backups', type);
            await fs.mkdir(backupDir, { recursive: true });
            
            const filename = `${type}_${Date.now()}.json`;
            const filepath = path.join(backupDir, filename);
            
            await fs.writeFile(filepath, JSON.stringify(data, null, 2));
            console.log(`💾 Stored ${data.length} ${type} to local backup: ${filename}`);
            
        } catch (error) {
            console.error(`Error storing local backup for ${type}:`, error);
        }
    }

    async flushBuffers() {
        await Promise.all([
            this.flushEventBuffer(),
            this.flushAlertBuffer(),
            this.flushLogBuffer()
        ]);
    }

    startHeartbeat() {
        this.heartbeatInterval = setInterval(async () => {
            try {
                const status = await this.getStatus();
                
                if (this.cloudConnection && this.cloudConnection.isConnected()) {
                await this.cloudConnection.sendHeartbeat(status);
                }
                
                this.emit('heartbeat', status);
                
            } catch (error) {
                console.error('Error sending heartbeat:', error);
            }
        }, this.config.heartbeatInterval || 30000);
    }

    startDataTransmission() {
        // Periodic buffer flush
        setInterval(() => {
            this.flushBuffers();
        }, this.config.transmissionInterval || 60000);
    }

    setupEventHandlers() {
        // Setup internal event handlers
        this.on('packet', this.handlePacket.bind(this));
        this.on('connection', this.handleConnection.bind(this));
        this.on('error', (error) => {
            console.error('Agent error:', error);
        });
    }

    setupLogCollectorEvents() {
        if (!this.logCollector) return;
        
        this.logCollector.on('log', (logEntry) => {
            this.handleLogEntry(logEntry);
        });
        
        this.logCollector.on('systemInfo', (systemInfo) => {
            this.handleSystemInfo(systemInfo);
        });
        
        this.logCollector.on('error', (error) => {
            console.error('Log collector error:', error);
        });
    }

    handleLogEntry(logEntry) {
        try {
            this.logsCollected++;
            
            // Analyze log entry for threats
            const threats = this.threatDetector.analyzeLogEntry ? 
                this.threatDetector.analyzeLogEntry(logEntry) : [];
        
        if (threats && threats.length > 0) {
                this.threatsDetected++;
                
                // Generate log-based alert
                this.generateLogAlert(threats[0], logEntry);
        }
        
            // Buffer log entry
        this.bufferLog(logEntry);
            
        } catch (error) {
            console.error('Error handling log entry:', error);
        }
    }

    handleSystemInfo(systemInfo) {
        try {
            // Update agent metrics with system information
            this.metricsCollector.updateSystemInfo(systemInfo);
            
            // Check for system-level threats
            if (systemInfo.cpuUsage > 90) {
                console.warn('⚠️  High CPU usage detected:', systemInfo.cpuUsage + '%');
            }
            
            if (systemInfo.memoryUsage > 90) {
                console.warn('⚠️  High memory usage detected:', systemInfo.memoryUsage + '%');
            }
            
        } catch (error) {
            console.error('Error handling system info:', error);
        }
    }

    async generateLogAlert(threat, logEntry) {
        try {
        const alert = {
            id: uuidv4(),
            timestamp: new Date().toISOString(),
                severity: this.getSeverityName(threat.severity || 3),
                type: 'log_analysis',
                title: `Log Threat: ${threat.type}`,
                description: threat.description,
                source: {
                    type: 'log',
                    details: {
                timestamp: logEntry.timestamp,
                        process: logEntry.process,
                message: logEntry.message,
                        category: logEntry.category,
                        level: logEntry.level
                    }
                },
                agent: {
                    id: this.config.agentId || 'unknown',
                    hostname: require('os').hostname(),
                    platform: process.platform
            },
            metadata: {
                    confidence: threat.confidence || 80,
                    riskScore: this.calculateRiskScore(threat),
                    recommendations: this.getRecommendations(threat)
            }
        };

            this.alertsGenerated++;
        this.bufferAlert(alert);
            this.emit('alert', alert);
            
            console.log(`🚨 Log Alert: ${alert.severity} - ${alert.title}`);
        
        } catch (error) {
            console.error('Error generating log alert:', error);
        }
    }

    bufferLog(logEntry) {
        this.logBuffer.push(logEntry);
        if (this.logBuffer.length >= this.maxBufferSize) {
            this.flushLogBuffer();
        }
    }

    async flushLogBuffer() {
        if (this.logBuffer.length === 0) return;
        
        try {
        const logs = [...this.logBuffer];
        this.logBuffer = [];
        
            // Send logs to cloud or local storage
            if (this.cloudConnection && this.cloudConnection.isConnected()) {
                await this.cloudConnection.sendLogs(logs);
            } else {
                await this.storeLocalBackup('logs', logs);
            }
            
            } catch (error) {
            console.error('Error flushing log buffer:', error);
            // Re-add logs to buffer if sending failed
                this.logBuffer.unshift(...logs);
        }
    }

    async getStatus() {
        const uptime = this.startTime ? Date.now() - this.startTime.getTime() : 0;
        const memUsage = process.memoryUsage();
        
        return {
            agent: {
                id: this.config.agentId || 'unknown',
                version: this.config.version || '1.2.4',
                hostname: require('os').hostname(),
                platform: process.platform,
                privilegeLevel: this.privilegeLevel ? 'root' : 'user'
            },
            status: {
            isRunning: this.isRunning,
                uptime: uptime,
                startTime: this.startTime
            },
            performance: {
                packetsProcessed: this.packetsProcessed,
                threatsDetected: this.threatsDetected,
                alertsGenerated: this.alertsGenerated,
                logsCollected: this.logsCollected,
                memory: {
                    rss: memUsage.rss,
                    heapUsed: memUsage.heapUsed,
                    heapTotal: memUsage.heapTotal,
                    external: memUsage.external
                }
            },
            network: {
                interfaces: this.interfaces.length,
                activeCaptures: this.activeCaptures.size,
                monitoring: this.networkMonitor ? this.networkMonitor.isMonitoring : false
            },
            buffers: {
                events: this.eventBuffer.length,
                alerts: this.alertBuffer.length,
                logs: this.logBuffer.length
            }
        };
    }

    async getMetrics() {
        return {
            ...await this.getStatus(),
            system: await this.metricsCollector.getSystemMetrics(),
            network: this.networkMonitor ? await this.networkMonitor.getDetailedStatistics() : {},
            logs: this.logCollector ? this.logCollector.getStatistics() : {}
        };
    }

    async getCpuUsage() {
        return new Promise((resolve) => {
            const startUsage = process.cpuUsage();
            setTimeout(() => {
                const endUsage = process.cpuUsage(startUsage);
                const cpuPercent = ((endUsage.user + endUsage.system) / 1000000) * 100;
                resolve(Math.min(100, cpuPercent));
            }, 100);
        });
    }
}

module.exports = NetworkAgent; 