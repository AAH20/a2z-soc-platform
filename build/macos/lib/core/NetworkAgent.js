const pcap = require('pcap');
const EventEmitter = require('events');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const PacketAnalyzer = require('./PacketAnalyzer');
const ThreatDetector = require('./ThreatDetector');
const DataCompressor = require('../utils/DataCompressor');
const MetricsCollector = require('../utils/MetricsCollector');
const ApiServer = require('../api/ApiServer');

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
            port: config.apiPort || 3001,
            host: config.apiHost || '0.0.0.0'
        });
        
        // Log collector (platform-specific)
        if (LogCollector && config.logCollection?.enabled) {
            this.logCollector = new LogCollector(config.logCollection);
        } else {
            this.logCollector = null;
        }
        
        // Store reference to config manager if provided
        this.configManager = null;
        
        // Packet capture
        this.pcapSession = null;
        this.interfaces = [];
        
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
    }

    // Add method to set config manager reference
    setConfigManager(configManager) {
        this.configManager = configManager;
    }

    async initialize() {
        try {
            // Detect available network interfaces
            this.interfaces = this.getNetworkInterfaces();
            
            // Initialize packet analyzer
            await this.packetAnalyzer.initialize();
            
            // Initialize threat detector
            await this.threatDetector.initialize();
            
            // Load threat intelligence rules
            await this.threatDetector.loadRules();
            
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
            
            console.log(`🔍 Network Agent initialized with ${this.interfaces.length} interfaces`);
            
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
            
            // Start packet capture
            await this.startPacketCapture();
            
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
            // Stop packet capture
            if (this.pcapSession) {
                this.pcapSession.close();
                this.pcapSession = null;
            }
            
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
        console.log(`🔄 Restarting Network Agent...`);
        await this.stop();
        await new Promise(resolve => setTimeout(resolve, 1000)); // Wait 1 second
        await this.start();
        console.log(`🔄 Network Agent restarted successfully`);
    }

    getNetworkInterfaces() {
        try {
            const devices = pcap.findalldevs();
            return devices.filter(device => {
                // Filter out loopback and inactive interfaces
                return !device.name.includes('lo') && 
                       device.addresses && 
                       device.addresses.length > 0;
            }).map(device => ({
                name: device.name,
                description: device.description || 'Unknown interface',
                addresses: device.addresses
            }));
        } catch (error) {
            console.warn('⚠️  Could not enumerate network interfaces:', error.message);
            return [];
        }
    }

    async startPacketCapture() {
        const interfaceName = this.config.networkInterface || this.getDefaultInterface();
        
        if (!interfaceName) {
            throw new Error('No suitable network interface found');
        }

        try {
            // Create packet capture session
            this.pcapSession = pcap.createSession(interfaceName, {
                filter: this.config.pcapFilter || 'ip',
                buffer_size: this.config.bufferSize || 10 * 1024 * 1024, // 10MB
                buffer_timeout: this.config.bufferTimeout || 1000 // 1 second
            });

            this.pcapSession.on('packet', (rawPacket) => {
                this.handlePacket(rawPacket);
            });

            console.log(`📡 Started packet capture on interface: ${interfaceName}`);
            
        } catch (error) {
            throw new Error(`Failed to start packet capture: ${error.message}`);
        }
    }

    getDefaultInterface() {
        // Return the first non-loopback interface with IP address
        return this.interfaces.length > 0 ? this.interfaces[0].name : null;
    }

    async handlePacket(rawPacket) {
        try {
            this.packetsProcessed++;
            this.metricsCollector.incrementCounter('packets_processed');
            
            // Parse packet
            const packet = this.packetAnalyzer.parsePacket(rawPacket);
            if (!packet) return;
            
            // Analyze for threats
            const threats = await this.threatDetector.analyzePacket(packet);
            
            if (threats && threats.length > 0) {
                this.threatsDetected += threats.length;
                this.metricsCollector.incrementCounter('threats_detected', threats.length);
                
                // Generate alerts
                for (const threat of threats) {
                    await this.generateAlert(threat, packet);
                }
            }
            
            // Create security event
            const event = this.createSecurityEvent(packet, threats);
            this.bufferEvent(event);
            
        } catch (error) {
            console.error('❌ Error handling packet:', error);
            this.metricsCollector.incrementCounter('packet_errors');
        }
    }

    createSecurityEvent(packet, threats = []) {
        return {
            id: uuidv4(),
            timestamp: new Date().toISOString(),
            tenant_id: this.config.tenantId,
            agent_id: this.config.agentId,
            event_type: 'network_packet',
            source_ip: packet.payload?.payload?.saddr?.addr || 'unknown',
            destination_ip: packet.payload?.payload?.daddr?.addr || 'unknown',
            source_port: packet.payload?.payload?.sport || 0,
            destination_port: packet.payload?.payload?.dport || 0,
            protocol: packet.payload?.payload?.protocol || 'unknown',
            packet_size: packet.header?.len || 0,
            threat_count: threats.length,
            threats: threats.map(t => ({
                type: t.type,
                severity: t.severity,
                rule_id: t.ruleId,
                description: t.description
            })),
            metadata: {
                interface: this.config.networkInterface,
                ttl: packet.payload?.payload?.ttl,
                flags: packet.payload?.payload?.flags
            }
        };
    }

    async generateAlert(threat, packet) {
        const alert = {
            id: uuidv4(),
            timestamp: new Date().toISOString(),
            tenant_id: this.config.tenantId,
            agent_id: this.config.agentId,
            alert_type: 'network_threat',
            severity: threat.severity,
            title: threat.title || `${threat.type} detected`,
            description: threat.description,
            source_ip: packet.payload?.payload?.saddr?.addr,
            destination_ip: packet.payload?.payload?.daddr?.addr,
            rule_id: threat.ruleId,
            technique: threat.technique,
            tactics: threat.tactics || [],
            indicators: threat.indicators || [],
            raw_packet: this.config.includeRawPackets ? packet.header.toString('base64') : null,
            metadata: {
                confidence: threat.confidence || 0.8,
                false_positive_risk: threat.falsePositiveRisk || 'low',
                threat_score: threat.score || 50
            }
        };

        this.alertsGenerated++;
        this.metricsCollector.incrementCounter('alerts_generated');
        this.bufferAlert(alert);
        
        // Emit alert for real-time processing
        this.emit('alert', alert);
    }

    bufferEvent(event) {
        this.eventBuffer.push(event);
        
        if (this.eventBuffer.length >= this.maxBufferSize) {
            this.flushEventBuffer();
        }
    }

    bufferAlert(alert) {
        this.alertBuffer.push(alert);
        
        // Alerts are sent immediately for critical severities
        if (alert.severity === 'critical' || alert.severity === 'high') {
            this.flushAlertBuffer();
        } else if (this.alertBuffer.length >= 10) {
            this.flushAlertBuffer();
        }
    }

    async flushEventBuffer() {
        if (this.eventBuffer.length === 0) return;
        
        try {
            const events = [...this.eventBuffer];
            this.eventBuffer = [];
            
            // Compress data
            const compressedData = await this.dataCompressor.compress(events);
            
            // Send to cloud
            await this.cloudConnection.sendEvents({
                type: 'security_events',
                tenant_id: this.config.tenantId,
                agent_id: this.config.agentId,
                timestamp: new Date().toISOString(),
                count: events.length,
                data: compressedData
            });
            
            this.metricsCollector.incrementCounter('events_sent', events.length);
            
        } catch (error) {
            console.error('❌ Failed to flush event buffer:', error);
            this.metricsCollector.incrementCounter('transmission_errors');
        }
    }

    async flushAlertBuffer() {
        if (this.alertBuffer.length === 0) return;
        
        try {
            const alerts = [...this.alertBuffer];
            this.alertBuffer = [];
            
            // Send alerts (uncompressed for immediate processing)
            await this.cloudConnection.sendAlerts({
                type: 'security_alerts',
                tenant_id: this.config.tenantId,
                agent_id: this.config.agentId,
                timestamp: new Date().toISOString(),
                count: alerts.length,
                alerts: alerts
            });
            
            this.metricsCollector.incrementCounter('alerts_sent', alerts.length);
            
        } catch (error) {
            console.error('❌ Failed to flush alert buffer:', error);
            this.metricsCollector.incrementCounter('transmission_errors');
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
                await this.cloudConnection.sendHeartbeat(status);
                this.metricsCollector.incrementCounter('heartbeats_sent');
            } catch (error) {
                console.error('❌ Failed to send heartbeat:', error);
                this.metricsCollector.incrementCounter('heartbeat_errors');
            }
        }, this.config.heartbeatInterval || 30000); // 30 seconds
    }

    startDataTransmission() {
        // Periodic buffer flush
        setInterval(() => {
            this.flushEventBuffer();
        }, this.config.flushInterval || 10000); // 10 seconds
        
        // Periodic alert flush for low priority alerts
        setInterval(() => {
            this.flushAlertBuffer();
        }, this.config.alertFlushInterval || 5000); // 5 seconds
    }

    setupEventHandlers() {
        this.on('alert', (alert) => {
            console.log(`🚨 ${alert.severity.toUpperCase()} Alert: ${alert.title}`);
        });
        
        this.on('threat', (threat) => {
            console.log(`⚠️  Threat detected: ${threat.type}`);
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
        // Process log entry for threats
        const threats = this.threatDetector.analyzeLogEntry(logEntry);
        
        if (threats && threats.length > 0) {
            threats.forEach(threat => {
                this.generateLogAlert(threat, logEntry);
            });
        }
        
        // Buffer log entry for transmission
        this.bufferLog(logEntry);
        this.logsCollected++;
    }

    handleSystemInfo(systemInfo) {
        // Create system info event
        const event = {
            id: uuidv4(),
            type: 'system_info',
            timestamp: new Date().toISOString(),
            agentId: this.config.agentId,
            data: systemInfo,
            metadata: {
                version: this.config.version,
                platform: process.platform
            }
        };
        
        this.bufferEvent(event);
    }

    async generateLogAlert(threat, logEntry) {
        const alert = {
            id: uuidv4(),
            type: 'log_threat',
            severity: threat.severity || 'medium',
            timestamp: new Date().toISOString(),
            agentId: this.config.agentId,
            source: logEntry.source,
            threat: {
                name: threat.name,
                description: threat.description,
                category: threat.category,
                confidence: threat.confidence,
                indicators: threat.indicators || []
            },
            logData: {
                timestamp: logEntry.timestamp,
                level: logEntry.level,
                message: logEntry.message,
                hostname: logEntry.hostname
            },
            metadata: {
                platform: process.platform,
                version: this.config.version
            }
        };

        this.bufferAlert(alert);
        this.alertsGenerated++;
        
        console.log(`🚨 Log threat detected: ${threat.name} in ${logEntry.source}`);
    }

    bufferLog(logEntry) {
        this.logBuffer.push(logEntry);
        
        if (this.logBuffer.length >= this.maxBufferSize) {
            this.flushLogBuffer();
        }
    }

    async flushLogBuffer() {
        if (this.logBuffer.length === 0) return;
        
        const logs = [...this.logBuffer];
        this.logBuffer = [];
        
        const payload = {
            agentId: this.config.agentId,
            timestamp: new Date().toISOString(),
            type: 'logs',
            data: logs,
            metadata: {
                count: logs.length,
                platform: process.platform,
                version: this.config.version
            }
        };

        // Compress if enabled
        if (this.config.compression?.enabled) {
            payload.data = await this.dataCompressor.compress(JSON.stringify(payload.data));
            payload.compressed = true;
        }

        if (this.cloudConnection) {
            try {
                await this.cloudConnection.send(JSON.stringify(payload));
                console.log(`📤 Transmitted ${logs.length} log entries`);
            } catch (error) {
                console.error('Failed to transmit log data:', error);
                // Re-buffer if transmission failed
                this.logBuffer.unshift(...logs);
            }
        } else {
            // Store locally if no cloud connection
            console.log(`💾 Stored ${logs.length} log entries locally`);
        }
    }

    async getStatus() {
        const baseStatus = {
            isRunning: this.isRunning,
            startTime: this.startTime,
            uptime: this.startTime ? Date.now() - this.startTime.getTime() : 0,
            platform: process.platform,
            version: this.config.version,
            interfaces: this.interfaces.length,
            cloudConnected: !!this.cloudConnection,
            performance: {
                packetsProcessed: this.packetsProcessed,
                threatsDetected: this.threatsDetected,
                alertsGenerated: this.alertsGenerated,
                logsCollected: this.logsCollected
            },
            buffers: {
                events: this.eventBuffer.length,
                alerts: this.alertBuffer.length,
                logs: this.logBuffer.length
            }
        };

        // Add log collector status if available
        if (this.logCollector) {
            baseStatus.logCollection = {
                enabled: true,
                platform: process.platform,
                sources: this.config.logCollection?.sources || []
            };
        }

        return baseStatus;
    }

    async getMetrics() {
        const baseMetrics = await this.metricsCollector.getMetrics();
        
        return {
            ...baseMetrics,
            agent: {
                packetsProcessed: this.packetsProcessed,
                threatsDetected: this.threatsDetected,
                alertsGenerated: this.alertsGenerated,
                logsCollected: this.logsCollected,
                bufferSizes: {
                    events: this.eventBuffer.length,
                    alerts: this.alertBuffer.length,
                    logs: this.logBuffer.length
                }
            },
            platform: {
                name: process.platform,
                arch: process.arch,
                nodeVersion: process.version
            }
        };
    }
}

module.exports = NetworkAgent; 