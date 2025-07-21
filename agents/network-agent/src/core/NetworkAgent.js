const EventEmitter = require('events');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { Pool } = require('pg');
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
        
        // Database connection
        this.pool = new Pool({
            user: process.env.DB_USER || 'postgres',
            host: process.env.DB_HOST || 'localhost',
            database: process.env.DB_NAME || 'a2z_soc',
            password: process.env.DB_PASSWORD || 'postgres',
            port: process.env.DB_PORT || 5432,
        });
        
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
        }
        
        // Agent state
        this.agentId = config.agentId || uuidv4();
        this.agentVersion = config.version || '1.0.0';
        this.lastHeartbeat = null;
        this.metrics = {
            packetsProcessed: 0,
            threatsDetected: 0,
            alertsGenerated: 0,
            bytesTransferred: 0,
            uptime: 0
        };
        
        // Initialize database connection
        this.initializeDatabase();
        
        // Setup event handlers
        this.setupEventHandlers();
    }

    async initializeDatabase() {
        try {
            // Test database connection
            await this.pool.query('SELECT 1');
            console.log('✅ Database connection established');
            
            // Register or update agent in database
            await this.registerAgent();
            
        } catch (error) {
            console.error('❌ Database connection failed:', error.message);
            // Continue without database for now
        }
    }

    async registerAgent() {
        try {
            const agentData = {
                agent_id: this.agentId,
                name: this.config.name || `Network Agent ${this.agentId.slice(0, 8)}`,
                type: 'network-agent',
                version: this.agentVersion,
                platform: process.platform,
                hostname: require('os').hostname(),
                ip_address: await this.getLocalIP(),
                status: 'active',
                configuration: this.config,
                last_heartbeat: new Date(),
                created_at: new Date(),
                updated_at: new Date()
            };

            const query = `
                INSERT INTO network_agents (
                    agent_id, name, type, version, platform, hostname, 
                    ip_address, status, configuration, last_heartbeat, 
                    created_at, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                ON CONFLICT (agent_id) DO UPDATE SET
                    name = EXCLUDED.name,
                    version = EXCLUDED.version,
                    platform = EXCLUDED.platform,
                    hostname = EXCLUDED.hostname,
                    ip_address = EXCLUDED.ip_address,
                    status = EXCLUDED.status,
                    configuration = EXCLUDED.configuration,
                    last_heartbeat = EXCLUDED.last_heartbeat,
                    updated_at = EXCLUDED.updated_at
                RETURNING *
            `;

            const values = [
                agentData.agent_id,
                agentData.name,
                agentData.type,
                agentData.version,
                agentData.platform,
                agentData.hostname,
                agentData.ip_address,
                agentData.status,
                agentData.configuration,
                agentData.last_heartbeat,
                agentData.created_at,
                agentData.updated_at
            ];

            const result = await this.pool.query(query, values);
            console.log(`✅ Agent registered in database: ${this.agentId}`);
            
        } catch (error) {
            console.error('❌ Failed to register agent:', error.message);
        }
    }

    async getLocalIP() {
        try {
            const networkInterfaces = await si.networkInterfaces();
            const activeInterface = networkInterfaces.find(iface => 
                iface.ip4 && !iface.internal && iface.operstate === 'up'
            );
            return activeInterface ? activeInterface.ip4 : '127.0.0.1';
        } catch (error) {
            return '127.0.0.1';
        }
    }

    async storeNetworkEvent(eventData) {
        try {
            const query = `
                INSERT INTO network_events (
                    agent_id, event_type, timestamp, source_ip, destination_ip,
                    source_port, destination_port, protocol, packet_size,
                    threat_level, event_data, created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                RETURNING id
            `;

            const values = [
                this.agentId,
                eventData.type || 'network_activity',
                eventData.timestamp || new Date(),
                eventData.sourceIP,
                eventData.destinationIP,
                eventData.sourcePort,
                eventData.destinationPort,
                eventData.protocol,
                eventData.packetSize,
                eventData.threatLevel || 'low',
                eventData,
                new Date()
            ];

            const result = await this.pool.query(query, values);
            return result.rows[0].id;
            
        } catch (error) {
            console.error('Failed to store network event:', error.message);
            return null;
        }
    }

    async updateHeartbeat() {
        try {
            const query = `
                UPDATE network_agents 
                SET last_heartbeat = $1, 
                    status = $2,
                    metrics = $3,
                    updated_at = $4
                WHERE agent_id = $5
            `;

            const values = [
                new Date(),
                'active',
                this.metrics,
                new Date(),
                this.agentId
            ];

            await this.pool.query(query, values);
            this.lastHeartbeat = new Date();
            
        } catch (error) {
            console.error('Failed to update heartbeat:', error.message);
        }
    }

    setupEventHandlers() {
        // Network monitoring events
        this.networkMonitor.on('packet', (packet) => {
            this.handlePacket(packet);
        });

        this.networkMonitor.on('connection', (connection) => {
            this.handleConnection(connection);
        });

        // Threat detection events
        this.threatDetector.on('threat', (threat) => {
            this.handleThreat(threat);
        });

        // Log collection events
        if (this.logCollector) {
            this.logCollector.on('log', (log) => {
                this.handleLog(log);
            });
        }

        // Metrics collection
        this.metricsCollector.on('metrics', (metrics) => {
            this.handleMetrics(metrics);
        });
    }

    async handlePacket(packet) {
        try {
            this.metrics.packetsProcessed++;
            this.metrics.bytesTransferred += packet.size || 0;

            // Analyze packet
            const analysis = await this.packetAnalyzer.analyze(packet);
            
            // Check for threats
            const threatResult = await this.threatDetector.analyze(packet, analysis);
            
            if (threatResult.isThreat) {
                this.metrics.threatsDetected++;
                await this.handleThreat(threatResult);
            }

            // Store network event in database
            await this.storeNetworkEvent({
                type: 'packet',
                timestamp: new Date(),
                sourceIP: packet.sourceIP,
                destinationIP: packet.destinationIP,
                sourcePort: packet.sourcePort,
                destinationPort: packet.destinationPort,
                protocol: packet.protocol,
                packetSize: packet.size,
                threatLevel: threatResult.isThreat ? threatResult.level : 'low',
                analysis: analysis,
                threat: threatResult.isThreat ? threatResult : null
            });

            // Emit event for real-time monitoring
            this.emit('packet', {
                packet,
                analysis,
                threat: threatResult.isThreat ? threatResult : null
            });

        } catch (error) {
            console.error('Error handling packet:', error);
        }
    }

    async handleConnection(connection) {
        try {
            // Store connection event
            await this.storeNetworkEvent({
                type: 'connection',
                timestamp: new Date(),
                sourceIP: connection.localAddress,
                destinationIP: connection.remoteAddress,
                sourcePort: connection.localPort,
                destinationPort: connection.remotePort,
                protocol: connection.protocol,
                state: connection.state,
                threatLevel: 'low'
            });

            this.emit('connection', connection);
            
        } catch (error) {
            console.error('Error handling connection:', error);
        }
    }

    async handleThreat(threat) {
        try {
            this.metrics.alertsGenerated++;

            // Store threat in database
            const query = `
                INSERT INTO security_events (
                    agent_id, event_type, severity, title, description,
                    source_ip, destination_ip, indicators, raw_data,
                    created_at, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                RETURNING id
            `;

            const values = [
                this.agentId,
                'threat_detected',
                threat.severity || 'medium',
                threat.title || 'Network Threat Detected',
                threat.description || 'Suspicious network activity detected',
                threat.sourceIP,
                threat.destinationIP,
                threat.indicators || {},
                threat,
                new Date(),
                new Date()
            ];

            const result = await this.pool.query(query, values);
            
            // Send to cloud if connected
            if (this.cloudConnection && this.cloudConnection.isConnected()) {
                await this.cloudConnection.sendThreat(threat);
            }

            this.emit('threat', threat);
            
        } catch (error) {
            console.error('Error handling threat:', error);
        }
    }

    async handleLog(log) {
        try {
            // Store log in database
            await this.storeNetworkEvent({
                type: 'log',
                timestamp: log.timestamp || new Date(),
                sourceIP: log.sourceIP,
                message: log.message,
                level: log.level,
                threatLevel: log.threatLevel || 'low',
                logData: log
            });

            this.emit('log', log);
            
        } catch (error) {
            console.error('Error handling log:', error);
        }
    }

    async handleMetrics(metrics) {
        try {
            // Update internal metrics
            Object.assign(this.metrics, metrics);
            this.metrics.uptime = process.uptime();

            // Update heartbeat with metrics
            await this.updateHeartbeat();

            this.emit('metrics', this.metrics);
            
        } catch (error) {
            console.error('Error handling metrics:', error);
        }
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

    checkPrivileges() {
        if (process.platform === 'darwin') {
            // Check if running as root on macOS
            return process.getuid && process.getuid() === 0;
        }
        return false;
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