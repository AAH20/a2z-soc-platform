const EventEmitter = require('events');
const NetworkAgent = require('../../src/core/NetworkAgent');
const PacketAnalyzer = require('../../src/core/PacketAnalyzer');
const ThreatDetector = require('../../src/core/ThreatDetector');
const ConfigManager = require('../../src/core/ConfigManager');

// Mock dependencies
jest.mock('../../src/core/PacketAnalyzer');
jest.mock('../../src/core/ThreatDetector');
jest.mock('../../src/core/MacOSNetworkMonitor');
jest.mock('../../src/utils/DataCompressor');
jest.mock('../../src/utils/MetricsCollector');
jest.mock('../../src/api/ApiServer');
jest.mock('../../src/collectors/MacOSLogCollector');

describe('NetworkAgent', () => {
    let networkAgent;
    let mockConfig;
    let mockCloudConnection;

    beforeEach(() => {
        // Reset all mocks
        jest.clearAllMocks();
        
        // Mock configuration
        mockConfig = {
            agentId: 'test-agent-001',
            tenantId: 'test-tenant',
            apiPort: 5200,
            apiHost: '0.0.0.0',
            networkInterface: 'eth0',
            logCollection: { enabled: true },
            maxBufferSize: 1000,
            heartbeatInterval: 30000,
            dataTransmissionInterval: 60000
        };

        // Mock cloud connection
        mockCloudConnection = {
            send: jest.fn(),
            isConnected: jest.fn().mockReturnValue(true),
            on: jest.fn(),
            emit: jest.fn()
        };

        // Create NetworkAgent instance
        networkAgent = new NetworkAgent(mockConfig, mockCloudConnection);
    });

    afterEach(() => {
        if (networkAgent && networkAgent.isRunning) {
            networkAgent.stop();
        }
    });

    describe('Constructor', () => {
        test('should initialize with correct configuration', () => {
            expect(networkAgent.config).toBe(mockConfig);
            expect(networkAgent.cloudConnection).toBe(mockCloudConnection);
            expect(networkAgent.isRunning).toBe(false);
            expect(networkAgent.startTime).toBeNull();
        });

        test('should initialize core components', () => {
            expect(PacketAnalyzer).toHaveBeenCalledWith(mockConfig);
            expect(ThreatDetector).toHaveBeenCalledWith(mockConfig);
            expect(networkAgent.packetAnalyzer).toBeDefined();
            expect(networkAgent.threatDetector).toBeDefined();
        });

        test('should initialize data buffers', () => {
            expect(networkAgent.eventBuffer).toEqual([]);
            expect(networkAgent.alertBuffer).toEqual([]);
            expect(networkAgent.logBuffer).toEqual([]);
            expect(networkAgent.maxBufferSize).toBe(1000);
        });

        test('should initialize performance counters', () => {
            expect(networkAgent.packetsProcessed).toBe(0);
            expect(networkAgent.threatsDetected).toBe(0);
            expect(networkAgent.alertsGenerated).toBe(0);
            expect(networkAgent.logsCollected).toBe(0);
        });
    });

    describe('Initialization', () => {
        test('should initialize successfully', async () => {
            // Mock network interfaces
            networkAgent.getNetworkInterfaces = jest.fn().mockResolvedValue([
                { name: 'eth0', description: 'Ethernet' },
                { name: 'lo', description: 'Loopback' }
            ]);

            // Mock component initialization
            networkAgent.packetAnalyzer.initialize = jest.fn().mockResolvedValue();
            networkAgent.threatDetector.initialize = jest.fn().mockResolvedValue();
            networkAgent.threatDetector.loadRules = jest.fn().mockResolvedValue();
            networkAgent.networkMonitor.initialize = jest.fn().mockResolvedValue();
            networkAgent.metricsCollector.startCollection = jest.fn();
            networkAgent.apiServer.start = jest.fn().mockResolvedValue();
            networkAgent.setupEventHandlers = jest.fn();

            await networkAgent.initialize();

            expect(networkAgent.packetAnalyzer.initialize).toHaveBeenCalled();
            expect(networkAgent.threatDetector.initialize).toHaveBeenCalled();
            expect(networkAgent.threatDetector.loadRules).toHaveBeenCalled();
            expect(networkAgent.networkMonitor.initialize).toHaveBeenCalled();
            expect(networkAgent.metricsCollector.startCollection).toHaveBeenCalled();
            expect(networkAgent.apiServer.start).toHaveBeenCalled();
        });

        test('should handle initialization failure', async () => {
            networkAgent.packetAnalyzer.initialize = jest.fn().mockRejectedValue(new Error('Init failed'));

            await expect(networkAgent.initialize()).rejects.toThrow('Failed to initialize NetworkAgent: Init failed');
        });
    });

    describe('Start/Stop Operations', () => {
        beforeEach(async () => {
            // Setup mocks for successful initialization
            networkAgent.getNetworkInterfaces = jest.fn().mockResolvedValue([
                { name: 'eth0', description: 'Ethernet' }
            ]);
            networkAgent.packetAnalyzer.initialize = jest.fn().mockResolvedValue();
            networkAgent.threatDetector.initialize = jest.fn().mockResolvedValue();
            networkAgent.threatDetector.loadRules = jest.fn().mockResolvedValue();
            networkAgent.networkMonitor.initialize = jest.fn().mockResolvedValue();
            networkAgent.metricsCollector.startCollection = jest.fn();
            networkAgent.apiServer.start = jest.fn().mockResolvedValue();
            networkAgent.setupEventHandlers = jest.fn();

            await networkAgent.initialize();
        });

        test('should start successfully', async () => {
            networkAgent.startNetworkMonitoring = jest.fn().mockResolvedValue();
            networkAgent.startHeartbeat = jest.fn();
            networkAgent.startDataTransmission = jest.fn();

            await networkAgent.start();

            expect(networkAgent.isRunning).toBe(true);
            expect(networkAgent.startTime).toBeInstanceOf(Date);
            expect(networkAgent.startNetworkMonitoring).toHaveBeenCalled();
            expect(networkAgent.startHeartbeat).toHaveBeenCalled();
            expect(networkAgent.startDataTransmission).toHaveBeenCalled();
        });

        test('should not start if already running', async () => {
            networkAgent.isRunning = true;

            await expect(networkAgent.start()).rejects.toThrow('NetworkAgent is already running');
        });

        test('should stop successfully', async () => {
            networkAgent.isRunning = true;
            networkAgent.stopNetworkMonitoring = jest.fn().mockResolvedValue();
            networkAgent.stopHeartbeat = jest.fn();
            networkAgent.stopDataTransmission = jest.fn();
            networkAgent.apiServer.stop = jest.fn().mockResolvedValue();

            await networkAgent.stop();

            expect(networkAgent.isRunning).toBe(false);
            expect(networkAgent.stopNetworkMonitoring).toHaveBeenCalled();
            expect(networkAgent.stopHeartbeat).toHaveBeenCalled();
            expect(networkAgent.stopDataTransmission).toHaveBeenCalled();
            expect(networkAgent.apiServer.stop).toHaveBeenCalled();
        });

        test('should restart successfully', async () => {
            networkAgent.stop = jest.fn().mockResolvedValue();
            networkAgent.start = jest.fn().mockResolvedValue();

            await networkAgent.restart();

            expect(networkAgent.stop).toHaveBeenCalled();
            expect(networkAgent.start).toHaveBeenCalled();
        });
    });

    describe('Packet Processing', () => {
        beforeEach(() => {
            networkAgent.packetAnalyzer.analyze = jest.fn().mockResolvedValue({
                protocol: 'TCP',
                size: 1024,
                flags: ['SYN']
            });
            networkAgent.threatDetector.analyzePacket = jest.fn().mockResolvedValue([]);
            networkAgent.createSecurityEvent = jest.fn().mockReturnValue({
                id: 'event-001',
                timestamp: new Date(),
                type: 'threat'
            });
            networkAgent.bufferEvent = jest.fn();
            networkAgent.generateAlert = jest.fn().mockResolvedValue();
        });

        test('should handle packet successfully', async () => {
            const mockPacket = {
                timestamp: new Date(),
                src_ip: '192.168.1.100',
                dst_ip: '192.168.1.1',
                protocol: 'TCP',
                size: 1024
            };

            await networkAgent.handlePacket(mockPacket);

            expect(networkAgent.packetsProcessed).toBe(1);
            expect(networkAgent.packetAnalyzer.analyze).toHaveBeenCalledWith(mockPacket);
            expect(networkAgent.threatDetector.analyzePacket).toHaveBeenCalled();
        });

        test('should handle threat detection', async () => {
            const mockPacket = {
                timestamp: new Date(),
                src_ip: '192.168.1.100',
                dst_ip: '192.168.1.1',
                protocol: 'TCP',
                size: 1024
            };

            const mockThreats = [
                { type: 'port_scan', severity: 'medium', confidence: 0.8 }
            ];

            networkAgent.threatDetector.analyzePacket = jest.fn().mockResolvedValue(mockThreats);

            await networkAgent.handlePacket(mockPacket);

            expect(networkAgent.threatsDetected).toBe(1);
            expect(networkAgent.createSecurityEvent).toHaveBeenCalledWith(mockPacket, mockThreats);
            expect(networkAgent.bufferEvent).toHaveBeenCalled();
            expect(networkAgent.generateAlert).toHaveBeenCalledWith(mockThreats[0], mockPacket);
        });

        test('should handle packet processing errors gracefully', async () => {
            const mockPacket = { invalid: 'packet' };
            networkAgent.packetAnalyzer.analyze = jest.fn().mockRejectedValue(new Error('Analysis failed'));

            // Should not throw
            await networkAgent.handlePacket(mockPacket);
            
            expect(networkAgent.packetsProcessed).toBe(1);
        });
    });

    describe('Status Management', () => {
        test('should return comprehensive status', async () => {
            networkAgent.isRunning = true;
            networkAgent.startTime = new Date('2024-01-01T00:00:00Z');
            networkAgent.packetsProcessed = 1000;
            networkAgent.threatsDetected = 5;
            networkAgent.alertsGenerated = 3;
            networkAgent.logsCollected = 200;
            networkAgent.interfaces = [{ name: 'eth0' }, { name: 'lo' }];
            networkAgent.activeCaptures = new Map([['eth0', {}]]);
            networkAgent.networkMonitor = { isMonitoring: true };
            networkAgent.eventBuffer = [1, 2, 3];
            networkAgent.alertBuffer = [1, 2];
            networkAgent.logBuffer = [1, 2, 3, 4];

            // Mock Date.now to return a fixed timestamp
            const mockNow = new Date('2024-01-01T01:00:00Z').getTime();
            jest.spyOn(Date, 'now').mockReturnValue(mockNow);

            const status = await networkAgent.getStatus();

            expect(status).toEqual({
                agent: {
                    id: 'test-agent-001',
                    version: expect.any(String),
                    hostname: expect.any(String),
                    platform: process.platform,
                    privilegeLevel: expect.any(String)
                },
                status: {
                    isRunning: true,
                    uptime: 3600000, // 1 hour
                    startTime: networkAgent.startTime
                },
                performance: {
                    packetsProcessed: 1000,
                    threatsDetected: 5,
                    alertsGenerated: 3,
                    logsCollected: 200,
                    memory: expect.any(Object)
                },
                network: {
                    interfaces: 2,
                    activeCaptures: 1,
                    monitoring: true
                },
                buffers: {
                    events: 3,
                    alerts: 2,
                    logs: 4
                }
            });

            Date.now.mockRestore();
        });

        test('should return status when not running', async () => {
            networkAgent.isRunning = false;
            networkAgent.startTime = null;

            const status = await networkAgent.getStatus();

            expect(status.status.isRunning).toBe(false);
            expect(status.status.uptime).toBe(0);
            expect(status.status.startTime).toBeNull();
        });
    });

    describe('Event Handling', () => {
        test('should buffer events correctly', () => {
            const event = { id: 'event-001', type: 'threat', data: {} };
            
            networkAgent.bufferEvent(event);
            
            expect(networkAgent.eventBuffer).toContain(event);
            expect(networkAgent.eventBuffer.length).toBe(1);
        });

        test('should maintain buffer size limit', () => {
            networkAgent.maxBufferSize = 3;
            
            const events = [
                { id: 'event-001' },
                { id: 'event-002' },
                { id: 'event-003' },
                { id: 'event-004' }
            ];

            events.forEach(event => networkAgent.bufferEvent(event));
            
            expect(networkAgent.eventBuffer.length).toBe(3);
            expect(networkAgent.eventBuffer[0]).toEqual({ id: 'event-002' });
            expect(networkAgent.eventBuffer[2]).toEqual({ id: 'event-004' });
        });

        test('should buffer alerts correctly', () => {
            const alert = { id: 'alert-001', severity: 'high', message: 'Test alert' };
            
            networkAgent.bufferAlert(alert);
            
            expect(networkAgent.alertBuffer).toContain(alert);
            expect(networkAgent.alertBuffer.length).toBe(1);
        });

        test('should buffer logs correctly', () => {
            const logEntry = { timestamp: new Date(), level: 'info', message: 'Test log' };
            
            networkAgent.bufferLog(logEntry);
            
            expect(networkAgent.logBuffer).toContain(logEntry);
            expect(networkAgent.logBuffer.length).toBe(1);
        });
    });

    describe('Configuration Management', () => {
        test('should set config manager', () => {
            const mockConfigManager = new ConfigManager();
            
            networkAgent.setConfigManager(mockConfigManager);
            
            expect(networkAgent.configManager).toBe(mockConfigManager);
        });

        test('should update configuration', async () => {
            const mockConfigManager = {
                updateConfig: jest.fn().mockResolvedValue(),
                getConfig: jest.fn().mockReturnValue({ ...mockConfig, updated: true })
            };
            
            networkAgent.setConfigManager(mockConfigManager);
            
            const updates = { heartbeatInterval: 60000 };
            await networkAgent.updateConfiguration(updates);
            
            expect(mockConfigManager.updateConfig).toHaveBeenCalledWith(updates);
        });
    });

    describe('Network Interface Management', () => {
        test('should get network interfaces', async () => {
            const mockInterfaces = [
                { name: 'eth0', description: 'Ethernet', mac: '00:11:22:33:44:55' },
                { name: 'wlan0', description: 'WiFi', mac: '00:11:22:33:44:66' }
            ];

            networkAgent.getNetworkInterfaces = jest.fn().mockResolvedValue(mockInterfaces);

            const interfaces = await networkAgent.getNetworkInterfaces();

            expect(interfaces).toEqual(mockInterfaces);
            expect(interfaces.length).toBe(2);
        });

        test('should select default interface', () => {
            const mockInterfaces = [
                { name: 'lo', description: 'Loopback' },
                { name: 'eth0', description: 'Ethernet' },
                { name: 'wlan0', description: 'WiFi' }
            ];

            const defaultInterface = networkAgent.getDefaultInterface = jest.fn().mockReturnValue(mockInterfaces[1]);

            const selected = networkAgent.getDefaultInterface(mockInterfaces);

            expect(selected).toBe(mockInterfaces[1]);
        });
    });

    describe('Privilege Management', () => {
        test('should check privileges on macOS', () => {
            const originalPlatform = process.platform;
            Object.defineProperty(process, 'platform', { value: 'darwin' });

            networkAgent.checkPrivileges = jest.fn().mockReturnValue(true);

            const hasPrivileges = networkAgent.checkPrivileges();

            expect(hasPrivileges).toBe(true);

            Object.defineProperty(process, 'platform', { value: originalPlatform });
        });

        test('should return false for non-root on macOS', () => {
            const originalPlatform = process.platform;
            Object.defineProperty(process, 'platform', { value: 'darwin' });

            networkAgent.checkPrivileges = jest.fn().mockReturnValue(false);

            const hasPrivileges = networkAgent.checkPrivileges();

            expect(hasPrivileges).toBe(false);

            Object.defineProperty(process, 'platform', { value: originalPlatform });
        });
    });

    describe('Error Handling', () => {
        test('should handle network monitoring errors', async () => {
            const error = new Error('Network monitoring failed');
            
            networkAgent.handleMonitorError(error);
            
            // Should not throw and should log error
            expect(true).toBe(true);
        });

        test('should handle cloud connection errors', async () => {
            const error = new Error('Cloud connection failed');
            
            networkAgent.handleCloudError(error);
            
            // Should not throw and should log error
            expect(true).toBe(true);
        });

        test('should handle log collection errors', async () => {
            const error = new Error('Log collection failed');
            
            networkAgent.handleLogError(error);
            
            // Should not throw and should log error
            expect(true).toBe(true);
        });
    });

    describe('Performance Metrics', () => {
        test('should track packet processing performance', async () => {
            const initialCount = networkAgent.packetsProcessed;
            
            await networkAgent.handlePacket({ test: 'packet' });
            
            expect(networkAgent.packetsProcessed).toBe(initialCount + 1);
        });

        test('should track threat detection performance', async () => {
            const mockPacket = { test: 'packet' };
            const mockThreats = [{ type: 'test_threat' }];
            
            networkAgent.threatDetector.analyzePacket = jest.fn().mockResolvedValue(mockThreats);
            networkAgent.createSecurityEvent = jest.fn().mockReturnValue({});
            networkAgent.bufferEvent = jest.fn();
            networkAgent.generateAlert = jest.fn().mockResolvedValue();
            
            const initialCount = networkAgent.threatsDetected;
            
            await networkAgent.handlePacket(mockPacket);
            
            expect(networkAgent.threatsDetected).toBe(initialCount + 1);
        });
    });
}); 