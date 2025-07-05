#!/usr/bin/env node

const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs').promises;

class AgentTester {
    constructor() {
        this.platform = os.platform();
        this.testResults = [];
        this.startTime = Date.now();
        this.colors = {
            green: '\x1b[32m',
            red: '\x1b[31m',
            yellow: '\x1b[33m',
            blue: '\x1b[34m',
            reset: '\x1b[0m'
        };
    }

    log(message, color = 'reset') {
        const timestamp = new Date().toISOString();
        console.log(`${this.colors[color]}[${timestamp}] ${message}${this.colors.reset}`);
    }

    async runTest(testName, testFn) {
        this.log(`Running test: ${testName}`, 'blue');
        const startTime = Date.now();
        
        try {
            await testFn();
            const duration = Date.now() - startTime;
            this.testResults.push({
                name: testName,
                status: 'PASS',
                duration: duration,
                error: null
            });
            this.log(`✅ ${testName} - PASSED (${duration}ms)`, 'green');
        } catch (error) {
            const duration = Date.now() - startTime;
            this.testResults.push({
                name: testName,
                status: 'FAIL',
                duration: duration,
                error: error.message
            });
            this.log(`❌ ${testName} - FAILED (${duration}ms): ${error.message}`, 'red');
        }
    }

    async testPlatformCompatibility() {
        this.log(`Testing on platform: ${this.platform}`, 'yellow');
        
        // Test OS-specific features
        const osInfo = {
            platform: os.platform(),
            arch: os.arch(),
            release: os.release(),
            cpus: os.cpus().length,
            totalmem: Math.round(os.totalmem() / 1024 / 1024 / 1024) + 'GB',
            uptime: Math.round(os.uptime() / 3600) + 'h'
        };
        
        this.log(`System Info: ${JSON.stringify(osInfo, null, 2)}`, 'blue');
        
        // Test network interfaces
        const interfaces = os.networkInterfaces();
        const activeInterfaces = Object.keys(interfaces).filter(name => 
            !name.includes('lo') && !name.includes('Loopback')
        );
        
        if (activeInterfaces.length === 0) {
            throw new Error('No active network interfaces found');
        }
        
        this.log(`Found ${activeInterfaces.length} network interfaces: ${activeInterfaces.join(', ')}`, 'green');
    }

    async testAgentComponents() {
        const componentPath = path.join(__dirname, '..', 'src');
        
        // Test component loading
        const components = [
            'core/PacketAnalyzer',
            'core/ThreatDetector',
            'core/ConfigManager',
            'core/NetworkAgent',
            'communication/SecureChannel',
            'utils/DataCompressor',
            'utils/MetricsCollector',
            'utils/Logger'
        ];
        
        for (const component of components) {
            try {
                const ComponentClass = require(path.join(componentPath, component));
                if (typeof ComponentClass !== 'function') {
                    throw new Error(`${component} is not a valid class`);
                }
                this.log(`✅ Component ${component} loaded successfully`, 'green');
            } catch (error) {
                throw new Error(`Failed to load component ${component}: ${error.message}`);
            }
        }
    }

    async testConfigManager() {
        const ConfigManager = require('../src/core/ConfigManager');
        
        // Test config initialization
        const config = await ConfigManager.load();
        
        if (!config.agentId) {
            throw new Error('Agent ID not generated');
        }
        
        if (!config.version) {
            throw new Error('Version not set');
        }
        
        this.log(`Config loaded with Agent ID: ${config.agentId}`, 'green');
        
        // Test platform-specific paths
        const configManager = new ConfigManager();
        await configManager.initialize();
        
        const platformConfig = configManager.getPlatformConfig();
        this.log(`Platform config: ${JSON.stringify(platformConfig)}`, 'blue');
        
        // Test interface detection
        const interfaces = await configManager.detectAvailableInterfaces();
        if (interfaces.length === 0) {
            this.log('Warning: No network interfaces detected', 'yellow');
        } else {
            this.log(`Detected interfaces: ${interfaces.map(i => i.name).join(', ')}`, 'green');
        }
    }

    async testPacketAnalyzer() {
        const PacketAnalyzer = require('../src/core/PacketAnalyzer');
        const analyzer = new PacketAnalyzer({});
        
        await analyzer.initialize();
        
        // Test with mock packet data
        const mockPacket = this.createMockPacket();
        const parsed = analyzer.parsePacket(mockPacket);
        
        if (!parsed) {
            this.log('Warning: Packet parsing returned null (may be due to mock data)', 'yellow');
        } else {
            this.log('Packet parsing successful', 'green');
        }
        
        const stats = analyzer.getStatistics();
        this.log(`Analyzer stats: ${JSON.stringify(stats)}`, 'blue');
    }

    async testThreatDetector() {
        const ThreatDetector = require('../src/core/ThreatDetector');
        const detector = new ThreatDetector({});
        
        await detector.initialize();
        await detector.loadRules();
        
        const stats = detector.getStats();
        this.log(`Threat detector loaded ${stats.total_rules} rules`, 'green');
        
        // Test with mock packet
        const mockPacket = this.createMockPacket();
        const threats = await detector.analyzePacket(mockPacket);
        
        this.log(`Threat analysis complete: ${threats.length} threats detected`, 'blue');
    }

    async testDataCompressor() {
        const DataCompressor = require('../src/utils/DataCompressor');
        const compressor = new DataCompressor();
        
        const testData = JSON.stringify({
            test: 'data',
            timestamp: new Date().toISOString(),
            numbers: [1, 2, 3, 4, 5],
            nested: {
                key: 'value',
                array: ['a', 'b', 'c']
            }
        });
        
        const compressed = await compressor.compress(testData);
        if (!compressed.compressed) {
            this.log('Data was too small to compress', 'yellow');
        } else {
            const ratio = compressed.compressionRatio;
            this.log(`Compression successful: ${ratio.toFixed(2)}:1 ratio`, 'green');
        }
        
        const stats = compressor.getStats();
        this.log(`Compressor stats: ${JSON.stringify(stats)}`, 'blue');
    }

    async testMetricsCollector() {
        const MetricsCollector = require('../src/utils/MetricsCollector');
        const metrics = new MetricsCollector();
        
        metrics.startCollection();
        
        // Test different metric types
        metrics.incrementCounter('test_counter', 5);
        metrics.setGauge('test_gauge', 42);
        metrics.recordHistogram('test_histogram', 123);
        
        const timer = metrics.time('test_timer');
        await new Promise(resolve => setTimeout(resolve, 10));
        timer();
        
        const allMetrics = metrics.getAllMetrics();
        this.log(`Metrics collected: ${Object.keys(allMetrics.counters).length} counters, ${Object.keys(allMetrics.gauges).length} gauges`, 'green');
        
        metrics.stopCollection();
    }

    async testLogger() {
        const Logger = require('../src/utils/Logger');
        const logger = new Logger('TestLogger');
        
        logger.info('Test info message');
        logger.warn('Test warning message');
        logger.debug('Test debug message');
        logger.error('Test error message');
        
        logger.logSystemInfo();
        logger.logMemoryUsage('Test Memory Check');
        
        const stats = logger.getLogStats();
        this.log(`Logger stats: ${JSON.stringify(stats)}`, 'blue');
    }

    async testSecureChannel() {
        const { SecureChannel } = require('../src/communication/SecureChannel');
        
        // Test basic initialization (won't connect without valid config)
        const config = {
            agentId: 'test-agent',
            tenantId: 'test-tenant',
            agentKey: 'test-key',
            cloudEndpoint: 'wss://test.example.com'
        };
        
        const channel = new SecureChannel(config);
        
        // Test URL building
        const url = channel.buildWebSocketUrl();
        if (!url.includes('wss://')) {
            throw new Error('WebSocket URL format invalid');
        }
        
        this.log('SecureChannel initialization successful', 'green');
    }

    async testFullAgent() {
        const A2ZNetworkAgent = require('../src/index');
        
        // Test agent initialization (without starting)
        const agent = new A2ZNetworkAgent();
        
        try {
            await agent.initialize();
            this.log('Agent initialization successful', 'green');
        } catch (error) {
            // Expected to fail without proper config/network access or real server
            if (error.message.includes('ENOTFOUND') || 
                error.message.includes('connection') ||
                error.code === 'ENOTFOUND') {
                this.log(`Agent failed to connect to cloud (expected): ${error.code || 'ENOTFOUND'}`, 'yellow');
            } else {
                throw error; // Re-throw unexpected errors
            }
        }
        
        const status = await agent.getStatus();
        this.log(`Agent status: ${JSON.stringify(status)}`, 'blue');
    }

    async testCrossPlatformFeatures() {
        // Test platform-specific functionality
        switch (this.platform) {
            case 'win32':
                await this.testWindowsFeatures();
                break;
            case 'darwin':
                await this.testMacOSFeatures();
                break;
            case 'linux':
                await this.testLinuxFeatures();
                break;
            default:
                this.log(`Platform ${this.platform} - using generic Unix tests`, 'yellow');
                await this.testUnixFeatures();
        }
    }

    async testWindowsFeatures() {
        this.log('Testing Windows-specific features', 'blue');
        
        // Test Windows network interfaces
        const interfaces = os.networkInterfaces();
        const windowsInterfaces = Object.keys(interfaces).filter(name => 
            name.includes('Ethernet') || name.includes('Wi-Fi') || name.includes('Local Area Connection')
        );
        
        this.log(`Windows interfaces found: ${windowsInterfaces.join(', ')}`, 'green');
        
        // Test Windows paths
        const ConfigManager = require('../src/core/ConfigManager');
        const manager = new ConfigManager();
        const configPath = manager.getDefaultConfigPath();
        
        if (!configPath.includes('AppData')) {
            throw new Error('Windows config path incorrect');
        }
        
        this.log(`Windows config path: ${configPath}`, 'green');
    }

    async testMacOSFeatures() {
        this.log('Testing macOS-specific features', 'blue');
        
        // Test macOS network interfaces
        const interfaces = os.networkInterfaces();
        const macInterfaces = Object.keys(interfaces).filter(name => 
            name.startsWith('en') || name.startsWith('wifi')
        );
        
        this.log(`macOS interfaces found: ${macInterfaces.join(', ')}`, 'green');
        
        // Test macOS paths
        const ConfigManager = require('../src/core/ConfigManager');
        const manager = new ConfigManager();
        const configPath = manager.getDefaultConfigPath();
        
        if (!configPath.includes('Library/Application Support')) {
            throw new Error('macOS config path incorrect');
        }
        
        this.log(`macOS config path: ${configPath}`, 'green');
    }

    async testLinuxFeatures() {
        this.log('Testing Linux-specific features', 'blue');
        
        // Test Linux network interfaces
        const interfaces = os.networkInterfaces();
        const linuxInterfaces = Object.keys(interfaces).filter(name => 
            name.startsWith('eth') || name.startsWith('wlan') || name.startsWith('enp')
        );
        
        this.log(`Linux interfaces found: ${linuxInterfaces.join(', ')}`, 'green');
        
        // Test Linux paths
        const ConfigManager = require('../src/core/ConfigManager');
        const manager = new ConfigManager();
        const configPath = manager.getDefaultConfigPath();
        
        if (!configPath.includes('.a2z-soc')) {
            throw new Error('Linux config path incorrect');
        }
        
        this.log(`Linux config path: ${configPath}`, 'green');
    }

    async testUnixFeatures() {
        this.log('Testing Unix-like features', 'blue');
        
        // Test basic Unix features
        const interfaces = os.networkInterfaces();
        this.log(`Available interfaces: ${Object.keys(interfaces).join(', ')}`, 'green');
        
        // Test load average (Unix-specific)
        try {
            const loadAvg = os.loadavg();
            this.log(`Load average: ${loadAvg.map(l => l.toFixed(2)).join(', ')}`, 'green');
        } catch (error) {
            this.log('Load average not available', 'yellow');
        }
    }

    createMockPacket() {
        // Create a minimal mock packet structure
        const buffer = Buffer.alloc(64);
        
        // Ethernet header (14 bytes)
        buffer.writeUInt16BE(0x0800, 12); // IPv4 EtherType
        
        // IPv4 header (20 bytes starting at offset 14)
        buffer[14] = 0x45; // Version (4) + Header Length (5)
        buffer[15] = 0x00; // Type of Service
        buffer.writeUInt16BE(64, 16); // Total Length
        buffer[22] = 64; // TTL
        buffer[23] = 6; // Protocol (TCP)
        
        // Source IP (192.168.1.1)
        buffer[26] = 192;
        buffer[27] = 168;
        buffer[28] = 1;
        buffer[29] = 1;
        
        // Destination IP (192.168.1.100)
        buffer[30] = 192;
        buffer[31] = 168;
        buffer[32] = 1;
        buffer[33] = 100;
        
        return {
            header: {
                len: 64,
                caplen: 64,
                tv_sec: Math.floor(Date.now() / 1000),
                tv_usec: 0
            },
            buf: buffer
        };
    }

    async runPerformanceTest() {
        this.log('Running performance tests', 'blue');
        
        const iterations = 1000;
        const startTime = process.hrtime.bigint();
        
        // Test packet processing performance
        const PacketAnalyzer = require('../src/core/PacketAnalyzer');
        const analyzer = new PacketAnalyzer({});
        await analyzer.initialize();
        
        for (let i = 0; i < iterations; i++) {
            const mockPacket = this.createMockPacket();
            analyzer.parsePacket(mockPacket);
        }
        
        const endTime = process.hrtime.bigint();
        const duration = Number(endTime - startTime) / 1000000; // Convert to milliseconds
        const packetsPerSecond = (iterations / duration) * 1000;
        
        this.log(`Performance: ${packetsPerSecond.toFixed(0)} packets/second`, 'green');
        
        if (packetsPerSecond < 1000) {
            this.log('Warning: Performance below target (1000 pps)', 'yellow');
        }
    }

    printSummary() {
        const totalTime = Date.now() - this.startTime;
        const passed = this.testResults.filter(r => r.status === 'PASS').length;
        const failed = this.testResults.filter(r => r.status === 'FAIL').length;
        
        this.log('\n' + '='.repeat(60), 'blue');
        this.log('TEST SUMMARY', 'blue');
        this.log('='.repeat(60), 'blue');
        this.log(`Platform: ${this.platform}`, 'blue');
        this.log(`Total Tests: ${this.testResults.length}`, 'blue');
        this.log(`Passed: ${passed}`, 'green');
        this.log(`Failed: ${failed}`, failed > 0 ? 'red' : 'green');
        this.log(`Total Time: ${totalTime}ms`, 'blue');
        this.log('='.repeat(60), 'blue');
        
        if (failed > 0) {
            this.log('\nFAILED TESTS:', 'red');
            this.testResults
                .filter(r => r.status === 'FAIL')
                .forEach(test => {
                    this.log(`❌ ${test.name}: ${test.error}`, 'red');
                });
        }
        
        this.log(`\n✅ Agent testing completed on ${this.platform}`, 'green');
        
        return failed === 0;
    }

    async runAllTests() {
        this.log('🚀 Starting A2Z Network Agent Cross-Platform Tests', 'blue');
        this.log('='.repeat(60), 'blue');
        
        await this.runTest('Platform Compatibility', () => this.testPlatformCompatibility());
        await this.runTest('Agent Components', () => this.testAgentComponents());
        await this.runTest('Config Manager', () => this.testConfigManager());
        await this.runTest('Packet Analyzer', () => this.testPacketAnalyzer());
        await this.runTest('Threat Detector', () => this.testThreatDetector());
        await this.runTest('Data Compressor', () => this.testDataCompressor());
        await this.runTest('Metrics Collector', () => this.testMetricsCollector());
        await this.runTest('Logger', () => this.testLogger());
        await this.runTest('Secure Channel', () => this.testSecureChannel());
        await this.runTest('Full Agent', () => this.testFullAgent());
        await this.runTest('Cross-Platform Features', () => this.testCrossPlatformFeatures());
        await this.runTest('Performance Test', () => this.runPerformanceTest());
        
        return this.printSummary();
    }
}

// Main execution
async function main() {
    const tester = new AgentTester();
    
    try {
        const success = await tester.runAllTests();
        process.exit(success ? 0 : 1);
    } catch (error) {
        console.error('❌ Test runner failed:', error);
        process.exit(1);
    }
}

if (require.main === module) {
    main();
}

module.exports = AgentTester; 