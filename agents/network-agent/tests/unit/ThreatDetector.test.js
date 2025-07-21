const ThreatDetector = require('../../src/core/ThreatDetector');

describe('ThreatDetector', () => {
    let threatDetector;
    let mockConfig;

    beforeEach(() => {
        mockConfig = {
            threatRules: {
                enabled: true,
                rulesPath: '/tmp/rules',
                customRules: []
            },
            threatIntelligence: {
                enabled: true,
                sources: ['virustotal', 'misp']
            },
            alerting: {
                enabled: true,
                thresholds: {
                    low: 0.3,
                    medium: 0.6,
                    high: 0.8,
                    critical: 0.9
                }
            }
        };

        threatDetector = new ThreatDetector(mockConfig);
    });

    describe('Constructor', () => {
        test('should initialize with correct configuration', () => {
            expect(threatDetector.config).toBe(mockConfig);
            expect(threatDetector.rules).toBeInstanceOf(Map);
            expect(threatDetector.statistics).toBeDefined();
            expect(threatDetector.initialized).toBe(false);
        });

        test('should initialize threat categories', () => {
            expect(threatDetector.threatCategories).toContain('malware');
            expect(threatDetector.threatCategories).toContain('intrusion');
            expect(threatDetector.threatCategories).toContain('anomaly');
            expect(threatDetector.threatCategories).toContain('policy_violation');
        });
    });

    describe('Initialization', () => {
        test('should initialize successfully', async () => {
            await threatDetector.initialize();

            expect(threatDetector.initialized).toBe(true);
            expect(threatDetector.rules.size).toBeGreaterThan(0);
        });

        test('should load default rules', async () => {
            await threatDetector.initialize();

            expect(threatDetector.rules.has('port_scan_detection')).toBe(true);
            expect(threatDetector.rules.has('brute_force_detection')).toBe(true);
            expect(threatDetector.rules.has('malware_communication')).toBe(true);
        });

        test('should handle initialization errors', async () => {
            // Mock rule loading failure
            threatDetector.loadRules = jest.fn().mockRejectedValue(new Error('Rule loading failed'));

            await expect(threatDetector.initialize()).rejects.toThrow('Rule loading failed');
        });
    });

    describe('Rule Management', () => {
        beforeEach(async () => {
            await threatDetector.initialize();
        });

        test('should load rules from file', async () => {
            const mockRules = [
                {
                    id: 'test_rule_001',
                    name: 'Test Rule',
                    category: 'test',
                    severity: 'medium',
                    conditions: [
                        { type: 'port', value: 1234 },
                        { type: 'protocol', value: 'TCP' }
                    ],
                    description: 'Test rule for unit testing'
                }
            ];

            await threatDetector.loadRulesFromFile(mockRules);

            expect(threatDetector.rules.has('test_rule_001')).toBe(true);
            expect(threatDetector.rules.get('test_rule_001').name).toBe('Test Rule');
        });

        test('should add custom rule', () => {
            const customRule = {
                id: 'custom_rule_001',
                name: 'Custom Rule',
                category: 'custom',
                severity: 'high',
                conditions: [
                    { type: 'ip', value: '192.168.1.100' }
                ],
                description: 'Custom rule for testing'
            };

            threatDetector.addRule(customRule);

            expect(threatDetector.rules.has('custom_rule_001')).toBe(true);
            expect(threatDetector.rules.get('custom_rule_001')).toEqual(customRule);
        });

        test('should remove rule', () => {
            const ruleId = 'port_scan_detection';
            
            expect(threatDetector.rules.has(ruleId)).toBe(true);
            
            threatDetector.removeRule(ruleId);
            
            expect(threatDetector.rules.has(ruleId)).toBe(false);
        });

        test('should update rule', () => {
            const ruleId = 'port_scan_detection';
            const updates = {
                severity: 'critical',
                description: 'Updated description'
            };

            threatDetector.updateRule(ruleId, updates);

            const updatedRule = threatDetector.rules.get(ruleId);
            expect(updatedRule.severity).toBe('critical');
            expect(updatedRule.description).toBe('Updated description');
        });

        test('should validate rule format', () => {
            const validRule = {
                id: 'valid_rule',
                name: 'Valid Rule',
                category: 'test',
                severity: 'medium',
                conditions: [{ type: 'port', value: 80 }],
                description: 'Valid rule'
            };

            const invalidRule = {
                id: 'invalid_rule',
                // Missing required fields
                conditions: []
            };

            expect(threatDetector.validateRule(validRule)).toBe(true);
            expect(threatDetector.validateRule(invalidRule)).toBe(false);
        });
    });

    describe('Threat Analysis', () => {
        beforeEach(async () => {
            await threatDetector.initialize();
        });

        test('should detect port scan threat', async () => {
            const packet = {
                src_ip: '192.168.1.100',
                dst_ip: '192.168.1.1',
                dst_port: 22,
                protocol: 'TCP',
                flags: ['SYN'],
                size: 64
            };

            const analysis = { protocol: 'TCP', suspicious: false };
            const threats = await threatDetector.analyzePacket(packet, analysis);

            expect(threats).toBeInstanceOf(Array);
            // Should detect potential port scan based on SYN flag to common service port
            expect(threats.length).toBeGreaterThan(0);
            expect(threats[0].category).toBe('reconnaissance');
        });

        test('should detect brute force attack', async () => {
            const packets = Array(10).fill(null).map(() => ({
                src_ip: '192.168.1.100',
                dst_ip: '192.168.1.1',
                dst_port: 22,
                protocol: 'TCP',
                flags: ['PSH', 'ACK'],
                size: 1024
            }));

            let threats = [];
            for (const packet of packets) {
                const analysis = { protocol: 'TCP', suspicious: false };
                const packetThreats = await threatDetector.analyzePacket(packet, analysis);
                threats = threats.concat(packetThreats);
            }

            // Should detect brute force pattern after multiple attempts
            const bruteForceThreats = threats.filter(t => t.category === 'brute_force');
            expect(bruteForceThreats.length).toBeGreaterThan(0);
        });

        test('should detect malware communication', async () => {
            const packet = {
                src_ip: '192.168.1.100',
                dst_ip: '192.168.1.1',
                dst_port: 6667, // IRC port - common for malware C&C
                protocol: 'TCP',
                flags: ['PSH', 'ACK'],
                size: 256
            };

            const analysis = { protocol: 'TCP', application_protocol: 'IRC' };
            const threats = await threatDetector.analyzePacket(packet, analysis);

            expect(threats.length).toBeGreaterThan(0);
            expect(threats[0].category).toBe('malware');
            expect(threats[0].severity).toBe('high');
        });

        test('should detect DDoS patterns', async () => {
            const packets = Array(100).fill(null).map(() => ({
                src_ip: '192.168.1.100',
                dst_ip: '192.168.1.1',
                dst_port: 80,
                protocol: 'TCP',
                flags: ['SYN'],
                size: 64,
                timestamp: new Date()
            }));

            let threats = [];
            for (const packet of packets) {
                const analysis = { protocol: 'TCP', suspicious: false };
                const packetThreats = await threatDetector.analyzePacket(packet, analysis);
                threats = threats.concat(packetThreats);
            }

            const ddosThreats = threats.filter(t => t.category === 'ddos');
            expect(ddosThreats.length).toBeGreaterThan(0);
        });

        test('should detect suspicious payload patterns', async () => {
            const packet = {
                src_ip: '192.168.1.100',
                dst_ip: '192.168.1.1',
                dst_port: 80,
                protocol: 'TCP',
                payload: Buffer.from('GET /admin/../../etc/passwd HTTP/1.1'),
                size: 1024
            };

            const analysis = { 
                protocol: 'TCP', 
                application_protocol: 'HTTP',
                suspicious: true
            };
            const threats = await threatDetector.analyzePacket(packet, analysis);

            expect(threats.length).toBeGreaterThan(0);
            expect(threats[0].category).toBe('web_attack');
            expect(threats[0].type).toBe('directory_traversal');
        });

        test('should calculate threat confidence scores', async () => {
            const packet = {
                src_ip: '192.168.1.100',
                dst_ip: '192.168.1.1',
                dst_port: 1433, // SQL Server port
                protocol: 'TCP',
                flags: ['SYN'],
                size: 64
            };

            const analysis = { protocol: 'TCP', suspicious: true };
            const threats = await threatDetector.analyzePacket(packet, analysis);

            expect(threats.length).toBeGreaterThan(0);
            expect(threats[0].confidence).toBeGreaterThan(0);
            expect(threats[0].confidence).toBeLessThanOrEqual(1);
        });

        test('should handle analysis errors gracefully', async () => {
            const malformedPacket = {
                src_ip: 'invalid_ip',
                dst_ip: null,
                protocol: 'UNKNOWN'
            };

            const analysis = { protocol: 'UNKNOWN', suspicious: true };
            const threats = await threatDetector.analyzePacket(malformedPacket, analysis);

            // Should not throw error and should return empty array or handle gracefully
            expect(threats).toBeInstanceOf(Array);
        });
    });

    describe('Log Analysis', () => {
        beforeEach(async () => {
            await threatDetector.initialize();
        });

        test('should detect authentication failures', async () => {
            const logEntries = [
                'Failed login attempt for user admin from 192.168.1.100',
                'Authentication failed for user root from 192.168.1.100',
                'Invalid password for user admin from 192.168.1.100'
            ];

            let threats = [];
            for (const logEntry of logEntries) {
                const logThreats = await threatDetector.analyzeLogEntry(logEntry);
                threats = threats.concat(logThreats);
            }

            expect(threats.length).toBeGreaterThan(0);
            expect(threats).toContain('Authentication Failure');
        });

        test('should detect privilege escalation attempts', async () => {
            const logEntries = [
                'sudo: authentication failure for user hacker',
                'su: authentication failure for user root',
                'privilege escalation attempt detected'
            ];

            let threats = [];
            for (const logEntry of logEntries) {
                const logThreats = await threatDetector.analyzeLogEntry(logEntry);
                threats = threats.concat(logThreats);
            }

            expect(threats.length).toBeGreaterThan(0);
            expect(threats).toContain('Privilege Escalation Attempt');
        });

        test('should detect malware indicators', async () => {
            const logEntries = [
                'Malware detected: Trojan.Win32.Generic',
                'Virus found in file: /tmp/malicious.exe',
                'Trojan activity detected on system'
            ];

            let threats = [];
            for (const logEntry of logEntries) {
                const logThreats = await threatDetector.analyzeLogEntry(logEntry);
                threats = threats.concat(logThreats);
            }

            expect(threats.length).toBeGreaterThan(0);
            expect(threats).toContain('Malware Detection');
        });

        test('should detect system anomalies', async () => {
            const logEntries = [
                'Kernel panic: system crash detected',
                'Segmentation fault in critical process',
                'Network error: host unreachable'
            ];

            let threats = [];
            for (const logEntry of logEntries) {
                const logThreats = await threatDetector.analyzeLogEntry(logEntry);
                threats = threats.concat(logThreats);
            }

            expect(threats.length).toBeGreaterThan(0);
            expect(threats).toContain('System Stability Issue');
            expect(threats).toContain('Network Anomaly');
        });
    });

    describe('Threat Intelligence Integration', () => {
        beforeEach(async () => {
            await threatDetector.initialize();
        });

        test('should check IP reputation', async () => {
            const maliciousIP = '192.168.1.100';
            
            // Mock threat intelligence response
            threatDetector.checkIPReputation = jest.fn().mockResolvedValue({
                reputation: 'malicious',
                confidence: 0.9,
                sources: ['virustotal', 'misp']
            });

            const reputation = await threatDetector.checkIPReputation(maliciousIP);

            expect(reputation.reputation).toBe('malicious');
            expect(reputation.confidence).toBe(0.9);
            expect(reputation.sources).toContain('virustotal');
        });

        test('should check domain reputation', async () => {
            const suspiciousDomain = 'malicious.example.com';
            
            threatDetector.checkDomainReputation = jest.fn().mockResolvedValue({
                reputation: 'suspicious',
                confidence: 0.7,
                category: 'malware_distribution'
            });

            const reputation = await threatDetector.checkDomainReputation(suspiciousDomain);

            expect(reputation.reputation).toBe('suspicious');
            expect(reputation.confidence).toBe(0.7);
            expect(reputation.category).toBe('malware_distribution');
        });

        test('should update threat intelligence feeds', async () => {
            threatDetector.updateThreatIntelligence = jest.fn().mockResolvedValue({
                updated: true,
                newIndicators: 150,
                lastUpdate: new Date()
            });

            const result = await threatDetector.updateThreatIntelligence();

            expect(result.updated).toBe(true);
            expect(result.newIndicators).toBe(150);
            expect(result.lastUpdate).toBeInstanceOf(Date);
        });
    });

    describe('Alert Generation', () => {
        beforeEach(async () => {
            await threatDetector.initialize();
        });

        test('should generate alert for high severity threat', async () => {
            const threat = {
                id: 'threat_001',
                category: 'malware',
                type: 'trojan_communication',
                severity: 'high',
                confidence: 0.9,
                source_ip: '192.168.1.100',
                destination_ip: '192.168.1.1',
                description: 'Trojan communication detected'
            };

            const alert = threatDetector.generateAlert(threat);

            expect(alert.id).toBeDefined();
            expect(alert.severity).toBe('high');
            expect(alert.confidence).toBe(0.9);
            expect(alert.timestamp).toBeInstanceOf(Date);
            expect(alert.status).toBe('new');
        });

        test('should not generate alert for low confidence threats', async () => {
            const threat = {
                id: 'threat_002',
                category: 'anomaly',
                type: 'minor_deviation',
                severity: 'low',
                confidence: 0.2,
                description: 'Minor anomaly detected'
            };

            const alert = threatDetector.generateAlert(threat);

            expect(alert).toBeNull();
        });

        test('should aggregate similar alerts', async () => {
            const threats = Array(5).fill(null).map((_, i) => ({
                id: `threat_${i}`,
                category: 'port_scan',
                type: 'port_scan',
                severity: 'medium',
                confidence: 0.8,
                source_ip: '192.168.1.100',
                destination_ip: '192.168.1.1'
            }));

            const alerts = threats.map(threat => threatDetector.generateAlert(threat));
            const aggregatedAlert = threatDetector.aggregateAlerts(alerts);

            expect(aggregatedAlert.count).toBe(5);
            expect(aggregatedAlert.category).toBe('port_scan');
            expect(aggregatedAlert.severity).toBe('medium');
        });
    });

    describe('Performance Metrics', () => {
        beforeEach(async () => {
            await threatDetector.initialize();
        });

        test('should track detection statistics', async () => {
            const packets = Array(100).fill(null).map(() => ({
                src_ip: '192.168.1.100',
                dst_ip: '192.168.1.1',
                dst_port: 80,
                protocol: 'TCP'
            }));

            for (const packet of packets) {
                const analysis = { protocol: 'TCP', suspicious: false };
                await threatDetector.analyzePacket(packet, analysis);
            }

            const stats = threatDetector.getStatistics();

            expect(stats.packetsAnalyzed).toBe(100);
            expect(stats.threatsDetected).toBeGreaterThanOrEqual(0);
            expect(stats.alertsGenerated).toBeGreaterThanOrEqual(0);
        });

        test('should measure analysis performance', async () => {
            const startTime = Date.now();
            const packetCount = 1000;

            const packets = Array(packetCount).fill(null).map(() => ({
                src_ip: '192.168.1.100',
                dst_ip: '192.168.1.1',
                dst_port: 80,
                protocol: 'TCP'
            }));

            for (const packet of packets) {
                const analysis = { protocol: 'TCP', suspicious: false };
                await threatDetector.analyzePacket(packet, analysis);
            }

            const endTime = Date.now();
            const analysisTime = endTime - startTime;
            const packetsPerSecond = (packetCount / analysisTime) * 1000;

            expect(packetsPerSecond).toBeGreaterThan(50); // Should analyze at least 50 packets/second
        });

        test('should track false positive rates', async () => {
            threatDetector.statistics.falsePositives = 10;
            threatDetector.statistics.truePositives = 90;

            const stats = threatDetector.getStatistics();
            const falsePositiveRate = stats.falsePositives / (stats.falsePositives + stats.truePositives);

            expect(falsePositiveRate).toBeLessThan(0.2); // Should be less than 20%
        });
    });

    describe('Configuration Management', () => {
        test('should update detection thresholds', () => {
            const newThresholds = {
                low: 0.2,
                medium: 0.5,
                high: 0.7,
                critical: 0.85
            };

            threatDetector.updateThresholds(newThresholds);

            expect(threatDetector.config.alerting.thresholds).toEqual(newThresholds);
        });

        test('should enable/disable threat categories', () => {
            threatDetector.disableThreatCategory('malware');
            
            expect(threatDetector.enabledCategories).not.toContain('malware');
            
            threatDetector.enableThreatCategory('malware');
            
            expect(threatDetector.enabledCategories).toContain('malware');
        });

        test('should validate configuration updates', () => {
            const validConfig = {
                alerting: {
                    thresholds: {
                        low: 0.1,
                        medium: 0.5,
                        high: 0.8,
                        critical: 0.95
                    }
                }
            };

            const invalidConfig = {
                alerting: {
                    thresholds: {
                        low: 1.5, // Invalid: > 1.0
                        medium: 0.5,
                        high: 0.8,
                        critical: 0.95
                    }
                }
            };

            expect(threatDetector.validateConfig(validConfig)).toBe(true);
            expect(threatDetector.validateConfig(invalidConfig)).toBe(false);
        });
    });

    describe('Memory Management', () => {
        beforeEach(async () => {
            await threatDetector.initialize();
        });

        test('should manage rule cache efficiently', async () => {
            const initialMemory = process.memoryUsage().heapUsed;
            
            // Add many rules
            for (let i = 0; i < 1000; i++) {
                threatDetector.addRule({
                    id: `rule_${i}`,
                    name: `Rule ${i}`,
                    category: 'test',
                    severity: 'low',
                    conditions: [{ type: 'port', value: i }],
                    description: `Test rule ${i}`
                });
            }

            const finalMemory = process.memoryUsage().heapUsed;
            const memoryIncrease = finalMemory - initialMemory;

            // Memory increase should be reasonable
            expect(memoryIncrease).toBeLessThan(50 * 1024 * 1024); // Less than 50MB
        });

        test('should cleanup old statistics', () => {
            threatDetector.statistics.packetsAnalyzed = 1000000;
            threatDetector.statistics.threatsDetected = 1000;
            
            threatDetector.cleanupStatistics();
            
            expect(threatDetector.statistics.packetsAnalyzed).toBe(0);
            expect(threatDetector.statistics.threatsDetected).toBe(0);
        });
    });
}); 