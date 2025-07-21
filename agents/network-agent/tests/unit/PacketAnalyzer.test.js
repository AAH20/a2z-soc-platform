const PacketAnalyzer = require('../../src/core/PacketAnalyzer');

describe('PacketAnalyzer', () => {
    let packetAnalyzer;
    let mockConfig;

    beforeEach(() => {
        mockConfig = {
            networkInterface: 'eth0',
            pcapFilter: 'ip',
            bufferSize: 1024 * 1024,
            maxPacketSize: 65535
        };

        packetAnalyzer = new PacketAnalyzer(mockConfig);
    });

    describe('Constructor', () => {
        test('should initialize with correct configuration', () => {
            expect(packetAnalyzer.config).toBe(mockConfig);
            expect(packetAnalyzer.supportedProtocols).toContain('tcp');
            expect(packetAnalyzer.supportedProtocols).toContain('udp');
            expect(packetAnalyzer.supportedProtocols).toContain('http');
            expect(packetAnalyzer.supportedProtocols).toContain('https');
        });

        test('should initialize statistics tracking', () => {
            expect(packetAnalyzer.packetCounts).toBeInstanceOf(Map);
            expect(packetAnalyzer.protocolStats).toBeInstanceOf(Map);
            expect(packetAnalyzer.initialized).toBe(false);
        });
    });

    describe('Initialization', () => {
        test('should initialize successfully', async () => {
            await packetAnalyzer.initialize();

            expect(packetAnalyzer.initialized).toBe(true);
        });

        test('should handle initialization errors', async () => {
            // Mock an initialization error
            const originalInitialize = packetAnalyzer.initialize;
            packetAnalyzer.initialize = jest.fn().mockRejectedValue(new Error('Init failed'));

            await expect(packetAnalyzer.initialize()).rejects.toThrow('Init failed');
        });
    });

    describe('Packet Analysis', () => {
        beforeEach(async () => {
            await packetAnalyzer.initialize();
        });

        test('should analyze TCP packet', async () => {
            const mockPacket = {
                timestamp: new Date(),
                src_ip: '192.168.1.100',
                dst_ip: '192.168.1.1',
                src_port: 12345,
                dst_port: 80,
                protocol: 'TCP',
                size: 1024,
                flags: ['SYN'],
                payload: Buffer.from('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')
            };

            const result = await packetAnalyzer.analyze(mockPacket);

            expect(result).toEqual({
                protocol: 'TCP',
                size: 1024,
                flags: ['SYN'],
                application_protocol: 'HTTP',
                direction: 'outbound',
                suspicious: false,
                metadata: expect.any(Object)
            });
        });

        test('should analyze UDP packet', async () => {
            const mockPacket = {
                timestamp: new Date(),
                src_ip: '192.168.1.100',
                dst_ip: '8.8.8.8',
                src_port: 53,
                dst_port: 53,
                protocol: 'UDP',
                size: 512,
                payload: Buffer.from('DNS query data')
            };

            const result = await packetAnalyzer.analyze(mockPacket);

            expect(result).toEqual({
                protocol: 'UDP',
                size: 512,
                flags: [],
                application_protocol: 'DNS',
                direction: 'outbound',
                suspicious: false,
                metadata: expect.any(Object)
            });
        });

        test('should analyze ICMP packet', async () => {
            const mockPacket = {
                timestamp: new Date(),
                src_ip: '192.168.1.100',
                dst_ip: '8.8.8.8',
                protocol: 'ICMP',
                size: 64,
                type: 8, // Echo Request
                code: 0
            };

            const result = await packetAnalyzer.analyze(mockPacket);

            expect(result).toEqual({
                protocol: 'ICMP',
                size: 64,
                flags: [],
                application_protocol: 'ICMP',
                direction: 'outbound',
                suspicious: false,
                metadata: expect.objectContaining({
                    icmp_type: 8,
                    icmp_code: 0
                })
            });
        });

        test('should detect suspicious packet patterns', async () => {
            const mockPacket = {
                timestamp: new Date(),
                src_ip: '192.168.1.100',
                dst_ip: '192.168.1.1',
                src_port: 12345,
                dst_port: 23, // Telnet - suspicious
                protocol: 'TCP',
                size: 1024,
                flags: ['SYN']
            };

            const result = await packetAnalyzer.analyze(mockPacket);

            expect(result.suspicious).toBe(true);
            expect(result.metadata.suspicious_reasons).toContain('telnet_connection');
        });

        test('should handle malformed packets', async () => {
            const mockPacket = {
                timestamp: new Date(),
                src_ip: 'invalid_ip',
                dst_ip: '192.168.1.1',
                protocol: 'UNKNOWN',
                size: 0
            };

            const result = await packetAnalyzer.analyze(mockPacket);

            expect(result.protocol).toBe('UNKNOWN');
            expect(result.suspicious).toBe(true);
            expect(result.metadata.errors).toContain('invalid_source_ip');
        });
    });

    describe('Protocol Detection', () => {
        beforeEach(async () => {
            await packetAnalyzer.initialize();
        });

        test('should detect HTTP protocol', () => {
            const payload = Buffer.from('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n');
            const protocol = packetAnalyzer.detectApplicationProtocol(payload, 80);

            expect(protocol).toBe('HTTP');
        });

        test('should detect HTTPS protocol', () => {
            const payload = Buffer.from([0x16, 0x03, 0x01, 0x00, 0x01]); // TLS handshake
            const protocol = packetAnalyzer.detectApplicationProtocol(payload, 443);

            expect(protocol).toBe('HTTPS');
        });

        test('should detect DNS protocol', () => {
            const payload = Buffer.from([0x12, 0x34, 0x01, 0x00, 0x00, 0x01]); // DNS query
            const protocol = packetAnalyzer.detectApplicationProtocol(payload, 53);

            expect(protocol).toBe('DNS');
        });

        test('should detect SSH protocol', () => {
            const payload = Buffer.from('SSH-2.0-OpenSSH_7.4');
            const protocol = packetAnalyzer.detectApplicationProtocol(payload, 22);

            expect(protocol).toBe('SSH');
        });

        test('should detect FTP protocol', () => {
            const payload = Buffer.from('220 Welcome to FTP server');
            const protocol = packetAnalyzer.detectApplicationProtocol(payload, 21);

            expect(protocol).toBe('FTP');
        });

        test('should return unknown for unrecognized protocols', () => {
            const payload = Buffer.from('UNKNOWN_PROTOCOL_DATA');
            const protocol = packetAnalyzer.detectApplicationProtocol(payload, 9999);

            expect(protocol).toBe('UNKNOWN');
        });
    });

    describe('Statistics Tracking', () => {
        beforeEach(async () => {
            await packetAnalyzer.initialize();
        });

        test('should track packet counts by protocol', async () => {
            const packets = [
                { protocol: 'TCP', size: 1024 },
                { protocol: 'TCP', size: 512 },
                { protocol: 'UDP', size: 256 },
                { protocol: 'ICMP', size: 64 }
            ];

            for (const packet of packets) {
                await packetAnalyzer.analyze(packet);
            }

            const stats = packetAnalyzer.getStatistics();

            expect(stats.protocolCounts.TCP).toBe(2);
            expect(stats.protocolCounts.UDP).toBe(1);
            expect(stats.protocolCounts.ICMP).toBe(1);
        });

        test('should track bytes processed by protocol', async () => {
            const packets = [
                { protocol: 'TCP', size: 1024 },
                { protocol: 'TCP', size: 512 },
                { protocol: 'UDP', size: 256 }
            ];

            for (const packet of packets) {
                await packetAnalyzer.analyze(packet);
            }

            const stats = packetAnalyzer.getStatistics();

            expect(stats.bytesProcessed.TCP).toBe(1536);
            expect(stats.bytesProcessed.UDP).toBe(256);
            expect(stats.totalBytes).toBe(1792);
        });

        test('should track application protocols', async () => {
            const packets = [
                { protocol: 'TCP', dst_port: 80, payload: Buffer.from('GET / HTTP/1.1') },
                { protocol: 'TCP', dst_port: 443, payload: Buffer.from([0x16, 0x03, 0x01]) },
                { protocol: 'UDP', dst_port: 53, payload: Buffer.from([0x12, 0x34]) }
            ];

            for (const packet of packets) {
                await packetAnalyzer.analyze(packet);
            }

            const stats = packetAnalyzer.getStatistics();

            expect(stats.applicationProtocols.HTTP).toBe(1);
            expect(stats.applicationProtocols.HTTPS).toBe(1);
            expect(stats.applicationProtocols.DNS).toBe(1);
        });

        test('should track suspicious packets', async () => {
            const packets = [
                { protocol: 'TCP', dst_port: 23, size: 1024 }, // Telnet - suspicious
                { protocol: 'TCP', dst_port: 80, size: 1024 }, // HTTP - normal
                { protocol: 'TCP', dst_port: 1433, size: 1024 } // SQL Server - suspicious
            ];

            for (const packet of packets) {
                await packetAnalyzer.analyze(packet);
            }

            const stats = packetAnalyzer.getStatistics();

            expect(stats.suspiciousPackets).toBe(2);
            expect(stats.totalPackets).toBe(3);
        });

        test('should calculate throughput metrics', async () => {
            const startTime = Date.now();
            const packets = Array(100).fill(null).map(() => ({
                protocol: 'TCP',
                size: 1024,
                timestamp: new Date()
            }));

            for (const packet of packets) {
                await packetAnalyzer.analyze(packet);
            }

            const stats = packetAnalyzer.getStatistics();

            expect(stats.totalPackets).toBe(100);
            expect(stats.totalBytes).toBe(102400);
            expect(stats.packetsPerSecond).toBeGreaterThan(0);
            expect(stats.bytesPerSecond).toBeGreaterThan(0);
        });
    });

    describe('Packet Direction Detection', () => {
        beforeEach(async () => {
            await packetAnalyzer.initialize();
        });

        test('should detect outbound traffic', () => {
            const direction = packetAnalyzer.detectDirection('192.168.1.100', '8.8.8.8');
            expect(direction).toBe('outbound');
        });

        test('should detect inbound traffic', () => {
            const direction = packetAnalyzer.detectDirection('8.8.8.8', '192.168.1.100');
            expect(direction).toBe('inbound');
        });

        test('should detect internal traffic', () => {
            const direction = packetAnalyzer.detectDirection('192.168.1.100', '192.168.1.200');
            expect(direction).toBe('internal');
        });

        test('should detect loopback traffic', () => {
            const direction = packetAnalyzer.detectDirection('127.0.0.1', '127.0.0.1');
            expect(direction).toBe('loopback');
        });
    });

    describe('Suspicious Activity Detection', () => {
        beforeEach(async () => {
            await packetAnalyzer.initialize();
        });

        test('should detect port scan patterns', async () => {
            const packets = Array(10).fill(null).map((_, i) => ({
                src_ip: '192.168.1.100',
                dst_ip: '192.168.1.1',
                dst_port: 80 + i,
                protocol: 'TCP',
                flags: ['SYN'],
                size: 64
            }));

            for (const packet of packets) {
                await packetAnalyzer.analyze(packet);
            }

            const stats = packetAnalyzer.getStatistics();
            expect(stats.suspiciousActivity.portScan).toBeGreaterThan(0);
        });

        test('should detect unusual packet sizes', async () => {
            const largePacket = {
                protocol: 'TCP',
                size: 65000, // Unusually large
                dst_port: 80
            };

            const result = await packetAnalyzer.analyze(largePacket);
            expect(result.suspicious).toBe(true);
            expect(result.metadata.suspicious_reasons).toContain('unusual_packet_size');
        });

        test('should detect fragmented packets', async () => {
            const fragmentedPacket = {
                protocol: 'IP',
                size: 1500,
                flags: ['MF'], // More Fragments
                fragment_offset: 1480
            };

            const result = await packetAnalyzer.analyze(fragmentedPacket);
            expect(result.metadata.fragmented).toBe(true);
        });
    });

    describe('Performance Optimization', () => {
        beforeEach(async () => {
            await packetAnalyzer.initialize();
        });

        test('should handle high packet volume efficiently', async () => {
            const startTime = Date.now();
            const packetCount = 1000;
            
            const packets = Array(packetCount).fill(null).map(() => ({
                protocol: 'TCP',
                size: 1024,
                src_ip: '192.168.1.100',
                dst_ip: '192.168.1.1',
                dst_port: 80
            }));

            for (const packet of packets) {
                await packetAnalyzer.analyze(packet);
            }

            const endTime = Date.now();
            const processingTime = endTime - startTime;
            const packetsPerSecond = (packetCount / processingTime) * 1000;

            expect(packetsPerSecond).toBeGreaterThan(100); // Should process at least 100 packets/second
        });

        test('should manage memory efficiently', async () => {
            const initialMemory = process.memoryUsage().heapUsed;
            
            // Process many packets
            for (let i = 0; i < 1000; i++) {
                await packetAnalyzer.analyze({
                    protocol: 'TCP',
                    size: 1024,
                    src_ip: '192.168.1.100',
                    dst_ip: '192.168.1.1',
                    dst_port: 80
                });
            }

            const finalMemory = process.memoryUsage().heapUsed;
            const memoryIncrease = finalMemory - initialMemory;

            // Memory increase should be reasonable (less than 100MB)
            expect(memoryIncrease).toBeLessThan(100 * 1024 * 1024);
        });
    });

    describe('Error Handling', () => {
        beforeEach(async () => {
            await packetAnalyzer.initialize();
        });

        test('should handle null packets gracefully', async () => {
            const result = await packetAnalyzer.analyze(null);
            
            expect(result.protocol).toBe('UNKNOWN');
            expect(result.suspicious).toBe(true);
            expect(result.metadata.errors).toContain('null_packet');
        });

        test('should handle empty packets gracefully', async () => {
            const result = await packetAnalyzer.analyze({});
            
            expect(result.protocol).toBe('UNKNOWN');
            expect(result.suspicious).toBe(true);
            expect(result.metadata.errors).toContain('empty_packet');
        });

        test('should handle analysis errors gracefully', async () => {
            // Mock an analysis error
            const originalAnalyze = packetAnalyzer.analyze;
            packetAnalyzer.detectApplicationProtocol = jest.fn().mockImplementation(() => {
                throw new Error('Analysis error');
            });

            const result = await packetAnalyzer.analyze({
                protocol: 'TCP',
                size: 1024,
                dst_port: 80
            });

            expect(result.metadata.errors).toContain('analysis_error');
        });
    });

    describe('Configuration Management', () => {
        test('should update configuration', () => {
            const newConfig = {
                ...mockConfig,
                maxPacketSize: 32768,
                enableDeepInspection: true
            };

            packetAnalyzer.updateConfiguration(newConfig);

            expect(packetAnalyzer.config.maxPacketSize).toBe(32768);
            expect(packetAnalyzer.config.enableDeepInspection).toBe(true);
        });

        test('should validate configuration', () => {
            const invalidConfig = {
                maxPacketSize: -1,
                bufferSize: 0
            };

            expect(() => {
                packetAnalyzer.validateConfiguration(invalidConfig);
            }).toThrow('Invalid configuration');
        });
    });
}); 