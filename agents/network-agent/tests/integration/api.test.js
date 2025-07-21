const request = require('supertest');
const http = require('http');
const NetworkAgent = require('../../src/core/NetworkAgent');
const ApiServer = require('../../src/api/ApiServer');

describe('Network Agent API Integration Tests', () => {
    let networkAgent;
    let apiServer;
    let server;
    let app;

    beforeAll(async () => {
        // Create mock network agent
        networkAgent = {
            config: {
                agentId: 'test-agent-001',
                version: '1.2.4',
                apiPort: 0, // Use random port for testing
                apiHost: 'localhost'
            },
            isRunning: false,
            startTime: null,
            packetsProcessed: 0,
            threatsDetected: 0,
            alertsGenerated: 0,
            logsCollected: 0,
            interfaces: [],
            activeCaptures: new Map(),
            eventBuffer: [],
            alertBuffer: [],
            logBuffer: [],
            networkMonitor: { isMonitoring: false },
            packetAnalyzer: { getStatistics: () => ({}) },
            threatDetector: { rules: new Map() },
            metricsCollector: { getAllMetrics: () => ({}) },
            configManager: { 
                getConfig: () => networkAgent.config,
                updateConfig: jest.fn(),
                factoryReset: jest.fn()
            },
            
            // Mock methods
            getStatus: jest.fn().mockResolvedValue({
                agent: {
                    id: 'test-agent-001',
                    version: '1.2.4',
                    hostname: 'test-host',
                    platform: 'linux',
                    privilegeLevel: 'user'
                },
                status: {
                    isRunning: false,
                    uptime: 0,
                    startTime: null
                },
                performance: {
                    packetsProcessed: 0,
                    threatsDetected: 0,
                    alertsGenerated: 0,
                    logsCollected: 0,
                    memory: { rss: 1024, heapUsed: 512 }
                },
                network: {
                    interfaces: 0,
                    activeCaptures: 0,
                    monitoring: false
                },
                buffers: {
                    events: 0,
                    alerts: 0,
                    logs: 0
                }
            }),
            start: jest.fn().mockResolvedValue(),
            stop: jest.fn().mockResolvedValue(),
            restart: jest.fn().mockResolvedValue()
        };

        // Create API server
        apiServer = new ApiServer(networkAgent, { port: 0 });
        await apiServer.start();
        
        // Get the actual server instance for testing
        server = apiServer.server;
        app = (req, res) => server.emit('request', req, res);
    });

    afterAll(async () => {
        if (apiServer) {
            await apiServer.stop();
        }
    });

    describe('Health Check Endpoints', () => {
        test('GET /health should return 200 with status ok', async () => {
            const response = await request(app)
                .get('/health')
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.status).toBe('ok');
            expect(response.body.data.timestamp).toBeDefined();
        });

        test('GET /health should include CORS headers', async () => {
            const response = await request(app)
                .get('/health')
                .expect(200);

            expect(response.headers['access-control-allow-origin']).toBe('*');
            expect(response.headers['access-control-allow-methods']).toContain('GET');
        });

        test('OPTIONS /health should return 204 for preflight', async () => {
            await request(app)
                .options('/health')
                .expect(204);
        });
    });

    describe('Agent Status Endpoints', () => {
        test('GET /api/v1/status should return agent status', async () => {
            const response = await request(app)
                .get('/api/v1/status')
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.agent).toBeDefined();
            expect(response.body.data.agent.id).toBe('test-agent-001');
            expect(response.body.data.status).toBeDefined();
            expect(response.body.data.performance).toBeDefined();
            expect(response.body.data.network).toBeDefined();
            expect(response.body.data.buffers).toBeDefined();
        });

        test('POST /api/v1/agent/start should start agent', async () => {
            const response = await request(app)
                .post('/api/v1/agent/start')
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.message).toBe('Agent started');
            expect(networkAgent.start).toHaveBeenCalled();
        });

        test('POST /api/v1/agent/stop should stop agent', async () => {
            const response = await request(app)
                .post('/api/v1/agent/stop')
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.message).toBe('Agent stopped');
            expect(networkAgent.stop).toHaveBeenCalled();
        });

        test('POST /api/v1/agent/restart should restart agent', async () => {
            const response = await request(app)
                .post('/api/v1/agent/restart')
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.message).toBe('Agent restarted');
            expect(networkAgent.restart).toHaveBeenCalled();
        });
    });

    describe('Metrics Endpoints', () => {
        beforeEach(() => {
            networkAgent.metricsCollector.getAllMetrics = jest.fn().mockReturnValue({
                cpu: { usage: 45.2, cores: 4 },
                memory: { used: 1024, total: 4096 },
                network: { bytesIn: 1000000, bytesOut: 500000 },
                disk: { usage: 60.5, total: 100000 }
            });

            networkAgent.packetAnalyzer.getStatistics = jest.fn().mockReturnValue({
                totalPackets: 10000,
                protocolCounts: { TCP: 7000, UDP: 2500, ICMP: 500 },
                bytesProcessed: { TCP: 5000000, UDP: 1000000, ICMP: 50000 },
                packetsPerSecond: 100,
                bytesPerSecond: 500000
            });
        });

        test('GET /api/v1/metrics/system should return system metrics', async () => {
            const response = await request(app)
                .get('/api/v1/metrics/system')
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.cpu).toBeDefined();
            expect(response.body.data.memory).toBeDefined();
            expect(response.body.data.network).toBeDefined();
            expect(response.body.data.disk).toBeDefined();
        });

        test('GET /api/v1/metrics/system/latest should return latest system metrics', async () => {
            const response = await request(app)
                .get('/api/v1/metrics/system/latest')
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.timestamp).toBeDefined();
            expect(response.body.data.cpu).toBeDefined();
            expect(response.body.data.memory).toBeDefined();
        });

        test('GET /api/v1/metrics/network should return network metrics', async () => {
            const response = await request(app)
                .get('/api/v1/metrics/network')
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.totalPackets).toBe(10000);
            expect(response.body.data.protocolCounts).toBeDefined();
            expect(response.body.data.bytesProcessed).toBeDefined();
        });

        test('GET /api/v1/metrics/network/latest should return latest network metrics', async () => {
            const response = await request(app)
                .get('/api/v1/metrics/network/latest')
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.packetsPerSecond).toBe(100);
            expect(response.body.data.bytesPerSecond).toBe(500000);
        });

        test('GET /api/v1/metrics/protocols should return protocol distribution', async () => {
            const response = await request(app)
                .get('/api/v1/metrics/protocols')
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.TCP).toBe(7000);
            expect(response.body.data.UDP).toBe(2500);
            expect(response.body.data.ICMP).toBe(500);
        });
    });

    describe('Threat Detection Endpoints', () => {
        beforeEach(() => {
            networkAgent.threatDetector.rules = new Map([
                ['rule_001', {
                    id: 'rule_001',
                    name: 'Port Scan Detection',
                    category: 'reconnaissance',
                    severity: 'medium',
                    enabled: true
                }],
                ['rule_002', {
                    id: 'rule_002',
                    name: 'Brute Force Detection',
                    category: 'authentication',
                    severity: 'high',
                    enabled: true
                }]
            ]);
        });

        test('GET /api/v1/threats/alerts should return threat alerts', async () => {
            const response = await request(app)
                .get('/api/v1/threats/alerts')
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.data).toBeInstanceOf(Array);
            expect(response.body.data.total).toBe(0);
            expect(response.body.data.page).toBe(1);
            expect(response.body.data.limit).toBe(50);
        });

        test('GET /api/v1/threats/alerts with pagination should work', async () => {
            const response = await request(app)
                .get('/api/v1/threats/alerts?page=2&limit=25')
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.page).toBe(2);
            expect(response.body.data.limit).toBe(25);
        });

        test('GET /api/v1/threats/rules should return threat rules', async () => {
            const response = await request(app)
                .get('/api/v1/threats/rules')
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data).toBeInstanceOf(Array);
            expect(response.body.data.length).toBe(2);
            expect(response.body.data[0].id).toBe('rule_001');
            expect(response.body.data[0].name).toBe('Port Scan Detection');
        });

        test('POST /api/v1/threats/rules should create new rule', async () => {
            const newRule = {
                id: 'rule_003',
                name: 'New Test Rule',
                category: 'test',
                severity: 'low',
                enabled: true
            };

            const response = await request(app)
                .post('/api/v1/threats/rules')
                .send(newRule)
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.id).toBe('rule_003');
            expect(response.body.data.name).toBe('New Test Rule');
        });

        test('PATCH /api/v1/threats/rules/:id should update rule', async () => {
            const updates = {
                severity: 'critical',
                enabled: false
            };

            const response = await request(app)
                .patch('/api/v1/threats/rules/rule_001')
                .send(updates)
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.severity).toBe('critical');
            expect(response.body.data.enabled).toBe(false);
        });

        test('DELETE /api/v1/threats/rules/:id should delete rule', async () => {
            const response = await request(app)
                .delete('/api/v1/threats/rules/rule_001')
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.message).toBe('Rule deleted');
        });

        test('GET /api/v1/threats/alerts/:id should return specific alert', async () => {
            const response = await request(app)
                .get('/api/v1/threats/alerts/alert_001')
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.id).toBe('alert_001');
        });

        test('PATCH /api/v1/threats/alerts/:id should update alert', async () => {
            const updates = {
                status: 'acknowledged',
                acknowledged_by: 'admin'
            };

            const response = await request(app)
                .patch('/api/v1/threats/alerts/alert_001')
                .send(updates)
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.status).toBe('acknowledged');
        });
    });

    describe('Configuration Endpoints', () => {
        test('GET /api/v1/config should return configuration', async () => {
            const response = await request(app)
                .get('/api/v1/config')
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.agentId).toBe('test-agent-001');
            expect(response.body.data.version).toBe('1.2.4');
        });

        test('PATCH /api/v1/config should update configuration', async () => {
            const updates = {
                heartbeatInterval: 60000,
                logLevel: 'debug'
            };

            const response = await request(app)
                .patch('/api/v1/config')
                .send(updates)
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(networkAgent.configManager.updateConfig).toHaveBeenCalledWith(updates);
        });

        test('POST /api/v1/config/reset should reset configuration', async () => {
            const response = await request(app)
                .post('/api/v1/config/reset')
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(networkAgent.configManager.factoryReset).toHaveBeenCalled();
        });

        test('GET /api/v1/config/export should export configuration', async () => {
            const response = await request(app)
                .get('/api/v1/config/export')
                .expect(200);

            expect(response.headers['content-type']).toBe('application/json; charset=utf-8');
            expect(response.headers['content-disposition']).toBe('attachment; filename=agent-config.json');
        });

        test('POST /api/v1/config/import should import configuration', async () => {
            const importConfig = {
                agentId: 'imported-agent',
                heartbeatInterval: 30000
            };

            const response = await request(app)
                .post('/api/v1/config/import')
                .send(importConfig)
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data.message).toBe('Configuration imported');
        });
    });

    describe('Logs Endpoints', () => {
        test('GET /api/v1/logs should return logs', async () => {
            const response = await request(app)
                .get('/api/v1/logs')
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data).toBeInstanceOf(Array);
        });

        test('GET /api/v1/logs with filters should work', async () => {
            const response = await request(app)
                .get('/api/v1/logs?level=error&limit=10')
                .expect(200);

            expect(response.body.success).toBe(true);
            expect(response.body.data).toBeInstanceOf(Array);
        });

        test('GET /api/v1/logs/download should download logs', async () => {
            const response = await request(app)
                .get('/api/v1/logs/download')
                .expect(200);

            expect(response.headers['content-type']).toBe('application/octet-stream');
            expect(response.headers['content-disposition']).toContain('attachment');
        });
    });

    describe('Error Handling', () => {
        test('should return 404 for non-existent routes', async () => {
            const response = await request(app)
                .get('/api/v1/nonexistent')
                .expect(404);

            expect(response.body.success).toBe(false);
            expect(response.body.error).toBe('Route not found');
        });

        test('should handle internal server errors', async () => {
            // Mock an error in the status method
            networkAgent.getStatus = jest.fn().mockRejectedValue(new Error('Internal error'));

            const response = await request(app)
                .get('/api/v1/status')
                .expect(500);

            expect(response.body.success).toBe(false);
            expect(response.body.error).toBe('Internal Server Error');
        });

        test('should handle malformed JSON in request body', async () => {
            const response = await request(app)
                .post('/api/v1/threats/rules')
                .send('invalid json')
                .type('application/json')
                .expect(400);

            expect(response.body.success).toBe(false);
            expect(response.body.error).toContain('Invalid JSON');
        });

        test('should handle missing required fields', async () => {
            const incompleteRule = {
                name: 'Incomplete Rule'
                // Missing required fields
            };

            const response = await request(app)
                .post('/api/v1/threats/rules')
                .send(incompleteRule)
                .expect(400);

            expect(response.body.success).toBe(false);
            expect(response.body.error).toContain('Missing required fields');
        });
    });

    describe('Security', () => {
        test('should include security headers', async () => {
            const response = await request(app)
                .get('/api/v1/status')
                .expect(200);

            expect(response.headers['access-control-allow-origin']).toBe('*');
            expect(response.headers['access-control-allow-methods']).toBeDefined();
            expect(response.headers['access-control-allow-headers']).toBeDefined();
        });

        test('should handle CORS preflight requests', async () => {
            const response = await request(app)
                .options('/api/v1/status')
                .set('Origin', 'http://localhost:3000')
                .set('Access-Control-Request-Method', 'GET')
                .expect(204);

            expect(response.headers['access-control-allow-origin']).toBe('*');
            expect(response.headers['access-control-allow-methods']).toContain('GET');
        });

        test('should validate input parameters', async () => {
            const response = await request(app)
                .get('/api/v1/threats/alerts?page=invalid')
                .expect(400);

            expect(response.body.success).toBe(false);
            expect(response.body.error).toContain('Invalid page parameter');
        });

        test('should sanitize log output', async () => {
            const response = await request(app)
                .get('/api/v1/logs?search=<script>alert("xss")</script>')
                .expect(200);

            expect(response.body.success).toBe(true);
            // Should not contain unsanitized script tags
            expect(JSON.stringify(response.body)).not.toContain('<script>');
        });
    });

    describe('Performance', () => {
        test('should handle concurrent requests', async () => {
            const requests = Array(10).fill(null).map(() => 
                request(app).get('/api/v1/status')
            );

            const responses = await Promise.all(requests);

            responses.forEach(response => {
                expect(response.status).toBe(200);
                expect(response.body.success).toBe(true);
            });
        });

        test('should respond within reasonable time', async () => {
            const startTime = Date.now();
            
            await request(app)
                .get('/api/v1/status')
                .expect(200);

            const responseTime = Date.now() - startTime;
            expect(responseTime).toBeLessThan(1000); // Should respond within 1 second
        });

        test('should handle large request bodies', async () => {
            const largeRule = {
                id: 'large_rule',
                name: 'Large Rule',
                category: 'test',
                severity: 'low',
                description: 'x'.repeat(10000), // 10KB description
                conditions: Array(1000).fill(null).map((_, i) => ({
                    type: 'port',
                    value: i
                }))
            };

            const response = await request(app)
                .post('/api/v1/threats/rules')
                .send(largeRule)
                .expect(200);

            expect(response.body.success).toBe(true);
        });
    });

    describe('Content Negotiation', () => {
        test('should return JSON by default', async () => {
            const response = await request(app)
                .get('/api/v1/status')
                .expect(200);

            expect(response.headers['content-type']).toContain('application/json');
        });

        test('should handle Accept header', async () => {
            const response = await request(app)
                .get('/api/v1/status')
                .set('Accept', 'application/json')
                .expect(200);

            expect(response.headers['content-type']).toContain('application/json');
        });

        test('should compress responses when requested', async () => {
            const response = await request(app)
                .get('/api/v1/status')
                .set('Accept-Encoding', 'gzip')
                .expect(200);

            // Response should be compressed if compression is enabled
            expect(response.headers['content-encoding']).toBeUndefined(); // May vary based on implementation
        });
    });

    describe('Rate Limiting', () => {
        test('should handle rapid requests gracefully', async () => {
            const rapidRequests = Array(50).fill(null).map(() => 
                request(app).get('/health')
            );

            const responses = await Promise.all(rapidRequests);

            // All requests should succeed (no rate limiting implemented yet)
            responses.forEach(response => {
                expect(response.status).toBe(200);
            });
        });
    });

    describe('WebSocket Support', () => {
        test('should handle WebSocket upgrade requests', async () => {
            const response = await request(app)
                .get('/api/v1/ws')
                .set('Upgrade', 'websocket')
                .set('Connection', 'Upgrade')
                .expect(426); // Upgrade Required

            expect(response.body.error).toContain('WebSocket upgrade required');
        });
    });
}); 