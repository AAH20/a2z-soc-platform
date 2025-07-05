#!/usr/bin/env node

const express = require('express');
const http = require('http');
const cors = require('cors');
const path = require('path');

/**
 * Simple A2Z Network Monitoring Agent Server
 * Lightweight HTTP server for network monitoring capabilities
 */

class SimpleNetworkAgent {
    constructor() {
        this.app = express();
        this.server = null;
        this.port = process.env.PORT || 5200;
        this.isRunning = false;
        this.stats = {
            startTime: new Date(),
            packetsProcessed: 0,
            threatsDetected: 0,
            alertsGenerated: 0
        };
        this.setupRoutes();
    }

    setupRoutes() {
        // Enable CORS
        this.app.use(cors());
        this.app.use(express.json());

        // Health check endpoint
        this.app.get('/health', (req, res) => {
            res.json({
                status: 'healthy',
                service: 'network-agent-standalone',
                version: '1.0.0',
                timestamp: new Date().toISOString(),
                uptime: process.uptime()
            });
        });

        // Status endpoint
        this.app.get('/status', (req, res) => {
            res.json({
                status: 'running',
                agentId: 'standalone-agent',
                version: '1.0.0',
                platform: process.platform,
                uptime: process.uptime(),
                memory: process.memoryUsage(),
                timestamp: new Date().toISOString()
            });
        });

        // Basic logs endpoint
        this.app.get('/logs', (req, res) => {
            res.json({
                logs: [
                    {
                        timestamp: new Date().toISOString(),
                        level: 'info',
                        message: 'Network agent standalone server running',
                        source: 'network-agent'
                    }
                ]
            });
        });

        // Basic alerts endpoint
        this.app.get('/alerts', (req, res) => {
            res.json({
                alerts: []
            });
        });

        // Statistics endpoint
        this.app.get('/api/v1/stats', (req, res) => {
            res.json({
                ...this.stats,
                uptime: Date.now() - this.stats.startTime.getTime(),
                timestamp: new Date().toISOString()
            });
        });

        // Download agent endpoint (for customer downloads)
        this.app.get('/api/v1/download/agent', (req, res) => {
            res.json({
                message: 'A2Z Network Agent Download',
                version: '1.0.0',
                platforms: {
                    windows: '/downloads/a2z-agent-windows.exe',
                    linux: '/downloads/a2z-agent-linux',
                    macos: '/downloads/a2z-agent-macos',
                    docker: 'docker pull a2zsoc/network-agent:latest'
                },
                installation: {
                    requirements: ['Root/Administrator privileges', 'Network access'],
                    commands: [
                        'curl -O https://api.a2zsoc.com/downloads/install.sh',
                        'chmod +x install.sh',
                        'sudo ./install.sh'
                    ]
                }
            });
        });

        // Configuration endpoint
        this.app.get('/api/v1/config', (req, res) => {
            res.json({
                interface: process.env.A2Z_INTERFACE || 'any',
                mode: process.env.A2Z_MODE || 'passive',
                standalone: process.env.A2Z_STANDALONE === 'true',
                logLevel: process.env.LOG_LEVEL || 'info'
            });
        });

        // Simulate network monitoring
        this.app.post('/api/v1/monitor/start', (req, res) => {
            this.startMonitoring();
            res.json({
                message: 'Network monitoring started',
                interface: process.env.A2Z_INTERFACE || 'any',
                timestamp: new Date().toISOString()
            });
        });

        this.app.post('/api/v1/monitor/stop', (req, res) => {
            this.stopMonitoring();
            res.json({
                message: 'Network monitoring stopped',
                timestamp: new Date().toISOString()
            });
        });

        // Root endpoint
        this.app.get('/', (req, res) => {
            res.json({
                service: 'A2Z Network Monitoring Agent',
                version: '1.0.0',
                status: this.isRunning ? 'running' : 'stopped',
                endpoints: [
                    'GET /health - Health check',
                    'GET /status - Agent status',
                    'GET /logs - Logs',
                    'GET /alerts - Alerts',
                    'GET /api/v1/stats - Statistics',
                    'GET /api/v1/config - Configuration',
                    'GET /api/v1/download/agent - Download instructions',
                    'POST /api/v1/monitor/start - Start monitoring',
                    'POST /api/v1/monitor/stop - Stop monitoring'
                ]
            });
        });
    }

    startMonitoring() {
        this.isRunning = true;
        // Simulate packet processing
        this.monitoringInterval = setInterval(() => {
            this.stats.packetsProcessed += Math.floor(Math.random() * 100) + 10;
            
            // Simulate occasional threats
            if (Math.random() < 0.1) {
                this.stats.threatsDetected++;
                this.stats.alertsGenerated++;
            }
        }, 5000);
        
        console.log('🔍 Network monitoring started');
    }

    stopMonitoring() {
        this.isRunning = false;
        if (this.monitoringInterval) {
            clearInterval(this.monitoringInterval);
            this.monitoringInterval = null;
        }
        console.log('🛑 Network monitoring stopped');
    }

    async start() {
        return new Promise((resolve, reject) => {
            this.server = http.createServer(this.app);
            
            this.server.on('error', (error) => {
                if (error.code === 'EADDRINUSE') {
                    console.log(`Port ${this.port} is busy, trying ${this.port + 1}`);
                    this.port = this.port + 1;
                    setTimeout(() => {
                        this.server.close();
                        this.start().then(resolve).catch(reject);
                    }, 100);
                } else {
                    reject(error);
                }
            });

            this.server.listen(this.port, '0.0.0.0', () => {
                console.log(`🚀 Network Agent Standalone Server running on port ${this.port}`);
                console.log(`📊 Health endpoint: http://localhost:${this.port}/health`);
                console.log(`📋 Status endpoint: http://localhost:${this.port}/status`);
                
                // Auto-start monitoring
                this.startMonitoring();
                resolve();
            });
        });
    }

    async stop() {
        this.stopMonitoring();
        if (this.server) {
            return new Promise((resolve) => {
                this.server.close(() => {
                    console.log('🛑 Network Agent Standalone Server stopped');
                    resolve();
                });
            });
        }
    }
}

// Start the agent
if (require.main === module) {
    const agent = new SimpleNetworkAgent();
    
    // Handle graceful shutdown
    process.on('SIGTERM', async () => {
        console.log('📴 Received SIGTERM, shutting down gracefully');
        await agent.stop();
        process.exit(0);
    });

    process.on('SIGINT', async () => {
        console.log('📴 Received SIGINT, shutting down gracefully');
        await agent.stop();
        process.exit(0);
    });

    agent.start().catch((error) => {
        console.error('Failed to start Network Agent Standalone Server:', error);
        process.exit(1);
    });
}

module.exports = SimpleNetworkAgent; 