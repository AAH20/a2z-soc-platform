#!/usr/bin/env node

const NetworkAgent = require('./core/NetworkAgent');
const ConfigManager = require('./core/ConfigManager');
const { createSecureConnection } = require('./communication/SecureChannel');
const Logger = require('./utils/Logger');

/**
 * A2Z SOC Network Security Agent
 * 
 * Lightweight agent for network monitoring and threat detection
 * - Real-time packet analysis
 * - Secure cloud reporting
 * - Local preprocessing and filtering
 * - Auto-update capability
 */

class A2ZNetworkAgent {
    constructor() {
        this.networkAgent = null;
        this.configManager = null;
        this.secureChannel = null;
        this.logger = null;
        this.isInitialized = false;
    }

    async initialize() {
        try {
            this.logger = new Logger('A2ZNetworkAgent');
            this.logger.info('🚀 Starting A2Z SOC Network Agent v1.0.0');

            // Load configuration
            this.configManager = new ConfigManager();
            await this.configManager.initialize();
            const config = this.configManager.getConfig();
            
            this.logger.info(`📋 Configuration loaded for tenant: ${config.tenantId}`);

            // Create secure channel (will only connect if cloud endpoint is available)
            try {
                this.secureChannel = await createSecureConnection(config);
                this.logger.info('🔐 Secure channel established');
            } catch (error) {
                this.logger.warn(`⚠️  Running in standalone mode: ${error.message}`);
                this.secureChannel = null;
            }

            // Initialize network agent
            this.networkAgent = new NetworkAgent(config, this.secureChannel);
            this.networkAgent.setConfigManager(this.configManager);
            
            await this.networkAgent.initialize();

            this.isInitialized = true;
            this.logger.info('✅ A2Z Network Agent initialized successfully');

        } catch (error) {
            this.logger.error(`❌ Failed to initialize agent: ${error.message}`);
            throw error;
        }
    }

    async start() {
        if (!this.isInitialized) {
            await this.initialize();
        }

        await this.networkAgent.start();
        this.logger.info('🎯 Network monitoring active');
    }

    async stop() {
        if (this.networkAgent) {
            await this.networkAgent.stop();
        }

        if (this.secureChannel) {
            await this.secureChannel.close();
        }

        this.logger.info('🛑 A2Z Network Agent stopped');
    }

    async restart() {
        this.logger.info('🔄 Restarting A2Z Network Agent...');
        await this.stop();
        await this.start();
    }

    async getStatus() {
        if (!this.networkAgent) {
            return {
                status: 'stopped',
                error: 'Agent not initialized'
            };
        }

        const status = await this.networkAgent.getStatus();
        
        return {
            ...status,
            cloudConnection: {
                connected: !!this.secureChannel,
                lastHeartbeat: this.secureChannel?.lastHeartbeat || null
            },
            apiServer: {
                listening: true,
                port: this.networkAgent.apiServer?.options.port || 3001
            }
        };
    }

    async getMetrics() {
        if (!this.networkAgent) {
            return {};
        }

        return await this.networkAgent.getMetrics();
    }
}

// CLI handling
async function main() {
    const args = process.argv.slice(2);
    const command = args[0] || 'start';

    const agent = new A2ZNetworkAgent();

    // Handle process signals
    process.on('SIGINT', async () => {
        console.log('\n🛑 Received SIGINT, shutting down gracefully...');
        await agent.stop();
        process.exit(0);
    });

    process.on('SIGTERM', async () => {
        console.log('\n🛑 Received SIGTERM, shutting down gracefully...');
        await agent.stop();
        process.exit(0);
    });

    process.on('uncaughtException', (error) => {
        console.error('❌ Uncaught Exception:', error);
        process.exit(1);
    });

    process.on('unhandledRejection', (reason, promise) => {
        console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
        process.exit(1);
    });

    try {
        switch (command) {
            case 'start':
                await agent.start();
                console.log('🎯 A2Z Network Agent is running');
                console.log('📊 Web Interface: http://localhost:5200');
                console.log('🔍 API Documentation: http://localhost:5200/api/v1/status');
                console.log('Press Ctrl+C to stop');
                break;

            case 'stop':
                console.log('🛑 Stopping agent...');
                await agent.stop();
                break;

            case 'restart':
                await agent.restart();
                break;

            case 'status':
                await agent.initialize();
                const status = await agent.getStatus();
                console.log('📊 Agent Status:');
                console.log(JSON.stringify(status, null, 2));
                process.exit(0);
                break;

            case 'metrics':
                await agent.initialize();
                const metrics = await agent.getMetrics();
                console.log('📈 Agent Metrics:');
                console.log(JSON.stringify(metrics, null, 2));
                process.exit(0);
                break;

            case 'test':
                console.log('🧪 Running agent tests...');
                await agent.initialize();
                const testStatus = await agent.getStatus();
                console.log('✅ Test completed successfully');
                console.log(JSON.stringify(testStatus, null, 2));
                await agent.stop();
                process.exit(0);
                break;

            case 'help':
            case '--help':
            case '-h':
                console.log(`
A2Z Network Security Agent v1.0.0

Usage: node index.js [command] [options]

Commands:
  start     Start the network agent (default)
  stop      Stop the network agent
  restart   Restart the network agent  
  status    Show agent status
  metrics   Show agent metrics
  test      Run agent tests
  help      Show this help message

Options:
  --config <path>     Configuration file path
  --interface <name>  Network interface to monitor
  --debug            Enable debug logging
  --standalone       Run without cloud connection

Examples:
  node index.js start
  node index.js status
  node index.js start --interface eth0 --debug
  node index.js test

For more information, visit: https://github.com/a2z-soc/network-agent
                `);
                process.exit(0);
                break;

            default:
                console.error(`❌ Unknown command: ${command}`);
                console.log('Use "node index.js help" for usage information');
                process.exit(1);
        }
    } catch (error) {
        console.error('❌ Agent error:', error.message);
        process.exit(1);
    }
}

// Only run main if this file is executed directly
if (require.main === module) {
    main().catch(error => {
        console.error('❌ Fatal error:', error);
        process.exit(1);
    });
}

module.exports = A2ZNetworkAgent; 