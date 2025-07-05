const express = require('express');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const router = express.Router();

// Middleware
const { authenticateToken } = require('../middleware/auth');
const { tenantIsolation } = require('../middleware/tenantIsolation');

// Services
const AgentService = require('../services/agentService');
const DataIngestionService = require('../services/dataIngestionService');
const AlertProcessingService = require('../services/alertProcessingService');

// Initialize services
const agentService = new AgentService();
const dataIngestion = new DataIngestionService();
const alertProcessing = new AlertProcessingService();

// Agent Registration and Management
router.post('/register', authenticateToken, tenantIsolation(), async (req, res) => {
    try {
        const { agentType, systemInfo, capabilities } = req.body;
        const tenantId = req.user.tenantId;
        
        // Generate agent credentials
        const agentId = uuidv4();
        const agentKey = crypto.randomBytes(32).toString('hex');
        
        // Create agent record
        const agent = await agentService.registerAgent({
            id: agentId,
            tenantId: tenantId,
            type: agentType,
            key: agentKey,
            systemInfo: systemInfo,
            capabilities: capabilities,
            status: 'registered',
            registeredBy: req.user.id,
            registeredAt: new Date()
        });

        // Return agent configuration
        res.json({
            success: true,
            agent: {
                id: agentId,
                key: agentKey,
                type: agentType,
                cloudEndpoint: process.env.CLOUD_ENDPOINT || 'wss://api.a2zsoc.com',
                tenantId: tenantId,
                configuration: await agentService.getAgentConfig(agentId),
                downloadUrls: {
                    windows: `/api/v1/agents/download/windows/${agentId}`,
                    linux: `/api/v1/agents/download/linux/${agentId}`,
                    macos: `/api/v1/agents/download/macos/${agentId}`
                }
            }
        });

    } catch (error) {
        console.error('Agent registration error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to register agent'
        });
    }
});

// List tenant agents
router.get('/', authenticateToken, tenantIsolation(), async (req, res) => {
    try {
        const tenantId = req.user.tenantId;
        const { status, type, limit = 50, offset = 0 } = req.query;
        
        const agents = await agentService.listAgents(tenantId, {
            status,
            type,
            limit: parseInt(limit),
            offset: parseInt(offset)
        });

        res.json({
            success: true,
            agents: agents.map(agent => ({
                ...agent,
                key: undefined // Don't expose keys in list
            })),
            pagination: {
                limit: parseInt(limit),
                offset: parseInt(offset),
                total: await agentService.countAgents(tenantId, { status, type })
            }
        });

    } catch (error) {
        console.error('List agents error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to list agents'
        });
    }
});

// Get agent details
router.get('/:agentId', authenticateToken, tenantIsolation(), async (req, res) => {
    try {
        const { agentId } = req.params;
        const tenantId = req.user.tenantId;
        
        const agent = await agentService.getAgent(agentId, tenantId);
        if (!agent) {
            return res.status(404).json({
                success: false,
                error: 'Agent not found'
            });
        }

        // Get agent metrics
        const metrics = await agentService.getAgentMetrics(agentId);
        
        res.json({
            success: true,
            agent: {
                ...agent,
                key: undefined, // Don't expose key
                metrics: metrics
            }
        });

    } catch (error) {
        console.error('Get agent error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to get agent details'
        });
    }
});

// Update agent configuration
router.put('/:agentId/config', authenticateToken, tenantIsolation(), async (req, res) => {
    try {
        const { agentId } = req.params;
        const tenantId = req.user.tenantId;
        const { configuration } = req.body;
        
        const agent = await agentService.getAgent(agentId, tenantId);
        if (!agent) {
            return res.status(404).json({
                success: false,
                error: 'Agent not found'
            });
        }

        // Update configuration
        await agentService.updateAgentConfig(agentId, configuration);
        
        // Notify agent if connected
        await agentService.notifyAgentConfigUpdate(agentId, configuration);

        res.json({
            success: true,
            message: 'Agent configuration updated'
        });

    } catch (error) {
        console.error('Update agent config error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to update agent configuration'
        });
    }
});

// Send command to agent
router.post('/:agentId/command', authenticateToken, tenantIsolation(), async (req, res) => {
    try {
        const { agentId } = req.params;
        const tenantId = req.user.tenantId;
        const { command, parameters } = req.body;
        
        const agent = await agentService.getAgent(agentId, tenantId);
        if (!agent) {
            return res.status(404).json({
                success: false,
                error: 'Agent not found'
            });
        }

        // Send command to agent
        const response = await agentService.sendCommand(agentId, command, parameters);

        res.json({
            success: true,
            response: response
        });

    } catch (error) {
        console.error('Send command error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to send command to agent'
        });
    }
});

// Data ingestion endpoint
router.post('/:agentId/ingest', authenticateToken, tenantIsolation(), async (req, res) => {
    try {
        const { agentId } = req.params;
        const tenantId = req.user.tenantId;
        const { data } = req.body;
        
        const agent = await agentService.getAgent(agentId, tenantId);
        if (!agent) {
            return res.status(404).json({
                success: false,
                error: 'Agent not found'
            });
        }

        // Process the data
        const result = await dataIngestion.ingestData(tenantId, agentId, data);

        res.json(result);

    } catch (error) {
        console.error('Data ingestion error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to ingest data'
        });
    }
});

// Health check endpoint for agents
router.get('/:agentId/health', async (req, res) => {
    try {
        const { agentId } = req.params;
        
        res.json({
            success: true,
            agentId: agentId,
            status: 'healthy',
            timestamp: new Date().toISOString()
        });

    } catch (error) {
        console.error('Agent health check error:', error);
        res.status(500).json({
            success: false,
            error: 'Health check failed'
        });
    }
});

module.exports = router; 