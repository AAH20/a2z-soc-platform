const express = require('express');
const WebSocket = require('ws');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
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
        const { name, type, location, capabilities, version, platform } = req.body;
        const organizationId = req.organizationId;

        // Validate required fields
        if (!name || !type) {
            return res.status(400).json({
                error: 'Missing required fields',
                required: ['name', 'type']
            });
        }

        const agentId = uuidv4();
        
        // Insert new agent
        await db.query(`
            INSERT INTO agents (
                id, organization_id, name, type, location, capabilities, version,
                platform, status, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        `, [
            agentId, organizationId, name, type, location,
            JSON.stringify(capabilities || []), version, platform,
            'registered', new Date(), new Date()
        ]);

        // Get the created agent
        const agentResult = await db.query(
            'SELECT * FROM agents WHERE id = $1',
            [agentId]
        );

        // Log agent registration
        await db.createAuditLog({
            organization_id: organizationId,
            user_id: req.user.id,
            action: 'agent_registered',
            resource_type: 'agent',
            resource_id: agentId,
            details: { name, type, platform, version },
            ip_address: req.ip,
            user_agent: req.get('User-Agent')
        });

        res.status(201).json({
            agent: {
                id: agentId,
                name: name,
                type: type,
                location: location,
                status: 'registered',
                capabilities: capabilities,
                version: version,
                platform: platform
            }
        });

    } catch (error) {
        console.error('Agent registration error:', error);
        res.status(500).json({ 
            error: 'Failed to register agent',
            details: error.message 
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
            error: 'Failed to send command'
        });
    }
});

// Agent data ingestion endpoints
router.post('/ingest/events', async (req, res) => {
    try {
        const authHeader = req.headers['x-agent-auth'];
        if (!authHeader) {
            return res.status(401).json({ error: 'Missing agent authentication' });
        }

        // Validate agent authentication
        const agent = await agentService.validateAgentAuth(authHeader);
        if (!agent) {
            return res.status(401).json({ error: 'Invalid agent authentication' });
        }

        const { events, compressed } = req.body;
        
        // Process events
        const result = await dataIngestion.processEvents(agent.tenantId, agent.id, events, compressed);

        res.json({
            success: true,
            processed: result.processed,
            stored: result.stored,
            errors: result.errors
        });

    } catch (error) {
        console.error('Event ingestion error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to process events'
        });
    }
});

router.post('/ingest/alerts', async (req, res) => {
    try {
        const authHeader = req.headers['x-agent-auth'];
        if (!authHeader) {
            return res.status(401).json({ error: 'Missing agent authentication' });
        }

        // Validate agent authentication
        const agent = await agentService.validateAgentAuth(authHeader);
        if (!agent) {
            return res.status(401).json({ error: 'Invalid agent authentication' });
        }

        const { alerts } = req.body;
        
        // Process alerts (immediate processing for security alerts)
        const result = await alertProcessing.processAlerts(agent.tenantId, agent.id, alerts);

        res.json({
            success: true,
            processed: result.processed,
            triggered: result.triggered,
            escalated: result.escalated
        });

    } catch (error) {
        console.error('Alert ingestion error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to process alerts'
        });
    }
});

// Agent heartbeat endpoint
router.post('/:agentId/heartbeat', authenticateToken, tenantIsolation(), async (req, res) => {
  try {
    const { agentId } = req.params;
    const { timestamp, status, metrics } = req.body;
    const organizationId = req.organizationId;

    // Validate agent exists and belongs to organization
    const agentResult = await db.query(
      'SELECT * FROM agents WHERE id = $1 AND organization_id = $2',
      [agentId, organizationId]
    );

    if (agentResult.rows.length === 0) {
      return res.status(404).json({ error: 'Agent not found' });
    }

    // Update agent last seen and metrics
    await db.query(
      `UPDATE agents 
       SET last_seen = $1, status = $2, metrics = $3, updated_at = CURRENT_TIMESTAMP 
       WHERE id = $4 AND organization_id = $5`,
      [timestamp || new Date().toISOString(), status, JSON.stringify(metrics || {}), agentId, organizationId]
    );

    // Log heartbeat event
    await db.createAuditLog({
      organization_id: organizationId,
      user_id: req.user.id,
      action: 'agent_heartbeat',
      resource_type: 'agent',
      resource_id: agentId,
      details: { status, metrics },
      ip_address: req.ip,
      user_agent: req.get('User-Agent')
    });

    res.json({
      status: 'acknowledged',
      timestamp: new Date().toISOString(),
      agentId: agentId
    });

  } catch (error) {
    console.error('Agent heartbeat error:', error);
    res.status(500).json({ 
      error: 'Failed to process agent heartbeat',
      details: error.message 
    });
  }
});

// Note: WebSocket functionality temporarily disabled due to dependency issues
// Future implementation will include real-time agent communication

// Agent download endpoints
router.get('/download/:platform/:agentId', authenticateToken, tenantIsolation(), async (req, res) => {
    try {
        const { platform, agentId } = req.params;
        const tenantId = req.user.tenantId;
        
        // Validate agent belongs to tenant
        const agent = await agentService.getAgent(agentId, tenantId);
        if (!agent) {
            return res.status(404).json({
                success: false,
                error: 'Agent not found'
            });
        }

        // Generate platform-specific agent binary
        const binaryPath = await agentService.generateAgentBinary(agentId, platform);
        
        res.download(binaryPath, `a2z-agent-${platform}-${agentId}.${platform === 'windows' ? 'exe' : 'bin'}`);

    } catch (error) {
        console.error('Agent download error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to download agent'
        });
    }
});

// Agent installation script
router.get('/install/:agentId', authenticateToken, tenantIsolation(), async (req, res) => {
    try {
        const { agentId } = req.params;
        const tenantId = req.user.tenantId;
        
        // Validate agent belongs to tenant
        const agent = await agentService.getAgent(agentId, tenantId);
        if (!agent) {
            return res.status(404).json({
                success: false,
                error: 'Agent not found'
            });
        }

        // Generate installation script
        const script = await agentService.generateInstallScript(agentId);
        
        res.type('text/plain');
        res.send(script);

    } catch (error) {
        console.error('Install script error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to generate install script'
        });
    }
});

// Delete agent
router.delete('/:agentId', authenticateToken, tenantIsolation(), async (req, res) => {
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

        // Send shutdown command if agent is connected
        if (agent.status === 'connected') {
            await agentService.sendCommand(agentId, 'shutdown', {});
        }

        // Delete agent
        await agentService.deleteAgent(agentId);

        res.json({
            success: true,
            message: 'Agent deleted successfully'
        });

    } catch (error) {
        console.error('Delete agent error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to delete agent'
        });
    }
});

// Download MacOS Agent DMG
router.get('/download/macos', (req, res) => {
    const dmgPath = path.join(__dirname, '../../public/downloads/A2Z-SOC-Network-Agent-1.2.3.dmg');
    
    // Check if file exists
    if (!fs.existsSync(dmgPath)) {
        return res.status(404).json({ 
            error: 'MacOS agent DMG not found',
            message: 'The MacOS agent installer is currently unavailable. Please try again later.'
        });
    }
    
    // Set proper headers for DMG download
    res.setHeader('Content-Type', 'application/x-apple-diskimage');
    res.setHeader('Content-Disposition', 'attachment; filename="A2Z-SOC-Network-Agent-1.2.3.dmg"');
    res.setHeader('Cache-Control', 'no-cache');
    
    // Stream the file
    const fileStream = fs.createReadStream(dmgPath);
    fileStream.pipe(res);
    
    fileStream.on('error', (error) => {
        console.error('Error streaming DMG file:', error);
        if (!res.headersSent) {
            res.status(500).json({ 
                error: 'Download failed',
                message: 'An error occurred while downloading the MacOS agent.'
            });
        }
    });
});

// Get agent info
router.get('/info/macos', (req, res) => {
    res.json({
        name: 'A2Z SOC Network Agent for macOS',
        version: '1.2.3',
        platform: 'darwin',
        fileSize: '2.4MB',
        features: [
            'Real-time log collection from macOS Unified Logging',
            'Network monitoring and statistics',
            'Security threat detection with pattern matching',
            'HTTP API server on port 5200',
            'LaunchDaemon service integration',
            'Command-line interface for management'
        ],
        installation: [
            'Download and open the DMG file',
            'Double-click "Install A2Z SOC Agent.command"',
            'Enter administrator password when prompted',
            'Agent starts automatically'
        ],
        apiEndpoint: 'http://localhost:5200/status',
        documentation: 'https://docs.a2zsoc.com/agents/macos'
    });
});

// Agent data ingestion endpoint
router.post('/:agentId/ingest', authenticateToken, tenantIsolation(), async (req, res) => {
  try {
    const { agentId } = req.params;
    const { timestamp, events } = req.body;
    const organizationId = req.organizationId;

    // Validate agent exists and belongs to organization
    const agentResult = await db.query(
      'SELECT * FROM agents WHERE id = $1 AND organization_id = $2',
      [agentId, organizationId]
    );

    if (agentResult.rows.length === 0) {
      return res.status(404).json({ error: 'Agent not found' });
    }

    // Process events
    let eventsProcessed = 0;
    
    if (events && Array.isArray(events)) {
      for (const event of events) {
        // Store event in database (simplified for demo)
        await db.query(`
          INSERT INTO network_events (
            id, organization_id, agent_id, event_type, source_ip, dest_ip,
            protocol, bytes_transferred, timestamp, metadata
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        `, [
          uuidv4(), organizationId, agentId, event.type, event.source_ip,
          event.dest_ip, event.protocol, event.bytes_transferred || 0,
          timestamp || new Date(), JSON.stringify(event)
        ]);
        eventsProcessed++;
      }
    }

    // Update agent metrics
    await db.query(
      `UPDATE agents 
       SET last_data_received = $1, events_processed = COALESCE(events_processed, 0) + $2
       WHERE id = $3 AND organization_id = $4`,
      [new Date(), eventsProcessed, agentId, organizationId]
    );

    res.json({
      status: 'success',
      events_processed: eventsProcessed,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Agent data ingestion error:', error);
    res.status(500).json({ 
      error: 'Failed to process agent data',
      details: error.message 
    });
  }
});

module.exports = router; 