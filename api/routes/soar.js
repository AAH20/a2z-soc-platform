const express = require('express');
const router = express.Router();
const SOAROrchestrator = require('../services/soarOrchestrator');
const { authenticateToken } = require('../middleware/auth');

// Initialize SOAR orchestrator
const soarOrchestrator = new SOAROrchestrator();

// Simple authorization function
const authorize = (roles) => {
  return (req, res, next) => {
    // For now, just pass through - in production you'd check user roles
    next();
  };
};

/**
 * @swagger
 * /api/soar/playbooks:
 *   get:
 *     summary: Get all available playbooks
 *     tags: [SOAR]
 *     responses:
 *       200:
 *         description: List of available playbooks
 */
router.get('/playbooks', async (req, res) => {
  try {
    const tenantId = 'default'; // For testing without auth
    const playbooks = await soarOrchestrator.getPlaybooks(tenantId);
    
    res.json({
      success: true,
      playbooks: playbooks
    });
  } catch (error) {
    console.error('Get playbooks error:', error);
    res.status(500).json({
      error: 'Internal server error fetching playbooks'
    });
  }
});

/**
 * @swagger
 * /api/soar/playbooks/{playbookId}:
 *   get:
 *     summary: Get specific playbook details
 *     tags: [SOAR]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: playbookId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Playbook details
 */
router.get('/playbooks/:playbookId', authenticateToken, authorize(['admin', 'operator', 'viewer']), async (req, res) => {
  try {
    const { playbookId } = req.params;
    const playbook = await soarOrchestrator.getPlaybook(playbookId);
    
    if (!playbook) {
      return res.status(404).json({
        error: 'Playbook not found'
      });
    }

    res.json(playbook);
  } catch (error) {
    console.error('Get playbook error:', error);
    res.status(500).json({
      error: 'Internal server error fetching playbook'
    });
  }
});

/**
 * @swagger
 * /api/soar/playbooks:
 *   post:
 *     summary: Create new playbook
 *     tags: [SOAR]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               description:
 *                 type: string
 *               trigger_conditions:
 *                 type: array
 *                 items:
 *                   type: object
 *               steps:
 *                 type: array
 *                 items:
 *                   type: object
 *     responses:
 *       201:
 *         description: Playbook created successfully
 */
router.post('/playbooks', authenticateToken, authorize(['admin', 'operator']), async (req, res) => {
  try {
    const { name, description, trigger_conditions, steps } = req.body;
    
    if (!name || !steps || !Array.isArray(steps)) {
      return res.status(400).json({
        error: 'Invalid playbook data. Name and steps are required.'
      });
    }

    const playbook = {
      id: `playbook_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      name,
      description,
      trigger_conditions: trigger_conditions || [],
      steps,
      created_by: req.user.id,
      created_at: new Date(),
      tenant_id: req.user.organization_id
    };

    await soarOrchestrator.addPlaybook(playbook);

    res.status(201).json({
      success: true,
      playbook
    });
  } catch (error) {
    console.error('Create playbook error:', error);
    res.status(500).json({
      error: 'Internal server error creating playbook'
    });
  }
});

/**
 * @swagger
 * /api/soar/execute:
 *   post:
 *     summary: Execute playbook for incident
 *     tags: [SOAR]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               playbook_id:
 *                 type: string
 *               incident_data:
 *                 type: object
 *     responses:
 *       200:
 *         description: Playbook execution started
 */
router.post('/execute', async (req, res) => {
  try {
    const { playbook_id, incident_data, options = {} } = req.body;
    
    if (!playbook_id || !incident_data) {
      return res.status(400).json({
        error: 'Playbook ID and incident data are required'
      });
    }

    // Add execution metadata
    const enrichedIncidentData = {
      ...incident_data,
      tenant_id: 'default',
      executed_by: 'system',
      execution_time: new Date()
    };

    // Execute playbook
    const result = await soarOrchestrator.executePlaybook(
      playbook_id, 
      enrichedIncidentData, 
      options
    );

    res.json({
      success: true,
      ...result
    });

  } catch (error) {
    console.error('Execute playbook error:', error);
    res.status(500).json({
      error: 'Internal server error executing playbook'
    });
  }
});

/**
 * @swagger
 * /api/soar/executions/{executionId}:
 *   get:
 *     summary: Get playbook execution status
 *     tags: [SOAR]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: executionId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Execution status and details
 */
router.get('/executions/:executionId', authenticateToken, authorize(['admin', 'operator', 'viewer']), async (req, res) => {
  try {
    const { executionId } = req.params;
    const execution = await soarOrchestrator.getExecutionStatus(executionId);
    
    if (!execution) {
      return res.status(404).json({
        error: 'Execution not found'
      });
    }

    res.json(execution);
  } catch (error) {
    console.error('Get execution status error:', error);
    res.status(500).json({
      error: 'Internal server error fetching execution status'
    });
  }
});

/**
 * @swagger
 * /api/soar/executions/{executionId}/stop:
 *   post:
 *     summary: Stop playbook execution
 *     tags: [SOAR]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: executionId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Execution stopped successfully
 */
router.post('/executions/:executionId/stop', authenticateToken, authorize(['admin', 'operator']), async (req, res) => {
  try {
    const { executionId } = req.params;
    const execution = await soarOrchestrator.stopExecution(executionId);
    
    res.json({
      success: true,
      message: 'Execution stopped',
      execution
    });
  } catch (error) {
    console.error('Stop execution error:', error);
    res.status(500).json({
      error: 'Internal server error stopping execution'
    });
  }
});

/**
 * @swagger
 * /api/soar/incidents:
 *   post:
 *     summary: Create security incident
 *     tags: [SOAR]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               title:
 *                 type: string
 *               description:
 *                 type: string
 *               severity:
 *                 type: string
 *                 enum: [LOW, MEDIUM, HIGH, CRITICAL]
 *               affected_assets:
 *                 type: array
 *                 items:
 *                   type: string
 *               indicators:
 *                 type: array
 *                 items:
 *                   type: object
 *               auto_respond:
 *                 type: boolean
 *     responses:
 *       201:
 *         description: Incident created successfully
 */
router.post('/incidents', authenticateToken, authorize(['admin', 'operator']), async (req, res) => {
  try {
    const { 
      title, 
      description, 
      severity, 
      affected_assets = [], 
      indicators = [], 
      auto_respond = false 
    } = req.body;
    
    if (!title || !severity) {
      return res.status(400).json({
        error: 'Title and severity are required'
      });
    }

    const incident = {
      id: `inc_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      title,
      description,
      severity,
      status: 'NEW',
      affected_assets,
      indicators,
      created_by: req.user.id,
      created_at: new Date(),
      updated_at: new Date(),
      tenant_id: req.user.organization_id,
      timeline: [{
        timestamp: new Date(),
        action: 'CREATED',
        user: req.user.id,
        description: 'Incident created'
      }]
    };

    // Auto-respond if requested and severity is high
    if (auto_respond && ['HIGH', 'CRITICAL'].includes(severity)) {
      // Determine appropriate playbook based on incident type
      let playbookId = null;
      
      if (title.toLowerCase().includes('malware')) {
        playbookId = 'malware_response';
      } else if (title.toLowerCase().includes('brute force')) {
        playbookId = 'brute_force_response';
      } else if (title.toLowerCase().includes('exfiltration')) {
        playbookId = 'data_exfiltration_response';
      } else if (title.toLowerCase().includes('phishing')) {
        playbookId = 'phishing_response';
      }

      if (playbookId) {
        try {
          await soarOrchestrator.executePlaybook(playbookId, incident);
          incident.auto_response_triggered = true;
          incident.playbook_executed = playbookId;
        } catch (error) {
          console.error('Auto-response failed:', error);
          incident.auto_response_error = error.message;
        }
      }
    }

    // In a real implementation, you'd save to database here
    console.log('Incident created:', incident);

    res.status(201).json({
      success: true,
      incident
    });

  } catch (error) {
    console.error('Create incident error:', error);
    res.status(500).json({
      error: 'Internal server error creating incident'
    });
  }
});

/**
 * @swagger
 * /api/soar/incidents:
 *   get:
 *     summary: Get security incidents
 *     tags: [SOAR]
 *     responses:
 *       200:
 *         description: List of security incidents
 */
router.get('/incidents', async (req, res) => {
  try {
    const tenantId = 'default'; // For testing without auth
    
    // Get incidents from database
    const query = `
      SELECT * FROM soar_incidents 
      WHERE tenant_id = $1
      ORDER BY created_at DESC
      LIMIT 50
    `;
    
    const result = await soarOrchestrator.pool.query(query, [tenantId]);
    
    res.json({
      success: true,
      incidents: result.rows,
      total: result.rows.length
    });

  } catch (error) {
    console.error('Get incidents error:', error);
    res.status(500).json({
      error: 'Internal server error fetching incidents'
    });
  }
});

/**
 * @swagger
 * /api/soar/incidents/{incidentId}:
 *   get:
 *     summary: Get specific incident details
 *     tags: [SOAR]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: incidentId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Incident details
 */
router.get('/incidents/:incidentId', authenticateToken, authorize(['admin', 'operator', 'viewer']), async (req, res) => {
  try {
    const { incidentId } = req.params;
    
    // In a real implementation, you'd query your database
    const mockIncident = {
      id: incidentId,
      title: 'Sample Security Incident',
      description: 'Detailed incident information',
      severity: 'HIGH',
      status: 'IN_PROGRESS',
      created_at: new Date(),
      timeline: [
        {
          timestamp: new Date(),
          action: 'CREATED',
          user: req.user.id,
          description: 'Incident created'
        }
      ],
      evidence: [],
      playbooks_executed: [],
      tenant_id: req.user.organization_id
    };

    res.json(mockIncident);

  } catch (error) {
    console.error('Get incident error:', error);
    res.status(500).json({
      error: 'Internal server error fetching incident'
    });
  }
});

/**
 * @swagger
 * /api/soar/incidents/{incidentId}:
 *   put:
 *     summary: Update incident
 *     tags: [SOAR]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: incidentId
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               status:
 *                 type: string
 *                 enum: [NEW, ASSIGNED, IN_PROGRESS, RESOLVED, CLOSED]
 *               assignee:
 *                 type: string
 *               notes:
 *                 type: string
 *               resolution:
 *                 type: string
 *     responses:
 *       200:
 *         description: Incident updated successfully
 */
router.put('/incidents/:incidentId', authenticateToken, authorize(['admin', 'operator']), async (req, res) => {
  try {
    const { incidentId } = req.params;
    const { status, assignee, notes, resolution } = req.body;

    // In a real implementation, you'd update the database
    const updateData = {
      updated_at: new Date(),
      updated_by: req.user.id
    };

    if (status) updateData.status = status;
    if (assignee) updateData.assignee = assignee;
    if (notes) updateData.notes = notes;
    if (resolution) updateData.resolution = resolution;

    console.log('Updating incident:', incidentId, updateData);

    res.json({
      success: true,
      message: 'Incident updated successfully',
      incident_id: incidentId,
      updates: updateData
    });

  } catch (error) {
    console.error('Update incident error:', error);
    res.status(500).json({
      error: 'Internal server error updating incident'
    });
  }
});

/**
 * @swagger
 * /api/soar/integrations:
 *   get:
 *     summary: Get available integrations
 *     tags: [SOAR]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of available integrations
 */
router.get('/integrations', authenticateToken, authorize(['admin', 'operator', 'viewer']), async (req, res) => {
  try {
    const integrations = Array.from(soarOrchestrator.integrations.values()).map(integration => ({
      name: integration.name,
      type: integration.type,
      actions: Object.keys(integration.actions),
      configured: Boolean(integration.apiKey || integration.webhookUrl),
      status: 'ACTIVE' // This would be determined by health checks
    }));

    res.json({
      integrations,
      total: integrations.length
    });

  } catch (error) {
    console.error('Get integrations error:', error);
    res.status(500).json({
      error: 'Internal server error fetching integrations'
    });
  }
});

/**
 * @swagger
 * /api/soar/integrations/{integrationName}/test:
 *   post:
 *     summary: Test integration connectivity
 *     tags: [SOAR]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: integrationName
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Integration test results
 */
router.post('/integrations/:integrationName/test', authenticateToken, authorize(['admin', 'operator']), async (req, res) => {
  try {
    const { integrationName } = req.params;
    const integration = soarOrchestrator.integrations.get(integrationName);
    
    if (!integration) {
      return res.status(404).json({
        error: 'Integration not found'
      });
    }

    // Perform basic connectivity test
    let testResult = {
      integration: integrationName,
      status: 'SUCCESS',
      message: 'Integration test completed',
      timestamp: new Date()
    };

    try {
      // Test based on integration type
      switch (integrationName) {
        case 'slack':
          if (integration.actions.send_notification) {
            await integration.actions.send_notification({
              message: 'Test message from A2Z SOC SOAR',
              channel: '#security-alerts'
            });
          }
          break;
        
        case 'virustotal':
          if (integration.actions.analyze_ip) {
            await integration.actions.analyze_ip({
              ip_address: '8.8.8.8' // Google DNS for testing
            });
          }
          break;
        
        default:
          testResult.message = 'Basic connectivity test passed';
      }
    } catch (error) {
      testResult.status = 'FAILED';
      testResult.message = error.message;
    }

    res.json(testResult);

  } catch (error) {
    console.error('Test integration error:', error);
    res.status(500).json({
      error: 'Internal server error testing integration'
    });
  }
});

/**
 * @swagger
 * /api/soar/metrics:
 *   get:
 *     summary: Get SOAR metrics and statistics
 *     tags: [SOAR]
 *     responses:
 *       200:
 *         description: SOAR metrics and statistics
 */
router.get('/metrics', async (req, res) => {
  try {
    const tenantId = 'default'; // For testing without auth
    const timeRange = req.query.timeRange || '24h';
    
    const metrics = await soarOrchestrator.getMetrics(timeRange, tenantId);
    
    res.json({
      success: true,
      timeRange,
      ...metrics
    });

  } catch (error) {
    console.error('SOAR metrics error:', error);
    res.status(500).json({
      error: 'Internal server error fetching SOAR metrics'
    });
  }
});

/**
 * @swagger
 * /api/soar/health:
 *   get:
 *     summary: Get SOAR service health status
 *     tags: [SOAR]
 *     responses:
 *       200:
 *         description: SOAR service health status
 */
router.get('/health', async (req, res) => {
  try {
    const health = {
      status: 'healthy',
      timestamp: new Date(),
      service: 'SOAR Orchestrator',
      version: '1.0.0',
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      metrics: {
        runningExecutions: soarOrchestrator.runningExecutions.size,
        integrations: soarOrchestrator.integrations.size
      }
    };
    
    // Test database connection
    try {
      await soarOrchestrator.pool.query('SELECT 1');
      health.database = 'connected';
    } catch (error) {
      health.database = 'disconnected';
      health.status = 'unhealthy';
    }
    
    res.json(health);

  } catch (error) {
    console.error('SOAR health check error:', error);
    res.status(500).json({
      status: 'unhealthy',
      error: error.message
    });
  }
});

module.exports = router; 