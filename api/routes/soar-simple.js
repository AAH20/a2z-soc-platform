const express = require('express');
const router = express.Router();
const SOAROrchestrator = require('../services/soarOrchestrator');

// Initialize SOAR orchestrator
const soarOrchestrator = new SOAROrchestrator();

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
    const tenantId = 'default';
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
    const tenantId = 'default';
    
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
    const tenantId = 'default';
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