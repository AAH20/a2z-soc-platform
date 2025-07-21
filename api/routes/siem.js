const express = require('express');
const router = express.Router();
const SIEMIngestionService = require('../services/siemIngestionService');
const { authenticateToken } = require('../middleware/auth');

// Initialize SIEM service
const siemService = new SIEMIngestionService();
siemService.start();

// Simple authorization function
const authorize = (roles) => {
  return (req, res, next) => {
    // For now, just pass through - in production you'd check user roles
    next();
  };
};

/**
 * @swagger
 * /api/siem/ingest:
 *   post:
 *     summary: Ingest security events into SIEM
 *     tags: [SIEM]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               events:
 *                 type: array
 *                 items:
 *                   type: object
 *                   properties:
 *                     source_type:
 *                       type: string
 *                       example: syslog
 *                     source_ip:
 *                       type: string
 *                       example: 192.168.1.100
 *                     destination_ip:
 *                       type: string
 *                       example: 192.168.1.1
 *                     message:
 *                       type: string
 *                       example: Failed login attempt
 *                     severity:
 *                       type: string
 *                       enum: [LOW, MEDIUM, HIGH, CRITICAL]
 *                     timestamp:
 *                       type: string
 *                       format: date-time
 *     responses:
 *       200:
 *         description: Events ingested successfully
 */
router.post('/ingest', authenticateToken, authorize(['admin', 'operator']), async (req, res) => {
  try {
    const { events } = req.body;
    const tenantId = req.user?.organization_id || 'default';
    
    if (!events || !Array.isArray(events)) {
      return res.status(400).json({
        error: 'Events array is required'
      });
    }

    const results = [];
    
    for (const event of events) {
      const result = await siemService.ingestEvent(event, tenantId);
      results.push(result);
    }

    const successCount = results.filter(r => r.success).length;
    const failureCount = results.length - successCount;

    res.json({
      success: true,
      ingested: successCount,
      failed: failureCount,
      results: results
    });

  } catch (error) {
    console.error('SIEM ingestion error:', error);
    res.status(500).json({
      error: 'Internal server error during event ingestion'
    });
  }
});

/**
 * @swagger
 * /api/siem/search:
 *   post:
 *     summary: Search SIEM events
 *     tags: [SIEM]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               query:
 *                 type: string
 *                 example: source_ip:192.168.1.100
 *               filters:
 *                 type: object
 *                 properties:
 *                   time_range:
 *                     type: object
 *                     properties:
 *                       start:
 *                         type: string
 *                         format: date-time
 *                       end:
 *                         type: string
 *                         format: date-time
 *                   source_type:
 *                     type: array
 *                     items:
 *                       type: string
 *                   severity:
 *                     type: array
 *                     items:
 *                       type: string
 *               size:
 *                 type: integer
 *                 default: 100
 *     responses:
 *       200:
 *         description: Search results
 */
router.post('/search', authenticateToken, authorize(['admin', 'operator', 'viewer']), async (req, res) => {
  try {
    const tenantId = req.user?.organization_id || 'default';
    const searchParams = req.body;
    
    const results = await siemService.searchEvents(searchParams, tenantId);
    
    res.json({
      success: true,
      ...results
    });

  } catch (error) {
    console.error('SIEM search error:', error);
    res.status(500).json({
      error: 'Internal server error during search'
    });
  }
});

/**
 * @swagger
 * /api/siem/alerts:
 *   get:
 *     summary: Get security alerts
 *     tags: [SIEM]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [OPEN, IN_PROGRESS, RESOLVED, CLOSED]
 *       - in: query
 *         name: severity
 *         schema:
 *           type: string
 *           enum: [LOW, MEDIUM, HIGH, CRITICAL]
 *       - in: query
 *         name: assignee
 *         schema:
 *           type: string
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 50
 *     responses:
 *       200:
 *         description: List of security alerts
 */
router.get('/alerts', authenticateToken, authorize(['admin', 'operator', 'viewer']), async (req, res) => {
  try {
    const tenantId = req.user?.organization_id || 'default';
    const filters = {
      status: req.query.status,
      severity: req.query.severity,
      assignee: req.query.assignee,
      limit: parseInt(req.query.limit) || 50
    };
    
    const results = await siemService.getAlerts(filters, tenantId);
    
    res.json({
      success: true,
      ...results
    });

  } catch (error) {
    console.error('SIEM alerts error:', error);
    res.status(500).json({
      error: 'Internal server error fetching alerts'
    });
  }
});

/**
 * @swagger
 * /api/siem/alerts/{alertId}:
 *   get:
 *     summary: Get specific alert details
 *     tags: [SIEM]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: alertId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Alert details
 */
router.get('/alerts/:alertId', authenticateToken, authorize(['admin', 'operator', 'viewer']), async (req, res) => {
  try {
    const { alertId } = req.params;
    const tenantId = req.user?.organization_id || 'default';
    
    // Get alert details from database
    const query = `
      SELECT * FROM siem_alerts 
      WHERE alert_id = $1 AND tenant_id = $2
    `;
    
    const result = await siemService.pool.query(query, [alertId, tenantId]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({
        error: 'Alert not found'
      });
    }
    
    res.json({
      success: true,
      alert: result.rows[0]
    });

  } catch (error) {
    console.error('SIEM alert details error:', error);
    res.status(500).json({
      error: 'Internal server error fetching alert details'
    });
  }
});

/**
 * @swagger
 * /api/siem/alerts/{alertId}:
 *   put:
 *     summary: Update alert status
 *     tags: [SIEM]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: alertId
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
 *                 enum: [OPEN, IN_PROGRESS, RESOLVED, CLOSED]
 *               assigned_to:
 *                 type: string
 *               resolution_notes:
 *                 type: string
 *     responses:
 *       200:
 *         description: Alert updated successfully
 */
router.put('/alerts/:alertId', authenticateToken, authorize(['admin', 'operator']), async (req, res) => {
  try {
    const { alertId } = req.params;
    const { status, assigned_to, resolution_notes } = req.body;
    const tenantId = req.user?.organization_id || 'default';
    
    // Build update query dynamically
    const updates = [];
    const values = [];
    let paramIndex = 1;
    
    if (status) {
      updates.push(`status = $${paramIndex}`);
      values.push(status);
      paramIndex++;
    }
    
    if (assigned_to) {
      updates.push(`assigned_to = $${paramIndex}`);
      values.push(assigned_to);
      paramIndex++;
    }
    
    if (resolution_notes) {
      updates.push(`resolution_notes = $${paramIndex}`);
      values.push(resolution_notes);
      paramIndex++;
    }
    
    if (status === 'RESOLVED' || status === 'CLOSED') {
      updates.push(`resolved_at = CURRENT_TIMESTAMP`);
    }
    
    updates.push(`updated_at = CURRENT_TIMESTAMP`);
    
    // Add WHERE clause parameters
    values.push(alertId, tenantId);
    
    const query = `
      UPDATE siem_alerts 
      SET ${updates.join(', ')}
      WHERE alert_id = $${paramIndex} AND tenant_id = $${paramIndex + 1}
      RETURNING *
    `;
    
    const result = await siemService.pool.query(query, values);
    
    if (result.rows.length === 0) {
      return res.status(404).json({
        error: 'Alert not found'
      });
    }
    
    res.json({
      success: true,
      message: 'Alert updated successfully',
      alert: result.rows[0]
    });

  } catch (error) {
    console.error('SIEM alert update error:', error);
    res.status(500).json({
      error: 'Internal server error updating alert'
    });
  }
});

/**
 * @swagger
 * /api/siem/metrics:
 *   get:
 *     summary: Get SIEM metrics and statistics
 *     tags: [SIEM]
 *     responses:
 *       200:
 *         description: SIEM metrics and statistics
 */
router.get('/metrics', async (req, res) => {
  try {
    const tenantId = 'default'; // For testing without auth
    const timeRange = req.query.timeRange || '24h';
    
    const metrics = await siemService.getMetrics(timeRange, tenantId);
    
    res.json({
      success: true,
      timeRange,
      ...metrics
    });

  } catch (error) {
    console.error('SIEM metrics error:', error);
    res.status(500).json({
      error: 'Internal server error fetching metrics'
    });
  }
});

/**
 * @swagger
 * /api/siem/correlation-rules:
 *   get:
 *     summary: Get correlation rules
 *     tags: [SIEM]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of correlation rules
 */
router.get('/correlation-rules', authenticateToken, authorize(['admin', 'operator', 'viewer']), async (req, res) => {
  try {
    const tenantId = req.user?.organization_id || 'default';
    
    const query = `
      SELECT * FROM siem_correlation_rules 
      WHERE tenant_id = $1
      ORDER BY name
    `;
    
    const result = await siemService.pool.query(query, [tenantId]);
    
    res.json({
      success: true,
      rules: result.rows,
      total: result.rows.length
    });

  } catch (error) {
    console.error('SIEM correlation rules error:', error);
    res.status(500).json({
      error: 'Internal server error fetching correlation rules'
    });
  }
});

/**
 * @swagger
 * /api/siem/correlation-rules:
 *   post:
 *     summary: Create new correlation rule
 *     tags: [SIEM]
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
 *               query:
 *                 type: string
 *               conditions:
 *                 type: object
 *               severity:
 *                 type: string
 *                 enum: [LOW, MEDIUM, HIGH, CRITICAL]
 *               time_window:
 *                 type: integer
 *                 default: 300
 *               threshold:
 *                 type: integer
 *                 default: 1
 *     responses:
 *       201:
 *         description: Correlation rule created successfully
 */
router.post('/correlation-rules', authenticateToken, authorize(['admin', 'operator']), async (req, res) => {
  try {
    const { name, description, query, conditions, severity, time_window, threshold } = req.body;
    const tenantId = req.user?.organization_id || 'default';
    
    if (!name || !query || !conditions) {
      return res.status(400).json({
        error: 'Name, query, and conditions are required'
      });
    }
    
    const ruleId = `rule_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    const insertQuery = `
      INSERT INTO siem_correlation_rules (
        tenant_id, rule_id, name, description, query, conditions,
        severity, time_window, threshold, created_by, created_at, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING *
    `;
    
    const values = [
      tenantId,
      ruleId,
      name,
      description,
      query,
      conditions,
      severity || 'MEDIUM',
      time_window || 300,
      threshold || 1,
      req.user.id,
      new Date(),
      new Date()
    ];
    
    const result = await siemService.pool.query(insertQuery, values);
    
    // Reload correlation rules in the engine
    await siemService.loadCorrelationRules();
    
    res.status(201).json({
      success: true,
      message: 'Correlation rule created successfully',
      rule: result.rows[0]
    });

  } catch (error) {
    console.error('SIEM correlation rule creation error:', error);
    res.status(500).json({
      error: 'Internal server error creating correlation rule'
    });
  }
});

/**
 * @swagger
 * /api/siem/health:
 *   get:
 *     summary: Get SIEM service health status
 *     tags: [SIEM]
 *     responses:
 *       200:
 *         description: SIEM service health status
 */
router.get('/health', async (req, res) => {
  try {
    const health = {
      status: 'healthy',
      timestamp: new Date(),
      service: 'SIEM Ingestion Service',
      version: '1.0.0',
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      metrics: {
        isRunning: siemService.isRunning,
        eventsPerSecond: siemService.eventsPerSecond,
        totalEvents: siemService.totalEvents,
        bufferSize: siemService.eventBuffer.length
      }
    };
    
    // Test database connection
    try {
      await siemService.pool.query('SELECT 1');
      health.database = 'connected';
    } catch (error) {
      health.database = 'disconnected';
      health.status = 'unhealthy';
    }
    
    res.json(health);

  } catch (error) {
    console.error('SIEM health check error:', error);
    res.status(500).json({
      status: 'unhealthy',
      error: error.message
    });
  }
});

// Real-time event streaming endpoint
router.get('/events/stream', authenticateToken, authorize(['admin', 'operator', 'viewer']), (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Cache-Control'
  });

  const tenantId = req.user?.organization_id || 'default';

  // Send initial connection message
  res.write(`data: ${JSON.stringify({ type: 'connected', timestamp: new Date() })}\n\n`);

  // Listen for new events
  const eventHandler = (event) => {
    if (event.tenant_id === tenantId) {
      res.write(`data: ${JSON.stringify({ type: 'event', data: event })}\n\n`);
    }
  };

  const alertHandler = (alert) => {
    if (alert.tenant_id === tenantId) {
      res.write(`data: ${JSON.stringify({ type: 'alert', data: alert })}\n\n`);
    }
  };

  siemService.on('event', eventHandler);
  siemService.on('alert', alertHandler);

  // Clean up on client disconnect
  req.on('close', () => {
    siemService.removeListener('event', eventHandler);
    siemService.removeListener('alert', alertHandler);
  });

  // Send keepalive every 30 seconds
  const keepAlive = setInterval(() => {
    res.write(`data: ${JSON.stringify({ type: 'keepalive', timestamp: new Date() })}\n\n`);
  }, 30000);

  req.on('close', () => {
    clearInterval(keepAlive);
  });
});

module.exports = router; 