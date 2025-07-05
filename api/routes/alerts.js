const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../middleware/auth');
const { tenantIsolation } = require('../middleware/tenantIsolation');
const db = require('../services/databaseService');
const { v4: uuidv4 } = require('uuid');

// Get alerts with filtering and pagination
router.get('/', authenticateToken, tenantIsolation(), async (req, res) => {
  try {
    const { page = 1, limit = 20, severity, status, type, startDate, endDate } = req.query;
    const organizationId = req.organizationId;

    let query = `
      SELECT * FROM security_alerts 
      WHERE organization_id = $1
    `;
    let params = [organizationId];
    let paramIndex = 2;

    // Add filters
    if (severity) {
      query += ` AND severity = $${paramIndex}`;
      params.push(severity);
      paramIndex++;
    }

    if (status) {
      query += ` AND status = $${paramIndex}`;
      params.push(status);
      paramIndex++;
    }

    if (type) {
      query += ` AND alert_type = $${paramIndex}`;
      params.push(type);
      paramIndex++;
    }

    if (startDate) {
      query += ` AND created_at >= $${paramIndex}`;
      params.push(startDate);
      paramIndex++;
    }

    if (endDate) {
      query += ` AND created_at <= $${paramIndex}`;
      params.push(endDate);
      paramIndex++;
    }

    query += ` ORDER BY created_at DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
    params.push(parseInt(limit), (parseInt(page) - 1) * parseInt(limit));

    const alertsResult = await db.query(query, params);

    // Get total count for pagination
    let countQuery = `
      SELECT COUNT(*) as total FROM security_alerts 
      WHERE organization_id = $1
    `;
    let countParams = [organizationId];
    let countParamIndex = 2;

    if (severity) {
      countQuery += ` AND severity = $${countParamIndex}`;
      countParams.push(severity);
      countParamIndex++;
    }

    if (status) {
      countQuery += ` AND status = $${countParamIndex}`;
      countParams.push(status);
      countParamIndex++;
    }

    if (type) {
      countQuery += ` AND alert_type = $${countParamIndex}`;
      countParams.push(type);
      countParamIndex++;
    }

    if (startDate) {
      countQuery += ` AND created_at >= $${countParamIndex}`;
      countParams.push(startDate);
      countParamIndex++;
    }

    if (endDate) {
      countQuery += ` AND created_at <= $${countParamIndex}`;
      countParams.push(endDate);
      countParamIndex++;
    }

    const countResult = await db.query(countQuery, countParams);
    const total = parseInt(countResult.rows[0].total);

    // If no alerts exist, create some sample data
    if (total === 0) {
      await generateSampleAlerts(organizationId);
      // Re-run the query
      const newAlertsResult = await db.query(query, params);
      const newCountResult = await db.query(countQuery, countParams);
      
      return res.json({
        alerts: newAlertsResult.rows.map(formatAlert),
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: parseInt(newCountResult.rows[0].total),
          totalPages: Math.ceil(parseInt(newCountResult.rows[0].total) / parseInt(limit))
        }
      });
    }

    res.json({
      alerts: alertsResult.rows.map(formatAlert),
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        totalPages: Math.ceil(total / parseInt(limit))
      }
    });

  } catch (error) {
    console.error('Get alerts error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch alerts',
      details: error.message 
    });
  }
});

// Create new alert
router.post('/', authenticateToken, tenantIsolation(), async (req, res) => {
  try {
    const { title, description, severity, source, type, metadata } = req.body;
    const organizationId = req.organizationId;

    // Validate required fields
    if (!title || !description || !severity) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: ['title', 'description', 'severity']
      });
    }

    // Validate severity
    const validSeverities = ['low', 'medium', 'high', 'critical'];
    if (!validSeverities.includes(severity.toLowerCase())) {
      return res.status(400).json({
        error: 'Invalid severity level',
        valid: validSeverities
      });
    }

    const alertId = uuidv4();
    
    await db.query(`
      INSERT INTO security_alerts (
        id, organization_id, title, description, severity, alert_type, 
        source, metadata, status, created_by, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    `, [
      alertId, organizationId, title, description, severity.toLowerCase(),
      type || 'security_event', source || 'manual', JSON.stringify(metadata || {}),
      'open', req.user.id, new Date()
    ]);

    // Get the created alert
    const alertResult = await db.query(
      'SELECT * FROM security_alerts WHERE id = $1',
      [alertId]
    );

    // Log alert creation
    await db.createAuditLog({
      organization_id: organizationId,
      user_id: req.user.id,
      action: 'alert_created',
      resource_type: 'security_alert',
      resource_id: alertId,
      details: { title, severity, type },
      ip_address: req.ip,
      user_agent: req.get('User-Agent')
    });

    res.status(201).json({
      id: alertId,
      alert: formatAlert(alertResult.rows[0])
    });

  } catch (error) {
    console.error('Create alert error:', error);
    res.status(500).json({ 
      error: 'Failed to create alert',
      details: error.message 
    });
  }
});

// Update alert
router.put('/:alertId', authenticateToken, tenantIsolation(), async (req, res) => {
  try {
    const { alertId } = req.params;
    const { status, notes, severity, assignee } = req.body;
    const organizationId = req.organizationId;

    // Check if alert exists and belongs to organization
    const alertResult = await db.query(
      'SELECT * FROM security_alerts WHERE id = $1 AND organization_id = $2',
      [alertId, organizationId]
    );

    if (alertResult.rows.length === 0) {
      return res.status(404).json({ error: 'Alert not found' });
    }

    // Build update query dynamically
    let updateFields = [];
    let params = [];
    let paramIndex = 1;

    if (status) {
      updateFields.push(`status = $${paramIndex}`);
      params.push(status);
      paramIndex++;
    }

    if (notes) {
      updateFields.push(`notes = $${paramIndex}`);
      params.push(notes);
      paramIndex++;
    }

    if (severity) {
      updateFields.push(`severity = $${paramIndex}`);
      params.push(severity);
      paramIndex++;
    }

    if (assignee) {
      updateFields.push(`assigned_to = $${paramIndex}`);
      params.push(assignee);
      paramIndex++;
    }

    if (updateFields.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }

    updateFields.push(`updated_at = $${paramIndex}`);
    params.push(new Date());
    paramIndex++;

    updateFields.push(`updated_by = $${paramIndex}`);
    params.push(req.user.id);
    paramIndex++;

    params.push(alertId, organizationId);

    const updateQuery = `
      UPDATE security_alerts 
      SET ${updateFields.join(', ')}
      WHERE id = $${paramIndex - 1} AND organization_id = $${paramIndex}
      RETURNING *
    `;

    const updatedResult = await db.query(updateQuery, params);

    // Log alert update
    await db.createAuditLog({
      organization_id: organizationId,
      user_id: req.user.id,
      action: 'alert_updated',
      resource_type: 'security_alert',
      resource_id: alertId,
      details: { status, notes, severity, assignee },
      ip_address: req.ip,
      user_agent: req.get('User-Agent')
    });

    res.json({
      alert: formatAlert(updatedResult.rows[0])
    });

  } catch (error) {
    console.error('Update alert error:', error);
    res.status(500).json({ 
      error: 'Failed to update alert',
      details: error.message 
    });
  }
});

// Get single alert
router.get('/:alertId', authenticateToken, tenantIsolation(), async (req, res) => {
  try {
    const { alertId } = req.params;
    const organizationId = req.organizationId;

    const alertResult = await db.query(
      'SELECT * FROM security_alerts WHERE id = $1 AND organization_id = $2',
      [alertId, organizationId]
    );

    if (alertResult.rows.length === 0) {
      return res.status(404).json({ error: 'Alert not found' });
    }

    res.json({
      alert: formatAlert(alertResult.rows[0])
    });

  } catch (error) {
    console.error('Get alert error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch alert',
      details: error.message 
    });
  }
});

// Delete alert
router.delete('/:alertId', authenticateToken, tenantIsolation(), async (req, res) => {
  try {
    const { alertId } = req.params;
    const organizationId = req.organizationId;

    const result = await db.query(
      'DELETE FROM security_alerts WHERE id = $1 AND organization_id = $2 RETURNING *',
      [alertId, organizationId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Alert not found' });
    }

    // Log alert deletion
    await db.createAuditLog({
      organization_id: organizationId,
      user_id: req.user.id,
      action: 'alert_deleted',
      resource_type: 'security_alert',
      resource_id: alertId,
      details: { alert: result.rows[0] },
      ip_address: req.ip,
      user_agent: req.get('User-Agent')
    });

    res.json({
      message: 'Alert deleted successfully',
      deletedAlert: formatAlert(result.rows[0])
    });

  } catch (error) {
    console.error('Delete alert error:', error);
    res.status(500).json({ 
      error: 'Failed to delete alert',
      details: error.message 
    });
  }
});

// Helper function to format alert data
function formatAlert(alert) {
  return {
    id: alert.id,
    title: alert.title,
    description: alert.description,
    severity: alert.severity,
    status: alert.status,
    type: alert.alert_type,
    source: alert.source,
    metadata: typeof alert.metadata === 'string' ? JSON.parse(alert.metadata) : alert.metadata,
    assignedTo: alert.assigned_to,
    notes: alert.notes,
    createdAt: alert.created_at,
    updatedAt: alert.updated_at,
    createdBy: alert.created_by,
    updatedBy: alert.updated_by
  };
}

// Generate sample alerts for testing
async function generateSampleAlerts(organizationId) {
  const sampleAlerts = [
    {
      id: uuidv4(),
      title: 'Suspicious Network Activity Detected',
      description: 'Unusual outbound connections to known malicious IP addresses detected from internal network.',
      severity: 'high',
      alert_type: 'network_anomaly',
      source: 'network_monitor',
      metadata: JSON.stringify({
        source_ip: '192.168.1.100',
        dest_ip: '203.0.113.50',
        connections: 47,
        protocol: 'TCP',
        ports: [80, 443, 8080]
      }),
      status: 'open'
    },
    {
      id: uuidv4(),
      title: 'Failed Login Attempts',
      description: 'Multiple failed login attempts detected from single IP address.',
      severity: 'medium',
      alert_type: 'authentication_failure',
      source: 'auth_monitor',
      metadata: JSON.stringify({
        source_ip: '198.51.100.25',
        attempts: 15,
        timeframe: '5 minutes',
        targeted_accounts: ['admin', 'root', 'administrator']
      }),
      status: 'acknowledged'
    },
    {
      id: uuidv4(),
      title: 'Malware Signature Detected',
      description: 'Known malware signature found in network traffic.',
      severity: 'critical',
      alert_type: 'malware_detection',
      source: 'ids_engine',
      metadata: JSON.stringify({
        signature: 'Trojan.Generic.KD.32344556',
        file_hash: 'a1b2c3d4e5f6789012345678901234567890abcd',
        source_ip: '10.0.0.50',
        detection_engine: 'signature_match'
      }),
      status: 'investigating'
    }
  ];

  for (const alert of sampleAlerts) {
    await db.query(`
      INSERT INTO security_alerts (
        id, organization_id, title, description, severity, alert_type,
        source, metadata, status, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
    `, [
      alert.id, organizationId, alert.title, alert.description,
      alert.severity, alert.alert_type, alert.source, alert.metadata,
      alert.status, new Date()
    ]);
  }
}

module.exports = router; 