const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../middleware/auth');
const { tenantIsolation } = require('../middleware/tenantIsolation');
const db = require('../services/databaseService');
const { v4: uuidv4 } = require('uuid');

// Create security event (IPS blocking, threat detection, etc.)
router.post('/', authenticateToken, tenantIsolation(), async (req, res) => {
  try {
    const { 
      timestamp, action_type, rule_id, source_ip, dest_ip, protocol, 
      dest_port, reason, duration, automatic, severity, impact 
    } = req.body;
    const organizationId = req.organizationId;

    // Validate required fields
    if (!action_type || !source_ip || !severity) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: ['action_type', 'source_ip', 'severity']
      });
    }

    const eventId = uuidv4();
    
    // Insert security event
    await db.query(`
      INSERT INTO security_events (
        id, organization_id, event_type, source_ip, dest_ip, protocol,
        dest_port, severity, action_taken, rule_id, reason, duration,
        automatic, impact, metadata, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
    `, [
      eventId, organizationId, action_type, source_ip, dest_ip, protocol,
      dest_port, severity, action_type, rule_id, reason, duration,
      automatic || false, JSON.stringify(impact || {}), 
      JSON.stringify(req.body), timestamp || new Date()
    ]);

    // Also create an alert for high severity events
    if (['high', 'critical'].includes(severity?.toLowerCase())) {
      const alertId = uuidv4();
      await db.query(`
        INSERT INTO security_alerts (
          id, organization_id, title, description, severity, alert_type,
          source, metadata, status, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      `, [
        alertId, organizationId,
        `Security Event: ${action_type.replace('_', ' ').toUpperCase()}`,
        reason || `${action_type} detected from ${source_ip}`,
        severity.toLowerCase(),
        'security_event',
        'ips_engine',
        JSON.stringify({ 
          event_id: eventId, 
          source_ip, 
          dest_ip, 
          rule_id,
          action_type 
        }),
        'open',
        new Date()
      ]);
    }

    // Log the security event
    await db.createAuditLog({
      organization_id: organizationId,
      user_id: req.user.id,
      action: 'security_event_created',
      resource_type: 'security_event',
      resource_id: eventId,
      details: { action_type, source_ip, severity, rule_id },
      ip_address: req.ip,
      user_agent: req.get('User-Agent')
    });

    res.status(201).json({
      event_id: eventId,
      status: 'recorded',
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('Security event creation error:', error);
    res.status(500).json({ 
      error: 'Failed to record security event',
      details: error.message 
    });
  }
});

// Get security events with filtering
router.get('/', authenticateToken, tenantIsolation(), async (req, res) => {
  try {
    const { 
      page = 1, limit = 20, severity, action_type, source_ip, 
      startDate, endDate 
    } = req.query;
    const organizationId = req.organizationId;

    let query = `
      SELECT * FROM security_events 
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

    if (action_type) {
      query += ` AND event_type = $${paramIndex}`;
      params.push(action_type);
      paramIndex++;
    }

    if (source_ip) {
      query += ` AND source_ip = $${paramIndex}`;
      params.push(source_ip);
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

    const eventsResult = await db.query(query, params);

    // Get total count for pagination
    let countQuery = `
      SELECT COUNT(*) as total FROM security_events 
      WHERE organization_id = $1
    `;
    let countParams = [organizationId];

    const countResult = await db.query(countQuery, countParams);
    const total = parseInt(countResult.rows[0].total);

    res.json({
      events: eventsResult.rows.map(formatSecurityEvent),
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        totalPages: Math.ceil(total / parseInt(limit))
      }
    });

  } catch (error) {
    console.error('Get security events error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch security events',
      details: error.message 
    });
  }
});

// Get security event by ID
router.get('/:eventId', authenticateToken, tenantIsolation(), async (req, res) => {
  try {
    const { eventId } = req.params;
    const organizationId = req.organizationId;

    const eventResult = await db.query(
      'SELECT * FROM security_events WHERE id = $1 AND organization_id = $2',
      [eventId, organizationId]
    );

    if (eventResult.rows.length === 0) {
      return res.status(404).json({ error: 'Security event not found' });
    }

    res.json({
      event: formatSecurityEvent(eventResult.rows[0])
    });

  } catch (error) {
    console.error('Get security event error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch security event',
      details: error.message 
    });
  }
});

// Helper function to format security event data
function formatSecurityEvent(event) {
  return {
    id: event.id,
    eventType: event.event_type,
    sourceIp: event.source_ip,
    destIp: event.dest_ip,
    protocol: event.protocol,
    destPort: event.dest_port,
    severity: event.severity,
    actionTaken: event.action_taken,
    ruleId: event.rule_id,
    reason: event.reason,
    duration: event.duration,
    automatic: event.automatic,
    impact: typeof event.impact === 'string' ? JSON.parse(event.impact) : event.impact,
    metadata: typeof event.metadata === 'string' ? JSON.parse(event.metadata) : event.metadata,
    createdAt: event.created_at
  };
}

module.exports = router; 