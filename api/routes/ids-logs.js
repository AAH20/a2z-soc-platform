const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../middleware/auth');
const { tenantIsolation } = require('../middleware/tenantIsolation');
const db = require('../services/databaseService');
const { v4: uuidv4 } = require('uuid');

// Create IDS log entry (signature detection, anomaly detection)
router.post('/', authenticateToken, tenantIsolation(), async (req, res) => {
  try {
    const { 
      timestamp, detection_type, signature_id, signature_name, source_ip, 
      dest_ip, source_port, dest_port, protocol, payload, severity, 
      confidence, raw_packet, anomaly_type, description, baseline_value,
      observed_value, anomaly_score, ml_model, features
    } = req.body;
    const organizationId = req.organizationId;

    // Validate required fields
    if (!detection_type || !source_ip || !severity) {
      return res.status(400).json({
        error: 'Missing required fields',
        required: ['detection_type', 'source_ip', 'severity']
      });
    }

    const logId = uuidv4();
    
    // Insert IDS log entry
    await db.query(`
      INSERT INTO ids_logs (
        id, organization_id, detection_type, signature_id, signature_name,
        source_ip, dest_ip, source_port, dest_port, protocol, payload,
        severity, confidence, raw_packet, anomaly_type, description,
        baseline_value, observed_value, anomaly_score, ml_model, features,
        metadata, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)
    `, [
      logId, organizationId, detection_type, signature_id, signature_name,
      source_ip, dest_ip, source_port, dest_port, protocol, payload,
      severity, confidence, raw_packet, anomaly_type, description,
      baseline_value, observed_value, anomaly_score, ml_model,
      JSON.stringify(features || {}), JSON.stringify(req.body),
      timestamp || new Date()
    ]);

    // Create alert for high confidence detections
    if (confidence >= 0.8 || ['high', 'critical'].includes(severity?.toLowerCase())) {
      const alertId = uuidv4();
      const alertTitle = detection_type === 'signature_match' 
        ? `IDS Detection: ${signature_name || 'Unknown Signature'}`
        : `IDS Anomaly: ${anomaly_type || 'Traffic Anomaly'}`;
      
      const alertDescription = detection_type === 'signature_match'
        ? `Signature-based detection: ${signature_name} (ID: ${signature_id}) from ${source_ip}`
        : `Anomaly detected: ${description || 'Unusual traffic pattern detected'} from ${source_ip}`;

      await db.query(`
        INSERT INTO security_alerts (
          id, organization_id, title, description, severity, alert_type,
          source, metadata, status, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      `, [
        alertId, organizationId, alertTitle, alertDescription,
        severity.toLowerCase(), 'ids_detection', 'ids_engine',
        JSON.stringify({ 
          ids_log_id: logId, 
          detection_type, 
          source_ip, 
          dest_ip,
          confidence,
          signature_id: signature_id || null,
          anomaly_score: anomaly_score || null
        }),
        'open', new Date()
      ]);
    }

    // Log the IDS detection
    await db.createAuditLog({
      organization_id: organizationId,
      user_id: req.user.id,
      action: 'ids_detection_logged',
      resource_type: 'ids_log',
      resource_id: logId,
      details: { 
        detection_type, 
        source_ip, 
        severity, 
        signature_id: signature_id || null,
        confidence: confidence || null
      },
      ip_address: req.ip,
      user_agent: req.get('User-Agent')
    });

    res.status(201).json({
      id: logId,
      status: 'logged',
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('IDS log creation error:', error);
    res.status(500).json({ 
      error: 'Failed to log IDS detection',
      details: error.message 
    });
  }
});

// Get IDS logs with filtering
router.get('/', authenticateToken, tenantIsolation(), async (req, res) => {
  try {
    const { 
      page = 1, limit = 20, detection_type, severity, source_ip, 
      signature_id, startDate, endDate 
    } = req.query;
    const organizationId = req.organizationId;

    let query = `
      SELECT * FROM ids_logs 
      WHERE organization_id = $1
    `;
    let params = [organizationId];
    let paramIndex = 2;

    // Add filters
    if (detection_type) {
      query += ` AND detection_type = $${paramIndex}`;
      params.push(detection_type);
      paramIndex++;
    }

    if (severity) {
      query += ` AND severity = $${paramIndex}`;
      params.push(severity);
      paramIndex++;
    }

    if (source_ip) {
      query += ` AND source_ip = $${paramIndex}`;
      params.push(source_ip);
      paramIndex++;
    }

    if (signature_id) {
      query += ` AND signature_id = $${paramIndex}`;
      params.push(signature_id);
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

    const logsResult = await db.query(query, params);

    // Get total count for pagination
    let countQuery = `
      SELECT COUNT(*) as total FROM ids_logs 
      WHERE organization_id = $1
    `;
    let countParams = [organizationId];

    const countResult = await db.query(countQuery, countParams);
    const total = parseInt(countResult.rows[0].total);

    // If no logs exist, create some sample data
    if (total === 0) {
      await generateSampleIDSLogs(organizationId);
      // Re-run the query
      const newLogsResult = await db.query(query, params);
      const newCountResult = await db.query(countQuery, countParams);
      
      return res.json({
        logs: newLogsResult.rows.map(formatIDSLog),
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total: parseInt(newCountResult.rows[0].total),
          totalPages: Math.ceil(parseInt(newCountResult.rows[0].total) / parseInt(limit))
        }
      });
    }

    res.json({
      logs: logsResult.rows.map(formatIDSLog),
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        totalPages: Math.ceil(total / parseInt(limit))
      }
    });

  } catch (error) {
    console.error('Get IDS logs error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch IDS logs',
      details: error.message 
    });
  }
});

// Get IDS log by ID
router.get('/:logId', authenticateToken, tenantIsolation(), async (req, res) => {
  try {
    const { logId } = req.params;
    const organizationId = req.organizationId;

    const logResult = await db.query(
      'SELECT * FROM ids_logs WHERE id = $1 AND organization_id = $2',
      [logId, organizationId]
    );

    if (logResult.rows.length === 0) {
      return res.status(404).json({ error: 'IDS log not found' });
    }

    res.json({
      log: formatIDSLog(logResult.rows[0])
    });

  } catch (error) {
    console.error('Get IDS log error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch IDS log',
      details: error.message 
    });
  }
});

// Helper function to format IDS log data
function formatIDSLog(log) {
  return {
    id: log.id,
    detectionType: log.detection_type,
    signatureId: log.signature_id,
    signatureName: log.signature_name,
    sourceIp: log.source_ip,
    destIp: log.dest_ip,
    sourcePort: log.source_port,
    destPort: log.dest_port,
    protocol: log.protocol,
    payload: log.payload,
    severity: log.severity,
    confidence: log.confidence,
    anomalyType: log.anomaly_type,
    description: log.description,
    baselineValue: log.baseline_value,
    observedValue: log.observed_value,
    anomalyScore: log.anomaly_score,
    mlModel: log.ml_model,
    features: typeof log.features === 'string' ? JSON.parse(log.features) : log.features,
    metadata: typeof log.metadata === 'string' ? JSON.parse(log.metadata) : log.metadata,
    createdAt: log.created_at
  };
}

// Generate sample IDS logs for testing
async function generateSampleIDSLogs(organizationId) {
  const sampleLogs = [
    {
      id: uuidv4(),
      detection_type: 'signature_match',
      signature_id: 'ET-2001-001',
      signature_name: 'SQL Injection Attempt Detected',
      source_ip: '203.0.113.100',
      dest_ip: '192.168.1.10',
      source_port: 45678,
      dest_port: 80,
      protocol: 'TCP',
      payload: 'GET /login.php?username=admin%27%20OR%20%271%27%3D%271',
      severity: 'high',
      confidence: 0.95
    },
    {
      id: uuidv4(),
      detection_type: 'anomaly',
      anomaly_type: 'traffic_volume',
      description: 'Unusual traffic volume detected from internal host',
      source_ip: '192.168.1.50',
      dest_ip: '8.8.8.8',
      protocol: 'UDP',
      dest_port: 53,
      severity: 'medium',
      baseline_value: 100,
      observed_value: 5000,
      anomaly_score: 0.87,
      ml_model: 'isolation_forest_v2.1',
      features: JSON.stringify({
        packet_rate: 5000,
        byte_rate: 1024000,
        connection_duration: 300
      })
    },
    {
      id: uuidv4(),
      detection_type: 'signature_match',
      signature_id: 'ET-MALWARE-001',
      signature_name: 'Known Malware Communication Pattern',
      source_ip: '192.168.1.75',
      dest_ip: '198.51.100.25',
      source_port: 49152,
      dest_port: 443,
      protocol: 'TCP',
      severity: 'critical',
      confidence: 0.98
    }
  ];

  for (const log of sampleLogs) {
    await db.query(`
      INSERT INTO ids_logs (
        id, organization_id, detection_type, signature_id, signature_name,
        source_ip, dest_ip, source_port, dest_port, protocol, payload,
        severity, confidence, anomaly_type, description, baseline_value,
        observed_value, anomaly_score, ml_model, features, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
    `, [
      log.id, organizationId, log.detection_type, log.signature_id, log.signature_name,
      log.source_ip, log.dest_ip, log.source_port, log.dest_port, log.protocol,
      log.payload, log.severity, log.confidence, log.anomaly_type, log.description,
      log.baseline_value, log.observed_value, log.anomaly_score, log.ml_model,
      log.features, new Date()
    ]);
  }
}

module.exports = router; 