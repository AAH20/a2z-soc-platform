const express = require('express');
const router = express.Router();
const DatabaseService = require('../services/databaseService');
const { authenticateToken } = require('../middleware/auth');
const { tenantIsolation } = require('../middleware/tenantIsolation');

// Get security event techniques (attack patterns)
router.get('/techniques', async (req, res) => {
  try {
    const db = require('../services/databaseService');
    
    // Get aggregated technique data from security events
    const query = `
      SELECT 
        COALESCE(mitre_technique_id, 'T0000') as mitre_technique_id,
        COALESCE(mitre_technique_name, event_type) AS technique_name,
        COALESCE(mitre_tactic, 'Unknown') as mitre_tactic,
        COUNT(*) as event_count,
        severity,
        STRING_AGG(DISTINCT source, ', ') as data_sources,
        MAX(timestamp) as last_seen,
        description
      FROM security_events 
      WHERE timestamp >= NOW() - INTERVAL '30 days'
      GROUP BY mitre_technique_id, mitre_technique_name, mitre_tactic, severity, description, event_type
      ORDER BY event_count DESC, last_seen DESC
      LIMIT 100
    `;
    
    const { rows } = await db.pool.query(query);
    
    // Transform data for frontend
    const techniques = rows.map(row => ({
      id: row.mitre_technique_id,
      name: row.technique_name,
      mitre_technique_id: row.mitre_technique_id,
      technique_name: row.technique_name,
      mitre_tactic: row.mitre_tactic,
      severity: row.severity,
      data_sources: row.data_sources,
      platforms: 'Multiple', // Default since we don't store this
      procedure: `Detected ${row.event_count} times in security monitoring`,
      detection_methods: `Monitor for ${row.technique_name} indicators`,
      mitigation_steps: `Implement controls to prevent ${row.technique_name}`,
      description: row.description || `${row.technique_name} technique detected in security events`,
      event_count: row.event_count,
      last_seen: row.last_seen
    }));
    
    res.json({
      success: true,
      data: techniques,
      total: techniques.length
    });
    
  } catch (error) {
    console.error('Error fetching techniques:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch techniques data'
    });
  }
});

// Get all security events
router.get('/', async (req, res) => {
  try {
    const db = require('../services/databaseService');
    const { limit = 50, offset = 0, severity, source } = req.query;
    
    let query = `
      SELECT 
        id,
        event_type,
        description,
        severity,
        source,
        source_ip,
        destination_ip,
        timestamp,
        status,
        mitre_technique_name,
        mitre_tactic
      FROM security_events 
      WHERE 1=1
    `;
    
    const params = [];
    let paramIndex = 1;
    
    if (severity) {
      query += ` AND severity = $${paramIndex}`;
      params.push(severity);
      paramIndex++;
    }
    
    if (source) {
      query += ` AND source = $${paramIndex}`;
      params.push(source);
      paramIndex++;
    }
    
    query += ` ORDER BY timestamp DESC LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`;
    params.push(limit, offset);
    
    const { rows } = await db.pool.query(query, params);
    
    res.json({
      success: true,
      data: rows,
      total: rows.length
    });
    
  } catch (error) {
    console.error('Error fetching security events:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch security events'
    });
  }
});

// Delete all security events (for clearing alerts)
router.delete('/', async (req, res) => {
  try {
    const db = require('../services/databaseService');
    
    const { rows } = await db.pool.query('DELETE FROM security_events RETURNING COUNT(*)');
    
    res.json({
      success: true,
      message: 'All security events cleared',
      deleted_count: rows.length
    });
    
  } catch (error) {
    console.error('Error clearing security events:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to clear security events'
    });
  }
});

module.exports = router; 