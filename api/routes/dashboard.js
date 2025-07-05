const express = require('express');
const router = express.Router();
const db = require('../services/databaseService');
const { authenticateToken } = require('../middleware/auth');
const { tenantIsolation } = require('../middleware/tenantIsolation');

// Get dashboard statistics
router.get('/stats', authenticateToken, tenantIsolation(), async (req, res) => {
  try {
    const organizationId = req.organizationId;

    // Get comprehensive dashboard statistics
    const stats = await db.getDashboardStats(organizationId);

    res.json({
      success: true,
      data: stats
    });
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Get security events summary for techniques
router.get('/techniques', authenticateToken, tenantIsolation(), async (req, res) => {
  try {
    const organizationId = req.organizationId;

    const result = await db.query(`
      SELECT 
        COALESCE(mitre_technique, event_type) as technique_name,
        event_type,
        COUNT(*) as count,
        MAX(severity) as max_severity,
        MIN(created_at) as first_seen,
        MAX(created_at) as last_seen
      FROM security_events 
      WHERE organization_id = $1 
        AND created_at >= NOW() - INTERVAL '30 days'
      GROUP BY COALESCE(mitre_technique, event_type), event_type
      ORDER BY count DESC
      LIMIT 20
    `, [organizationId]);

    const techniques = result.rows.map(row => ({
      technique_name: row.technique_name,
      event_type: row.event_type,
      count: parseInt(row.count),
      description: `${row.technique_name} attacks detected`,
      max_severity: row.max_severity,
      first_seen: row.first_seen,
      last_seen: row.last_seen
    }));

    res.json({
      success: true,
      data: techniques
    });
  } catch (error) {
    console.error('Dashboard techniques error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Get real-time system health
router.get('/health', authenticateToken, tenantIsolation(), async (req, res) => {
  try {
    const organizationId = req.organizationId;

    // Get system health metrics
    const [agentHealth, eventHealth] = await Promise.all([
      // Agent health
      db.query(`
        SELECT 
          COUNT(*) as total_agents,
          COUNT(*) FILTER (WHERE status = 'online') as online_agents,
          COUNT(*) FILTER (WHERE last_heartbeat >= NOW() - INTERVAL '5 minutes') as recent_heartbeat
        FROM network_agents 
        WHERE organization_id = $1
      `, [organizationId]),

      // Event processing health  
      db.query(`
        SELECT 
          COUNT(*) as total_events,
          COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '1 hour') as events_last_hour,
          COUNT(*) FILTER (WHERE severity IN ('high', 'critical')) as high_severity_events,
          AVG(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) * 100 as resolution_rate
        FROM security_events 
        WHERE organization_id = $1 
          AND created_at >= NOW() - INTERVAL '24 hours'
      `, [organizationId])
    ]);

    const agentData = agentHealth.rows[0] || {};
    const eventData = eventHealth.rows[0] || {};

    // Get database health
    const dbHealthy = await db.healthCheck();

    const health = {
      overall_status: dbHealthy ? 'healthy' : 'degraded',
      agents: {
        total: parseInt(agentData.total_agents) || 0,
        online: parseInt(agentData.online_agents) || 0,
        recent_heartbeat: parseInt(agentData.recent_heartbeat) || 0,
        health_percentage: agentData.total_agents > 0 ? 
          Math.round((agentData.online_agents / agentData.total_agents) * 100) : 100
      },
      events: {
        total_24h: parseInt(eventData.total_events) || 0,
        last_hour: parseInt(eventData.events_last_hour) || 0,
        high_severity: parseInt(eventData.high_severity_events) || 0,
        resolution_rate: parseFloat(eventData.resolution_rate) || 0
      },
      database: {
        status: dbHealthy ? 'ok' : 'error',
        connection_time: 0,
        last_check: new Date().toISOString()
      }
    };

    res.json({
      success: true,
      data: health
    });
  } catch (error) {
    console.error('Dashboard health error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// Get alert trends
router.get('/trends', authenticateToken, tenantIsolation(), async (req, res) => {
  try {
    const organizationId = req.organizationId;
    const days = parseInt(req.query.days) || 7;

    const result = await db.query(`
      SELECT 
        DATE(created_at) as date,
        COUNT(*) as total_events,
        COUNT(*) FILTER (WHERE severity = 'critical') as critical_events,
        COUNT(*) FILTER (WHERE severity = 'high') as high_events,
        COUNT(*) FILTER (WHERE severity = 'medium') as medium_events,
        COUNT(*) FILTER (WHERE severity = 'low') as low_events,
        COUNT(DISTINCT source_ip) as unique_sources,
        COUNT(DISTINCT event_type) as unique_event_types
      FROM security_events 
      WHERE organization_id = $1 
        AND created_at >= NOW() - INTERVAL '${days} days'
      GROUP BY DATE(created_at)
      ORDER BY date DESC
    `, [organizationId]);

    res.json({
      success: true,
      data: result.rows
    });
  } catch (error) {
    console.error('Dashboard trends error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router; 