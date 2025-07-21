const express = require('express');
const router = express.Router();
const { Pool } = require('pg');

// Database connection
const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'a2z_soc',
  password: process.env.DB_PASSWORD || 'postgres',
  port: process.env.DB_PORT || 5432,
});

/**
 * @swagger
 * /api/network-agents/health:
 *   get:
 *     summary: Get network agents health status
 *     tags: [Network Agents]
 *     responses:
 *       200:
 *         description: Network agents health status
 */
router.get('/health', async (req, res) => {
  try {
    const query = `
      SELECT 
        COUNT(*) as total_agents,
        COUNT(CASE WHEN status = 'online' THEN 1 END) as active_agents,
        COUNT(CASE WHEN last_heartbeat > NOW() - INTERVAL '5 minutes' THEN 1 END) as healthy_agents,
        COUNT(CASE WHEN last_heartbeat <= NOW() - INTERVAL '5 minutes' OR last_heartbeat IS NULL THEN 1 END) as unhealthy_agents
      FROM network_agents
    `;
    
    const result = await pool.query(query);
    const stats = result.rows[0];
    
    res.json({
      success: true,
      timestamp: new Date(),
      statistics: {
        total_agents: parseInt(stats.total_agents),
        active_agents: parseInt(stats.active_agents),
        healthy_agents: parseInt(stats.healthy_agents),
        unhealthy_agents: parseInt(stats.unhealthy_agents)
      },
      health_status: parseInt(stats.healthy_agents) > 0 ? 'healthy' : 'unhealthy'
    });
    
  } catch (error) {
    console.error('Network agents health check error:', error);
    res.status(500).json({
      error: 'Internal server error checking network agents health'
    });
  }
});

/**
 * @swagger
 * /api/network-agents:
 *   get:
 *     summary: Get all network agents
 *     tags: [Network Agents]
 *     responses:
 *       200:
 *         description: List of network agents
 */
router.get('/', async (req, res) => {
  try {
    const query = `
      SELECT 
        na.*,
        COUNT(ne.id) as event_count,
        MAX(ne.created_at) as last_event
      FROM network_agents na
      LEFT JOIN network_events ne ON na.id = ne.agent_id
      GROUP BY na.id
      ORDER BY na.last_heartbeat DESC
    `;
    
    const result = await pool.query(query);
    
    res.json({
      success: true,
      agents: result.rows,
      total: result.rows.length
    });
    
  } catch (error) {
    console.error('Get network agents error:', error);
    res.status(500).json({
      error: 'Internal server error fetching network agents'
    });
  }
});

/**
 * @swagger
 * /api/network-agents/{agentId}:
 *   get:
 *     summary: Get specific network agent
 *     tags: [Network Agents]
 *     parameters:
 *       - in: path
 *         name: agentId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Network agent details
 */
router.get('/:agentId', async (req, res) => {
  try {
    const { agentId } = req.params;
    
    const agentQuery = `
      SELECT * FROM network_agents 
      WHERE id = $1
    `;
    
    const agentResult = await pool.query(agentQuery, [agentId]);
    
    if (agentResult.rows.length === 0) {
      return res.status(404).json({
        error: 'Network agent not found'
      });
    }
    
    // Get recent events
    const eventsQuery = `
      SELECT * FROM network_events 
      WHERE agent_id = $1 
      ORDER BY created_at DESC 
      LIMIT 100
    `;
    
    const eventsResult = await pool.query(eventsQuery, [agentId]);
    
    // Get network interfaces
    const interfacesQuery = `
      SELECT * FROM network_interfaces 
      WHERE agent_id = $1 
      ORDER BY interface_name
    `;
    
    const interfacesResult = await pool.query(interfacesQuery, [agentId]);
    
    res.json({
      success: true,
      agent: agentResult.rows[0],
      events: eventsResult.rows,
      interfaces: interfacesResult.rows
    });
    
  } catch (error) {
    console.error('Get network agent error:', error);
    res.status(500).json({
      error: 'Internal server error fetching network agent'
    });
  }
});

/**
 * @swagger
 * /api/network-agents/{agentId}/events:
 *   get:
 *     summary: Get network events for specific agent
 *     tags: [Network Agents]
 *     parameters:
 *       - in: path
 *         name: agentId
 *         required: true
 *         schema:
 *           type: string
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 100
 *       - in: query
 *         name: event_type
 *         schema:
 *           type: string
 *       - in: query
 *         name: threat_level
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Network events
 */
router.get('/:agentId/events', async (req, res) => {
  try {
    const { agentId } = req.params;
    const { limit = 100, event_type, threat_level } = req.query;
    
    let query = `
      SELECT * FROM network_events 
      WHERE agent_id = $1
    `;
    
    const values = [agentId];
    let paramIndex = 2;
    
    if (event_type) {
      query += ` AND event_type = $${paramIndex}`;
      values.push(event_type);
      paramIndex++;
    }
    
    if (threat_level) {
      query += ` AND threat_level = $${paramIndex}`;
      values.push(threat_level);
      paramIndex++;
    }
    
    query += ` ORDER BY created_at DESC LIMIT $${paramIndex}`;
    values.push(limit);
    
    const result = await pool.query(query, values);
    
    res.json({
      success: true,
      events: result.rows,
      total: result.rows.length
    });
    
  } catch (error) {
    console.error('Get network events error:', error);
    res.status(500).json({
      error: 'Internal server error fetching network events'
    });
  }
});

/**
 * @swagger
 * /api/network-agents/{agentId}/metrics:
 *   get:
 *     summary: Get network agent metrics
 *     tags: [Network Agents]
 *     parameters:
 *       - in: path
 *         name: agentId
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Network agent metrics
 */
router.get('/:agentId/metrics', async (req, res) => {
  try {
    const { agentId } = req.params;
    
    // Get agent metrics
    const agentQuery = `
      SELECT configuration, last_heartbeat, status 
      FROM network_agents 
      WHERE id = $1
    `;
    
    const agentResult = await pool.query(agentQuery, [agentId]);
    
    if (agentResult.rows.length === 0) {
      return res.status(404).json({
        error: 'Network agent not found'
      });
    }
    
    // Get event statistics
    const statsQuery = `
      SELECT 
        COUNT(*) as total_events,
        COUNT(CASE WHEN threat_level = 'high' OR threat_level = 'critical' THEN 1 END) as high_threat_events,
        COUNT(CASE WHEN created_at >= NOW() - INTERVAL '1 hour' THEN 1 END) as events_last_hour,
        COUNT(CASE WHEN created_at >= NOW() - INTERVAL '24 hours' THEN 1 END) as events_last_24h
      FROM network_events 
      WHERE agent_id = $1
    `;
    
    const statsResult = await pool.query(statsQuery, [agentId]);
    
    // Get interface statistics - using a mock since the table might not have the expected columns
    const interfaceStatsQuery = `
      SELECT 
        COUNT(*) as interface_count
      FROM network_interfaces 
      WHERE agent_id = $1
    `;
    
    const interfaceStatsResult = await pool.query(interfaceStatsQuery, [agentId]);
    
    const agent = agentResult.rows[0];
    const stats = statsResult.rows[0];
    const interfaceStats = interfaceStatsResult.rows[0];
    
    res.json({
      success: true,
      agent_id: agentId,
      status: agent.status,
      last_heartbeat: agent.last_heartbeat,
      metrics: agent.configuration || {},
      statistics: {
        events: {
          total: parseInt(stats.total_events),
          high_threat: parseInt(stats.high_threat_events),
          last_hour: parseInt(stats.events_last_hour),
          last_24h: parseInt(stats.events_last_24h)
        },
        interfaces: {
          total: parseInt(interfaceStats.interface_count),
          active: 0,
          rx_bytes: 0,
          tx_bytes: 0,
          rx_packets: 0,
          tx_packets: 0
        }
      }
    });
    
  } catch (error) {
    console.error('Get network agent metrics error:', error);
    res.status(500).json({
      error: 'Internal server error fetching network agent metrics'
    });
  }
});

module.exports = router; 