const express = require('express');
const router = express.Router();
const { body, validationResult, query } = require('express-validator');
const { authenticateToken } = require('../middleware/auth');

// Admin-only middleware
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'super_admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// Apply admin middleware to all routes
router.use(authenticateToken);
router.use(requireAdmin);

// =============================================================================
// TENANT MANAGEMENT
// =============================================================================

// Get All Tenants
router.get('/tenants', [
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 100 }),
  query('search').optional().trim(),
  query('status').optional().isIn(['active', 'inactive', 'suspended', 'trial'])
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Validation failed', details: errors.array() });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;
    const search = req.query.search || '';
    const status = req.query.status;

    let whereClause = 'WHERE 1=1';
    const params = [];
    let paramCount = 0;

    if (search) {
      paramCount++;
      whereClause += ` AND (t.name ILIKE $${paramCount} OR t.domain ILIKE $${paramCount})`;
      params.push(`%${search}%`);
    }

    if (status) {
      paramCount++;
      whereClause += ` AND t.status = $${paramCount}`;
      params.push(status);
    }

    // Get tenants with aggregated data
    const query = `
      SELECT 
        t.*,
        COUNT(u.id) as user_count,
        s.status as subscription_status,
        s.plan_name,
        s.amount as monthly_amount,
        COALESCE(SUM(ua.requests_count), 0) as monthly_api_requests,
        COALESCE(SUM(ua.storage_used), 0) as storage_used
      FROM tenants t
      LEFT JOIN users u ON t.id = u.tenant_id AND u.status = 'active'
      LEFT JOIN subscriptions s ON t.id = s.tenant_id AND s.status = 'active'
      LEFT JOIN usage_analytics ua ON t.id = ua.tenant_id AND ua.period_start >= DATE_TRUNC('month', CURRENT_DATE)
      ${whereClause}
      GROUP BY t.id, s.status, s.plan_name, s.amount
      ORDER BY t.created_at DESC
      LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}
    `;

    params.push(limit, offset);

    const result = await req.db.query(query, params);

    // Get total count
    const countQuery = `
      SELECT COUNT(DISTINCT t.id) as total
      FROM tenants t
      ${whereClause}
    `;

    const countResult = await req.db.query(countQuery, params.slice(0, -2));

    res.json({
      tenants: result.rows,
      pagination: {
        page,
        limit,
        total: parseInt(countResult.rows[0].total),
        pages: Math.ceil(countResult.rows[0].total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get Tenant Details
router.get('/tenants/:tenantId', async (req, res) => {
  try {
    const tenantId = req.params.tenantId;

    const tenantQuery = `
      SELECT 
        t.*,
        COUNT(u.id) as user_count,
        s.status as subscription_status,
        s.plan_name,
        s.amount as monthly_amount,
        s.current_period_start,
        s.current_period_end,
        s.trial_end
      FROM tenants t
      LEFT JOIN users u ON t.id = u.tenant_id AND u.status = 'active'
      LEFT JOIN subscriptions s ON t.id = s.tenant_id AND s.status = 'active'
      WHERE t.id = $1
      GROUP BY t.id, s.status, s.plan_name, s.amount, s.current_period_start, s.current_period_end, s.trial_end
    `;

    const tenantResult = await req.db.query(tenantQuery, [tenantId]);

    if (tenantResult.rows.length === 0) {
      return res.status(404).json({ error: 'Tenant not found' });
    }

    // Get recent activity
    const activityQuery = `
      SELECT 
        'login' as type,
        created_at,
        metadata
      FROM user_sessions 
      WHERE tenant_id = $1
      UNION ALL
      SELECT 
        'api_request' as type,
        created_at,
        metadata
      FROM api_usage_logs 
      WHERE tenant_id = $1
      ORDER BY created_at DESC
      LIMIT 50
    `;

    const activityResult = await req.db.query(activityQuery, [tenantId]);

    // Get usage analytics
    const usageQuery = `
      SELECT 
        SUM(requests_count) as total_requests,
        SUM(storage_used) as total_storage,
        AVG(requests_count) as avg_daily_requests
      FROM usage_analytics 
      WHERE tenant_id = $1 AND period_start >= CURRENT_DATE - INTERVAL '30 days'
    `;

    const usageResult = await req.db.query(usageQuery, [tenantId]);

    res.json({
      tenant: tenantResult.rows[0],
      recent_activity: activityResult.rows,
      usage_stats: usageResult.rows[0]
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update Tenant Status
router.put('/tenants/:tenantId/status', [
  body('status').isIn(['active', 'inactive', 'suspended']),
  body('reason').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Validation failed', details: errors.array() });
    }

    const { status, reason } = req.body;
    const tenantId = req.params.tenantId;

    await req.db.query(
      'UPDATE tenants SET status = $1, updated_at = NOW() WHERE id = $2',
      [status, tenantId]
    );

    // Log admin action
    await req.db.query(
      `INSERT INTO admin_audit_logs (admin_id, action, target_type, target_id, details, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW())`,
      [req.user.userId, 'status_change', 'tenant', tenantId, JSON.stringify({ status, reason })]
    );

    res.json({ message: 'Tenant status updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// USER MANAGEMENT
// =============================================================================

// Get All Users
router.get('/users', [
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 100 }),
  query('search').optional().trim(),
  query('tenant_id').optional().isUUID(),
  query('role').optional().isIn(['admin', 'user', 'viewer'])
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Validation failed', details: errors.array() });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    let whereClause = 'WHERE 1=1';
    const params = [];
    let paramCount = 0;

    if (req.query.search) {
      paramCount++;
      whereClause += ` AND (u.first_name ILIKE $${paramCount} OR u.last_name ILIKE $${paramCount} OR u.email ILIKE $${paramCount})`;
      params.push(`%${req.query.search}%`);
    }

    if (req.query.tenant_id) {
      paramCount++;
      whereClause += ` AND u.tenant_id = $${paramCount}`;
      params.push(req.query.tenant_id);
    }

    if (req.query.role) {
      paramCount++;
      whereClause += ` AND u.role = $${paramCount}`;
      params.push(req.query.role);
    }

    const query = `
      SELECT 
        u.id,
        u.email,
        u.first_name,
        u.last_name,
        u.role,
        u.status,
        u.email_verified,
        u.last_login,
        u.created_at,
        t.name as tenant_name,
        t.domain as tenant_domain
      FROM users u
      LEFT JOIN tenants t ON u.tenant_id = t.id
      ${whereClause}
      ORDER BY u.created_at DESC
      LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}
    `;

    params.push(limit, offset);

    const result = await req.db.query(query, params);

    // Get total count
    const countQuery = `
      SELECT COUNT(*) as total
      FROM users u
      LEFT JOIN tenants t ON u.tenant_id = t.id
      ${whereClause}
    `;

    const countResult = await req.db.query(countQuery, params.slice(0, -2));

    res.json({
      users: result.rows,
      pagination: {
        page,
        limit,
        total: parseInt(countResult.rows[0].total),
        pages: Math.ceil(countResult.rows[0].total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// ANALYTICS & METRICS
// =============================================================================

// Get Platform Overview
router.get('/overview', async (req, res) => {
  try {
    const overviewQuery = `
      SELECT 
        (SELECT COUNT(*) FROM tenants WHERE status = 'active') as active_tenants,
        (SELECT COUNT(*) FROM tenants WHERE created_at >= CURRENT_DATE - INTERVAL '30 days') as new_tenants_30d,
        (SELECT COUNT(*) FROM users WHERE status = 'active') as total_users,
        (SELECT COUNT(*) FROM users WHERE created_at >= CURRENT_DATE - INTERVAL '7 days') as new_users_7d,
        (SELECT SUM(amount) FROM subscriptions WHERE status = 'active') as monthly_revenue,
        (SELECT COUNT(*) FROM subscriptions WHERE status = 'active') as active_subscriptions,
        (SELECT SUM(requests_count) FROM usage_analytics WHERE period_start >= CURRENT_DATE - INTERVAL '24 hours') as api_requests_24h,
        (SELECT AVG(requests_count) FROM usage_analytics WHERE period_start >= CURRENT_DATE - INTERVAL '30 days') as avg_daily_requests
    `;

    const overviewResult = await req.db.query(overviewQuery);

    // Get growth metrics
    const growthQuery = `
      SELECT 
        DATE_TRUNC('day', created_at) as date,
        COUNT(*) as new_tenants
      FROM tenants 
      WHERE created_at >= CURRENT_DATE - INTERVAL '30 days'
      GROUP BY DATE_TRUNC('day', created_at)
      ORDER BY date
    `;

    const growthResult = await req.db.query(growthQuery);

    // Get revenue metrics
    const revenueQuery = `
      SELECT 
        DATE_TRUNC('month', created_at) as month,
        SUM(amount) as revenue
      FROM subscriptions 
      WHERE status = 'active' AND created_at >= CURRENT_DATE - INTERVAL '12 months'
      GROUP BY DATE_TRUNC('month', created_at)
      ORDER BY month
    `;

    const revenueResult = await req.db.query(revenueQuery);

    // Get top tenants by usage
    const topTenantsQuery = `
      SELECT 
        t.name,
        t.domain,
        SUM(ua.requests_count) as total_requests,
        s.plan_name,
        s.amount
      FROM tenants t
      LEFT JOIN usage_analytics ua ON t.id = ua.tenant_id AND ua.period_start >= CURRENT_DATE - INTERVAL '30 days'
      LEFT JOIN subscriptions s ON t.id = s.tenant_id AND s.status = 'active'
      WHERE t.status = 'active'
      GROUP BY t.id, t.name, t.domain, s.plan_name, s.amount
      ORDER BY total_requests DESC NULLS LAST
      LIMIT 10
    `;

    const topTenantsResult = await req.db.query(topTenantsQuery);

    res.json({
      overview: overviewResult.rows[0],
      growth_chart: growthResult.rows,
      revenue_chart: revenueResult.rows,
      top_tenants: topTenantsResult.rows
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get System Health
router.get('/health', async (req, res) => {
  try {
    // Check database connection
    const dbCheck = await req.db.query('SELECT NOW()');
    
    // Check recent errors
    const errorQuery = `
      SELECT COUNT(*) as error_count
      FROM system_logs 
      WHERE level = 'error' AND created_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour'
    `;
    
    const errorResult = await req.db.query(errorQuery);

    // Check API response times
    const apiHealthQuery = `
      SELECT 
        AVG(response_time) as avg_response_time,
        COUNT(*) as total_requests,
        COUNT(CASE WHEN status_code >= 500 THEN 1 END) as error_requests
      FROM api_usage_logs 
      WHERE created_at >= CURRENT_TIMESTAMP - INTERVAL '1 hour'
    `;

    const apiHealthResult = await req.db.query(apiHealthQuery);

    // Check subscription health
    const subscriptionHealthQuery = `
      SELECT 
        COUNT(CASE WHEN status = 'active' THEN 1 END) as active,
        COUNT(CASE WHEN status = 'past_due' THEN 1 END) as past_due,
        COUNT(CASE WHEN status = 'canceled' THEN 1 END) as canceled
      FROM subscriptions
    `;

    const subscriptionHealthResult = await req.db.query(subscriptionHealthQuery);

    const health = {
      database: {
        status: 'healthy',
        response_time: Date.now() - new Date(dbCheck.rows[0].now).getTime()
      },
      errors: {
        last_hour: parseInt(errorResult.rows[0].error_count)
      },
      api: {
        avg_response_time: parseFloat(apiHealthResult.rows[0].avg_response_time) || 0,
        total_requests: parseInt(apiHealthResult.rows[0].total_requests) || 0,
        error_rate: apiHealthResult.rows[0].total_requests > 0 
          ? (parseInt(apiHealthResult.rows[0].error_requests) / parseInt(apiHealthResult.rows[0].total_requests) * 100).toFixed(2)
          : 0
      },
      subscriptions: subscriptionHealthResult.rows[0]
    };

    res.json(health);
  } catch (error) {
    res.status(500).json({ 
      error: error.message,
      database: { status: 'unhealthy' }
    });
  }
});

// =============================================================================
// CONFIGURATION MANAGEMENT
// =============================================================================

// Get System Configuration
router.get('/config', async (req, res) => {
  try {
    const configQuery = `
      SELECT key, value, description, updated_at
      FROM system_config
      ORDER BY key
    `;

    const result = await req.db.query(configQuery);

    const config = {};
    result.rows.forEach(row => {
      config[row.key] = {
        value: row.value,
        description: row.description,
        updated_at: row.updated_at
      };
    });

    res.json(config);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update System Configuration
router.put('/config/:key', [
  body('value').notEmpty(),
  body('description').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Validation failed', details: errors.array() });
    }

    const { key } = req.params;
    const { value, description } = req.body;

    await req.db.query(
      `INSERT INTO system_config (key, value, description, updated_at)
       VALUES ($1, $2, $3, NOW())
       ON CONFLICT (key) DO UPDATE SET
       value = $2, description = COALESCE($3, system_config.description), updated_at = NOW()`,
      [key, value, description]
    );

    // Log admin action
    await req.db.query(
      `INSERT INTO admin_audit_logs (admin_id, action, target_type, target_id, details, created_at)
       VALUES ($1, $2, $3, $4, $5, NOW())`,
      [req.user.userId, 'config_update', 'system', key, JSON.stringify({ value, description })]
    );

    res.json({ message: 'Configuration updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// AUDIT LOGS
// =============================================================================

// Get Audit Logs
router.get('/audit-logs', [
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 100 }),
  query('action').optional().trim(),
  query('target_type').optional().trim(),
  query('admin_id').optional().isUUID()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Validation failed', details: errors.array() });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;

    let whereClause = 'WHERE 1=1';
    const params = [];
    let paramCount = 0;

    if (req.query.action) {
      paramCount++;
      whereClause += ` AND al.action = $${paramCount}`;
      params.push(req.query.action);
    }

    if (req.query.target_type) {
      paramCount++;
      whereClause += ` AND al.target_type = $${paramCount}`;
      params.push(req.query.target_type);
    }

    if (req.query.admin_id) {
      paramCount++;
      whereClause += ` AND al.admin_id = $${paramCount}`;
      params.push(req.query.admin_id);
    }

    const query = `
      SELECT 
        al.*,
        u.first_name,
        u.last_name,
        u.email
      FROM admin_audit_logs al
      LEFT JOIN users u ON al.admin_id = u.id
      ${whereClause}
      ORDER BY al.created_at DESC
      LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}
    `;

    params.push(limit, offset);

    const result = await req.db.query(query, params);

    // Get total count
    const countQuery = `
      SELECT COUNT(*) as total
      FROM admin_audit_logs al
      ${whereClause}
    `;

    const countResult = await req.db.query(countQuery, params.slice(0, -2));

    res.json({
      logs: result.rows,
      pagination: {
        page,
        limit,
        total: parseInt(countResult.rows[0].total),
        pages: Math.ceil(countResult.rows[0].total / limit)
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// =============================================================================
// SUPPORT TICKETS
// =============================================================================

// Get All Support Tickets
router.get('/support-tickets', [
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 100 }),
  query('status').optional().isIn(['open', 'in_progress', 'resolved', 'closed']),
  query('priority').optional().isIn(['low', 'medium', 'high', 'urgent'])
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Validation failed', details: errors.array() });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    let whereClause = 'WHERE 1=1';
    const params = [];
    let paramCount = 0;

    if (req.query.status) {
      paramCount++;
      whereClause += ` AND st.status = $${paramCount}`;
      params.push(req.query.status);
    }

    if (req.query.priority) {
      paramCount++;
      whereClause += ` AND st.priority = $${paramCount}`;
      params.push(req.query.priority);
    }

    const query = `
      SELECT 
        st.*,
        u.first_name,
        u.last_name,
        u.email,
        t.name as tenant_name
      FROM support_tickets st
      LEFT JOIN users u ON st.user_id = u.id
      LEFT JOIN tenants t ON st.tenant_id = t.id
      ${whereClause}
      ORDER BY 
        CASE st.priority 
          WHEN 'urgent' THEN 1
          WHEN 'high' THEN 2
          WHEN 'medium' THEN 3
          WHEN 'low' THEN 4
        END,
        st.created_at DESC
      LIMIT $${paramCount + 1} OFFSET $${paramCount + 2}
    `;

    params.push(limit, offset);

    const result = await req.db.query(query, params);

    res.json({
      tickets: result.rows,
      pagination: {
        page,
        limit,
        total: result.rows.length
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update Support Ticket Status
router.put('/support-tickets/:ticketId/status', [
  body('status').isIn(['open', 'in_progress', 'resolved', 'closed']),
  body('response').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ error: 'Validation failed', details: errors.array() });
    }

    const { status, response } = req.body;
    const ticketId = req.params.ticketId;

    await req.db.query(
      'UPDATE support_tickets SET status = $1, updated_at = NOW() WHERE id = $2',
      [status, ticketId]
    );

    if (response) {
      await req.db.query(
        `INSERT INTO support_responses (ticket_id, user_id, response, created_at)
         VALUES ($1, $2, $3, NOW())`,
        [ticketId, req.user.userId, response]
      );
    }

    res.json({ message: 'Support ticket updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router; 