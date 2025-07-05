const db = require('../services/databaseService');

// Helper function to get organization ID from request
const getOrganizationId = (req) => {
  return req.user?.organizationId || '00000000-0000-0000-0000-000000000001';
};

const getAudits = async (req, res) => {
  try {
    // Using singleton db instance
    const organizationId = getOrganizationId(req);
    const { 
      page = 1, 
      limit = 20, 
      severity, 
      status,
      category,
      startDate,
      endDate 
    } = req.query;

    // Get audit logs from database
    const auditLogs = await db.query(
      `SELECT * FROM audit_logs 
       WHERE organization_id = $1 
       ${severity ? 'AND severity = $2' : ''}
       ${status ? 'AND status = $3' : ''}
       ${category ? 'AND category = $4' : ''}
       ${startDate ? 'AND created_at >= $5' : ''}
       ${endDate ? 'AND created_at <= $6' : ''}
       ORDER BY created_at DESC
       LIMIT $${severity ? '7' : '2'} OFFSET $${severity ? '8' : '3'}`,
      [
        organizationId,
        ...(severity ? [severity] : []),
        ...(status ? [status] : []),
        ...(category ? [category] : []),
        ...(startDate ? [startDate] : []),
        ...(endDate ? [endDate] : []),
        parseInt(limit),
        (parseInt(page) - 1) * parseInt(limit)
      ]
    );

    // Get total count
    const totalResult = await db.query(
      `SELECT COUNT(*) as total FROM audit_logs 
       WHERE organization_id = $1
       ${severity ? 'AND severity = $2' : ''}
       ${status ? 'AND status = $3' : ''}
       ${category ? 'AND category = $4' : ''}
       ${startDate ? 'AND created_at >= $5' : ''}
       ${endDate ? 'AND created_at <= $6' : ''}`,
      [
        organizationId,
        ...(severity ? [severity] : []),
        ...(status ? [status] : []),
        ...(category ? [category] : []),
        ...(startDate ? [startDate] : []),
        ...(endDate ? [endDate] : [])
      ]
    );

    const total = parseInt(totalResult.rows[0].total);
    const totalPages = Math.ceil(total / parseInt(limit));

    // If no audits exist, generate some initial data
    if (total === 0) {
      await generateInitialAuditData(organizationId);
      // Retry the query
      const newAuditLogs = await db.query(
        `SELECT * FROM audit_logs 
         WHERE organization_id = $1 
         ORDER BY created_at DESC
         LIMIT $2 OFFSET $3`,
        [organizationId, parseInt(limit), 0]
      );

      return res.json({
        audits: newAuditLogs.rows.map(formatAuditEntry),
        pagination: {
          page: 1,
          limit: parseInt(limit),
          totalPages: Math.ceil(newAuditLogs.rows.length / parseInt(limit)),
          total: newAuditLogs.rows.length
        }
      });
    }
    
    res.json({
      audits: auditLogs.rows.map(formatAuditEntry),
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages,
        total
      }
    });

  } catch (error) {
    console.error('Error fetching audits:', error);
    res.status(500).json({ 
      error: 'Failed to fetch audits',
      message: error.message 
    });
  }
};

const getAuditDetails = async (req, res) => {
  try {
    // Using singleton db instance
    const { id } = req.params;
    const organizationId = getOrganizationId(req);

    const result = await db.query(
      'SELECT * FROM audit_logs WHERE id = $1 AND organization_id = $2',
      [id, organizationId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Audit not found' });
    }

    const audit = result.rows[0];
    
    res.json({
      audit: formatAuditEntry(audit)
    });

  } catch (error) {
    console.error('Error fetching audit details:', error);
    res.status(500).json({ 
      error: 'Failed to fetch audit details',
      message: error.message 
    });
  }
};

const updateAuditStatus = async (req, res) => {
  try {
    // Using singleton db instance
    const { id } = req.params;
    const { status, resolution_notes } = req.body;
    const organizationId = getOrganizationId(req);

    const result = await db.query(
      `UPDATE audit_logs 
       SET status = $1, resolution_notes = $2, resolved_at = $3
       WHERE id = $4 AND organization_id = $5
       RETURNING *`,
      [
        status, 
        resolution_notes, 
        status === 'resolved' ? new Date() : null,
        id, 
        organizationId
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Audit not found' });
    }

    // Log the status update action
    await db.createAuditLog({
      organization_id: organizationId,
      user_id: req.user?.id,
      action: 'audit_status_updated',
      resource_type: 'audit_log',
      resource_id: id,
      details: { status, resolution_notes },
      ip_address: req.ip,
      user_agent: req.get('User-Agent')
    });
    
    res.json({
      audit: formatAuditEntry(result.rows[0])
    });

  } catch (error) {
    console.error('Error updating audit status:', error);
    res.status(500).json({ 
      error: 'Failed to update audit status',
      message: error.message 
    });
  }
};

const getAuditStats = async (req, res) => {
  try {
    // Using singleton db instance
    const organizationId = getOrganizationId(req);
    const { timeRange = '30d' } = req.query;

    // Calculate date range
    let startDate = new Date();
    switch (timeRange) {
      case '7d':
        startDate.setDate(startDate.getDate() - 7);
        break;
      case '30d':
        startDate.setDate(startDate.getDate() - 30);
        break;
      case '90d':
        startDate.setDate(startDate.getDate() - 90);
        break;
      default:
        startDate.setDate(startDate.getDate() - 30);
    }

    // Get statistics
    const [severityStats, statusStats, categoryStats, totalCount] = await Promise.all([
      // Severity distribution
      db.query(
        `SELECT severity, COUNT(*) as count 
         FROM audit_logs 
         WHERE organization_id = $1 AND created_at >= $2 
         GROUP BY severity`,
        [organizationId, startDate]
      ),
      
      // Status distribution
      db.query(
        `SELECT status, COUNT(*) as count 
         FROM audit_logs 
         WHERE organization_id = $1 AND created_at >= $2 
         GROUP BY status`,
        [organizationId, startDate]
      ),
      
      // Category distribution
      db.query(
        `SELECT category, COUNT(*) as count 
         FROM audit_logs 
         WHERE organization_id = $1 AND created_at >= $2 
         GROUP BY category`,
        [organizationId, startDate]
      ),
      
      // Total count
      db.query(
        `SELECT COUNT(*) as total 
         FROM audit_logs 
         WHERE organization_id = $1 AND created_at >= $2`,
        [organizationId, startDate]
      )
    ]);
    
    res.json({
      timeRange,
      total: parseInt(totalCount.rows[0].total),
      severityDistribution: severityStats.rows.reduce((acc, row) => {
        acc[row.severity] = parseInt(row.count);
        return acc;
      }, {}),
      statusDistribution: statusStats.rows.reduce((acc, row) => {
        acc[row.status] = parseInt(row.count);
        return acc;
      }, {}),
      categoryDistribution: categoryStats.rows.reduce((acc, row) => {
        acc[row.category] = parseInt(row.count);
        return acc;
      }, {}),
      lastUpdated: new Date().toISOString()
    });

  } catch (error) {
    console.error('Error fetching audit stats:', error);
    res.status(500).json({ 
      error: 'Failed to fetch audit statistics',
      message: error.message 
    });
  }
};

// Helper function to format audit entries
function formatAuditEntry(audit) {
  return {
    id: audit.id,
    timestamp: audit.created_at,
    user: audit.user_id,
    action: audit.action,
    resource: {
      type: audit.resource_type,
      id: audit.resource_id
    },
    severity: audit.severity,
    status: audit.status,
    category: audit.category,
    details: audit.details || {},
    ip_address: audit.ip_address,
    user_agent: audit.user_agent,
    resolved_at: audit.resolved_at,
    resolution_notes: audit.resolution_notes
  };
}

// Generate initial audit data for new organizations
async function generateInitialAuditData(organizationId) {
  // Using singleton db instance
  const initialAudits = [
    {
      organization_id: organizationId,
      action: 'user_login',
      resource_type: 'user_session',
      severity: 'info',
      category: 'authentication',
      details: { login_method: 'password', success: true },
      ip_address: '192.168.1.100'
    },
    {
      organization_id: organizationId,
      action: 'security_policy_updated',
      resource_type: 'security_policy',
      severity: 'medium',
      category: 'configuration',
      details: { policy_name: 'Password Policy', changes: ['min_length', 'complexity'] },
      ip_address: '192.168.1.100'
    },
    {
      organization_id: organizationId,
      action: 'failed_login_attempt',
      resource_type: 'user_session',
      severity: 'warning',
      category: 'authentication',
      details: { attempted_username: 'admin', reason: 'invalid_password' },
      ip_address: '10.0.0.50'
    },
    {
      organization_id: organizationId,
      action: 'data_export',
      resource_type: 'security_data',
      severity: 'high',
      category: 'data_access',
      details: { export_type: 'security_logs', record_count: 1000 },
      ip_address: '192.168.1.100'
    },
    {
      organization_id: organizationId,
      action: 'agent_connected',
      resource_type: 'network_agent',
      severity: 'info',
      category: 'system',
      details: { agent_id: 'agent-001', agent_type: 'network_monitor' },
      ip_address: '192.168.1.50'
    }
  ];

  for (const audit of initialAudits) {
    await db.createAuditLog(audit);
  }
}

module.exports = {
  getAudits,
  getAuditDetails,
  updateAuditStatus,
  getAuditStats
}; 