const { Pool } = require('pg');

class DatabaseService {
  constructor() {
    this.pool = new Pool({
      user: process.env.DB_USER || 'a2z_user',
      host: process.env.DB_HOST || 'localhost',
      database: process.env.DB_NAME || 'a2z_soc',
      password: process.env.DB_PASSWORD || 'a2z_secure_pass',
      port: process.env.DB_PORT || 5432,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 2000,
    });

    this.pool.on('error', (err) => {
      console.error('Database pool error:', err);
    });
  }

  async query(text, params = []) {
    const client = await this.pool.connect();
    try {
      const result = await client.query(text, params);
      return result;
    } finally {
      client.release();
    }
  }

  async transaction(queries) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const results = [];
      
      for (const { text, params } of queries) {
        const result = await client.query(text, params);
        results.push(result);
      }
      
      await client.query('COMMIT');
      return results;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  // ===========================
  // ORGANIZATION OPERATIONS
  // ===========================

  async getOrganization(orgId) {
    const result = await this.query(
      'SELECT * FROM organizations WHERE id = $1',
      [orgId]
    );
    return result.rows[0];
  }

  async createOrganization(data) {
    const { name, domain, subscription_tier } = data;
    const result = await this.query(
      `INSERT INTO organizations (name, domain, subscription_tier) 
       VALUES ($1, $2, $3) RETURNING *`,
      [name, domain, subscription_tier]
    );
    return result.rows[0];
  }

  // ===========================
  // USER OPERATIONS
  // ===========================

  async getUserByEmail(email) {
    const result = await this.query(
      `SELECT u.*, o.name as organization_name, o.subscription_tier 
       FROM users u 
       LEFT JOIN organizations o ON u.organization_id = o.id 
       WHERE u.email = $1`,
      [email]
    );
    return result.rows[0];
  }

  async createUser(data) {
    const { email, password_hash, first_name, last_name, role, organization_id } = data;
    const result = await this.query(
      `INSERT INTO users (email, password_hash, first_name, last_name, role, organization_id) 
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [email, password_hash, first_name, last_name, role, organization_id]
    );
    return result.rows[0];
  }

  async updateUserLastLogin(userId) {
    await this.query(
      'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1',
      [userId]
    );
  }

  // ===========================
  // NETWORK AGENT OPERATIONS
  // ===========================

  async getNetworkAgents(organizationId, filters = {}) {
    let query = `
      SELECT na.*, ni.interface_name, ni.ip_address as interface_ip
      FROM network_agents na
      LEFT JOIN network_interfaces ni ON na.id = ni.agent_id
      WHERE na.organization_id = $1
    `;
    const params = [organizationId];

    if (filters.status) {
      query += ' AND na.status = $2';
      params.push(filters.status);
    }

    if (filters.agent_type) {
      query += ` AND na.agent_type = $${params.length + 1}`;
      params.push(filters.agent_type);
    }

    query += ' ORDER BY na.created_at DESC';

    const result = await this.query(query, params);
    return result.rows;
  }

  async createNetworkAgent(data) {
    const { 
      organization_id, name, agent_type, ip_address, 
      hostname, operating_system, version, configuration 
    } = data;
    
    const result = await this.query(
      `INSERT INTO network_agents 
       (organization_id, name, agent_type, ip_address, hostname, operating_system, version, configuration) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [organization_id, name, agent_type, ip_address, hostname, operating_system, version, JSON.stringify(configuration)]
    );
    return result.rows[0];
  }

  async updateAgentHeartbeat(agentId, status = 'online') {
    await this.query(
      'UPDATE network_agents SET last_heartbeat = CURRENT_TIMESTAMP, status = $1 WHERE id = $2',
      [status, agentId]
    );
  }

  // ===========================
  // SECURITY EVENTS OPERATIONS
  // ===========================

  async getSecurityEvents(organizationId, filters = {}) {
    let query = `
      SELECT se.*, na.name as agent_name
      FROM security_events se
      LEFT JOIN network_agents na ON se.agent_id = na.id
      WHERE se.organization_id = $1
    `;
    const params = [organizationId];

    if (filters.severity) {
      query += ` AND se.severity = $${params.length + 1}`;
      params.push(filters.severity);
    }

    if (filters.event_type) {
      query += ` AND se.event_type = $${params.length + 1}`;
      params.push(filters.event_type);
    }

    if (filters.status) {
      query += ` AND se.status = $${params.length + 1}`;
      params.push(filters.status);
    }

    if (filters.start_date) {
      query += ` AND se.created_at >= $${params.length + 1}`;
      params.push(filters.start_date);
    }

    if (filters.end_date) {
      query += ` AND se.created_at <= $${params.length + 1}`;
      params.push(filters.end_date);
    }

    query += ' ORDER BY se.created_at DESC';

    if (filters.limit) {
      query += ` LIMIT $${params.length + 1}`;
      params.push(filters.limit);
    }

    if (filters.offset) {
      query += ` OFFSET $${params.length + 1}`;
      params.push(filters.offset);
    }

    const result = await this.query(query, params);
    return result.rows;
  }

  async createSecurityEvent(data) {
    const {
      organization_id, agent_id, event_type, severity, source_ip,
      destination_ip, source_port, destination_port, protocol,
      rule_id, rule_name, description, mitre_technique,
      confidence_score, raw_data
    } = data;

    const result = await this.query(
      `INSERT INTO security_events 
       (organization_id, agent_id, event_type, severity, source_ip, destination_ip,
        source_port, destination_port, protocol, rule_id, rule_name, description,
        mitre_technique, confidence_score, raw_data)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) 
       RETURNING *`,
      [organization_id, agent_id, event_type, severity, source_ip, destination_ip,
       source_port, destination_port, protocol, rule_id, rule_name, description,
       mitre_technique, confidence_score, JSON.stringify(raw_data)]
    );
    return result.rows[0];
  }

  async getSecurityEventsCount(organizationId, filters = {}) {
    let query = 'SELECT COUNT(*) FROM security_events WHERE organization_id = $1';
    const params = [organizationId];

    if (filters.severity) {
      query += ` AND severity = $${params.length + 1}`;
      params.push(filters.severity);
    }

    if (filters.start_date) {
      query += ` AND created_at >= $${params.length + 1}`;
      params.push(filters.start_date);
    }

    if (filters.end_date) {
      query += ` AND created_at <= $${params.length + 1}`;
      params.push(filters.end_date);
    }

    const result = await this.query(query, params);
    return parseInt(result.rows[0].count);
  }

  // ===========================
  // IDS LOGS OPERATIONS
  // ===========================

  async getIdsLogs(organizationId, filters = {}) {
    let query = `
      SELECT il.*, na.name as agent_name
      FROM ids_logs il
      LEFT JOIN network_agents na ON il.agent_id = na.id
      WHERE il.organization_id = $1
    `;
    const params = [organizationId];

    if (filters.log_level) {
      query += ` AND il.log_level = $${params.length + 1}`;
      params.push(filters.log_level);
    }

    if (filters.source) {
      query += ` AND il.source = $${params.length + 1}`;
      params.push(filters.source);
    }

    if (filters.category) {
      query += ` AND il.category = $${params.length + 1}`;
      params.push(filters.category);
    }

    if (filters.start_date) {
      query += ` AND il.created_at >= $${params.length + 1}`;
      params.push(filters.start_date);
    }

    if (filters.end_date) {
      query += ` AND il.created_at <= $${params.length + 1}`;
      params.push(filters.end_date);
    }

    query += ' ORDER BY il.created_at DESC';

    if (filters.limit) {
      query += ` LIMIT $${params.length + 1}`;
      params.push(filters.limit);
    }

    if (filters.offset) {
      query += ` OFFSET $${params.length + 1}`;
      params.push(filters.offset);
    }

    const result = await this.query(query, params);
    return result.rows;
  }

  async createIdsLog(data) {
    const { organization_id, agent_id, log_level, source, category, message, metadata } = data;
    
    const result = await this.query(
      `INSERT INTO ids_logs (organization_id, agent_id, log_level, source, category, message, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [organization_id, agent_id, log_level, source, category, message, JSON.stringify(metadata)]
    );
    return result.rows[0];
  }

  // ===========================
  // DETECTION RULES OPERATIONS
  // ===========================

  async getDetectionRules(organizationId, filters = {}) {
    let query = 'SELECT * FROM detection_rules WHERE organization_id = $1';
    const params = [organizationId];

    if (filters.rule_type) {
      query += ` AND rule_type = $${params.length + 1}`;
      params.push(filters.rule_type);
    }

    if (filters.is_enabled !== undefined) {
      query += ` AND is_enabled = $${params.length + 1}`;
      params.push(filters.is_enabled);
    }

    query += ' ORDER BY created_at DESC';

    const result = await this.query(query, params);
    return result.rows;
  }

  async createDetectionRule(data) {
    const {
      organization_id, rule_id, name, description, rule_content,
      rule_type, severity, category, is_enabled
    } = data;

    const result = await this.query(
      `INSERT INTO detection_rules 
       (organization_id, rule_id, name, description, rule_content, rule_type, severity, category, is_enabled)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [organization_id, rule_id, name, description, rule_content, rule_type, severity, category, is_enabled]
    );
    return result.rows[0];
  }

  // ===========================
  // AI ANALYSIS OPERATIONS
  // ===========================

  async createAiAnalysisResult(data) {
    const {
      organization_id, analysis_type, input_data, results,
      confidence_score, model_version, processing_time_ms
    } = data;

    const result = await this.query(
      `INSERT INTO ai_analysis_results 
       (organization_id, analysis_type, input_data, results, confidence_score, model_version, processing_time_ms)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [organization_id, analysis_type, JSON.stringify(input_data), JSON.stringify(results),
       confidence_score, model_version, processing_time_ms]
    );
    return result.rows[0];
  }

  async getSecurityRecommendations(organizationId, filters = {}) {
    let query = 'SELECT * FROM security_recommendations WHERE organization_id = $1';
    const params = [organizationId];

    if (filters.status) {
      query += ` AND status = $${params.length + 1}`;
      params.push(filters.status);
    }

    if (filters.severity) {
      query += ` AND severity = $${params.length + 1}`;
      params.push(filters.severity);
    }

    query += ' ORDER BY created_at DESC';

    const result = await this.query(query, params);
    return result.rows;
  }

  async createSecurityRecommendation(data) {
    const {
      organization_id, recommendation_type, title, description,
      severity, implementation_effort, risk_reduction_score
    } = data;

    const result = await this.query(
      `INSERT INTO security_recommendations 
       (organization_id, recommendation_type, title, description, severity, implementation_effort, risk_reduction_score)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [organization_id, recommendation_type, title, description, severity, implementation_effort, risk_reduction_score]
    );
    return result.rows[0];
  }

  // ===========================
  // COMPLIANCE OPERATIONS
  // ===========================

  async getComplianceFrameworks() {
    const result = await this.query('SELECT * FROM compliance_frameworks ORDER BY name');
    return result.rows;
  }

  async getComplianceAssessments(organizationId) {
    const result = await this.query(
      `SELECT ca.*, cf.name as framework_name 
       FROM compliance_assessments ca
       JOIN compliance_frameworks cf ON ca.framework_id = cf.id
       WHERE ca.organization_id = $1
       ORDER BY ca.created_at DESC`,
      [organizationId]
    );
    return result.rows;
  }

  async createComplianceAssessment(data) {
    const { organization_id, framework_id, assessment_name, results } = data;
    
    const result = await this.query(
      `INSERT INTO compliance_assessments (organization_id, framework_id, assessment_name, results)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [organization_id, framework_id, assessment_name, JSON.stringify(results)]
    );
    return result.rows[0];
  }

  // ===========================
  // BILLING OPERATIONS
  // ===========================

  async getSubscriptionPlans() {
    const result = await this.query('SELECT * FROM subscription_plans WHERE is_active = true ORDER BY price_monthly');
    return result.rows;
  }

  async getBillingInfo(organizationId) {
    const result = await this.query(
      `SELECT bi.*, sp.name as plan_name, sp.price_monthly, sp.price_yearly, sp.features
       FROM billing_info bi
       LEFT JOIN subscription_plans sp ON bi.plan_id = sp.id
       WHERE bi.organization_id = $1`,
      [organizationId]
    );
    return result.rows[0];
  }

  async createBillingInfo(data) {
    const {
      organization_id, stripe_customer_id, subscription_id,
      plan_id, billing_email, payment_method
    } = data;

    const result = await this.query(
      `INSERT INTO billing_info 
       (organization_id, stripe_customer_id, subscription_id, plan_id, billing_email, payment_method)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [organization_id, stripe_customer_id, subscription_id, plan_id, billing_email, JSON.stringify(payment_method)]
    );
    return result.rows[0];
  }

  // ===========================
  // USAGE METRICS OPERATIONS
  // ===========================

  async getUsageMetrics(organizationId, metricType, startDate, endDate) {
    const result = await this.query(
      `SELECT * FROM usage_metrics 
       WHERE organization_id = $1 AND metric_type = $2 
       AND period_start >= $3 AND period_end <= $4
       ORDER BY period_start`,
      [organizationId, metricType, startDate, endDate]
    );
    return result.rows;
  }

  async createUsageMetric(data) {
    const { organization_id, metric_type, metric_value, period_start, period_end } = data;
    
    const result = await this.query(
      `INSERT INTO usage_metrics (organization_id, metric_type, metric_value, period_start, period_end)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [organization_id, metric_type, metric_value, period_start, period_end]
    );
    return result.rows[0];
  }

  // ===========================
  // AUDIT LOG OPERATIONS
  // ===========================

  async createAuditLog(data) {
    const {
      organization_id, user_id, action, resource_type,
      resource_id, details, ip_address, user_agent
    } = data;

    await this.query(
      `INSERT INTO audit_logs 
       (organization_id, user_id, action, resource_type, resource_id, details, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [organization_id, user_id, action, resource_type, resource_id, JSON.stringify(details), ip_address, user_agent]
    );
  }

  // ===========================
  // STATISTICS & ANALYTICS
  // ===========================

  async getDashboardStats(organizationId) {
    const queries = [
      // Total agents
      this.query('SELECT COUNT(*) as total_agents FROM network_agents WHERE organization_id = $1', [organizationId]),
      
      // Active agents (last heartbeat within 5 minutes)
      this.query(
        'SELECT COUNT(*) as active_agents FROM network_agents WHERE organization_id = $1 AND last_heartbeat > NOW() - INTERVAL \'5 minutes\'',
        [organizationId]
      ),
      
      // Total events today
      this.query(
        'SELECT COUNT(*) as events_today FROM security_events WHERE organization_id = $1 AND created_at >= CURRENT_DATE',
        [organizationId]
      ),
      
      // Critical events today
      this.query(
        'SELECT COUNT(*) as critical_events FROM security_events WHERE organization_id = $1 AND severity = \'critical\' AND created_at >= CURRENT_DATE',
        [organizationId]
      ),
      
      // Events by severity
      this.query(
        'SELECT severity, COUNT(*) as count FROM security_events WHERE organization_id = $1 AND created_at >= CURRENT_DATE GROUP BY severity',
        [organizationId]
      ),
      
      // Recent alerts
      this.query(
        'SELECT * FROM security_events WHERE organization_id = $1 ORDER BY created_at DESC LIMIT 10',
        [organizationId]
      )
    ];

    const results = await Promise.all(queries);

    return {
      totalAgents: parseInt(results[0].rows[0].total_agents),
      activeAgents: parseInt(results[1].rows[0].active_agents),
      eventsToday: parseInt(results[2].rows[0].events_today),
      criticalEvents: parseInt(results[3].rows[0].critical_events),
      eventsBySeverity: results[4].rows,
      recentAlerts: results[5].rows
    };
  }

  // ===========================
  // UTILITIES
  // ===========================

  async healthCheck() {
    try {
      const result = await this.query('SELECT 1 as health');
      return result.rows[0].health === 1;
    } catch (error) {
      console.error('Database health check failed:', error);
      return false;
    }
  }

  async close() {
    await this.pool.end();
  }
}

module.exports = new DatabaseService(); 